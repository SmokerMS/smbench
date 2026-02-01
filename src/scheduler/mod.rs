use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep_until, Duration, Instant};

use crate::backend::{ConnectionState, SMBBackend};
use crate::ir::{Operation, WorkloadIr};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ScheduledEvent {
    pub deadline_us: u64,
    pub client_idx: u32,
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deadline_us
            .cmp(&other.deadline_us)
            .then_with(|| self.client_idx.cmp(&other.client_idx))
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct ClientQueue {
    pub client_idx: u32,
    pub client_id: String,
    pub pending_ops: VecDeque<Operation>,
    pub in_flight_op: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompletionEvent {
    pub client_idx: u32,
    pub op_id: String,
    pub status: CompletionStatus,
    pub latency: Duration,
}

#[derive(Debug, Clone)]
pub enum CompletionStatus {
    Success,
    Error { message: String },
}

pub struct WorkItem {
    pub client_idx: u32,
    pub client_id: String,
    pub op_id: String,
    pub operation: Operation,
    pub _permit: tokio::sync::OwnedSemaphorePermit,
}

pub struct SchedulerConfig {
    pub max_concurrent: usize,
    pub time_scale: f64,
    pub worker_count: usize,
    pub backend_mode: crate::backend::BackendMode,
}

pub struct Scheduler {
    heap: BinaryHeap<std::cmp::Reverse<ScheduledEvent>>,
    client_queues: Vec<ClientQueue>,
    #[allow(dead_code)]
    client_index: HashMap<String, u32>,
    semaphore: Arc<Semaphore>,
    work_tx: mpsc::Sender<WorkItem>,
    work_rx: Option<mpsc::Receiver<WorkItem>>,
    completion_tx: mpsc::Sender<CompletionEvent>,
    completion_rx: mpsc::Receiver<CompletionEvent>,
    start_time: Option<Instant>,
    time_scale: f64,
    worker_count: usize,
    backend_mode: crate::backend::BackendMode,
}

impl Scheduler {
    pub fn from_ir(ir: WorkloadIr, config: SchedulerConfig) -> Result<Self> {
        let mut client_index = HashMap::new();
        let mut client_queues = Vec::new();
        for (idx, client) in ir.clients.iter().enumerate() {
            let client_idx = idx as u32;
            client_index.insert(client.client_id.clone(), client_idx);
            client_queues.push(ClientQueue {
                client_idx,
                client_id: client.client_id.clone(),
                pending_ops: VecDeque::new(),
                in_flight_op: None,
            });
        }

        for op in ir.operations.into_iter() {
            let client_idx = client_index
                .get(op.client_id())
                .copied()
                .ok_or_else(|| anyhow!("Unknown client_id: {}", op.client_id()))?;
            client_queues[client_idx as usize]
                .pending_ops
                .push_back(op);
        }

        for queue in &mut client_queues {
            let mut ops: Vec<_> = queue.pending_ops.drain(..).collect();
            ops.sort_by_key(|op| op.timestamp_us());
            queue.pending_ops.extend(ops);
        }

        let mut heap = BinaryHeap::new();
        for queue in &client_queues {
            if let Some(op) = queue.pending_ops.front() {
                let deadline_us = (op.timestamp_us() as f64 * config.time_scale) as u64;
                heap.push(std::cmp::Reverse(ScheduledEvent {
                    deadline_us,
                    client_idx: queue.client_idx,
                }));
            }
        }

        let (work_tx, work_rx) = mpsc::channel(config.max_concurrent * 2 + 1);
        let (completion_tx, completion_rx) = mpsc::channel(config.max_concurrent * 2 + 1);

        Ok(Self {
            heap,
            client_queues,
            client_index,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            work_tx,
            work_rx: Some(work_rx),
            completion_tx,
            completion_rx,
            start_time: None,
            time_scale: config.time_scale,
            worker_count: config.worker_count,
            backend_mode: config.backend_mode,
        })
    }

    pub async fn run(mut self, backend: Arc<dyn SMBBackend>) -> Result<()> {
        crate::backend::ensure_backend_allowed(backend.as_ref(), self.backend_mode)?;
        self.start_time = Some(Instant::now());
        self.spawn_workers(backend).await?;

        loop {
            if let Some(next_deadline) = self.find_next_eligible_deadline() {
                tokio::select! {
                    _ = sleep_until(next_deadline) => {
                        if let Some(event) = self.pop_next_eligible_event() {
                            self.dispatch_event(event).await?;
                        }
                    }
                    Some(completion) = self.completion_rx.recv() => {
                        self.handle_completion(completion).await?;
                    }
                    else => {
                        if self.is_complete() {
                            break;
                        }
                    }
                }
            } else {
                if self.is_complete() {
                    break;
                }

                match self.completion_rx.recv().await {
                    Some(completion) => {
                        self.handle_completion(completion).await?;
                    }
                    None => {
                        return Err(anyhow!("Completion channel closed before completion"));
                    }
                }
            }
        }

        Ok(())
    }

    fn find_next_eligible_deadline(&self) -> Option<Instant> {
        let mut selected: Option<ScheduledEvent> = None;
        for std::cmp::Reverse(event) in self.heap.iter() {
            let queue = &self.client_queues[event.client_idx as usize];
            if queue.in_flight_op.is_none() {
                if selected
                    .as_ref()
                    .map(|current| event.deadline_us < current.deadline_us)
                    .unwrap_or(true)
                {
                    selected = Some(*event);
                }
            }
        }
        let start_time = self.start_time?;
        selected.map(|event| start_time + Duration::from_micros(event.deadline_us))
    }

    fn pop_next_eligible_event(&mut self) -> Option<ScheduledEvent> {
        let mut skipped = Vec::new();
        let mut selected = None;
        while let Some(std::cmp::Reverse(event)) = self.heap.pop() {
            let queue = &self.client_queues[event.client_idx as usize];
            if queue.in_flight_op.is_none() {
                selected = Some(event);
                break;
            }
            skipped.push(std::cmp::Reverse(event));
        }
        for item in skipped {
            self.heap.push(item);
        }
        selected
    }

    async fn dispatch_event(&mut self, event: ScheduledEvent) -> Result<()> {
        let queue = &mut self.client_queues[event.client_idx as usize];
        if queue.in_flight_op.is_some() {
            return Err(anyhow!("Invariant violation: client already in-flight"));
        }

        let op = queue
            .pending_ops
            .pop_front()
            .ok_or_else(|| anyhow!("Queue unexpectedly empty"))?;
        queue.in_flight_op = Some(op.op_id().to_string());

        let permit = self.semaphore.clone().acquire_owned().await?;
        self.work_tx
            .send(WorkItem {
                client_idx: event.client_idx,
                client_id: queue.client_id.clone(),
                op_id: op.op_id().to_string(),
                operation: op,
                _permit: permit,
            })
            .await?;

        Ok(())
    }

    async fn handle_completion(&mut self, completion: CompletionEvent) -> Result<()> {
        let queue = &mut self.client_queues[completion.client_idx as usize];
        let expected = queue.in_flight_op.as_ref();
        if expected != Some(&completion.op_id) {
            return Err(anyhow!(
                "Completion mismatch: expected {:?}, got {}",
                expected,
                completion.op_id
            ));
        }

        queue.in_flight_op = None;
        if let Some(next_op) = queue.pending_ops.front() {
            let deadline_us = (next_op.timestamp_us() as f64 * self.time_scale) as u64;
            self.heap.push(std::cmp::Reverse(ScheduledEvent {
                deadline_us,
                client_idx: completion.client_idx,
            }));
        }

        tracing::info!(
            client_idx = completion.client_idx,
            op_id = completion.op_id,
            status = ?completion.status,
            latency_ms = completion.latency.as_millis(),
            "Operation completed"
        );

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.heap.is_empty()
            && self
                .client_queues
                .iter()
                .all(|q| q.pending_ops.is_empty() && q.in_flight_op.is_none())
    }

    async fn spawn_workers(&mut self, backend: Arc<dyn SMBBackend>) -> Result<()> {
        let Some(work_rx) = self.work_rx.take() else {
            return Err(anyhow!("Worker pool already started"));
        };

        let work_rx = Arc::new(Mutex::new(work_rx));
        let connection_map: Arc<Mutex<HashMap<u32, Arc<Mutex<ConnectionState>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let completion_tx = self.completion_tx.clone();

        for _ in 0..self.worker_count {
            let work_rx = work_rx.clone();
            let completion_tx = completion_tx.clone();
            let backend = backend.clone();
            let connection_map = connection_map.clone();

            tokio::spawn(async move {
                loop {
                    let work = {
                        let mut rx = work_rx.lock().await;
                        rx.recv().await
                    };
                    let Some(work) = work else {
                        break;
                    };

                    let span = tracing::info_span!(
                        "execute_op",
                        client_idx = work.client_idx,
                        op_id = work.op_id
                    );
                    let _guard = span.enter();

                    let conn_arc = {
                        let mut connections = connection_map.lock().await;
                        if let Some(conn) = connections.get(&work.client_idx) {
                            conn.clone()
                        } else {
                            let conn = match backend.connect(&work.client_id).await {
                                Ok(conn) => conn,
                                Err(err) => {
                                    let _ = completion_tx
                                        .send(CompletionEvent {
                                            client_idx: work.client_idx,
                                            op_id: work.op_id.clone(),
                                            status: CompletionStatus::Error {
                                                message: err.to_string(),
                                            },
                                            latency: Duration::from_millis(0),
                                        })
                                        .await;
                                    continue;
                                }
                            };
                            let conn_arc = Arc::new(Mutex::new(conn));
                            connections.insert(work.client_idx, conn_arc.clone());
                            conn_arc
                        }
                    };

                    let start = Instant::now();
                    let status = {
                        let mut conn = conn_arc.lock().await;
                        match conn.execute(&work.operation).await {
                            Ok(()) => CompletionStatus::Success,
                            Err(err) => CompletionStatus::Error {
                                message: err.to_string(),
                            },
                        }
                    };
                    let latency = start.elapsed();

                    let _ = completion_tx
                        .send(CompletionEvent {
                            client_idx: work.client_idx,
                            op_id: work.op_id.clone(),
                            status,
                            latency,
                        })
                        .await;
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ClientSpec, Metadata, Operation, WorkloadIr};

    #[tokio::test]
    async fn test_completion_mismatch_rejected() {
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "test".to_string(),
                duration_seconds: 1.0,
                client_count: 1,
            },
            clients: vec![ClientSpec {
                client_id: "client_1".to_string(),
                operation_count: 1,
            }],
            operations: vec![Operation::Delete {
                op_id: "op_1".to_string(),
                client_id: "client_1".to_string(),
                timestamp_us: 0,
                path: "/tmp/file".to_string(),
            }],
        };

        let mut scheduler = Scheduler::from_ir(
            ir,
            SchedulerConfig {
                max_concurrent: 1,
                time_scale: 1.0,
                worker_count: 1,
                backend_mode: crate::backend::BackendMode::Development,
            },
        )
        .unwrap();

        scheduler.client_queues[0].in_flight_op = Some("op_1".to_string());

        let result = scheduler
            .handle_completion(CompletionEvent {
                client_idx: 0,
                op_id: "wrong_op".to_string(),
                status: CompletionStatus::Success,
                latency: Duration::from_millis(1),
            })
            .await;

        assert!(result.is_err(), "Expected completion mismatch error");
    }
}
