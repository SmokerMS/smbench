use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering as AtomicOrdering},
    Arc,
};

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep_until, Duration, Instant};

use crate::backend::{ConnectionState, SMBBackend};
use crate::ir::{Operation, WorkloadIr};

/// Summary returned after a scheduler run completes.
#[derive(Debug, Clone)]
pub struct RunSummary {
    /// Total operations dispatched to workers.
    pub dispatched: u64,
    /// Total operations completed successfully.
    pub succeeded: u64,
    /// Total operations completed with error.
    pub failed: u64,
    /// Invariant violations detected during the run.
    pub invariant_violations: u64,
    /// Wall-clock duration of the entire run.
    pub wall_clock: Duration,
    /// Per-client latency statistics.
    pub client_stats: Vec<ClientLatencyStats>,
}

/// Latency statistics for a single client.
#[derive(Debug, Clone)]
pub struct ClientLatencyStats {
    pub client_id: String,
    pub operation_count: u64,
    pub min_latency: Duration,
    pub max_latency: Duration,
    pub total_latency: Duration,
}

impl ClientLatencyStats {
    pub fn mean_latency(&self) -> Duration {
        if self.operation_count == 0 {
            Duration::ZERO
        } else {
            self.total_latency / self.operation_count as u32
        }
    }
}

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
    pub in_flight_started: Option<Instant>,
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
    pub invariant_mode: InvariantMode,
    pub debug_dump_on_error: bool,
    pub watchdog_interval: Duration,
    pub inflight_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum InvariantMode {
    Panic,
    LogAndContinue,
}

#[derive(Debug, Default)]
struct SchedulerMetrics {
    dispatch_count: AtomicU64,
    completion_count: AtomicU64,
    error_count: AtomicU64,
    invariant_violations: AtomicU64,
}

/// Tracks per-client latency accumulation during a run.
struct ClientLatencyAccumulator {
    client_id: String,
    count: u64,
    min: Duration,
    max: Duration,
    total: Duration,
}

impl ClientLatencyAccumulator {
    fn new(client_id: String) -> Self {
        Self {
            client_id,
            count: 0,
            min: Duration::from_secs(u64::MAX),
            max: Duration::ZERO,
            total: Duration::ZERO,
        }
    }

    fn record(&mut self, latency: Duration) {
        self.count += 1;
        if latency < self.min {
            self.min = latency;
        }
        if latency > self.max {
            self.max = latency;
        }
        self.total += latency;
    }

    fn into_stats(self) -> ClientLatencyStats {
        ClientLatencyStats {
            client_id: self.client_id,
            operation_count: self.count,
            min_latency: if self.count == 0 {
                Duration::ZERO
            } else {
                self.min
            },
            max_latency: self.max,
            total_latency: self.total,
        }
    }
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
    invariant_mode: InvariantMode,
    debug_dump_on_error: bool,
    watchdog_interval: Duration,
    inflight_timeout: Duration,
    metrics: SchedulerMetrics,
    latency_accumulators: Vec<ClientLatencyAccumulator>,
    /// Shared connection map so we can clean up after the run.
    connection_map: Option<Arc<Mutex<HashMap<u32, Arc<Mutex<ConnectionState>>>>>>,
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
                in_flight_started: None,
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

        let latency_accumulators = client_queues
            .iter()
            .map(|q| ClientLatencyAccumulator::new(q.client_id.clone()))
            .collect();

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
            invariant_mode: config.invariant_mode,
            debug_dump_on_error: config.debug_dump_on_error,
            watchdog_interval: config.watchdog_interval,
            inflight_timeout: config.inflight_timeout,
            metrics: SchedulerMetrics::default(),
            latency_accumulators,
            connection_map: None,
        })
    }

    pub async fn run(mut self, backend: Arc<dyn SMBBackend>) -> Result<RunSummary> {
        crate::backend::ensure_backend_allowed(backend.as_ref(), self.backend_mode)?;
        let run_start = Instant::now();
        self.start_time = Some(run_start);
        self.spawn_workers(backend).await?;

        loop {
            if let Some(next_deadline) = self.find_next_eligible_deadline() {
                let watchdog = tokio::time::sleep(self.watchdog_interval);
                tokio::pin!(watchdog);
                tokio::select! {
                    _ = sleep_until(next_deadline) => {
                        if let Some(event) = self.pop_next_eligible_event() {
                            self.dispatch_event(event).await?;
                        }
                    }
                    Some(completion) = self.completion_rx.recv() => {
                        self.handle_completion(completion).await?;
                    }
                    _ = &mut watchdog => {
                        self.check_inflight_timeouts();
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
                tokio::select! {
                    Some(completion) = self.completion_rx.recv() => {
                        self.handle_completion(completion).await?;
                    }
                    _ = tokio::time::sleep(self.watchdog_interval) => {
                        self.check_inflight_timeouts();
                    }
                    else => {
                        return Err(anyhow!("Completion channel closed before completion"));
                    }
                }
            }
        }

        // Connection cleanup: close all open handles and drop connections.
        self.cleanup_connections().await;

        let wall_clock = run_start.elapsed();
        let dispatched = self.metrics.dispatch_count.load(AtomicOrdering::Relaxed);
        let completed = self.metrics.completion_count.load(AtomicOrdering::Relaxed);
        let failed = self.metrics.error_count.load(AtomicOrdering::Relaxed);
        let invariant_violations = self
            .metrics
            .invariant_violations
            .load(AtomicOrdering::Relaxed);
        let client_stats = self
            .latency_accumulators
            .drain(..)
            .map(|a| a.into_stats())
            .collect();

        Ok(RunSummary {
            dispatched,
            succeeded: completed.saturating_sub(failed),
            failed,
            invariant_violations,
            wall_clock,
            client_stats,
        })
    }

    /// Close all connections and their handles after a workload completes.
    async fn cleanup_connections(&mut self) {
        if let Some(conn_map) = self.connection_map.take() {
            let mut map = conn_map.lock().await;
            let keys: Vec<u32> = map.keys().copied().collect();
            for key in keys {
                if let Some(conn_arc) = map.remove(&key) {
                    let mut conn = conn_arc.lock().await;
                    conn.close_all_handles().await;
                }
            }
            tracing::debug!("All connections cleaned up");
        }
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
            return self.handle_invariant_violation(
                "Invariant violation: client already in-flight",
                Some(event),
            );
        }

        let op = queue
            .pending_ops
            .pop_front()
            .ok_or_else(|| anyhow!("Queue unexpectedly empty"))?;
        queue.in_flight_op = Some(op.op_id().to_string());
        queue.in_flight_started = Some(Instant::now());
        self.metrics
            .dispatch_count
            .fetch_add(1, AtomicOrdering::Relaxed);

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
        if completion.client_idx as usize >= self.client_queues.len() {
            return self.handle_invariant_violation(
                &format!("Completion client_idx out of range: {}", completion.client_idx),
                None,
            );
        }
        let expected = self.client_queues[completion.client_idx as usize]
            .in_flight_op
            .clone();
        if expected.as_deref() != Some(&completion.op_id) {
            return self.handle_invariant_violation(
                &format!(
                    "Completion mismatch: expected {:?}, got {}",
                    expected, completion.op_id
                ),
                None,
            );
        }

        let idx = completion.client_idx as usize;
        let queue = &mut self.client_queues[idx];
        queue.in_flight_op = None;
        queue.in_flight_started = None;
        self.metrics
            .completion_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        if matches!(completion.status, CompletionStatus::Error { .. }) {
            self.metrics
                .error_count
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        if idx < self.latency_accumulators.len() {
            self.latency_accumulators[idx].record(completion.latency);
        }
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

    fn handle_invariant_violation(
        &mut self,
        message: &str,
        event: Option<ScheduledEvent>,
    ) -> Result<()> {
        self.metrics
            .invariant_violations
            .fetch_add(1, AtomicOrdering::Relaxed);
        tracing::error!(error = message, "Invariant violation");
        if self.debug_dump_on_error {
            self.log_state_dump("invariant_violation");
        }
        match self.invariant_mode {
            InvariantMode::Panic => panic!("{message}"),
            InvariantMode::LogAndContinue => {
                if let Some(event) = event {
                    self.heap.push(std::cmp::Reverse(event));
                }
                Ok(())
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.heap.is_empty()
            && self
                .client_queues
                .iter()
                .all(|q| q.pending_ops.is_empty() && q.in_flight_op.is_none())
    }

    fn check_inflight_timeouts(&self) {
        let now = Instant::now();
        for queue in &self.client_queues {
            if let (Some(op_id), Some(started)) = (&queue.in_flight_op, queue.in_flight_started) {
                let elapsed = now.saturating_duration_since(started);
                if elapsed > self.inflight_timeout {
                    tracing::warn!(
                        client_idx = queue.client_idx,
                        op_id = op_id,
                        elapsed_ms = elapsed.as_millis(),
                        "In-flight operation exceeded timeout"
                    );
                    if self.debug_dump_on_error {
                        self.log_state_dump("inflight_timeout");
                    }
                }
            }
        }
    }

    fn log_state_dump(&self, reason: &str) {
        let pending_total: usize = self
            .client_queues
            .iter()
            .map(|q| q.pending_ops.len())
            .sum();
        let inflight_total: usize = self
            .client_queues
            .iter()
            .filter(|q| q.in_flight_op.is_some())
            .count();
        let violations = self
            .metrics
            .invariant_violations
            .load(AtomicOrdering::Relaxed);
        tracing::error!(
            reason = reason,
            heap_len = self.heap.len(),
            pending_total = pending_total,
            inflight_total = inflight_total,
            dispatch_count = self.metrics.dispatch_count.load(AtomicOrdering::Relaxed),
            completion_count = self.metrics.completion_count.load(AtomicOrdering::Relaxed),
            invariant_violations = violations,
            "Scheduler state dump"
        );
    }

    async fn spawn_workers(&mut self, backend: Arc<dyn SMBBackend>) -> Result<()> {
        let Some(work_rx) = self.work_rx.take() else {
            return Err(anyhow!("Worker pool already started"));
        };

        let work_rx = Arc::new(Mutex::new(work_rx));
        let connection_map: Arc<Mutex<HashMap<u32, Arc<Mutex<ConnectionState>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        self.connection_map = Some(connection_map.clone());
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
                            if let Some(mut rx) = conn_arc.lock().await.take_oplock_receiver() {
                                let handler_conn = conn_arc.clone();
                                tokio::spawn(async move {
                                    while let Some(break_msg) = rx.recv().await {
                                        let mut conn = handler_conn.lock().await;
                                        conn.handle_oplock_break(break_msg).await;
                                    }
                                });
                            }
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
    #[should_panic(expected = "Completion mismatch")]
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
                invariant_mode: InvariantMode::Panic,
                debug_dump_on_error: false,
                watchdog_interval: Duration::from_millis(50),
                inflight_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();

        scheduler.client_queues[0].in_flight_op = Some("op_1".to_string());

        let _ = scheduler
            .handle_completion(CompletionEvent {
                client_idx: 0,
                op_id: "wrong_op".to_string(),
                status: CompletionStatus::Success,
                latency: Duration::from_millis(1),
            })
            .await;
    }

    #[tokio::test]
    async fn test_completion_mismatch_log_and_continue() {
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
                invariant_mode: InvariantMode::LogAndContinue,
                debug_dump_on_error: false,
                watchdog_interval: Duration::from_millis(50),
                inflight_timeout: Duration::from_secs(1),
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

        assert!(result.is_ok(), "Expected mismatch to be logged");
        assert_eq!(
            scheduler.client_queues[0].in_flight_op.as_deref(),
            Some("op_1")
        );
    }

    #[tokio::test]
    async fn test_completion_invalid_client_idx_log_and_continue() {
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
                invariant_mode: InvariantMode::LogAndContinue,
                debug_dump_on_error: false,
                watchdog_interval: Duration::from_millis(50),
                inflight_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();

        let result = scheduler
            .handle_completion(CompletionEvent {
                client_idx: 99,
                op_id: "op_1".to_string(),
                status: CompletionStatus::Success,
                latency: Duration::from_millis(1),
            })
            .await;

        assert!(result.is_ok(), "Expected out-of-range to be logged");
    }
}
