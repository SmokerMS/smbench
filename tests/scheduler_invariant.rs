use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use smbench::backend::{ConnectionState, SMBBackend, SMBConnectionInner, SMBFileHandle};
use smbench::ir::{ClientSpec, Metadata, OpenMode, Operation, WorkloadIr};
use smbench::scheduler::{InvariantMode, Scheduler, SchedulerConfig};

struct TestBackend {
    delay: Duration,
    violations: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl SMBBackend for TestBackend {
    fn capabilities(&self) -> smbench::backend::BackendCapabilities {
        smbench::backend::BackendCapabilities {
            name: "test".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, client_id: &str) -> Result<ConnectionState> {
        Ok(ConnectionState::new(Box::new(TestConnection {
            client_id: client_id.to_string(),
            delay: self.delay,
            in_flight: Arc::new(Mutex::new(false)),
            violations: self.violations.clone(),
        })))
    }
}

struct TestConnection {
    client_id: String,
    delay: Duration,
    in_flight: Arc<Mutex<bool>>,
    violations: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl SMBConnectionInner for TestConnection {
    async fn open_simple(
        &self,
        _path: &str,
        _mode: OpenMode,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(TestHandle))
    }

    async fn open_extended(
        &self,
        _path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(TestHandle))
    }

    async fn execute_misc(&self, op: &Operation) -> Result<()> {
        {
            let mut in_flight = self.in_flight.lock().await;
            if *in_flight {
                let mut violations = self.violations.lock().await;
                violations.push(format!(
                    "overlap client={} op_id={}",
                    self.client_id,
                    op.op_id()
                ));
            }
            *in_flight = true;
        }

        sleep(self.delay).await;

        let mut in_flight = self.in_flight.lock().await;
        *in_flight = false;
        Ok(())
    }
}

struct TestHandle;

#[async_trait]
impl SMBFileHandle for TestHandle {
    async fn read(&self, _offset: u64, _length: u64) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn write(&self, _offset: u64, data: &[u8]) -> Result<u64> {
        Ok(data.len() as u64)
    }

    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

fn build_ir(ops_per_client: u32, clients: &[&str]) -> WorkloadIr {
    let mut operations = Vec::new();
    for (client_idx, client_id) in clients.iter().enumerate() {
        for op_idx in 0..ops_per_client {
            operations.push(Operation::Delete {
                op_id: format!("op_{}_{}", client_idx, op_idx),
                client_id: client_id.to_string(),
                timestamp_us: 10_000 + (op_idx as u64) * 10,
                path: format!("/tmp/file_{}_{}", client_idx, op_idx),
            });
        }
    }

    WorkloadIr {
        version: 1,
        metadata: Metadata {
            source: "test".to_string(),
            duration_seconds: 1.0,
            client_count: clients.len() as u32,
        },
        clients: clients
            .iter()
            .map(|id| ClientSpec {
                client_id: id.to_string(),
                operation_count: ops_per_client,
            })
            .collect(),
        operations,
    }
}

#[tokio::test]
async fn test_scheduler_invariant_no_overlap_single_client() {
    let violations = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TestBackend {
        delay: Duration::from_millis(20),
        violations: violations.clone(),
    });

    let ir = build_ir(5, &["client_1"]);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 4,
            time_scale: 1.0,
            worker_count: 2,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: InvariantMode::Panic,
            debug_dump_on_error: false,
            watchdog_interval: Duration::from_millis(50),
            inflight_timeout: Duration::from_secs(2),
        },
    )
    .unwrap();

    scheduler.run(backend).await.unwrap();

    let violations = violations.lock().await;
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[tokio::test]
async fn test_scheduler_invariant_verification_multi_client() {
    let violations = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TestBackend {
        delay: Duration::from_millis(30),
        violations: violations.clone(),
    });

    let ir = build_ir(4, &["client_a", "client_b", "client_c"]);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 3,
            time_scale: 1.0,
            worker_count: 3,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: InvariantMode::Panic,
            debug_dump_on_error: false,
            watchdog_interval: Duration::from_millis(50),
            inflight_timeout: Duration::from_secs(2),
        },
    )
    .unwrap();

    scheduler.run(backend).await.unwrap();

    let violations = violations.lock().await;
    assert!(violations.is_empty(), "violations: {violations:?}");
}
