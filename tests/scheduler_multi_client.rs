use std::sync::Arc;
use std::time::Instant as StdInstant;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::Duration;

use smbench::backend::{
    BackendCapabilities, BackendMode, ConnectionState, SMBBackend, SMBConnectionInner,
    SMBFileHandle,
};
use smbench::ir::{ClientSpec, Metadata, OpenMode, Operation, WorkloadIr};
use smbench::scheduler::{InvariantMode, Scheduler, SchedulerConfig};

// ---------------------------------------------------------------------------
// Helpers: configurable test backend
// ---------------------------------------------------------------------------

/// A backend that tracks execution order and optionally injects delays.
struct TrackingBackend {
    delay: Duration,
    log: Arc<Mutex<Vec<(String, String)>>>,
}

#[async_trait]
impl SMBBackend for TrackingBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "tracking".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        Ok(ConnectionState::new(Box::new(TrackingConnection {
            delay: self.delay,
            log: self.log.clone(),
        })))
    }
}

struct TrackingConnection {
    delay: Duration,
    log: Arc<Mutex<Vec<(String, String)>>>,
}

#[async_trait]
impl SMBConnectionInner for TrackingConnection {
    async fn open_simple(&self, _path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }

    async fn open_extended(
        &self,
        _path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }

    async fn execute_misc(&self, op: &Operation) -> Result<()> {
        {
            let mut log = self.log.lock().await;
            log.push((op.client_id().to_string(), op.op_id().to_string()));
        }
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        Ok(())
    }
}

struct NoopHandle;

#[async_trait]
impl SMBFileHandle for NoopHandle {
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

/// A backend that fails on connect for specific client IDs.
struct FailingBackend {
    fail_clients: Vec<String>,
}

#[async_trait]
impl SMBBackend for FailingBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "failing".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, client_id: &str) -> Result<ConnectionState> {
        if self.fail_clients.contains(&client_id.to_string()) {
            return Err(anyhow!("Connection refused for {}", client_id));
        }
        Ok(ConnectionState::new(Box::new(FailingConnection)))
    }
}

struct FailingConnection;

#[async_trait]
impl SMBConnectionInner for FailingConnection {
    async fn open_simple(&self, _path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }
    async fn open_extended(
        &self,
        _path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }
    async fn execute_misc(&self, _op: &Operation) -> Result<()> {
        Ok(())
    }
}

/// A backend where operations on specific clients fail.
struct OpFailBackend {
    fail_ops_for: Vec<String>,
}

#[async_trait]
impl SMBBackend for OpFailBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "op-fail".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        Ok(ConnectionState::new(Box::new(OpFailConnection {
            fail_ops_for: self.fail_ops_for.clone(),
        })))
    }
}

struct OpFailConnection {
    fail_ops_for: Vec<String>,
}

#[async_trait]
impl SMBConnectionInner for OpFailConnection {
    async fn open_simple(&self, _path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }
    async fn open_extended(
        &self,
        _path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NoopHandle))
    }
    async fn execute_misc(&self, op: &Operation) -> Result<()> {
        if self.fail_ops_for.contains(&op.client_id().to_string()) {
            return Err(anyhow!("Injected failure for {}", op.client_id()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IR builder helpers
// ---------------------------------------------------------------------------

fn build_ir_delete(ops_per_client: u32, clients: &[&str], spacing_us: u64) -> WorkloadIr {
    let mut operations = Vec::new();
    for (client_idx, client_id) in clients.iter().enumerate() {
        for op_idx in 0..ops_per_client {
            operations.push(Operation::Delete {
                op_id: format!("op_{}_{}", client_idx, op_idx),
                client_id: client_id.to_string(),
                timestamp_us: (op_idx as u64) * spacing_us,
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

fn default_config() -> SchedulerConfig {
    SchedulerConfig {
        max_concurrent: 64,
        time_scale: 1.0,
        worker_count: 4,
        backend_mode: BackendMode::Development,
        invariant_mode: InvariantMode::LogAndContinue,
        debug_dump_on_error: false,
        watchdog_interval: Duration::from_millis(100),
        inflight_timeout: Duration::from_secs(5),
    }
}

// ---------------------------------------------------------------------------
// A3: Multi-client scheduler tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_10_client_concurrent_dispatch() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TrackingBackend {
        delay: Duration::from_millis(5),
        log: log.clone(),
    });

    let client_names: Vec<String> = (0..10).map(|i| format!("client_{}", i)).collect();
    let client_refs: Vec<&str> = client_names.iter().map(|s| s.as_str()).collect();

    let ir = build_ir_delete(3, &client_refs, 1_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 10,
            worker_count: 4,
            time_scale: 0.001, // very fast
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    assert_eq!(summary.dispatched, 30, "10 clients * 3 ops each");
    assert_eq!(summary.succeeded, 30);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.invariant_violations, 0);
    assert_eq!(summary.client_stats.len(), 10);

    // Verify all operations were logged
    let log = log.lock().await;
    assert_eq!(log.len(), 30);

    // Verify each client got exactly 3 operations
    for i in 0..10 {
        let client = format!("client_{}", i);
        let count = log.iter().filter(|(c, _)| c == &client).count();
        assert_eq!(count, 3, "Client {} should have 3 ops", client);
    }
}

#[tokio::test]
async fn test_time_scale_halves_wall_clock() {
    let log = Arc::new(Mutex::new(Vec::new()));

    // Build workload: 1 client, 5 ops spaced 100ms apart
    // At time_scale=1.0 this should take ~400ms (4 gaps)
    // At time_scale=0.5 this should take ~200ms
    let ir = build_ir_delete(5, &["client_1"], 100_000); // 100ms spacing

    // Run at time_scale 1.0
    let backend1 = Arc::new(TrackingBackend {
        delay: Duration::ZERO,
        log: log.clone(),
    });
    let scheduler1 = Scheduler::from_ir(
        ir.clone(),
        SchedulerConfig {
            time_scale: 1.0,
            max_concurrent: 1,
            worker_count: 1,
            ..default_config()
        },
    )
    .unwrap();

    let start1 = StdInstant::now();
    let summary1 = scheduler1.run(backend1).await.unwrap();
    let elapsed1 = start1.elapsed();

    // Run at time_scale 0.5
    let backend2 = Arc::new(TrackingBackend {
        delay: Duration::ZERO,
        log: Arc::new(Mutex::new(Vec::new())),
    });
    let scheduler2 = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            time_scale: 0.5,
            max_concurrent: 1,
            worker_count: 1,
            ..default_config()
        },
    )
    .unwrap();

    let start2 = StdInstant::now();
    let summary2 = scheduler2.run(backend2).await.unwrap();
    let elapsed2 = start2.elapsed();

    assert_eq!(summary1.dispatched, 5);
    assert_eq!(summary2.dispatched, 5);

    // time_scale=0.5 should be roughly half the wall-clock time of time_scale=1.0
    // Allow generous tolerance since CI/test environments can be slow
    let ratio = elapsed1.as_millis() as f64 / elapsed2.as_millis().max(1) as f64;
    assert!(
        ratio > 1.3,
        "Expected time_scale=1.0 ({:?}) to be significantly slower than time_scale=0.5 ({:?}), ratio={}",
        elapsed1,
        elapsed2,
        ratio
    );
}

#[tokio::test]
async fn test_per_client_sequential_ordering() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TrackingBackend {
        delay: Duration::from_millis(10),
        log: log.clone(),
    });

    // 3 clients, 5 ops each, timestamps spaced so order is deterministic per-client
    let ir = build_ir_delete(5, &["a", "b", "c"], 10_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 3, // allow all 3 clients in parallel
            worker_count: 3,
            time_scale: 0.001,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();
    assert_eq!(summary.dispatched, 15);
    assert_eq!(summary.succeeded, 15);

    // Verify per-client ordering: for each client, op_X_0 appears before op_X_1, etc.
    let log = log.lock().await;
    for client_idx in 0..3 {
        let client_ops: Vec<&str> = log
            .iter()
            .filter(|(c, _)| {
                c == match client_idx {
                    0 => "a",
                    1 => "b",
                    _ => "c",
                }
            })
            .map(|(_, op)| op.as_str())
            .collect();

        for i in 0..client_ops.len() - 1 {
            let current_idx: u32 = client_ops[i].split('_').last().unwrap().parse().unwrap();
            let next_idx: u32 = client_ops[i + 1].split('_').last().unwrap().parse().unwrap();
            assert!(
                current_idx < next_idx,
                "Client {} ops out of order: {} before {}",
                client_idx,
                client_ops[i],
                client_ops[i + 1]
            );
        }
    }
}

#[tokio::test]
async fn test_100_client_stress() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TrackingBackend {
        delay: Duration::ZERO,
        log: log.clone(),
    });

    let client_names: Vec<String> = (0..100).map(|i| format!("c{}", i)).collect();
    let client_refs: Vec<&str> = client_names.iter().map(|s| s.as_str()).collect();

    let ir = build_ir_delete(10, &client_refs, 100); // 100us spacing, very tight
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 50,
            worker_count: 8,
            time_scale: 0.001,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    assert_eq!(summary.dispatched, 1000, "100 clients * 10 ops");
    assert_eq!(summary.succeeded, 1000);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.invariant_violations, 0);
    assert_eq!(summary.client_stats.len(), 100);

    // Verify every client has exactly 10 operations
    let log = log.lock().await;
    for name in &client_names {
        let count = log.iter().filter(|(c, _)| c == name).count();
        assert_eq!(count, 10, "Client {} should have 10 ops, got {}", name, count);
    }
}

#[tokio::test]
async fn test_run_summary_latency_stats() {
    let backend = Arc::new(TrackingBackend {
        delay: Duration::from_millis(5),
        log: Arc::new(Mutex::new(Vec::new())),
    });

    let ir = build_ir_delete(3, &["x", "y"], 1_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            time_scale: 0.001,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    assert_eq!(summary.client_stats.len(), 2);
    for stats in &summary.client_stats {
        assert_eq!(stats.operation_count, 3);
        assert!(stats.min_latency > Duration::ZERO);
        assert!(stats.max_latency >= stats.min_latency);
        assert!(stats.mean_latency() > Duration::ZERO);
    }
}

// ---------------------------------------------------------------------------
// A4: Error recovery tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_connection_failure_log_and_continue() {
    // client_bad fails on connect, client_good succeeds
    let backend = Arc::new(FailingBackend {
        fail_clients: vec!["client_bad".to_string()],
    });

    let ir = build_ir_delete(2, &["client_good", "client_bad"], 1_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            time_scale: 0.001,
            invariant_mode: InvariantMode::LogAndContinue,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    // client_good's 2 ops succeed, client_bad's 2 ops fail on connect
    assert_eq!(summary.dispatched, 4);
    assert_eq!(summary.failed, 2, "client_bad's ops should fail");
    assert_eq!(summary.succeeded, 2, "client_good's ops should succeed");
}

#[tokio::test]
async fn test_operation_error_does_not_block_subsequent() {
    // Operations fail for client_fail but succeed for client_ok
    let backend = Arc::new(OpFailBackend {
        fail_ops_for: vec!["client_fail".to_string()],
    });

    let ir = build_ir_delete(3, &["client_ok", "client_fail"], 1_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            time_scale: 0.001,
            invariant_mode: InvariantMode::LogAndContinue,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    // All 6 ops dispatched
    assert_eq!(summary.dispatched, 6);
    // client_fail's 3 ops fail, client_ok's 3 succeed
    assert_eq!(summary.failed, 3);
    assert_eq!(summary.succeeded, 3);
    // No invariant violations - errors are handled gracefully
    assert_eq!(summary.invariant_violations, 0);
}

#[tokio::test]
async fn test_error_metrics_in_run_summary() {
    let backend = Arc::new(OpFailBackend {
        fail_ops_for: vec!["bad".to_string()],
    });

    let ir = build_ir_delete(2, &["good", "bad"], 1_000);
    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            time_scale: 0.001,
            invariant_mode: InvariantMode::LogAndContinue,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    // Verify the per-client stats reflect errors
    let good_stats = summary
        .client_stats
        .iter()
        .find(|s| s.client_id == "good")
        .unwrap();
    let bad_stats = summary
        .client_stats
        .iter()
        .find(|s| s.client_id == "bad")
        .unwrap();

    assert_eq!(good_stats.operation_count, 2);
    assert_eq!(bad_stats.operation_count, 2);

    assert_eq!(summary.succeeded, 2);
    assert_eq!(summary.failed, 2);
}

/// Helper: build an IR with all 7 new operation types, each needing an open/close pair.
fn build_ir_new_ops(client_id: &str) -> WorkloadIr {
    let operations = vec![
        Operation::Open {
            op_id: "op_open".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 0,
            path: "test/file.txt".to_string(),
            mode: OpenMode::ReadWrite,
            handle_ref: "h_1".to_string(),
            extensions: None,
        },
        Operation::QueryDirectory {
            op_id: "op_qd".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 1000,
            handle_ref: "h_1".to_string(),
            pattern: "*.txt".to_string(),
            info_class: 37,
        },
        Operation::QueryInfo {
            op_id: "op_qi".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 2000,
            handle_ref: "h_1".to_string(),
            info_type: 1,
            info_class: 5,
        },
        Operation::Flush {
            op_id: "op_fl".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 3000,
            handle_ref: "h_1".to_string(),
        },
        Operation::Lock {
            op_id: "op_lk".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 4000,
            handle_ref: "h_1".to_string(),
            offset: 0,
            length: 1024,
            exclusive: true,
        },
        Operation::Unlock {
            op_id: "op_ul".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 5000,
            handle_ref: "h_1".to_string(),
            offset: 0,
            length: 1024,
        },
        Operation::Ioctl {
            op_id: "op_io".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 6000,
            handle_ref: "h_1".to_string(),
            ctl_code: 0x00060194,
            input_blob_path: None,
        },
        Operation::ChangeNotify {
            op_id: "op_cn".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 7000,
            handle_ref: "h_1".to_string(),
            filter: 0x17,
            recursive: true,
        },
        Operation::Close {
            op_id: "op_close".to_string(),
            client_id: client_id.to_string(),
            timestamp_us: 8000,
            handle_ref: "h_1".to_string(),
        },
    ];

    WorkloadIr {
        version: 1,
        metadata: Metadata {
            source: "test_new_ops".to_string(),
            duration_seconds: 0.01,
            client_count: 1,
        },
        clients: vec![ClientSpec {
            client_id: client_id.to_string(),
            operation_count: operations.len() as u32,
        }],
        operations,
    }
}

#[tokio::test]
async fn test_new_ops_dispatch_through_scheduler() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(TrackingBackend {
        delay: Duration::ZERO,
        log: log.clone(),
    });

    let ir = build_ir_new_ops("c1");
    let total_ops = ir.operations.len();

    let scheduler = Scheduler::from_ir(
        ir,
        SchedulerConfig {
            max_concurrent: 1,
            time_scale: 0.001,
            worker_count: 1,
            ..default_config()
        },
    )
    .unwrap();

    let summary = scheduler.run(backend).await.unwrap();

    assert_eq!(summary.dispatched, total_ops as u64);
    assert_eq!(summary.succeeded, total_ops as u64);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.invariant_violations, 0);

    // QueryDirectory, QueryInfo, Ioctl, ChangeNotify are now routed through
    // the file handle methods (like flush/lock/unlock), not execute_misc.
    // The succeeded count already confirms they were dispatched successfully.
    // The log only captures execute_misc calls now (Rename, Delete, Mkdir, Rmdir).
}
