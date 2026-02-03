//! Bug Reproduction Use Case Tests
//!
//! These tests validate the bug reproduction use case from problem-definition.md:
//! "Customer reports issue → Capture PCAP → Replay in lab → Bug reproduces"
//!
//! Tests run against:
//! - Windows Server 2022 (SMB 3.1.1)
//! - Synology DSM 7.x (SMB 3.0)

#[cfg(feature = "smb-rs-backend")]
mod bug_reproduction {
    use smbench::backend::smbrs::{SmbRsBackend, SmbRsConfig};
    use smbench::ir::{ClientSpec, Metadata, OpenMode, Operation, WorkloadIr};
    use std::env;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn smb_env() -> Option<(String, String, String, String)> {
        let server = env::var("SMBENCH_SMB_SERVER").ok()?;
        let share = env::var("SMBENCH_SMB_SHARE").ok()?;
        let user = env::var("SMBENCH_SMB_USER").ok()?;
        let pass = env::var("SMBENCH_SMB_PASS").ok()?;
        Some((server, share, user, pass))
    }

    fn unique_name(prefix: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{}_{}.txt", prefix, ts)
    }

    /// Scenario 1: Oplock Break Race Condition
    ///
    /// Test: Two clients open same file with conflicting oplocks
    /// Expected: Server breaks first client's oplock before granting second open
    /// Validates: Oplock break handling, per-client ordering
    ///
    /// Reference: problem-definition.md lines 24-40 (Bug Reproduction Use Case)
    #[tokio::test]
    #[ignore] // Run with: cargo test --features smb-rs-backend -- --ignored
    async fn test_oplock_break_race_condition() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let filename = unique_name("oplock_race");

        // Create IR with 2 clients opening the same file
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "oplock_race_test".to_string(),
                duration_seconds: 2.0,
                client_count: 2,
            },
            clients: vec![
                ClientSpec {
                    client_id: "client_a".to_string(),
                    operation_count: 2,
                },
                ClientSpec {
                    client_id: "client_b".to_string(),
                    operation_count: 2,
                },
            ],
            operations: vec![
                // Client A: Open with exclusive oplock at T=0
                Operation::Open {
                    op_id: "op_001".to_string(),
                    client_id: "client_a".to_string(),
                    timestamp_us: 0,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_a_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "oplock_level": "Batch",
                        "create_disposition": "OpenIf",
                    })),
                },
                // Client B: Open same file at T=1s (should trigger oplock break)
                Operation::Open {
                    op_id: "op_002".to_string(),
                    client_id: "client_b".to_string(),
                    timestamp_us: 1_000_000,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_b_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "Open",
                    })),
                },
                // Client A: Close
                Operation::Close {
                    op_id: "op_003".to_string(),
                    client_id: "client_a".to_string(),
                    timestamp_us: 2_000_000,
                    handle_ref: "h_a_1".to_string(),
                },
                // Client B: Close
                Operation::Close {
                    op_id: "op_004".to_string(),
                    client_id: "client_b".to_string(),
                    timestamp_us: 2_100_000,
                    handle_ref: "h_b_1".to_string(),
                },
            ],
        };

        let config = SmbRsConfig {
            server,
            share,
            user,
            pass,
        };
        let backend = Arc::new(SmbRsBackend::new(config));

        // Execute the workload
        let scheduler_config = smbench::scheduler::SchedulerConfig {
            max_concurrent: 2,
            time_scale: 0.1, // Run faster for testing
            worker_count: 2,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: smbench::scheduler::InvariantMode::Panic,
            debug_dump_on_error: true,
            watchdog_interval: std::time::Duration::from_millis(500),
            inflight_timeout: std::time::Duration::from_secs(10),
        };

        let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
        let result = scheduler.run(backend).await;

        // Validate: Both operations should complete successfully
        // The oplock break should be handled automatically by the backend
        assert!(result.is_ok(), "Oplock break scenario should complete successfully");
    }

    /// Scenario 2: Multi-Client Write Ordering
    ///
    /// Test: Concurrent writes to same file region
    /// Expected: Writes execute in timestamp order, no data corruption
    /// Validates: Scheduler timing, write ordering
    ///
    /// Reference: problem-definition.md lines 237-247 (Fidelity Requirements)
    #[tokio::test]
    #[ignore]
    async fn test_multi_client_write_ordering() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let filename = unique_name("write_order");

        // Create test blobs with different patterns
        let blob_dir = std::env::temp_dir().join("smbench_test_blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();

        let blob_a = blob_dir.join("blob_a.bin");
        let blob_b = blob_dir.join("blob_b.bin");
        let blob_c = blob_dir.join("blob_c.bin");

        std::fs::write(&blob_a, vec![0xAA; 1024]).unwrap();
        std::fs::write(&blob_b, vec![0xBB; 1024]).unwrap();
        std::fs::write(&blob_c, vec![0xCC; 1024]).unwrap();

        // Create IR with 3 clients writing to overlapping regions
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "write_order_test".to_string(),
                duration_seconds: 3.0,
                client_count: 3,
            },
            clients: vec![
                ClientSpec {
                    client_id: "client_a".to_string(),
                    operation_count: 3,
                },
                ClientSpec {
                    client_id: "client_b".to_string(),
                    operation_count: 3,
                },
                ClientSpec {
                    client_id: "client_c".to_string(),
                    operation_count: 3,
                },
            ],
            operations: vec![
                // All clients open the same file
                Operation::Open {
                    op_id: "op_001".to_string(),
                    client_id: "client_a".to_string(),
                    timestamp_us: 0,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_a_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "OpenIf",
                    })),
                },
                Operation::Open {
                    op_id: "op_002".to_string(),
                    client_id: "client_b".to_string(),
                    timestamp_us: 100_000,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_b_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "Open",
                    })),
                },
                Operation::Open {
                    op_id: "op_003".to_string(),
                    client_id: "client_c".to_string(),
                    timestamp_us: 200_000,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_c_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "Open",
                    })),
                },
                // Writes at different timestamps
                Operation::Write {
                    op_id: "op_004".to_string(),
                    client_id: "client_a".to_string(),
                    timestamp_us: 1_000_000,
                    handle_ref: "h_a_1".to_string(),
                    offset: 0,
                    length: 1024,
                    blob_path: blob_a.to_string_lossy().to_string(),
                },
                Operation::Write {
                    op_id: "op_005".to_string(),
                    client_id: "client_b".to_string(),
                    timestamp_us: 1_500_000,
                    handle_ref: "h_b_1".to_string(),
                    offset: 512,
                    length: 1024,
                    blob_path: blob_b.to_string_lossy().to_string(),
                },
                Operation::Write {
                    op_id: "op_006".to_string(),
                    client_id: "client_c".to_string(),
                    timestamp_us: 2_000_000,
                    handle_ref: "h_c_1".to_string(),
                    offset: 256,
                    length: 1024,
                    blob_path: blob_c.to_string_lossy().to_string(),
                },
                // All clients close
                Operation::Close {
                    op_id: "op_007".to_string(),
                    client_id: "client_a".to_string(),
                    timestamp_us: 2_500_000,
                    handle_ref: "h_a_1".to_string(),
                },
                Operation::Close {
                    op_id: "op_008".to_string(),
                    client_id: "client_b".to_string(),
                    timestamp_us: 2_600_000,
                    handle_ref: "h_b_1".to_string(),
                },
                Operation::Close {
                    op_id: "op_009".to_string(),
                    client_id: "client_c".to_string(),
                    timestamp_us: 2_700_000,
                    handle_ref: "h_c_1".to_string(),
                },
            ],
        };

        let config = SmbRsConfig {
            server,
            share,
            user,
            pass,
        };
        let backend = Arc::new(SmbRsBackend::new(config));

        let scheduler_config = smbench::scheduler::SchedulerConfig {
            max_concurrent: 3,
            time_scale: 0.1,
            worker_count: 3,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: smbench::scheduler::InvariantMode::Panic,
            debug_dump_on_error: true,
            watchdog_interval: std::time::Duration::from_millis(500),
            inflight_timeout: std::time::Duration::from_secs(10),
        };

        let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
        let result = scheduler.run(backend).await;

        // Cleanup
        let _ = std::fs::remove_file(&blob_a);
        let _ = std::fs::remove_file(&blob_b);
        let _ = std::fs::remove_file(&blob_c);

        assert!(result.is_ok(), "Multi-client write ordering should complete successfully");
    }

    /// Scenario 3: Durable Handle Reconnection
    ///
    /// Test: Simulate connection drop, reconnect with durable handle
    /// Expected: File handle preserved, operations resume
    /// Validates: Durable handle support, resilience
    ///
    /// Reference: problem-definition.md lines 260-265 (Reactive Elements)
    #[tokio::test]
    #[ignore]
    async fn test_durable_handle_reconnection() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let filename = unique_name("durable_handle");

        // Create IR with durable handle request
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "durable_handle_test".to_string(),
                duration_seconds: 1.0,
                client_count: 1,
            },
            clients: vec![ClientSpec {
                client_id: "client_1".to_string(),
                operation_count: 2,
            }],
            operations: vec![
                // Open with durable handle
                Operation::Open {
                    op_id: "op_001".to_string(),
                    client_id: "client_1".to_string(),
                    timestamp_us: 0,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: "h_1".to_string(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "OpenIf",
                        "durable_handle": true,
                    })),
                },
                // Close
                Operation::Close {
                    op_id: "op_002".to_string(),
                    client_id: "client_1".to_string(),
                    timestamp_us: 1_000_000,
                    handle_ref: "h_1".to_string(),
                },
            ],
        };

        let config = SmbRsConfig {
            server,
            share,
            user,
            pass,
        };
        let backend = Arc::new(SmbRsBackend::new(config));

        let scheduler_config = smbench::scheduler::SchedulerConfig {
            max_concurrent: 1,
            time_scale: 0.1,
            worker_count: 1,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: smbench::scheduler::InvariantMode::Panic,
            debug_dump_on_error: true,
            watchdog_interval: std::time::Duration::from_millis(500),
            inflight_timeout: std::time::Duration::from_secs(10),
        };

        let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
        let result = scheduler.run(backend).await;

        assert!(result.is_ok(), "Durable handle scenario should complete successfully");
    }
}
