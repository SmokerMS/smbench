//! Load Testing Use Case Tests
//!
//! These tests validate the load testing use case from problem-definition.md:
//! "Scale to 5000 concurrent users, measure throughput/latency"
//!
//! Tests run against:
//! - Windows Server 2022 (target: 5000 users)
//! - Synology DSM 7.x (target: 1000 users)

#[cfg(feature = "smb-rs-backend")]
mod load_testing {
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

    /// Generate a scaled workload IR with multiple clients
    fn generate_scaled_workload(num_clients: usize, ops_per_client: usize) -> WorkloadIr {
        let clients: Vec<ClientSpec> = (0..num_clients)
            .map(|i| ClientSpec {
                client_id: format!("user{:04}", i + 1),
                operation_count: (ops_per_client * 4) as u32, // open, write, read, close
            })
            .collect();

        let mut operations = Vec::new();
        let base_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        // Create test blob
        let blob_dir = std::env::temp_dir().join("smbench_load_test");
        std::fs::create_dir_all(&blob_dir).ok();
        let blob_path = blob_dir.join("test_data.bin");
        std::fs::write(&blob_path, vec![0x42; 4096]).ok();

        for (client_idx, client) in clients.iter().enumerate() {
            for op_idx in 0..ops_per_client {
                let base_time = (client_idx * 1000 + op_idx * 100) as u64;
                let filename = format!("user{:04}/file_{:03}.dat", client_idx + 1, op_idx);
                let handle_ref = format!("h_{}_{}", client_idx, op_idx);

                // Open
                operations.push(Operation::Open {
                    op_id: format!("op_{}_{}_open", client_idx, op_idx),
                    client_id: client.client_id.clone(),
                    timestamp_us: base_timestamp + base_time,
                    path: filename.clone(),
                    mode: OpenMode::Write,
                    handle_ref: handle_ref.clone(),
                    extensions: Some(serde_json::json!({
                        "create_disposition": "OpenIf",
                    })),
                });

                // Write
                operations.push(Operation::Write {
                    op_id: format!("op_{}_{}_write", client_idx, op_idx),
                    client_id: client.client_id.clone(),
                    timestamp_us: base_timestamp + base_time + 10,
                    handle_ref: handle_ref.clone(),
                    offset: 0,
                    length: 4096,
                    blob_path: blob_path.to_string_lossy().to_string(),
                });

                // Read
                operations.push(Operation::Read {
                    op_id: format!("op_{}_{}_read", client_idx, op_idx),
                    client_id: client.client_id.clone(),
                    timestamp_us: base_timestamp + base_time + 20,
                    handle_ref: handle_ref.clone(),
                    offset: 0,
                    length: 4096,
                });

                // Close
                operations.push(Operation::Close {
                    op_id: format!("op_{}_{}_close", client_idx, op_idx),
                    client_id: client.client_id.clone(),
                    timestamp_us: base_timestamp + base_time + 30,
                    handle_ref,
                });
            }
        }

        WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "load_test_generator".to_string(),
                duration_seconds: (num_clients * ops_per_client) as f64 * 0.001,
                client_count: num_clients as u32,
            },
            clients,
            operations,
        }
    }

    /// Scenario 4: Scaled Workload (100 Users)
    ///
    /// Test: Clone single-user workload to 100 users
    /// Expected: System remains stable, realistic operation mix preserved
    /// Validates: Scheduler scalability, connection pooling
    ///
    /// Reference: problem-definition.md lines 41-55 (Load Testing Use Case)
    #[tokio::test]
    #[ignore] // Run with: cargo test --features smb-rs-backend test_scaled_workload_100_users -- --ignored
    async fn test_scaled_workload_100_users() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        // Generate IR with 100 clients, 10 operations each = 4000 total operations
        let ir = generate_scaled_workload(100, 10);

        let config = SmbRsConfig {
            server,
            share,
            user,
            pass,
        };
        let backend = Arc::new(SmbRsBackend::new(config));

        let scheduler_config = smbench::scheduler::SchedulerConfig {
            max_concurrent: 100,
            time_scale: 0.01, // Run much faster for testing
            worker_count: 8,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: smbench::scheduler::InvariantMode::Panic,
            debug_dump_on_error: true,
            watchdog_interval: std::time::Duration::from_secs(1),
            inflight_timeout: std::time::Duration::from_secs(30),
        };

        let start = std::time::Instant::now();
        let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
        let result = scheduler.run(backend).await;
        let duration = start.elapsed();

        println!("100-user load test completed in {:?}", duration);

        assert!(
            result.is_ok(),
            "100-user scaled workload should complete successfully"
        );
        assert!(
            duration < std::time::Duration::from_secs(120),
            "Test should complete within 2 minutes"
        );
    }

    /// Scenario 5: Sustained Load (1 Hour)
    ///
    /// Test: Run scaled workload for extended duration
    /// Expected: No memory leaks, stable performance
    /// Validates: Production readiness, resource management
    ///
    /// Reference: problem-definition.md lines 319-324 (Scale Targets)
    #[tokio::test]
    #[ignore] // Run with: cargo test --features smb-rs-backend test_sustained_load -- --ignored --test-threads=1
    async fn test_sustained_load() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        // Generate IR with 50 clients, continuous operations
        // For a 1-hour test, we'd need many more operations, but for testing we'll use a shorter duration
        let test_duration_seconds = env::var("SMBENCH_SUSTAINED_TEST_DURATION")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60); // Default to 60 seconds for testing

        let ops_per_client = (test_duration_seconds * 10) as usize; // 10 ops/second per client
        let ir = generate_scaled_workload(50, ops_per_client);

        let config = SmbRsConfig {
            server,
            share,
            user,
            pass,
        };
        let backend = Arc::new(SmbRsBackend::new(config));

        let scheduler_config = smbench::scheduler::SchedulerConfig {
            max_concurrent: 50,
            time_scale: 1.0, // Real-time for sustained test
            worker_count: 8,
            backend_mode: smbench::backend::BackendMode::Development,
            invariant_mode: smbench::scheduler::InvariantMode::LogAndContinue,
            debug_dump_on_error: true,
            watchdog_interval: std::time::Duration::from_secs(5),
            inflight_timeout: std::time::Duration::from_secs(30),
        };

        let start = std::time::Instant::now();
        let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
        let result = scheduler.run(backend).await;
        let duration = start.elapsed();

        println!(
            "Sustained load test ({} seconds) completed in {:?}",
            test_duration_seconds, duration
        );

        assert!(
            result.is_ok(),
            "Sustained load test should complete successfully"
        );
    }
}
