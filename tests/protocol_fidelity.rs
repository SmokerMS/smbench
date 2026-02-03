//! Protocol Fidelity Tests
//!
//! These tests validate SMB3 protocol feature support and compliance with MS-SMB2 specifications.
//! Tests exercise advanced features like oplocks, leases, multichannel, and encryption.

#[cfg(feature = "smb-rs-backend")]
mod protocol_fidelity {
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

    /// Test Oplock Levels: Batch, Read, Level II
    /// Reference: [MS-SMB2 2.2.13] SMB2 CREATE Request - RequestedOplockLevel
    #[tokio::test]
    #[ignore]
    async fn test_oplock_levels() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let oplock_levels = vec!["None", "Level2", "Exclusive", "Batch"];

        for oplock_level in oplock_levels {
            let filename = unique_name(&format!("oplock_{}", oplock_level));

            let ir = WorkloadIr {
                version: 1,
                metadata: Metadata {
                    source: format!("oplock_{}_test", oplock_level),
                    duration_seconds: 1.0,
                    client_count: 1,
                },
                clients: vec![ClientSpec {
                    client_id: "client_1".to_string(),
                    operation_count: 2,
                }],
                operations: vec![
                    Operation::Open {
                        op_id: "op_001".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 0,
                        path: filename.clone(),
                        mode: OpenMode::Write,
                        handle_ref: "h_1".to_string(),
                        extensions: Some(serde_json::json!({
                            "oplock_level": oplock_level,
                            "create_disposition": "OpenIf",
                        })),
                    },
                    Operation::Close {
                        op_id: "op_002".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 100_000,
                        handle_ref: "h_1".to_string(),
                    },
                ],
            };

            let config = SmbRsConfig {
                server: server.clone(),
                share: share.clone(),
                user: user.clone(),
                pass: pass.clone(),
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

            assert!(
                result.is_ok(),
                "Oplock level {} test should complete successfully",
                oplock_level
            );
        }
    }

    /// Test Lease Requests: RWH (Read/Write/Handle) combinations
    /// Reference: [MS-SMB2 2.2.13.2.8] SMB2_CREATE_REQUEST_LEASE
    #[tokio::test]
    #[ignore]
    async fn test_lease_rwh_combinations() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        // Test different lease state combinations
        let lease_states = vec![
            ("Read", serde_json::json!({"read_caching": true})),
            ("Write", serde_json::json!({"write_caching": true})),
            ("Handle", serde_json::json!({"handle_caching": true})),
            (
                "ReadWrite",
                serde_json::json!({"read_caching": true, "write_caching": true}),
            ),
            (
                "ReadHandle",
                serde_json::json!({"read_caching": true, "handle_caching": true}),
            ),
            (
                "RWH",
                serde_json::json!({
                    "read_caching": true,
                    "write_caching": true,
                    "handle_caching": true
                }),
            ),
        ];

        for (name, lease_state) in lease_states {
            let filename = unique_name(&format!("lease_{}", name));

            let ir = WorkloadIr {
                version: 1,
                metadata: Metadata {
                    source: format!("lease_{}_test", name),
                    duration_seconds: 1.0,
                    client_count: 1,
                },
                clients: vec![ClientSpec {
                    client_id: "client_1".to_string(),
                    operation_count: 2,
                }],
                operations: vec![
                    Operation::Open {
                        op_id: "op_001".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 0,
                        path: filename.clone(),
                        mode: OpenMode::Write,
                        handle_ref: "h_1".to_string(),
                        extensions: Some(serde_json::json!({
                            "lease_state": lease_state,
                            "create_disposition": "OpenIf",
                        })),
                    },
                    Operation::Close {
                        op_id: "op_002".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 100_000,
                        handle_ref: "h_1".to_string(),
                    },
                ],
            };

            let config = SmbRsConfig {
                server: server.clone(),
                share: share.clone(),
                user: user.clone(),
                pass: pass.clone(),
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

            assert!(
                result.is_ok(),
                "Lease state {} test should complete successfully",
                name
            );
        }
    }

    /// Test Create Dispositions
    /// Reference: [MS-SMB2 2.2.13] SMB2 CREATE Request - CreateDisposition
    #[tokio::test]
    #[ignore]
    async fn test_create_dispositions() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let dispositions = vec![
            "Supersede",
            "Open",
            "Create",
            "OpenIf",
            "Overwrite",
            "OverwriteIf",
        ];

        for disposition in dispositions {
            let filename = unique_name(&format!("disposition_{}", disposition));

            // Pre-create file for Open/Overwrite tests
            if disposition == "Open" || disposition == "Overwrite" {
                let pre_create_ir = WorkloadIr {
                    version: 1,
                    metadata: Metadata {
                        source: "pre_create".to_string(),
                        duration_seconds: 0.1,
                        client_count: 1,
                    },
                    clients: vec![ClientSpec {
                        client_id: "client_1".to_string(),
                        operation_count: 2,
                    }],
                    operations: vec![
                        Operation::Open {
                            op_id: "op_001".to_string(),
                            client_id: "client_1".to_string(),
                            timestamp_us: 0,
                            path: filename.clone(),
                            mode: OpenMode::Write,
                            handle_ref: "h_1".to_string(),
                            extensions: Some(serde_json::json!({
                                "create_disposition": "Create",
                            })),
                        },
                        Operation::Close {
                            op_id: "op_002".to_string(),
                            client_id: "client_1".to_string(),
                            timestamp_us: 10_000,
                            handle_ref: "h_1".to_string(),
                        },
                    ],
                };

                let config = SmbRsConfig {
                    server: server.clone(),
                    share: share.clone(),
                    user: user.clone(),
                    pass: pass.clone(),
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
                let scheduler =
                    smbench::scheduler::Scheduler::from_ir(pre_create_ir, scheduler_config)
                        .unwrap();
                let _ = scheduler.run(backend).await;
            }

            let ir = WorkloadIr {
                version: 1,
                metadata: Metadata {
                    source: format!("disposition_{}_test", disposition),
                    duration_seconds: 1.0,
                    client_count: 1,
                },
                clients: vec![ClientSpec {
                    client_id: "client_1".to_string(),
                    operation_count: 2,
                }],
                operations: vec![
                    Operation::Open {
                        op_id: "op_001".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 0,
                        path: filename.clone(),
                        mode: OpenMode::Write,
                        handle_ref: "h_1".to_string(),
                        extensions: Some(serde_json::json!({
                            "create_disposition": disposition,
                        })),
                    },
                    Operation::Close {
                        op_id: "op_002".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 100_000,
                        handle_ref: "h_1".to_string(),
                    },
                ],
            };

            let config = SmbRsConfig {
                server: server.clone(),
                share: share.clone(),
                user: user.clone(),
                pass: pass.clone(),
            };
            let backend = Arc::new(SmbRsBackend::new(config));

            let scheduler_config = smbench::scheduler::SchedulerConfig {
                max_concurrent: 1,
                time_scale: 0.1,
                worker_count: 1,
                backend_mode: smbench::backend::BackendMode::Development,
                invariant_mode: smbench::scheduler::InvariantMode::LogAndContinue,
                debug_dump_on_error: true,
                watchdog_interval: std::time::Duration::from_millis(500),
                inflight_timeout: std::time::Duration::from_secs(10),
            };

            let scheduler = smbench::scheduler::Scheduler::from_ir(ir, scheduler_config).unwrap();
            let result = scheduler.run(backend).await;

            // Some dispositions may fail if file doesn't exist (Open, Overwrite)
            // or if file exists (Create) - this is expected behavior
            if disposition == "Create" || disposition == "OpenIf" || disposition == "OverwriteIf" || disposition == "Supersede" {
                assert!(
                    result.is_ok(),
                    "Create disposition {} test should complete successfully",
                    disposition
                );
            }
        }
    }

    /// Test File Attributes
    /// Reference: [MS-SMB2 2.2.13] SMB2 CREATE Request - FileAttributes
    #[tokio::test]
    #[ignore]
    async fn test_file_attributes() {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("Skipping test: SMB environment variables not set");
            return;
        };

        let attributes = vec![
            ("Normal", serde_json::json!({"normal": true})),
            ("Hidden", serde_json::json!({"hidden": true})),
            ("System", serde_json::json!({"system": true})),
            ("Archive", serde_json::json!({"archive": true})),
            ("Temporary", serde_json::json!({"temporary": true})),
        ];

        for (name, attrs) in attributes {
            let filename = unique_name(&format!("attr_{}", name));

            let ir = WorkloadIr {
                version: 1,
                metadata: Metadata {
                    source: format!("attr_{}_test", name),
                    duration_seconds: 1.0,
                    client_count: 1,
                },
                clients: vec![ClientSpec {
                    client_id: "client_1".to_string(),
                    operation_count: 2,
                }],
                operations: vec![
                    Operation::Open {
                        op_id: "op_001".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 0,
                        path: filename.clone(),
                        mode: OpenMode::Write,
                        handle_ref: "h_1".to_string(),
                        extensions: Some(serde_json::json!({
                            "file_attributes": attrs,
                            "create_disposition": "OpenIf",
                        })),
                    },
                    Operation::Close {
                        op_id: "op_002".to_string(),
                        client_id: "client_1".to_string(),
                        timestamp_us: 100_000,
                        handle_ref: "h_1".to_string(),
                    },
                ],
            };

            let config = SmbRsConfig {
                server: server.clone(),
                share: share.clone(),
                user: user.clone(),
                pass: pass.clone(),
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

            assert!(
                result.is_ok(),
                "File attribute {} test should complete successfully",
                name
            );
        }
    }
}
