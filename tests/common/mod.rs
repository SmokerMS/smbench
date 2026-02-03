/// Common test utilities for SMBench integration tests
use smbench::ir::{ClientSpec, Metadata, OpenMode, Operation, WorkloadIr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a test IR with the specified number of clients and operations per client
pub fn create_test_ir(clients: usize, ops_per_client: usize) -> WorkloadIr {
    let client_specs: Vec<ClientSpec> = (0..clients)
        .map(|i| ClientSpec {
            client_id: format!("client_{:03}", i + 1),
            operation_count: ops_per_client as u32,
        })
        .collect();

    let mut operations = Vec::new();
    let mut op_counter = 0;

    for (client_idx, client) in client_specs.iter().enumerate() {
        for op_idx in 0..ops_per_client {
            let timestamp_us = (op_idx * 1000) as u64; // 1ms between ops
            let handle_ref = format!("h_{}_{}", client_idx, op_idx);
            let path = format!("testfile_{}_{}.txt", client_idx, op_idx);

            // Create a simple open/write/close sequence
            match op_idx % 3 {
                0 => {
                    // Open
                    operations.push(Operation::Open {
                        op_id: format!("op_{:06}", op_counter),
                        client_id: client.client_id.clone(),
                        timestamp_us,
                        path: path.clone(),
                        mode: OpenMode::Write,
                        handle_ref: handle_ref.clone(),
                        extensions: None,
                    });
                    op_counter += 1;
                }
                1 => {
                    // Write
                    let blob_path = format!("/tmp/smbench_test_blob_{}.bin", op_counter);
                    operations.push(Operation::Write {
                        op_id: format!("op_{:06}", op_counter),
                        client_id: client.client_id.clone(),
                        timestamp_us,
                        handle_ref: format!("h_{}_{}", client_idx, (op_idx / 3) * 3),
                        offset: 0,
                        length: 1024,
                        blob_path,
                    });
                    op_counter += 1;
                }
                2 => {
                    // Close
                    operations.push(Operation::Close {
                        op_id: format!("op_{:06}", op_counter),
                        client_id: client.client_id.clone(),
                        timestamp_us,
                        handle_ref: format!("h_{}_{}", client_idx, ((op_idx / 3) * 3)),
                    });
                    op_counter += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    WorkloadIr {
        version: 1,
        metadata: Metadata {
            source: "test_generator".to_string(),
            duration_seconds: (ops_per_client as f64 * 0.001 * clients as f64),
            client_count: clients as u32,
        },
        clients: client_specs,
        operations,
    }
}

/// Generate a unique test file name with timestamp
pub fn unique_test_name(prefix: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{}_{}.txt", prefix, ts)
}

/// Create test blob data of specified size
pub fn create_test_blob(size: usize, pattern: u8) -> Vec<u8> {
    vec![pattern; size]
}
