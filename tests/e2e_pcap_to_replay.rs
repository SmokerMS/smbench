//! End-to-end test: PCAP → Compile → Validate IR.
//!
//! This test validates the complete workflow from a synthetic PCAP file
//! through the compiler pipeline to a valid WorkloadIr that could be
//! replayed. The actual replay against an SMB server is gated behind
//! the `smb-rs-backend` feature and env vars.
//!
//! Requires the `pcap-compiler` feature.

#![cfg(feature = "pcap-compiler")]

mod pcap_helpers;

use smbench::compiler::PcapCompiler;
use smbench::ir::{Operation, WorkloadIr};

#[tokio::test]
async fn test_e2e_pcap_compile_and_validate() {
    let dir = std::env::temp_dir().join("smbench_e2e_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Step 1: Generate a synthetic PCAP.
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    assert!(pcap.exists(), "PCAP was not generated");

    // Step 2: Compile PCAP → WorkloadIr.
    let out_dir = dir.join("output");
    let compiler = PcapCompiler::new(pcap.to_string_lossy().to_string()).unwrap();
    let ir_path = compiler.compile(&out_dir).await.unwrap();
    let ir_file = std::path::Path::new(&ir_path);
    assert!(ir_file.exists(), "workload.json was not generated");

    // Step 3: Load and validate the IR.
    let ir_json = std::fs::read_to_string(&ir_path).unwrap();
    let ir: WorkloadIr = serde_json::from_str(&ir_json).unwrap();
    ir.validate().unwrap();

    // Step 4: Structural assertions.
    assert_eq!(ir.version, 1, "IR version mismatch");
    assert_eq!(ir.metadata.source, "pcap_compiler");
    assert!(ir.metadata.client_count >= 1, "No clients extracted");
    assert!(!ir.clients.is_empty(), "Client list is empty");

    // Step 5: Verify operation types are present.
    let has_open = ir.operations.iter().any(|o| matches!(o, Operation::Open { .. }));
    let has_close = ir.operations.iter().any(|o| matches!(o, Operation::Close { .. }));
    assert!(has_open, "Missing Open operation in IR");
    assert!(has_close, "Missing Close operation in IR");

    // Step 6: Verify timestamps are chronologically ordered.
    for window in ir.operations.windows(2) {
        assert!(
            window[0].timestamp_us() <= window[1].timestamp_us(),
            "Operations are not in chronological order"
        );
    }

    // Step 7: Verify blob directory.
    let blobs_dir = out_dir.join("blobs");
    assert!(blobs_dir.exists(), "blobs/ directory missing");

    // Step 8: Verify Write ops have blob_path set (if present).
    for op in &ir.operations {
        if let Operation::Write { blob_path, .. } = op {
            // blob_path should be non-empty if data was captured.
            // In our simple PCAP, writes have data.
            if !blob_path.is_empty() {
                assert!(
                    blob_path.starts_with("blobs/"),
                    "blob_path should start with 'blobs/', got: {}",
                    blob_path
                );
                let abs_blob = out_dir.join(blob_path);
                assert!(abs_blob.exists(), "Blob file missing: {}", blob_path);
            }
        }
    }

    // Step 9: Verify handle_ref consistency (opens and closes reference same handles).
    let open_handles: std::collections::HashSet<_> = ir.operations.iter()
        .filter_map(|o| if let Operation::Open { handle_ref, .. } = o { Some(handle_ref.clone()) } else { None })
        .collect();
    let close_handles: std::collections::HashSet<_> = ir.operations.iter()
        .filter_map(|o| if let Operation::Close { handle_ref, .. } = o { Some(handle_ref.clone()) } else { None })
        .collect();
    // Every close should reference an opened handle.
    for ch in &close_handles {
        assert!(
            open_handles.contains(ch),
            "Close references unknown handle_ref: {}",
            ch
        );
    }

    // Step 10: Summary
    let summary = ir.summary();
    println!(
        "E2E test summary: {} clients, {} ops (open={}, read={}, write={}, close={}, rename={}, delete={})",
        summary.client_count,
        summary.operation_count,
        summary.open_ops,
        summary.read_ops,
        summary.write_ops,
        summary.close_ops,
        summary.rename_ops,
        summary.delete_ops,
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_e2e_multi_client_compile() {
    let dir = std::env::temp_dir().join("smbench_e2e_multi");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let pcap = pcap_helpers::generate_multi_client_pcap(&dir);
    let out_dir = dir.join("output");
    let compiler = PcapCompiler::new(pcap.to_string_lossy().to_string()).unwrap();
    let ir_path = compiler.compile(&out_dir).await.unwrap();

    let ir: WorkloadIr = serde_json::from_str(
        &std::fs::read_to_string(&ir_path).unwrap()
    ).unwrap();
    ir.validate().unwrap();

    // 3 clients
    assert!(
        ir.metadata.client_count >= 3,
        "Expected >= 3 clients, got {}",
        ir.metadata.client_count
    );

    // Each client: open + write + close = 3 ops minimum, 3 clients = 9
    assert!(
        ir.operations.len() >= 9,
        "Expected >= 9 operations, got {}",
        ir.operations.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
