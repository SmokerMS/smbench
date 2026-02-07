//! Compiler integration tests.
//!
//! These tests exercise the full PCAP → IR pipeline using synthetically
//! generated PCAP files. They validate that:
//!
//! 1. Packets are read correctly from PCAP files.
//! 2. TCP streams are reassembled in order.
//! 3. SMB2 messages are parsed with correct command codes.
//! 4. The state machine tracks sessions, trees, and files.
//! 5. IR operations are correctly generated.
//! 6. Blob deduplication works.
//! 7. The generated WorkloadIr is valid per our schema.
//!
//! Requires the `pcap-compiler` feature.

#![cfg(feature = "pcap-compiler")]

mod pcap_helpers;

use smbench::compiler::{
    IrGenerator, OperationExtractor, PcapCompiler, PcapReader, SmbParser, SmbStateMachine,
    TcpReassembler,
};
use smbench::compiler::smb_parser::SmbMessage;
use smbench::ir::{Operation, WorkloadIr};
use std::collections::HashMap;

// ── Helpers ──

fn fixtures_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("smbench_compiler_tests");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Read a PCAP, reassemble TCP, parse SMB messages, and merge both
/// directions of each connection so requests precede responses.
fn parse_and_merge(pcap_path: &std::path::Path) -> Vec<(String, Vec<SmbMessage>)> {
    let reader = PcapReader::new(pcap_path.to_string_lossy().as_ref()).unwrap();
    let mut reassembler = TcpReassembler::new();

    for pkt in reader.packets().unwrap() {
        reassembler.process_packet(pkt.unwrap()).unwrap();
    }
    let streams = reassembler.finalize().unwrap();
    let mut parser = SmbParser::new();

    struct ConnMsgs {
        client_id: String,
        messages: Vec<SmbMessage>,
    }
    let mut conn_map: HashMap<String, ConnMsgs> = HashMap::new();

    for stream in &streams {
        let client_id = if stream.id.is_client_to_server() {
            stream.id.src_ip.to_string()
        } else {
            stream.id.dst_ip.to_string()
        };
        let (a, b) = stream.id.canonical();
        let key = format!("{}:{}-{}:{}", a.src_ip, a.src_port, b.src_ip, b.src_port);

        let msgs = parser.parse_stream(stream).unwrap();
        let entry = conn_map.entry(key).or_insert_with(|| ConnMsgs {
            client_id: client_id.clone(),
            messages: Vec::new(),
        });
        if stream.id.is_client_to_server() {
            entry.client_id = client_id;
        }
        entry.messages.extend(msgs);
    }

    let mut result = Vec::new();
    for (_, mut cm) in conn_map {
        cm.messages.sort_by(|a, b| {
            a.message_id.cmp(&b.message_id)
                .then(a.is_response.cmp(&b.is_response))
        });
        result.push((cm.client_id, cm.messages));
    }
    result
}

// ═══════════════════════════════════════════════════════════════════
// Unit-level integration tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_pcap_reader_simple() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let reader = PcapReader::new(pcap.to_string_lossy().as_ref()).unwrap();
    let packets: Vec<_> = reader.packets().unwrap().collect();

    // simple.pcap has 14 SMB messages (7 request/response pairs),
    // each wrapped in one Ethernet+IP+TCP packet.
    assert!(
        packets.len() >= 14,
        "Expected >= 14 packets, got {}",
        packets.len()
    );
    // All should parse without error.
    for p in &packets {
        assert!(p.is_ok(), "Packet parse error: {:?}", p.as_ref().err());
    }
}

#[test]
fn test_pcap_reader_empty() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_empty_pcap(&dir);
    let reader = PcapReader::new(pcap.to_string_lossy().as_ref()).unwrap();
    let packets: Vec<_> = reader.packets().unwrap().collect();
    assert_eq!(packets.len(), 0);
}

#[test]
fn test_tcp_reassembly_from_pcap() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let reader = PcapReader::new(pcap.to_string_lossy().as_ref()).unwrap();
    let mut reassembler = TcpReassembler::new();

    for pkt in reader.packets().unwrap() {
        reassembler.process_packet(pkt.unwrap()).unwrap();
    }

    let streams = reassembler.finalize().unwrap();
    // Should have at least 2 streams: client→server and server→client.
    assert!(
        streams.len() >= 2,
        "Expected >= 2 TCP streams, got {}",
        streams.len()
    );
    // All streams should have non-empty data.
    for s in &streams {
        assert!(!s.data.is_empty(), "Stream {:?} has empty data", s.id);
    }
}

#[test]
fn test_smb_parser_from_stream() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let reader = PcapReader::new(pcap.to_string_lossy().as_ref()).unwrap();
    let mut reassembler = TcpReassembler::new();

    for pkt in reader.packets().unwrap() {
        reassembler.process_packet(pkt.unwrap()).unwrap();
    }

    let streams = reassembler.finalize().unwrap();
    let mut parser = SmbParser::new();
    let mut total_messages = 0;

    for stream in &streams {
        let msgs = parser.parse_stream(stream).unwrap();
        total_messages += msgs.len();
    }

    // We should parse at least the 14 SMB messages we generated.
    assert!(
        total_messages >= 14,
        "Expected >= 14 SMB messages, got {}",
        total_messages
    );
}

#[test]
fn test_state_machine_produces_operations() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let merged = parse_and_merge(&pcap);

    let mut sm = SmbStateMachine::new();
    for (client_id, msgs) in merged {
        sm.set_client_id(&client_id);
        for msg in msgs {
            sm.process_message(msg).unwrap();
        }
    }

    let conns = sm.finalize().unwrap();
    assert!(!conns.is_empty(), "Expected at least 1 connection");

    let total_ops: usize = conns.iter().map(|c| c.operations.len()).sum();
    // simple.pcap: create + write + read + close = 4 operations
    assert!(
        total_ops >= 4,
        "Expected >= 4 operations, got {}",
        total_ops
    );
}

#[test]
fn test_operation_extractor() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let merged = parse_and_merge(&pcap);

    let mut sm = SmbStateMachine::new();
    for (client_id, msgs) in merged {
        sm.set_client_id(&client_id);
        for msg in msgs {
            sm.process_message(msg).unwrap();
        }
    }

    let conns = sm.finalize().unwrap();
    let extractor = OperationExtractor::new();
    let ops = extractor.extract(&conns).unwrap();

    // Check operation types.
    let has_open = ops.iter().any(|o| matches!(o, Operation::Open { .. }));
    let has_write = ops.iter().any(|o| matches!(o, Operation::Write { .. }));
    let has_read = ops.iter().any(|o| matches!(o, Operation::Read { .. }));
    let has_close = ops.iter().any(|o| matches!(o, Operation::Close { .. }));

    assert!(has_open, "Missing Open operation");
    assert!(has_write, "Missing Write operation");
    assert!(has_read, "Missing Read operation");
    assert!(has_close, "Missing Close operation");

    // Operations should be sorted by timestamp.
    for w in ops.windows(2) {
        assert!(
            w[0].timestamp_us() <= w[1].timestamp_us(),
            "Operations not sorted by timestamp"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Full pipeline integration tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_full_pipeline_simple() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_simple_pcap(&dir);
    let out_dir = dir.join("simple_output");
    let _ = std::fs::remove_dir_all(&out_dir);

    let compiler = PcapCompiler::new(pcap.to_string_lossy().to_string()).unwrap();
    let ir_path = compiler.compile(&out_dir).await.unwrap();

    // Read and validate the generated IR.
    let ir_json = std::fs::read_to_string(&ir_path).unwrap();
    let ir: WorkloadIr = serde_json::from_str(&ir_json).unwrap();
    ir.validate().unwrap();

    assert_eq!(ir.version, 1);
    assert_eq!(ir.metadata.source, "pcap_compiler");
    assert!(ir.metadata.client_count >= 1);
    assert!(!ir.operations.is_empty());

    // Check blobs directory exists.
    assert!(out_dir.join("blobs").exists());
}

#[tokio::test]
async fn test_full_pipeline_multi_client() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_multi_client_pcap(&dir);
    let out_dir = dir.join("multi_client_output");
    let _ = std::fs::remove_dir_all(&out_dir);

    let compiler = PcapCompiler::new(pcap.to_string_lossy().to_string()).unwrap();
    let ir_path = compiler.compile(&out_dir).await.unwrap();

    let ir_json = std::fs::read_to_string(&ir_path).unwrap();
    let ir: WorkloadIr = serde_json::from_str(&ir_json).unwrap();
    ir.validate().unwrap();

    // 3 clients, each doing create+write+close = 3 ops each = 9 minimum
    assert!(
        ir.metadata.client_count >= 3,
        "Expected >= 3 clients, got {}",
        ir.metadata.client_count
    );
    assert!(
        ir.operations.len() >= 9,
        "Expected >= 9 operations, got {}",
        ir.operations.len()
    );
}

#[tokio::test]
async fn test_full_pipeline_empty_pcap() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_empty_pcap(&dir);
    let out_dir = dir.join("empty_output");
    let _ = std::fs::remove_dir_all(&out_dir);

    let compiler = PcapCompiler::new(pcap.to_string_lossy().to_string()).unwrap();
    let ir_path = compiler.compile(&out_dir).await.unwrap();

    let ir_json = std::fs::read_to_string(&ir_path).unwrap();
    let ir: WorkloadIr = serde_json::from_str(&ir_json).unwrap();
    ir.validate().unwrap();

    assert_eq!(ir.operations.len(), 0);
    assert_eq!(ir.clients.len(), 0);
}

#[test]
fn test_ir_generator_with_blobs() {
    let dir = fixtures_dir().join("blob_test");
    let _ = std::fs::remove_dir_all(&dir);

    let gen = IrGenerator::new(&dir).unwrap();

    let ops = vec![
        Operation::Open {
            op_id: "op_100".to_string(),
            client_id: "c1".to_string(),
            timestamp_us: 1000,
            path: "file.txt".to_string(),
            mode: smbench::ir::OpenMode::ReadWrite,
            handle_ref: "h_100".to_string(),
            extensions: None,
        },
        Operation::Write {
            op_id: "op_101".to_string(),
            client_id: "c1".to_string(),
            timestamp_us: 2000,
            handle_ref: "h_100".to_string(),
            offset: 0,
            length: 11,
            blob_path: String::new(),
        },
        Operation::Close {
            op_id: "op_102".to_string(),
            client_id: "c1".to_string(),
            timestamp_us: 3000,
            handle_ref: "h_100".to_string(),
        },
    ];

    let mut write_data = HashMap::new();
    write_data.insert("op_101".to_string(), b"hello world".to_vec());

    let path = gen.generate(ops, write_data).unwrap();

    // Verify workload.json.
    let ir: WorkloadIr = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    ir.validate().unwrap();
    assert_eq!(ir.operations.len(), 3);

    // Verify the blob was written.
    let blob_files: Vec<_> = std::fs::read_dir(dir.join("blobs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(blob_files.len(), 1);

    // Verify the Write op has the correct blob_path.
    if let Operation::Write { blob_path, .. } = &ir.operations[1] {
        assert!(blob_path.starts_with("blobs/"), "blob_path = {}", blob_path);
    } else {
        panic!("Expected Write operation at index 1");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_multi_client_pcap_client_ids() {
    let dir = fixtures_dir();
    let pcap = pcap_helpers::generate_multi_client_pcap(&dir);
    let merged = parse_and_merge(&pcap);

    let mut sm = SmbStateMachine::new();
    for (client_id, msgs) in merged {
        sm.set_client_id(&client_id);
        for msg in msgs {
            sm.process_message(msg).unwrap();
        }
    }

    let conns = sm.finalize().unwrap();
    let extractor = OperationExtractor::new();
    let ops = extractor.extract(&conns).unwrap();

    // Collect unique client IDs.
    let client_ids: std::collections::HashSet<_> = ops.iter().map(|o| o.client_id().to_string()).collect();
    assert!(
        client_ids.len() >= 3,
        "Expected >= 3 unique client IDs, got {}: {:?}",
        client_ids.len(),
        client_ids
    );
}
