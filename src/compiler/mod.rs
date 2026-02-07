//! PCAP Compiler Module
//!
//! Extracts SMB2/3 operations from PCAP files and generates WorkloadIr.
//!
//! ## Pipeline
//!
//! ```text
//! PCAP File
//!   → PcapReader (packet streaming)
//!   → TcpReassembler (TCP stream reconstruction)
//!   → SmbParser (SMB2/3 message parsing)
//!   → SmbStateMachine (protocol state tracking)
//!   → OperationExtractor (IR operation conversion)
//!   → IrGenerator (WorkloadIr JSON + blob storage)
//! ```
//!
//! ## References
//!
//! - [MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3
//! - [RFC 793] Transmission Control Protocol

#[cfg(feature = "pcap-compiler")]
pub mod pcap_reader;

#[cfg(feature = "pcap-compiler")]
pub mod tcp_reassembly;

#[cfg(feature = "pcap-compiler")]
pub mod smb_parser;

#[cfg(feature = "pcap-compiler")]
pub mod state_machine;

#[cfg(feature = "pcap-compiler")]
pub mod operation_extractor;

#[cfg(feature = "pcap-compiler")]
pub mod ir_generator;

#[cfg(feature = "pcap-compiler")]
pub use pcap_reader::PcapReader;

#[cfg(feature = "pcap-compiler")]
pub use tcp_reassembly::TcpReassembler;

#[cfg(feature = "pcap-compiler")]
pub use smb_parser::SmbParser;

#[cfg(feature = "pcap-compiler")]
pub use state_machine::SmbStateMachine;

#[cfg(feature = "pcap-compiler")]
pub use operation_extractor::OperationExtractor;

#[cfg(feature = "pcap-compiler")]
pub use ir_generator::IrGenerator;

#[cfg(feature = "pcap-compiler")]
use crate::ir::Operation;
#[cfg(feature = "pcap-compiler")]
use std::collections::HashMap;
#[cfg(feature = "pcap-compiler")]
use smb_parser::SmbMessage;

/// Configuration options for the PCAP compiler.
#[cfg(feature = "pcap-compiler")]
#[derive(Debug, Clone, Default)]
pub struct CompilerOptions {
    /// Only include traffic from/to this client IP.
    pub filter_client: Option<String>,
    /// Only include traffic for this share name.
    pub filter_share: Option<String>,
    /// Replace IPs and paths with anonymized values.
    pub anonymize: bool,
    /// Verbose logging.
    pub verbose: bool,
}

/// Main PCAP compiler interface.
///
/// Orchestrates the full pipeline from PCAP file to WorkloadIr JSON.
#[cfg(feature = "pcap-compiler")]
pub struct PcapCompiler {
    pcap_path: String,
    options: CompilerOptions,
}

#[cfg(feature = "pcap-compiler")]
impl PcapCompiler {
    /// Create a new compiler for the given PCAP file.
    pub fn new(pcap_path: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            pcap_path: pcap_path.into(),
            options: CompilerOptions::default(),
        })
    }

    /// Create a new compiler with options.
    pub fn with_options(pcap_path: impl Into<String>, options: CompilerOptions) -> anyhow::Result<Self> {
        Ok(Self {
            pcap_path: pcap_path.into(),
            options,
        })
    }

    /// Compile PCAP → WorkloadIr.
    ///
    /// Returns the path to the generated `workload.json`.
    pub async fn compile(&self, output_dir: impl AsRef<std::path::Path>) -> anyhow::Result<String> {
        tracing::info!("Compiling PCAP: {}", self.pcap_path);

        // ── Phase 1: Read packets and reassemble TCP streams ──
        let reader = PcapReader::new(&self.pcap_path)?;
        let mut reassembler = TcpReassembler::new();

        let mut packet_count = 0u64;
        for packet in reader.packets()? {
            reassembler.process_packet(packet?)?;
            packet_count += 1;
        }
        tracing::info!("Read {} packets from PCAP", packet_count);

        let streams = reassembler.finalize()?;
        tracing::info!("Reassembled {} TCP streams", streams.len());

        // ── Phase 2: Parse SMB messages and merge both directions ──
        //
        // TCP reassembly produces separate streams per direction:
        //   - client→server (requests)
        //   - server→client (responses)
        //
        // The state machine needs to see requests before their matching
        // responses (paired by message_id). We group streams by their
        // bidirectional connection key, collect all messages, then sort
        // so requests (is_response=false) precede responses for the
        // same message_id.

        let mut parser = SmbParser::new();

        // (client_ip, messages_from_both_directions)
        struct ConnectionMessages {
            client_id: String,
            messages: Vec<SmbMessage>,
        }

        // Group by canonical connection (bidirectional).
        let mut conn_map: HashMap<String, ConnectionMessages> = HashMap::new();

        for stream in &streams {
            let client_id = if stream.id.is_client_to_server() {
                stream.id.src_ip.to_string()
            } else {
                stream.id.dst_ip.to_string()
            };

            // Apply client filter.
            if let Some(ref filter) = self.options.filter_client {
                if &client_id != filter {
                    continue;
                }
            }

            let messages = parser.parse_stream(stream)?;
            if self.options.verbose {
                tracing::debug!(
                    "Stream {:?}: {} SMB messages (client={})",
                    stream.id, messages.len(), client_id
                );
            }

            // Use canonical 4-tuple key: sorted (ip_a:port_a, ip_b:port_b).
            let (a, b) = stream.id.canonical();
            let key = format!("{}:{}-{}:{}", a.src_ip, a.src_port, b.src_ip, b.src_port);

            let entry = conn_map.entry(key).or_insert_with(|| ConnectionMessages {
                client_id: client_id.clone(),
                messages: Vec::new(),
            });
            // Make sure client_id is consistent (prefer the client→server direction).
            if stream.id.is_client_to_server() {
                entry.client_id = client_id;
            }
            entry.messages.extend(messages);
        }

        // ── Phase 3: Feed sorted messages to the state machine ──
        let mut state_machine = SmbStateMachine::new();

        for (_key, mut conn) in conn_map {
            // Sort: by message_id, then requests before responses.
            conn.messages.sort_by(|a, b| {
                a.message_id.cmp(&b.message_id)
                    .then(a.is_response.cmp(&b.is_response))
            });

            state_machine.set_client_id(&conn.client_id);
            for msg in conn.messages {
                state_machine.process_message(msg)?;
            }
        }

        let connections = state_machine.finalize()?;
        tracing::info!("Tracked {} SMB connections", connections.len());

        // ── Phase 4: Extract IR operations ──
        let extractor = OperationExtractor::new();
        let operations = extractor.extract(&connections)?;
        tracing::info!("Extracted {} operations", operations.len());

        // ── Phase 5: Collect write data for blob storage ──
        let mut write_data: HashMap<String, Vec<u8>> = HashMap::new();
        for conn in &connections {
            for tracked in &conn.operations {
                if tracked.operation_type == "Write" {
                    if let Some(data) = &tracked.data {
                        for op in &operations {
                            if let Operation::Write { op_id, handle_ref, timestamp_us, .. } = op {
                                if *timestamp_us == tracked.timestamp_us
                                    && tracked.handle_ref.as_deref() == Some(handle_ref.as_str())
                                {
                                    write_data.insert(op_id.clone(), data.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Phase 6: Generate WorkloadIr JSON + blobs ──
        let generator = IrGenerator::new(output_dir.as_ref())?;
        let ir_path = generator.generate(operations, write_data)?;
        tracing::info!("Generated WorkloadIr: {}", ir_path);

        Ok(ir_path)
    }
}
