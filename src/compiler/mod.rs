//! PCAP Compiler Module
//!
//! Extracts SMB operations from PCAP files and generates WorkloadIr.
//!
//! ## Architecture
//!
//! ```text
//! PCAP File → PcapReader → TcpReassembler → SmbParser → OperationExtractor → IrGenerator → WorkloadIr
//! ```
//!
//! ## Components
//!
//! - **PcapReader:** Streams packets from PCAP file
//! - **TcpReassembler:** Reconstructs TCP streams from packets
//! - **SmbParser:** Parses SMB2/3 messages using smb-msg crate
//! - **StateMachine:** Tracks SMB protocol state per connection
//! - **OperationExtractor:** Converts SMB messages to IR operations
//! - **IrGenerator:** Generates final WorkloadIr JSON + blob files
//!
//! ## Usage
//!
//! ```rust,no_run
//! use smbench::compiler::PcapCompiler;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let compiler = PcapCompiler::new("capture.pcap")?;
//! let ir = compiler.compile("output_dir").await?;
//! # Ok(())
//! # }
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
/// Main PCAP compiler interface
pub struct PcapCompiler {
    pcap_path: String,
}

#[cfg(feature = "pcap-compiler")]
impl PcapCompiler {
    /// Create a new PCAP compiler for the given file
    pub fn new(pcap_path: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            pcap_path: pcap_path.into(),
        })
    }

    /// Compile PCAP file to WorkloadIr
    ///
    /// # Arguments
    ///
    /// * `output_dir` - Directory to write WorkloadIr JSON and blob files
    ///
    /// # Returns
    ///
    /// Path to generated workload.json file
    pub async fn compile(&self, output_dir: impl AsRef<std::path::Path>) -> anyhow::Result<String> {
        tracing::info!("Compiling PCAP: {}", self.pcap_path);

        // Phase 1: Read PCAP and reassemble TCP streams
        let reader = PcapReader::new(&self.pcap_path)?;
        let mut reassembler = TcpReassembler::new();

        for packet in reader.packets()? {
            reassembler.process_packet(packet?)?;
        }

        let streams = reassembler.finalize()?;
        tracing::info!("Reassembled {} TCP streams", streams.len());

        // Phase 2: Parse SMB messages from TCP streams
        let mut parser = SmbParser::new();
        let mut state_machine = SmbStateMachine::new();

        for stream in streams {
            let messages = parser.parse_stream(&stream)?;
            tracing::debug!("Parsed {} SMB messages from stream", messages.len());

            // Phase 3: Track protocol state and extract operations
            for message in messages {
                state_machine.process_message(message)?;
            }
        }

        let connections = state_machine.finalize()?;
        tracing::info!("Tracked {} SMB connections", connections.len());

        // Phase 4: Extract IR operations from state machine
        let extractor = OperationExtractor::new();
        let operations = extractor.extract(&connections)?;
        tracing::info!("Extracted {} operations", operations.len());

        // Phase 5: Generate WorkloadIr JSON + blob files
        let generator = IrGenerator::new(output_dir.as_ref())?;
        let ir_path = generator.generate(operations)?;
        tracing::info!("Generated WorkloadIr: {}", ir_path);

        Ok(ir_path)
    }
}
