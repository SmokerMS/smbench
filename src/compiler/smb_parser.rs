//! SMB2/3 message parsing from TCP streams
//!
//! Reference: [MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3

use super::tcp_reassembly::TcpStream;
use anyhow::Result;

/// Parsed SMB message
#[derive(Debug, Clone)]
pub struct SmbMessage {
    pub timestamp_us: u64,
    pub message_id: u64,
    pub session_id: u64,
    pub tree_id: u32,
    pub command: SmbCommand,
    pub is_response: bool,
    pub status: u32,
}

/// SMB2/3 commands
#[derive(Debug, Clone)]
pub enum SmbCommand {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create { file_id: [u8; 16], path: String },
    Close { file_id: [u8; 16] },
    Read { file_id: [u8; 16], offset: u64, length: u32 },
    Write { file_id: [u8; 16], offset: u64, length: u32, data: Vec<u8> },
    Ioctl { file_id: [u8; 16], ctl_code: u32 },
    QueryDirectory { file_id: [u8; 16], pattern: String },
    ChangeNotify { file_id: [u8; 16] },
    QueryInfo { file_id: [u8; 16] },
    SetInfo { file_id: [u8; 16] },
    OplockBreak,
}

/// SMB message parser
pub struct SmbParser;

impl SmbParser {
    /// Create a new SMB parser
    pub fn new() -> Self {
        Self
    }

    /// Parse SMB messages from a TCP stream
    pub fn parse_stream(&mut self, _stream: &TcpStream) -> Result<Vec<SmbMessage>> {
        // TODO: Implement SMB message parsing
        // 1. Find SMB2/3 magic bytes (0xFE 'S' 'M' 'B')
        // 2. Parse SMB2 header (64 bytes)
        // 3. Parse command-specific payload
        // 4. Handle compound requests (NextCommand offset)
        // 5. Pair requests with responses using MessageId
        Ok(Vec::new())
    }
}

impl Default for SmbParser {
    fn default() -> Self {
        Self::new()
    }
}
