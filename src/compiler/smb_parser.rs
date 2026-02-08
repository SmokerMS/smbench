//! SMB2/3 message parsing from reassembled TCP streams.
//!
//! Parses the SMB2 transport framing (NetBIOS session service 4-byte length),
//! the 64-byte SMB2 header, and command-specific payloads for the operations
//! we need to extract for the IR.
//!
//! We use `nom` combinators for zero-copy parsing.
//!
//! ## References
//!
//! - [MS-SMB2 2.2.1] SMB2 Packet Header
//! - [MS-SMB2 2.2.3] SMB2 NEGOTIATE Request/Response
//! - [MS-SMB2 2.2.5] SMB2 SESSION_SETUP
//! - [MS-SMB2 2.2.9] SMB2 TREE_CONNECT
//! - [MS-SMB2 2.2.13] SMB2 CREATE Request
//! - [MS-SMB2 2.2.14] SMB2 CREATE Response
//! - [MS-SMB2 2.2.15] SMB2 CLOSE
//! - [MS-SMB2 2.2.19] SMB2 READ
//! - [MS-SMB2 2.2.21] SMB2 WRITE
//! - [MS-SMB2 2.2.31] SMB2 IOCTL
//! - [MS-SMB2 2.2.39] SMB2 SET_INFO

use super::tcp_reassembly::TcpStream;
use anyhow::{Result, anyhow};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::IResult;

// ── SMB2 command codes [MS-SMB2 2.2.1.2] ──

/// SMB2 command codes as defined in [MS-SMB2 2.2.1.2].
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbCommandCode {
    Negotiate       = 0x0000,
    SessionSetup    = 0x0001,
    Logoff          = 0x0002,
    TreeConnect     = 0x0003,
    TreeDisconnect  = 0x0004,
    Create          = 0x0005,
    Close           = 0x0006,
    Flush           = 0x0007,
    Read            = 0x0008,
    Write           = 0x0009,
    Lock            = 0x000A,
    Ioctl           = 0x000B,
    Cancel          = 0x000C,
    Echo            = 0x000D,
    QueryDirectory  = 0x000E,
    ChangeNotify    = 0x000F,
    QueryInfo       = 0x0010,
    SetInfo         = 0x0011,
    OplockBreak     = 0x0012,
}

impl SmbCommandCode {
    fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Self::Negotiate),
            0x0001 => Some(Self::SessionSetup),
            0x0002 => Some(Self::Logoff),
            0x0003 => Some(Self::TreeConnect),
            0x0004 => Some(Self::TreeDisconnect),
            0x0005 => Some(Self::Create),
            0x0006 => Some(Self::Close),
            0x0007 => Some(Self::Flush),
            0x0008 => Some(Self::Read),
            0x0009 => Some(Self::Write),
            0x000A => Some(Self::Lock),
            0x000B => Some(Self::Ioctl),
            0x000C => Some(Self::Cancel),
            0x000D => Some(Self::Echo),
            0x000E => Some(Self::QueryDirectory),
            0x000F => Some(Self::ChangeNotify),
            0x0010 => Some(Self::QueryInfo),
            0x0011 => Some(Self::SetInfo),
            0x0012 => Some(Self::OplockBreak),
            _ => None,
        }
    }
}

/// SMB2 flags field bits [MS-SMB2 2.2.1.1].
const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;

/// The SMB2 header magic bytes: 0xFE 'S' 'M' 'B'.
const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";

// ── parsed types ──

/// A parsed SMB2 message (header + command payload).
#[derive(Debug, Clone)]
pub struct SmbMessage {
    /// Timestamp of the TCP stream at the point this message starts.
    pub timestamp_us: u64,
    /// Message ID used to pair requests with responses [MS-SMB2 2.2.1].
    pub message_id: u64,
    /// Session ID [MS-SMB2 2.2.1].
    pub session_id: u64,
    /// Tree ID [MS-SMB2 2.2.1].
    pub tree_id: u32,
    /// Parsed command.
    pub command: SmbCommand,
    /// True if this is a server response (FLAGS_SERVER_TO_REDIR set).
    pub is_response: bool,
    /// NT status code from the header (only meaningful for responses).
    pub status: u32,
    /// CreditCharge from the header [MS-SMB2 2.2.1] — for multi-credit tracking.
    pub credit_charge: u16,
    /// Index within a compound request (0 = standalone or first, 1+ = subsequent).
    pub compound_index: u16,
    /// Whether this message is the last in a compound chain.
    pub compound_last: bool,
    /// Whether this is an async response (STATUS_PENDING with async flag set).
    pub is_async: bool,
}

/// Parsed SMB2 command payloads.
#[derive(Debug, Clone)]
pub enum SmbCommand {
    Negotiate,
    SessionSetup {
        /// Session flags from response (IS_GUEST=0x01, IS_NULL=0x02, ENCRYPT_DATA=0x04).
        session_flags: Option<u16>,
    },
    Logoff,
    TreeConnect {
        /// Share path (from request) or empty (from response).
        path: String,
        /// Share type from response (0x01=Disk, 0x02=Pipe, 0x03=Print).
        share_type: Option<u8>,
        /// Share flags from response [MS-SMB2 2.2.10].
        share_flags: Option<u32>,
        /// Share capabilities from response [MS-SMB2 2.2.10].
        share_capabilities: Option<u32>,
    },
    TreeDisconnect,
    Create(CreateParams),
    Close {
        file_id: FileId,
    },
    Read {
        file_id: FileId,
        offset: u64,
        length: u32,
        /// SMB2 READ flags byte (e.g., SMB2_READFLAG_READ_UNBUFFERED = 0x01).
        flags: u8,
    },
    Write {
        file_id: FileId,
        offset: u64,
        length: u32,
        data: Vec<u8>,
        /// SMB2 WRITE flags (e.g., SMB2_WRITEFLAG_WRITE_THROUGH = 0x01).
        flags: u32,
    },
    Ioctl {
        file_id: FileId,
        ctl_code: u32,
        /// Input buffer size (bytes).
        input_count: u32,
        /// Output buffer size (bytes) — from response, or MaxOutputResponse from request.
        output_count: u32,
    },
    SetInfo(SetInfoParams),
    QueryDirectory {
        file_id: FileId,
        pattern: String,
        info_class: u8,
    },
    ChangeNotify {
        file_id: FileId,
        filter: u32,
        recursive: bool,
    },
    QueryInfo {
        file_id: FileId,
        info_type: u8,
        info_class: u8,
        /// Output buffer length from response, or requested OutputBufferLength from request.
        output_buffer_length: u32,
    },
    Flush {
        file_id: FileId,
    },
    Lock {
        file_id: FileId,
        locks: Vec<LockElement>,
        /// LockSequenceNumber combined field [MS-SMB2 2.2.26].
        lock_sequence: u32,
    },
    OplockBreak {
        file_id: FileId,
        oplock_level: u8,
    },
    Echo,
    Cancel {
        cancelled_message_id: u64,
    },
    /// Commands we don't parse in detail.
    Other {
        code: u16,
    },
}

/// Parameters extracted from SMB2_CREATE request/response.
#[derive(Debug, Clone)]
pub struct CreateParams {
    /// File ID (only valid in responses; zero in requests).
    pub file_id: FileId,
    /// Requested file path (only in requests).
    pub path: String,
    /// DesiredAccess mask [MS-SMB2 2.2.13].
    pub desired_access: u32,
    /// CreateDisposition [MS-SMB2 2.2.13].
    pub create_disposition: u32,
    /// Oplock level requested/granted.
    pub oplock_level: u8,
    /// CreateOptions flags [MS-SMB2 2.2.13].
    pub create_options: u32,
    /// ShareAccess flags [MS-SMB2 2.2.13].
    pub share_access: u32,
    /// FileAttributes [MS-SMB2 2.2.13].
    pub file_attributes: u32,
    /// CreateAction from response (FILE_SUPERSEDED=0, FILE_OPENED=1, FILE_CREATED=2, FILE_OVERWRITTEN=3).
    pub create_action: Option<u32>,
    /// Raw create context tags extracted from the request (e.g., "MxAc", "QFid", "DH2Q").
    pub create_context_tags: Vec<String>,
}

/// Parameters from SMB2_SET_INFO used to detect rename operations.
#[derive(Debug, Clone)]
pub struct SetInfoParams {
    pub file_id: FileId,
    /// InfoType: 0x01 = file, 0x02 = filesystem, 0x03 = security.
    pub info_type: u8,
    /// FileInfoClass [MS-SMB2 2.2.39].
    pub file_info_class: u8,
    /// If this is a FileRenameInformation (class 10 / 0x0A), the new name.
    pub rename_target: Option<String>,
}

/// A single lock element from an SMB2 LOCK request [MS-SMB2 2.2.26.1].
#[derive(Debug, Clone)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    /// Flags: bit 0 = shared, bit 1 = exclusive, bit 2 = unlock, bit 3 = fail_immediately
    pub flags: u32,
}

/// 16-byte SMB2 FileId [MS-SMB2 2.2.14.1].
pub type FileId = [u8; 16];

// ── parser implementation ──

/// SMB message parser.
pub struct SmbParser;

impl SmbParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse all SMB2 messages from a reassembled TCP stream.
    ///
    /// SMB messages are framed by the NetBIOS session service:
    /// a 4-byte big-endian length prefix followed by the SMB2 message.
    pub fn parse_stream(&mut self, stream: &TcpStream) -> Result<Vec<SmbMessage>> {
        let mut messages = Vec::new();
        let mut offset = 0usize;
        let data = &stream.data;

        while offset + 4 <= data.len() {
            // NetBIOS session service length (4 bytes, big-endian).
            // The first byte should be 0x00 (session message type).
            let nb_len = u32::from_be_bytes([
                data[offset] & 0x01, // only 1 bit of the type byte contributes to length
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;

            offset += 4;

            if nb_len == 0 || offset + nb_len > data.len() {
                break; // truncated or empty
            }

            let msg_data = &data[offset..offset + nb_len];
            offset += nb_len;

            // Parse potentially compound messages from this SMB PDU.
            self.parse_smb_pdu(msg_data, stream.start_time_us, &mut messages)?;
        }

        Ok(messages)
    }

    /// Parse one or more (compound) SMB2 messages from a single NetBIOS PDU.
    fn parse_smb_pdu(
        &self,
        data: &[u8],
        base_timestamp_us: u64,
        out: &mut Vec<SmbMessage>,
    ) -> Result<()> {
        let mut cursor = data;
        let mut compound_idx: u16 = 0;
        loop {
            if cursor.len() < 64 {
                break;
            }
            // Validate magic
            if &cursor[0..4] != SMB2_MAGIC {
                break;
            }

            match self.parse_header_and_command(cursor, base_timestamp_us) {
                Ok((next_command_offset, mut msg)) => {
                    msg.compound_index = compound_idx;
                    out.push(msg);
                    compound_idx += 1;
                    if next_command_offset == 0 {
                        break; // last in compound
                    }
                    if next_command_offset as usize > cursor.len() {
                        break;
                    }
                    cursor = &cursor[next_command_offset as usize..];
                }
                Err(_) => break, // unparseable; stop
            }
        }
        Ok(())
    }

    /// Parse the 64-byte header and the command payload.
    /// Returns `(NextCommand offset, parsed message)`.
    fn parse_header_and_command(
        &self,
        data: &[u8],
        base_timestamp_us: u64,
    ) -> Result<(u32, SmbMessage)> {
        // [MS-SMB2 2.2.1] SMB2 Packet Header
        //  0..4   ProtocolId  (0xFE 'S' 'M' 'B')
        //  4..6   StructureSize (64)
        //  6..8   CreditCharge
        //  8..12  Status (in response) / ChannelSequence (in request)
        // 12..14  Command
        // 14..16  CreditRequest/CreditResponse
        // 16..20  Flags
        // 20..24  NextCommand
        // 24..32  MessageId
        // 32..36  (Reserved / AsyncId high, depends on ASYNC flag)
        // 36..40  (Reserved / AsyncId low)
        // 40..44  TreeId (or AsyncId continued)
        // 44..52  SessionId
        // 52..68  Signature

        let (_, hdr) = parse_smb2_header(data)
            .map_err(|e| anyhow!("SMB2 header parse error: {:?}", e))?;

        let is_response = (hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
        let is_async = (hdr.flags & SMB2_FLAGS_ASYNC_COMMAND) != 0;
        let payload = &data[64..];

        let command = if let Some(code) = SmbCommandCode::from_u16(hdr.command) {
            self.parse_command_payload(code, payload, is_response)?
        } else {
            SmbCommand::Other { code: hdr.command }
        };

        Ok((
            hdr.next_command,
            SmbMessage {
                timestamp_us: base_timestamp_us,
                message_id: hdr.message_id,
                session_id: hdr.session_id,
                tree_id: hdr.tree_id,
                command,
                is_response,
                status: hdr.status,
                credit_charge: hdr.credit_charge,
                compound_index: 0, // set by caller in parse_smb_pdu
                compound_last: hdr.next_command == 0,
                is_async: is_async && hdr.status == 0x0000_0103, // STATUS_PENDING
            },
        ))
    }

    fn parse_command_payload(
        &self,
        code: SmbCommandCode,
        payload: &[u8],
        is_response: bool,
    ) -> Result<SmbCommand> {
        match code {
            SmbCommandCode::Negotiate => Ok(SmbCommand::Negotiate),
            SmbCommandCode::SessionSetup => {
                if is_response && payload.len() >= 4 {
                    let session_flags = u16::from_le_bytes([payload[2], payload[3]]);
                    Ok(SmbCommand::SessionSetup { session_flags: Some(session_flags) })
                } else {
                    Ok(SmbCommand::SessionSetup { session_flags: None })
                }
            }
            SmbCommandCode::Logoff => Ok(SmbCommand::Logoff),
            SmbCommandCode::TreeConnect => {
                if is_response {
                    // [MS-SMB2 2.2.10] TREE_CONNECT Response
                    // StructureSize(2) + ShareType(1) + Reserved(1) + ShareFlags(4) + Capabilities(4) + MaximalAccess(4)
                    if payload.len() >= 16 {
                        let share_type = payload[2];
                        let share_flags = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        let share_capabilities = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
                        Ok(SmbCommand::TreeConnect {
                            path: String::new(),
                            share_type: Some(share_type),
                            share_flags: Some(share_flags),
                            share_capabilities: Some(share_capabilities),
                        })
                    } else {
                        Ok(SmbCommand::TreeConnect {
                            path: String::new(),
                            share_type: None,
                            share_flags: None,
                            share_capabilities: None,
                        })
                    }
                } else {
                    let path = parse_tree_connect_request(payload).unwrap_or_default();
                    Ok(SmbCommand::TreeConnect {
                        path,
                        share_type: None,
                        share_flags: None,
                        share_capabilities: None,
                    })
                }
            }
            SmbCommandCode::TreeDisconnect => Ok(SmbCommand::TreeDisconnect),
            SmbCommandCode::Create => {
                if is_response {
                    parse_create_response(payload)
                } else {
                    parse_create_request(payload)
                }
            }
            SmbCommandCode::Close => {
                let fid = parse_file_id_at(payload, if is_response { 4 } else { 8 })?;
                Ok(SmbCommand::Close { file_id: fid })
            }
            SmbCommandCode::Read => {
                if is_response {
                    // We extract length from the response for pairing.
                    let length = if payload.len() >= 8 {
                        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
                    } else { 0 };
                    // Response has no file_id; we'll pair by message_id.
                    Ok(SmbCommand::Read {
                        file_id: [0; 16],
                        offset: 0,
                        length,
                        flags: 0,
                    })
                } else {
                    parse_read_request(payload)
                }
            }
            SmbCommandCode::Write => {
                if is_response {
                    let count = if payload.len() >= 8 {
                        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
                    } else { 0 };
                    Ok(SmbCommand::Write {
                        file_id: [0; 16],
                        offset: 0,
                        length: count,
                        data: Vec::new(),
                        flags: 0,
                    })
                } else {
                    parse_write_request(payload)
                }
            }
            SmbCommandCode::Ioctl => {
                // [MS-SMB2 2.2.31/2.2.32] IOCTL Request/Response
                // StructureSize(2) + Reserved(2) + CtlCode(4) + FileId(16) +
                //   InputOffset(4) + InputCount(4) + MaxInputResponse(4) +
                //   OutputOffset(4) + OutputCount(4) + MaxOutputResponse(4) + Flags(4) + Reserved2(4)
                if payload.len() >= 52 {
                    let ctl_code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let fid = parse_file_id_at(payload, 8)?;
                    let input_count = u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]);
                    let output_count = u32::from_le_bytes([payload[36], payload[37], payload[38], payload[39]]);
                    Ok(SmbCommand::Ioctl { file_id: fid, ctl_code, input_count, output_count })
                } else if payload.len() >= 20 {
                    let ctl_code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let fid = parse_file_id_at(payload, 8)?;
                    Ok(SmbCommand::Ioctl { file_id: fid, ctl_code, input_count: 0, output_count: 0 })
                } else {
                    Ok(SmbCommand::Ioctl { file_id: [0; 16], ctl_code: 0, input_count: 0, output_count: 0 })
                }
            }
            SmbCommandCode::SetInfo => {
                if !is_response && payload.len() >= 32 {
                    parse_set_info_request(payload)
                } else {
                    Ok(SmbCommand::SetInfo(SetInfoParams {
                        file_id: [0; 16],
                        info_type: 0,
                        file_info_class: 0,
                        rename_target: None,
                    }))
                }
            }
            SmbCommandCode::Flush => {
                // [MS-SMB2 2.2.17] FLUSH Request: StructureSize(2) + Reserved1(2) + Reserved2(4) + FileId(16)
                if !is_response && payload.len() >= 24 {
                    let fid = parse_file_id_at(payload, 8)?;
                    Ok(SmbCommand::Flush { file_id: fid })
                } else {
                    Ok(SmbCommand::Flush { file_id: [0; 16] })
                }
            }
            SmbCommandCode::Lock => {
                // [MS-SMB2 2.2.26] LOCK Request
                // StructureSize(2) + LockCount(2) + LockSequenceNumber/Index(4) + FileId(16) + Locks(variable)
                if !is_response && payload.len() >= 24 {
                    let lock_count = u16::from_le_bytes([payload[2], payload[3]]) as usize;
                    let lock_sequence = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let fid = parse_file_id_at(payload, 8)?;
                    let mut locks = Vec::with_capacity(lock_count);
                    // Each LockElement is 24 bytes: Offset(8) + Length(8) + Flags(4) + Reserved(4)
                    let locks_start = 24;
                    for i in 0..lock_count {
                        let base = locks_start + i * 24;
                        if base + 24 > payload.len() { break; }
                        let offset = u64::from_le_bytes([
                            payload[base], payload[base+1], payload[base+2], payload[base+3],
                            payload[base+4], payload[base+5], payload[base+6], payload[base+7],
                        ]);
                        let length = u64::from_le_bytes([
                            payload[base+8], payload[base+9], payload[base+10], payload[base+11],
                            payload[base+12], payload[base+13], payload[base+14], payload[base+15],
                        ]);
                        let flags = u32::from_le_bytes([
                            payload[base+16], payload[base+17], payload[base+18], payload[base+19],
                        ]);
                        locks.push(LockElement { offset, length, flags });
                    }
                    Ok(SmbCommand::Lock { file_id: fid, locks, lock_sequence })
                } else {
                    Ok(SmbCommand::Lock { file_id: [0; 16], locks: Vec::new(), lock_sequence: 0 })
                }
            }
            SmbCommandCode::QueryDirectory => {
                // [MS-SMB2 2.2.33] QUERY_DIRECTORY Request
                // StructureSize(2) + FileInformationClass(1) + Flags(1) + FileIndex(4)
                // + FileId(16) + FileNameOffset(2) + FileNameLength(2) + OutputBufferLength(4)
                if !is_response && payload.len() >= 32 {
                    let info_class = payload[2];
                    let fid = parse_file_id_at(payload, 8)?;
                    let name_offset = u16::from_le_bytes([payload[24], payload[25]]) as usize;
                    let name_length = u16::from_le_bytes([payload[26], payload[27]]) as usize;
                    let adj = name_offset.saturating_sub(64);
                    let pattern = if name_length > 0 && adj + name_length <= payload.len() {
                        decode_utf16le(&payload[adj..adj + name_length]).unwrap_or_else(|| "*".to_string())
                    } else {
                        "*".to_string()
                    };
                    Ok(SmbCommand::QueryDirectory { file_id: fid, pattern, info_class })
                } else {
                    Ok(SmbCommand::QueryDirectory { file_id: [0; 16], pattern: String::new(), info_class: 0 })
                }
            }
            SmbCommandCode::ChangeNotify => {
                // [MS-SMB2 2.2.35] CHANGE_NOTIFY Request
                // StructureSize(2) + Flags(2) + OutputBufferLength(4) + FileId(16) + CompletionFilter(4) + Reserved(4)
                if !is_response && payload.len() >= 32 {
                    let flags = u16::from_le_bytes([payload[2], payload[3]]);
                    let recursive = (flags & 0x0001) != 0; // WATCH_TREE
                    let fid = parse_file_id_at(payload, 8)?;
                    let filter = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
                    Ok(SmbCommand::ChangeNotify { file_id: fid, filter, recursive })
                } else {
                    Ok(SmbCommand::ChangeNotify { file_id: [0; 16], filter: 0, recursive: false })
                }
            }
            SmbCommandCode::QueryInfo => {
                // [MS-SMB2 2.2.37] QUERY_INFO Request
                // StructureSize(2) + InfoType(1) + FileInfoClass(1) + OutputBufferLength(4)
                // + InputBufferOffset(2) + Reserved(2) + InputBufferLength(4) + AdditionalInformation(4)
                // + Flags(4) + FileId(16)
                if is_response && payload.len() >= 8 {
                    // [MS-SMB2 2.2.38] QUERY_INFO Response
                    // StructureSize(2) + OutputBufferOffset(2) + OutputBufferLength(4)
                    let output_buffer_length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    Ok(SmbCommand::QueryInfo { file_id: [0; 16], info_type: 0, info_class: 0, output_buffer_length })
                } else if !is_response && payload.len() >= 40 {
                    let info_type = payload[2];
                    let info_class = payload[3];
                    let output_buffer_length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let fid = parse_file_id_at(payload, 24)?;
                    Ok(SmbCommand::QueryInfo { file_id: fid, info_type, info_class, output_buffer_length })
                } else {
                    Ok(SmbCommand::QueryInfo { file_id: [0; 16], info_type: 0, info_class: 0, output_buffer_length: 0 })
                }
            }
            SmbCommandCode::Echo => Ok(SmbCommand::Echo),
            SmbCommandCode::Cancel => {
                // Cancel doesn't have payload fields we need for pairing.
                // The cancelled_message_id comes from the SMB2 header, not the payload.
                Ok(SmbCommand::Cancel { cancelled_message_id: 0 })
            }
            SmbCommandCode::OplockBreak => {
                // [MS-SMB2 2.2.24.1/2] Oplock Break Notification / Acknowledgment
                // StructureSize(2) + OplockLevel(1) + Reserved(1) + Reserved2(4) + FileId(16)
                let oplock_level = if payload.len() >= 3 { payload[2] } else { 0 };
                let file_id = if payload.len() >= 24 {
                    parse_file_id_at(payload, 8)?
                } else {
                    [0; 16]
                };
                Ok(SmbCommand::OplockBreak { file_id, oplock_level })
            }
        }
    }
}

impl Default for SmbParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── nom sub-parsers ──

struct RawHeader {
    status: u32,
    command: u16,
    credit_charge: u16,
    flags: u32,
    next_command: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
}

fn parse_smb2_header(input: &[u8]) -> IResult<&[u8], RawHeader> {
    let (input, _magic) = take(4usize)(input)?;       //  0..4
    let (input, _struct_size) = le_u16(input)?;        //  4..6
    let (input, credit_charge) = le_u16(input)?;       //  6..8
    let (input, status) = le_u32(input)?;              //  8..12
    let (input, command) = le_u16(input)?;             // 12..14
    let (input, _credits) = le_u16(input)?;            // 14..16
    let (input, flags) = le_u32(input)?;               // 16..20
    let (input, next_command) = le_u32(input)?;        // 20..24
    let (input, message_id) = le_u64(input)?;          // 24..32
    let (input, _reserved) = le_u32(input)?;           // 32..36
    let (input, tree_id) = le_u32(input)?;             // 36..40  (note: async uses 8 bytes starting at 32)
    let (input, session_id) = le_u64(input)?;          // 40..48
    let (input, _signature) = take(16usize)(input)?;   // 48..64
    Ok((input, RawHeader {
        status,
        command,
        credit_charge,
        flags,
        next_command,
        message_id,
        tree_id,
        session_id,
    }))
}

fn parse_file_id_at(data: &[u8], offset: usize) -> Result<FileId> {
    if data.len() < offset + 16 {
        return Err(anyhow!("data too short for file_id at offset {}", offset));
    }
    let mut fid = [0u8; 16];
    fid.copy_from_slice(&data[offset..offset + 16]);
    Ok(fid)
}

/// [MS-SMB2 2.2.9] TREE_CONNECT Request
fn parse_tree_connect_request(payload: &[u8]) -> Option<String> {
    // StructureSize (2) + Reserved/Flags (2) + PathOffset (2) + PathLength (2) = 8
    if payload.len() < 8 {
        return None;
    }
    let path_offset = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    let path_length = u16::from_le_bytes([payload[6], payload[7]]) as usize;
    // PathOffset is relative to the beginning of the SMB2 header (byte 0 of the packet).
    // Since we receive `payload` starting after the 64-byte header, adjust:
    let adjusted_offset = path_offset.checked_sub(64 + 8)?; // header + struct before buffer
    // The path is typically at the end of the fixed-size portion.
    // Try using path_offset relative to the start of the payload's buffer area.
    // Simplification: assume path bytes start right after the 8-byte structure.
    let buf_start = if adjusted_offset < payload.len() { adjusted_offset } else { 8 };
    if buf_start + path_length > payload.len() {
        // Fall back to reading whatever is there.
        let avail = &payload[8..];
        return decode_utf16le(avail);
    }
    decode_utf16le(&payload[buf_start..buf_start + path_length])
}

/// [MS-SMB2 2.2.13] CREATE Request
fn parse_create_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + SecurityFlags (1) + RequestedOplockLevel (1)
    // + ImpersonationLevel (4) + SmbCreateFlags (8) + Reserved (8)
    // + DesiredAccess (4) + FileAttributes (4) + ShareAccess (4)
    // + CreateDisposition (4) + CreateOptions (4)
    // + NameOffset (2) + NameLength (2) + CreateContextsOffset (4) + CreateContextsLength (4)
    // = 56 bytes fixed portion
    if payload.len() < 56 {
        return Ok(SmbCommand::Create(CreateParams {
            file_id: [0; 16],
            path: String::new(),
            desired_access: 0,
            create_disposition: 0,
            oplock_level: 0,
            create_options: 0,
            share_access: 0,
            file_attributes: 0,
            create_action: None,
            create_context_tags: Vec::new(),
        }));
    }
    let oplock_level = payload[3];
    let desired_access = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let file_attributes = u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]);
    let share_access = u32::from_le_bytes([payload[32], payload[33], payload[34], payload[35]]);
    let create_disposition = u32::from_le_bytes([payload[36], payload[37], payload[38], payload[39]]);
    let create_options = u32::from_le_bytes([payload[40], payload[41], payload[42], payload[43]]);
    let name_offset = u16::from_le_bytes([payload[44], payload[45]]) as usize;
    let name_length = u16::from_le_bytes([payload[46], payload[47]]) as usize;
    let ctx_offset = u32::from_le_bytes([payload[48], payload[49], payload[50], payload[51]]) as usize;
    let ctx_length = u32::from_le_bytes([payload[52], payload[53], payload[54], payload[55]]) as usize;

    // name_offset is relative to start of SMB2 header; we have payload starting after 64 bytes.
    let adj = name_offset.saturating_sub(64);
    let path = if adj + name_length <= payload.len() {
        decode_utf16le(&payload[adj..adj + name_length]).unwrap_or_default()
    } else {
        String::new()
    };

    // Parse create context tags
    let create_context_tags = if ctx_offset > 0 && ctx_length > 0 {
        let ctx_adj = ctx_offset.saturating_sub(64);
        if ctx_adj + ctx_length <= payload.len() {
            parse_create_context_tags(&payload[ctx_adj..ctx_adj + ctx_length])
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(SmbCommand::Create(CreateParams {
        file_id: [0; 16],
        path,
        desired_access,
        create_disposition,
        oplock_level,
        create_options,
        share_access,
        file_attributes,
        create_action: None,
        create_context_tags,
    }))
}

/// [MS-SMB2 2.2.14] CREATE Response
fn parse_create_response(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + OplockLevel (1) + Flags (1) + CreateAction (4)
    // + CreationTime (8) + LastAccessTime (8) + LastWriteTime (8) + ChangeTime (8)
    // + AllocationSize (8) + EndofFile (8)
    // + FileAttributes (4) + Reserved2 (4) + FileId (16) + ...
    // FileId starts at offset 64 within the response body.
    if payload.len() < 80 {
        return Ok(SmbCommand::Create(CreateParams {
            file_id: [0; 16],
            path: String::new(),
            desired_access: 0,
            create_disposition: 0,
            oplock_level: payload.first().copied().unwrap_or(0),
            create_options: 0,
            share_access: 0,
            file_attributes: 0,
            create_action: None,
            create_context_tags: Vec::new(),
        }));
    }
    let oplock_level = payload[2];
    let create_action = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let file_attributes = u32::from_le_bytes([payload[56], payload[57], payload[58], payload[59]]);
    let file_id = parse_file_id_at(payload, 64)?;
    Ok(SmbCommand::Create(CreateParams {
        file_id,
        path: String::new(),
        desired_access: 0,
        create_disposition: 0,
        oplock_level,
        create_options: 0,
        share_access: 0,
        file_attributes,
        create_action: Some(create_action),
        create_context_tags: Vec::new(),
    }))
}

/// Parse create context tags from a raw create context buffer.
///
/// [MS-SMB2 2.2.13.2] Each create context has:
///   Next (4) + NameOffset (2) + NameLength (2) + Reserved (2) + DataOffset (2) + DataLength (4)
///   = 16 bytes header, followed by name and data.
fn parse_create_context_tags(buf: &[u8]) -> Vec<String> {
    let mut tags = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset + 16 > buf.len() {
            break;
        }
        let next = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        let name_offset = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]) as usize;
        let name_length = u16::from_le_bytes([buf[offset + 6], buf[offset + 7]]) as usize;

        let name_start = offset + name_offset;
        if name_start + name_length <= buf.len() && name_length > 0 {
            // Create context names are typically ASCII tags like "MxAc", "QFid", "DH2Q"
            let tag = String::from_utf8_lossy(&buf[name_start..name_start + name_length])
                .trim_end_matches('\0')
                .to_string();
            if !tag.is_empty() {
                tags.push(tag);
            }
        }

        if next == 0 {
            break;
        }
        offset += next as usize;
    }
    tags
}

/// [MS-SMB2 2.2.19] READ Request
fn parse_read_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + Padding (1) + Flags (1) + Length (4)
    // + Offset (8) + FileId (16) + ...
    if payload.len() < 32 {
        return Err(anyhow!("READ request too short"));
    }
    let flags = payload[3];
    let length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let offset = u64::from_le_bytes([
        payload[8], payload[9], payload[10], payload[11],
        payload[12], payload[13], payload[14], payload[15],
    ]);
    let file_id = parse_file_id_at(payload, 16)?;
    Ok(SmbCommand::Read { file_id, offset, length, flags })
}

/// [MS-SMB2 2.2.21] WRITE Request
fn parse_write_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + DataOffset (2) + Length (4) + Offset (8)
    // + FileId (16) + Channel (4) + RemainingBytes (4)
    // + WriteChannelInfoOffset (2) + WriteChannelInfoLength (2) + Flags (4)
    if payload.len() < 32 {
        return Err(anyhow!("WRITE request too short"));
    }
    let data_offset_field = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    let length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let offset = u64::from_le_bytes([
        payload[8], payload[9], payload[10], payload[11],
        payload[12], payload[13], payload[14], payload[15],
    ]);
    let file_id = parse_file_id_at(payload, 16)?;
    // Flags field at offset 44 (if present)
    let flags = if payload.len() >= 48 {
        u32::from_le_bytes([payload[44], payload[45], payload[46], payload[47]])
    } else {
        0
    };

    // DataOffset is relative to the start of the SMB2 header.
    let adj = data_offset_field.saturating_sub(64);
    let data = if adj + length as usize <= payload.len() {
        payload[adj..adj + length as usize].to_vec()
    } else {
        Vec::new()
    };

    Ok(SmbCommand::Write { file_id, offset, length, data, flags })
}

/// [MS-SMB2 2.2.39] SET_INFO Request
fn parse_set_info_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + InfoType (1) + FileInfoClass (1)
    // + BufferLength (4) + BufferOffset (2) + Reserved (2)
    // + AdditionalInformation (4) + FileId (16)
    if payload.len() < 32 {
        return Err(anyhow!("SET_INFO too short"));
    }
    let info_type = payload[2];
    let file_info_class = payload[3];
    let buffer_length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let buffer_offset = u16::from_le_bytes([payload[8], payload[9]]) as usize;
    let file_id = parse_file_id_at(payload, 16)?;

    let mut rename_target = None;

    // FileRenameInformation = class 10 (0x0A), InfoType = FILE (0x01)
    if info_type == 0x01 && file_info_class == 0x0A {
        let adj = buffer_offset.saturating_sub(64);
        if adj + buffer_length <= payload.len() && buffer_length >= 24 {
            let rename_buf = &payload[adj..adj + buffer_length];
            // FileRenameInformation2 [MS-FSCC 2.4.34.2]:
            //  ReplaceIfExists (1) + Reserved (7) + RootDirectory (8) + FileNameLength (4) + FileName
            let name_len = u32::from_le_bytes([
                rename_buf[16], rename_buf[17], rename_buf[18], rename_buf[19],
            ]) as usize;
            if 20 + name_len <= rename_buf.len() {
                rename_target = decode_utf16le(&rename_buf[20..20 + name_len]);
            }
        }
    }

    Ok(SmbCommand::SetInfo(SetInfoParams {
        file_id,
        info_type,
        file_info_class,
        rename_target,
    }))
}

/// Decode a UTF-16LE byte slice into a Rust String.
fn decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() % 2 != 0 {
        return None;
    }
    let u16s: Vec<u16> = data.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&u16s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ──────────────────────────────────────────────────

    /// Build a minimal SMB2 message (header + payload) for testing.
    fn build_smb2_message(
        command: u16,
        flags: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        status: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        build_smb2_message_ex(command, flags, message_id, session_id, tree_id, status, 1, 0, payload)
    }

    /// Extended builder with credit_charge and next_command fields.
    fn build_smb2_message_ex(
        command: u16,
        flags: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        status: u32,
        credit_charge: u16,
        next_command: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(SMB2_MAGIC);                  //  0..4
        msg.extend_from_slice(&64u16.to_le_bytes());         //  4..6  StructureSize
        msg.extend_from_slice(&credit_charge.to_le_bytes()); //  6..8  CreditCharge
        msg.extend_from_slice(&status.to_le_bytes());        //  8..12
        msg.extend_from_slice(&command.to_le_bytes());       // 12..14
        msg.extend_from_slice(&1u16.to_le_bytes());          // 14..16 Credits
        msg.extend_from_slice(&flags.to_le_bytes());         // 16..20
        msg.extend_from_slice(&next_command.to_le_bytes());  // 20..24 NextCommand
        msg.extend_from_slice(&message_id.to_le_bytes());    // 24..32
        msg.extend_from_slice(&0u32.to_le_bytes());          // 32..36 Reserved
        msg.extend_from_slice(&tree_id.to_le_bytes());       // 36..40
        msg.extend_from_slice(&session_id.to_le_bytes());    // 40..48
        msg.extend_from_slice(&[0u8; 16]);                   // 48..64 Signature
        msg.extend_from_slice(payload);
        msg
    }

    /// Wrap an SMB2 message with a NetBIOS length prefix.
    fn frame_netbios(msg: &[u8]) -> Vec<u8> {
        let len = msg.len() as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(msg);
        frame
    }

    /// Convenience: build a TcpStream and parse a single framed message.
    fn parse_one(smb_bytes: &[u8]) -> SmbMessage {
        let stream_data = frame_netbios(smb_bytes);
        let stream = super::super::tcp_reassembly::TcpStream {
            id: super::super::tcp_reassembly::StreamId {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 50000,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 445,
            },
            data: stream_data,
            start_time_us: 1000,
        };
        let mut parser = SmbParser::new();
        let msgs = parser.parse_stream(&stream).unwrap();
        assert_eq!(msgs.len(), 1, "expected exactly one message");
        msgs.into_iter().next().unwrap()
    }

    /// Convenience: parse multiple messages from a single raw PDU (for compound tests).
    fn parse_pdu(pdu_bytes: &[u8]) -> Vec<SmbMessage> {
        let stream_data = frame_netbios(pdu_bytes);
        let stream = super::super::tcp_reassembly::TcpStream {
            id: super::super::tcp_reassembly::StreamId {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 50000,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 445,
            },
            data: stream_data,
            start_time_us: 1000,
        };
        let mut parser = SmbParser::new();
        parser.parse_stream(&stream).unwrap()
    }

    /// Encode a Rust string as UTF-16LE bytes.
    fn encode_utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    // ── Original tests (preserved) ───────────────────────────────────

    #[test]
    fn test_parse_negotiate() {
        let msg = parse_one(&build_smb2_message(0x0000, 0, 0, 0, 0, 0, &[]));
        assert!(matches!(msg.command, SmbCommand::Negotiate));
        assert_eq!(msg.message_id, 0);
        assert!(!msg.is_response);
    }

    #[test]
    fn test_parse_response_flag() {
        let msg = parse_one(&build_smb2_message(0x0000, SMB2_FLAGS_SERVER_TO_REDIR, 1, 0, 0, 0, &[]));
        assert!(msg.is_response);
    }

    #[test]
    fn test_parse_read_request() {
        let mut payload = vec![0u8; 49];
        payload[0] = 49; // StructureSize
        payload[4..8].copy_from_slice(&4096u32.to_le_bytes()); // Length
        payload[8..16].copy_from_slice(&1024u64.to_le_bytes()); // Offset
        payload[16..32].copy_from_slice(&[0xAA; 16]); // FileId

        let msg = parse_one(&build_smb2_message(0x0008, 0, 5, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Read { file_id, offset, length, .. } => {
                assert_eq!(*file_id, [0xAA; 16]);
                assert_eq!(*offset, 1024);
                assert_eq!(*length, 4096);
            }
            other => panic!("expected Read, got {:?}", other),
        }
    }

    // ── Header metadata tests ────────────────────────────────────────

    #[test]
    fn test_parse_credit_charge() {
        let smb = build_smb2_message_ex(
            0x0008, 0, 5, 100, 200, 0,
            7,  // credit_charge = 7
            0,  // next_command
            &vec![0u8; 49], // minimal READ payload
        );
        let msg = parse_one(&smb);
        assert_eq!(msg.credit_charge, 7);
    }

    #[test]
    fn test_parse_status_code() {
        let smb = build_smb2_message(0x0000, SMB2_FLAGS_SERVER_TO_REDIR, 1, 0, 0, 0xC000_0022, &[]);
        let msg = parse_one(&smb);
        assert_eq!(msg.status, 0xC000_0022); // STATUS_ACCESS_DENIED
    }

    #[test]
    fn test_parse_session_and_tree_ids() {
        let smb = build_smb2_message(0x0000, 0, 42, 0xDEAD, 0xBEEF, 0, &[]);
        let msg = parse_one(&smb);
        assert_eq!(msg.message_id, 42);
        assert_eq!(msg.session_id, 0xDEAD);
        assert_eq!(msg.tree_id, 0xBEEF);
    }

    #[test]
    fn test_parse_async_status_pending() {
        // is_async is set when FLAGS has ASYNC bit AND status == STATUS_PENDING
        let smb = build_smb2_message(
            0x0008, // READ
            SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
            1, 100, 200,
            0x0000_0103, // STATUS_PENDING
            &vec![0u8; 49],
        );
        let msg = parse_one(&smb);
        assert!(msg.is_async, "should be marked async");
        assert!(msg.is_response);
    }

    #[test]
    fn test_parse_not_async_without_pending() {
        // ASYNC flag but status != STATUS_PENDING → not is_async
        let smb = build_smb2_message(
            0x0008,
            SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
            1, 100, 200,
            0, // STATUS_SUCCESS
            &vec![0u8; 49],
        );
        let msg = parse_one(&smb);
        assert!(!msg.is_async, "should NOT be marked async without STATUS_PENDING");
    }

    #[test]
    fn test_parse_compound_last_standalone() {
        let smb = build_smb2_message(0x0000, 0, 0, 0, 0, 0, &[]);
        let msg = parse_one(&smb);
        assert!(msg.compound_last, "standalone message should be compound_last");
        assert_eq!(msg.compound_index, 0);
    }

    // ── Compound message tests ───────────────────────────────────────

    #[test]
    fn test_parse_compound_messages() {
        // Build two messages in one PDU via NextCommand.
        // First msg: NEGOTIATE with NextCommand pointing to the second.
        // Second msg: ECHO with NextCommand = 0.
        let second_msg = build_smb2_message(0x000D, 0, 2, 0, 0, 0, &[]);

        // NextCommand is the offset from the START of the current message
        // to the start of the next message. So it's the total length of the first message.
        let first_len = 64u32; // header only, no payload
        let first_msg = build_smb2_message_ex(0x0000, 0, 1, 0, 0, 0, 1, first_len, &[]);

        let mut compound_pdu = Vec::new();
        compound_pdu.extend_from_slice(&first_msg);
        compound_pdu.extend_from_slice(&second_msg);

        let msgs = parse_pdu(&compound_pdu);
        assert_eq!(msgs.len(), 2, "expected two messages in compound");
        assert_eq!(msgs[0].compound_index, 0);
        assert!(!msgs[0].compound_last, "first in compound should not be last");
        assert_eq!(msgs[1].compound_index, 1);
        assert!(msgs[1].compound_last, "second (final) in compound should be last");
        assert!(matches!(msgs[0].command, SmbCommand::Negotiate));
        assert!(matches!(msgs[1].command, SmbCommand::Echo));
    }

    // ── SessionSetup tests ───────────────────────────────────────────

    #[test]
    fn test_parse_session_setup_response_flags() {
        // [MS-SMB2 2.2.6] SESSION_SETUP Response:
        // StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
        let mut payload = vec![0u8; 8];
        payload[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize
        payload[2..4].copy_from_slice(&0x0001u16.to_le_bytes()); // IS_GUEST flag
        let smb = build_smb2_message(0x0001, SMB2_FLAGS_SERVER_TO_REDIR, 1, 0, 0, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::SessionSetup { session_flags } => {
                assert_eq!(*session_flags, Some(0x0001));
            }
            other => panic!("expected SessionSetup, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_session_setup_request_no_flags() {
        // Request side: no session_flags parsed
        let smb = build_smb2_message(0x0001, 0, 1, 0, 0, 0, &[0u8; 4]);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::SessionSetup { session_flags } => {
                assert_eq!(*session_flags, None);
            }
            other => panic!("expected SessionSetup, got {:?}", other),
        }
    }

    // ── TreeConnect tests ────────────────────────────────────────────

    #[test]
    fn test_parse_tree_connect_response() {
        // [MS-SMB2 2.2.10] TREE_CONNECT Response:
        // StructureSize(2) + ShareType(1) + Reserved(1) + ShareFlags(4) + Capabilities(4) + MaximalAccess(4)
        let mut payload = vec![0u8; 16];
        payload[0..2].copy_from_slice(&16u16.to_le_bytes()); // StructureSize
        payload[2] = 0x01; // ShareType = Disk
        payload[4..8].copy_from_slice(&0x0000_0030u32.to_le_bytes()); // ShareFlags
        payload[8..12].copy_from_slice(&0x0000_0010u32.to_le_bytes()); // Capabilities
        let smb = build_smb2_message(0x0003, SMB2_FLAGS_SERVER_TO_REDIR, 1, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::TreeConnect { share_type, share_flags, share_capabilities, .. } => {
                assert_eq!(*share_type, Some(0x01));
                assert_eq!(*share_flags, Some(0x0000_0030));
                assert_eq!(*share_capabilities, Some(0x0000_0010));
            }
            other => panic!("expected TreeConnect, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_tree_connect_request_path() {
        // [MS-SMB2 2.2.9] TREE_CONNECT Request:
        // StructureSize(2) + Reserved/Flags(2) + PathOffset(2) + PathLength(2) + Buffer
        // The parser's adjusted_offset = path_offset - (64 + 8).  To make it point to
        // payload index 8 (where the buffer starts), we set path_offset = 64 + 8 + 8 = 80.
        let share_path = encode_utf16le("\\\\server\\share$");
        let path_offset = (64 + 8 + 8) as u16; // header + struct + buffer start within payload
        let path_length = share_path.len() as u16;
        let mut payload = vec![0u8; 8];
        payload[0..2].copy_from_slice(&9u16.to_le_bytes());
        payload[4..6].copy_from_slice(&path_offset.to_le_bytes());
        payload[6..8].copy_from_slice(&path_length.to_le_bytes());
        payload.extend_from_slice(&share_path);

        let smb = build_smb2_message(0x0003, 0, 1, 100, 0, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::TreeConnect { path, share_type, .. } => {
                assert_eq!(path, "\\\\server\\share$");
                assert_eq!(*share_type, None, "request should have no share_type");
            }
            other => panic!("expected TreeConnect, got {:?}", other),
        }
    }

    // ── CREATE tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_create_request_enriched() {
        // [MS-SMB2 2.2.13] CREATE Request: 56 bytes fixed + name buffer
        let filename = encode_utf16le("test.txt");
        let name_offset = (64 + 56) as u16; // header + fixed struct
        let name_length = filename.len() as u16;

        let mut payload = vec![0u8; 56];
        payload[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        payload[3] = 0x02; // OplockLevel = EXCLUSIVE
        payload[24..28].copy_from_slice(&0x8012_0089u32.to_le_bytes()); // DesiredAccess
        payload[28..32].copy_from_slice(&0x0000_0020u32.to_le_bytes()); // FileAttributes = ARCHIVE
        payload[32..36].copy_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess = R|W|D
        payload[36..40].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // CreateDisposition = FILE_OPEN
        payload[40..44].copy_from_slice(&0x0000_0040u32.to_le_bytes()); // CreateOptions = FILE_NON_DIRECTORY
        payload[44..46].copy_from_slice(&name_offset.to_le_bytes());
        payload[46..48].copy_from_slice(&name_length.to_le_bytes());
        // No create contexts: offset=0, length=0 (already zeroed)
        payload.extend_from_slice(&filename);

        let smb = build_smb2_message(0x0005, 0, 10, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::Create(params) => {
                assert_eq!(params.path, "test.txt");
                assert_eq!(params.desired_access, 0x8012_0089);
                assert_eq!(params.file_attributes, 0x0000_0020);
                assert_eq!(params.share_access, 0x0000_0007);
                assert_eq!(params.create_disposition, 0x0000_0001);
                assert_eq!(params.create_options, 0x0000_0040);
                assert_eq!(params.oplock_level, 0x02);
                assert_eq!(params.create_action, None, "request has no create_action");
                assert!(params.create_context_tags.is_empty());
                assert_eq!(params.file_id, [0; 16], "request file_id should be zero");
            }
            other => panic!("expected Create, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_create_response_enriched() {
        // [MS-SMB2 2.2.14] CREATE Response: 89 bytes fixed
        let mut payload = vec![0u8; 88]; // minimum 80 for file_id extraction
        payload[0..2].copy_from_slice(&89u16.to_le_bytes()); // StructureSize
        payload[2] = 0x01; // OplockLevel = LEVEL_II
        payload[4..8].copy_from_slice(&2u32.to_le_bytes()); // CreateAction = FILE_CREATED
        payload[56..60].copy_from_slice(&0x0000_0080u32.to_le_bytes()); // FileAttributes = NORMAL
        payload[64..80].copy_from_slice(&[0xBB; 16]); // FileId

        let smb = build_smb2_message(0x0005, SMB2_FLAGS_SERVER_TO_REDIR, 10, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::Create(params) => {
                assert_eq!(params.file_id, [0xBB; 16]);
                assert_eq!(params.oplock_level, 0x01);
                assert_eq!(params.create_action, Some(2)); // FILE_CREATED
                assert_eq!(params.file_attributes, 0x0000_0080);
                assert!(params.path.is_empty(), "response has no path");
            }
            other => panic!("expected Create, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_create_context_tags_parsing() {
        // Build a CREATE request with two create context entries: "MxAc" and "QFid"
        let filename = encode_utf16le("ctx.txt");
        let name_offset = (64 + 56) as u16;
        let name_length = filename.len() as u16;

        // Build create contexts buffer:
        // Each context: Next(4) + NameOffset(2) + NameLength(2) + Reserved(2) + DataOffset(2) + DataLength(4)
        // = 16 bytes header, then name, then data

        // Context 1: "MxAc" (4 bytes name, 0 bytes data)
        let ctx1_name = b"MxAc";
        let ctx1_name_offset: u16 = 16; // relative to start of this context
        let _ctx1_header_and_name = 16 + 4; // header + name
        // Pad to 8-byte alignment: 20 → 24
        let ctx1_padded = 24u32;

        // Context 2: "QFid" (4 bytes name, 0 bytes data)
        let ctx2_name = b"QFid";

        let mut ctx_buf = Vec::new();
        // Context 1 header
        ctx_buf.extend_from_slice(&ctx1_padded.to_le_bytes()); // Next (offset to ctx2)
        ctx_buf.extend_from_slice(&ctx1_name_offset.to_le_bytes()); // NameOffset
        ctx_buf.extend_from_slice(&4u16.to_le_bytes()); // NameLength
        ctx_buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        ctx_buf.extend_from_slice(&0u16.to_le_bytes()); // DataOffset
        ctx_buf.extend_from_slice(&0u32.to_le_bytes()); // DataLength
        ctx_buf.extend_from_slice(ctx1_name);
        ctx_buf.extend_from_slice(&[0u8; 4]); // padding to 24 bytes

        // Context 2 header
        ctx_buf.extend_from_slice(&0u32.to_le_bytes()); // Next = 0 (last)
        ctx_buf.extend_from_slice(&16u16.to_le_bytes()); // NameOffset
        ctx_buf.extend_from_slice(&4u16.to_le_bytes()); // NameLength
        ctx_buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        ctx_buf.extend_from_slice(&0u16.to_le_bytes()); // DataOffset
        ctx_buf.extend_from_slice(&0u32.to_le_bytes()); // DataLength
        ctx_buf.extend_from_slice(ctx2_name);

        // Build the full payload
        let ctx_offset = (64 + 56 + filename.len()) as u32; // after header + fixed struct + name
        let ctx_length = ctx_buf.len() as u32;

        let mut payload = vec![0u8; 56];
        payload[0..2].copy_from_slice(&57u16.to_le_bytes());
        payload[24..28].copy_from_slice(&0x8000_0000u32.to_le_bytes()); // DesiredAccess
        payload[36..40].copy_from_slice(&1u32.to_le_bytes()); // CreateDisposition
        payload[44..46].copy_from_slice(&name_offset.to_le_bytes());
        payload[46..48].copy_from_slice(&name_length.to_le_bytes());
        payload[48..52].copy_from_slice(&ctx_offset.to_le_bytes());
        payload[52..56].copy_from_slice(&ctx_length.to_le_bytes());
        payload.extend_from_slice(&filename);
        payload.extend_from_slice(&ctx_buf);

        let smb = build_smb2_message(0x0005, 0, 10, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::Create(params) => {
                assert_eq!(params.path, "ctx.txt");
                assert_eq!(params.create_context_tags, vec!["MxAc".to_string(), "QFid".to_string()]);
            }
            other => panic!("expected Create, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_create_context_tags_none() {
        // CREATE request with no create contexts (offset=0, length=0)
        let filename = encode_utf16le("plain.txt");
        let name_offset = (64 + 56) as u16;
        let name_length = filename.len() as u16;

        let mut payload = vec![0u8; 56];
        payload[0..2].copy_from_slice(&57u16.to_le_bytes());
        payload[24..28].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        payload[36..40].copy_from_slice(&1u32.to_le_bytes());
        payload[44..46].copy_from_slice(&name_offset.to_le_bytes());
        payload[46..48].copy_from_slice(&name_length.to_le_bytes());
        // ctx_offset and ctx_length are already 0
        payload.extend_from_slice(&filename);

        let smb = build_smb2_message(0x0005, 0, 10, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::Create(params) => {
                assert!(params.create_context_tags.is_empty());
            }
            other => panic!("expected Create, got {:?}", other),
        }
    }

    // ── READ / WRITE flag tests ──────────────────────────────────────

    #[test]
    fn test_parse_read_request_with_flags() {
        // [MS-SMB2 2.2.19] READ Request: Flags at offset 3
        let mut payload = vec![0u8; 49];
        payload[0] = 49; // StructureSize
        payload[3] = 0x01; // Flags = READ_UNBUFFERED
        payload[4..8].copy_from_slice(&8192u32.to_le_bytes());
        payload[8..16].copy_from_slice(&2048u64.to_le_bytes());
        payload[16..32].copy_from_slice(&[0xCC; 16]);

        let msg = parse_one(&build_smb2_message(0x0008, 0, 5, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Read { file_id, offset, length, flags } => {
                assert_eq!(*file_id, [0xCC; 16]);
                assert_eq!(*offset, 2048);
                assert_eq!(*length, 8192);
                assert_eq!(*flags, 0x01, "READ_UNBUFFERED flag");
            }
            other => panic!("expected Read, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_write_request_with_flags() {
        // [MS-SMB2 2.2.21] WRITE Request: Flags at offset 44
        let data_to_write = vec![0x42u8; 64];
        let data_offset = (64 + 48) as u16; // header + fixed struct up to flags
        let mut payload = vec![0u8; 48];
        payload[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
        payload[2..4].copy_from_slice(&data_offset.to_le_bytes()); // DataOffset
        payload[4..8].copy_from_slice(&(data_to_write.len() as u32).to_le_bytes()); // Length
        payload[8..16].copy_from_slice(&512u64.to_le_bytes()); // Offset
        payload[16..32].copy_from_slice(&[0xDD; 16]); // FileId
        payload[44..48].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // Flags = WRITE_THROUGH
        payload.extend_from_slice(&data_to_write);

        let msg = parse_one(&build_smb2_message(0x0009, 0, 6, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Write { file_id, offset, length, flags, data } => {
                assert_eq!(*file_id, [0xDD; 16]);
                assert_eq!(*offset, 512);
                assert_eq!(*length, 64);
                assert_eq!(*flags, 0x0000_0001, "WRITE_THROUGH flag");
                assert_eq!(data.len(), 64);
            }
            other => panic!("expected Write, got {:?}", other),
        }
    }

    // ── Close test ───────────────────────────────────────────────────

    #[test]
    fn test_parse_close_request() {
        // [MS-SMB2 2.2.15] CLOSE Request: StructureSize(2) + Flags(2) + Reserved(4) + FileId(16)
        let mut payload = vec![0u8; 24];
        payload[0..2].copy_from_slice(&24u16.to_le_bytes());
        payload[8..24].copy_from_slice(&[0xEE; 16]);
        let msg = parse_one(&build_smb2_message(0x0006, 0, 7, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Close { file_id } => {
                assert_eq!(*file_id, [0xEE; 16]);
            }
            other => panic!("expected Close, got {:?}", other),
        }
    }

    // ── Flush test ───────────────────────────────────────────────────

    #[test]
    fn test_parse_flush_request() {
        // [MS-SMB2 2.2.17] FLUSH: StructureSize(2) + Reserved1(2) + Reserved2(4) + FileId(16)
        let mut payload = vec![0u8; 24];
        payload[0..2].copy_from_slice(&24u16.to_le_bytes());
        payload[8..24].copy_from_slice(&[0x11; 16]);
        let msg = parse_one(&build_smb2_message(0x0007, 0, 8, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Flush { file_id } => {
                assert_eq!(*file_id, [0x11; 16]);
            }
            other => panic!("expected Flush, got {:?}", other),
        }
    }

    // ── Lock test ────────────────────────────────────────────────────

    #[test]
    fn test_parse_lock_request() {
        // [MS-SMB2 2.2.26] LOCK: StructureSize(2) + LockCount(2) + LockSequence(4) + FileId(16)
        //   + Lock elements: each 24 bytes (Offset(8) + Length(8) + Flags(4) + Reserved(4))
        let mut payload = vec![0u8; 24 + 2 * 24]; // header + 2 lock elements
        payload[0..2].copy_from_slice(&48u16.to_le_bytes()); // StructureSize
        payload[2..4].copy_from_slice(&2u16.to_le_bytes()); // LockCount = 2
        payload[4..8].copy_from_slice(&0x0000_0042u32.to_le_bytes()); // LockSequence
        payload[8..24].copy_from_slice(&[0x22; 16]); // FileId

        // Lock element 1: exclusive lock at offset 0, length 100
        let base1 = 24;
        payload[base1..base1 + 8].copy_from_slice(&0u64.to_le_bytes()); // Offset
        payload[base1 + 8..base1 + 16].copy_from_slice(&100u64.to_le_bytes()); // Length
        payload[base1 + 16..base1 + 20].copy_from_slice(&0x02u32.to_le_bytes()); // Flags = EXCLUSIVE

        // Lock element 2: shared lock at offset 1000, length 500
        let base2 = 24 + 24;
        payload[base2..base2 + 8].copy_from_slice(&1000u64.to_le_bytes());
        payload[base2 + 8..base2 + 16].copy_from_slice(&500u64.to_le_bytes());
        payload[base2 + 16..base2 + 20].copy_from_slice(&0x01u32.to_le_bytes()); // Flags = SHARED

        let msg = parse_one(&build_smb2_message(0x000A, 0, 9, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Lock { file_id, locks, lock_sequence } => {
                assert_eq!(*file_id, [0x22; 16]);
                assert_eq!(*lock_sequence, 0x0000_0042);
                assert_eq!(locks.len(), 2);
                assert_eq!(locks[0].offset, 0);
                assert_eq!(locks[0].length, 100);
                assert_eq!(locks[0].flags, 0x02); // EXCLUSIVE
                assert_eq!(locks[1].offset, 1000);
                assert_eq!(locks[1].length, 500);
                assert_eq!(locks[1].flags, 0x01); // SHARED
            }
            other => panic!("expected Lock, got {:?}", other),
        }
    }

    // ── IOCTL test ───────────────────────────────────────────────────

    #[test]
    fn test_parse_ioctl_request() {
        // [MS-SMB2 2.2.31] IOCTL Request: 56 bytes
        let mut payload = vec![0u8; 56];
        payload[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        payload[4..8].copy_from_slice(&0x0011_C017u32.to_le_bytes()); // CtlCode = FSCTL_PIPE_TRANSACT
        payload[8..24].copy_from_slice(&[0x33; 16]); // FileId
        payload[28..32].copy_from_slice(&256u32.to_le_bytes()); // InputCount
        payload[36..40].copy_from_slice(&0u32.to_le_bytes()); // OutputCount (request has max)
        payload[40..44].copy_from_slice(&4096u32.to_le_bytes()); // MaxOutputResponse

        let msg = parse_one(&build_smb2_message(0x000B, 0, 10, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::Ioctl { file_id, ctl_code, input_count, output_count } => {
                assert_eq!(*file_id, [0x33; 16]);
                assert_eq!(*ctl_code, 0x0011_C017);
                assert_eq!(*input_count, 256);
                // output_count comes from the OutputCount field at offset 36
                assert_eq!(*output_count, 0);
            }
            other => panic!("expected Ioctl, got {:?}", other),
        }
    }

    // ── QueryInfo test ───────────────────────────────────────────────

    #[test]
    fn test_parse_query_info_request() {
        // [MS-SMB2 2.2.37] QUERY_INFO Request: 40 bytes fixed + FileId at offset 24
        let mut payload = vec![0u8; 40];
        payload[0..2].copy_from_slice(&41u16.to_le_bytes()); // StructureSize
        payload[2] = 0x01; // InfoType = SMB2_0_INFO_FILE
        payload[3] = 0x05; // FileInfoClass = FileStandardInformation
        payload[4..8].copy_from_slice(&1024u32.to_le_bytes()); // OutputBufferLength
        payload[24..40].copy_from_slice(&[0x44; 16]); // FileId

        let msg = parse_one(&build_smb2_message(0x0010, 0, 11, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::QueryInfo { file_id, info_type, info_class, output_buffer_length } => {
                assert_eq!(*file_id, [0x44; 16]);
                assert_eq!(*info_type, 0x01);
                assert_eq!(*info_class, 0x05);
                assert_eq!(*output_buffer_length, 1024);
            }
            other => panic!("expected QueryInfo, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_query_info_response() {
        // [MS-SMB2 2.2.38] QUERY_INFO Response: StructureSize(2) + Offset(2) + Length(4)
        let mut payload = vec![0u8; 8];
        payload[0..2].copy_from_slice(&9u16.to_le_bytes());
        payload[4..8].copy_from_slice(&2048u32.to_le_bytes()); // OutputBufferLength

        let smb = build_smb2_message(0x0010, SMB2_FLAGS_SERVER_TO_REDIR, 11, 100, 200, 0, &payload);
        let msg = parse_one(&smb);
        match &msg.command {
            SmbCommand::QueryInfo { output_buffer_length, .. } => {
                assert_eq!(*output_buffer_length, 2048);
            }
            other => panic!("expected QueryInfo, got {:?}", other),
        }
    }

    // ── QueryDirectory test ──────────────────────────────────────────

    #[test]
    fn test_parse_query_directory_request() {
        // [MS-SMB2 2.2.33] QUERY_DIRECTORY: StructureSize(2) + InfoClass(1) + Flags(1)
        //   + FileIndex(4) + FileId(16) + FileNameOffset(2) + FileNameLength(2) + OutputBufferLength(4)
        let pattern = encode_utf16le("*.docx");
        let name_offset = (64 + 32) as u16; // header + fixed struct
        let name_length = pattern.len() as u16;

        let mut payload = vec![0u8; 32];
        payload[0..2].copy_from_slice(&33u16.to_le_bytes()); // StructureSize
        payload[2] = 0x25; // FileInformationClass = FileIdBothDirectoryInformation
        payload[8..24].copy_from_slice(&[0x55; 16]); // FileId
        payload[24..26].copy_from_slice(&name_offset.to_le_bytes());
        payload[26..28].copy_from_slice(&name_length.to_le_bytes());
        payload.extend_from_slice(&pattern);

        let msg = parse_one(&build_smb2_message(0x000E, 0, 12, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::QueryDirectory { file_id, pattern, info_class } => {
                assert_eq!(*file_id, [0x55; 16]);
                assert_eq!(pattern, "*.docx");
                assert_eq!(*info_class, 0x25);
            }
            other => panic!("expected QueryDirectory, got {:?}", other),
        }
    }

    // ── ChangeNotify test ────────────────────────────────────────────

    #[test]
    fn test_parse_change_notify_request() {
        // [MS-SMB2 2.2.35] CHANGE_NOTIFY: StructureSize(2) + Flags(2) + OutputBufferLength(4)
        //   + FileId(16) + CompletionFilter(4) + Reserved(4)
        let mut payload = vec![0u8; 32];
        payload[0..2].copy_from_slice(&32u16.to_le_bytes()); // StructureSize
        payload[2..4].copy_from_slice(&0x0001u16.to_le_bytes()); // Flags = WATCH_TREE (recursive)
        payload[8..24].copy_from_slice(&[0x66; 16]); // FileId
        payload[24..28].copy_from_slice(&0x0000_0017u32.to_le_bytes()); // CompletionFilter

        let msg = parse_one(&build_smb2_message(0x000F, 0, 13, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::ChangeNotify { file_id, filter, recursive } => {
                assert_eq!(*file_id, [0x66; 16]);
                assert_eq!(*filter, 0x0000_0017);
                assert!(*recursive, "WATCH_TREE flag should be true");
            }
            other => panic!("expected ChangeNotify, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_change_notify_non_recursive() {
        let mut payload = vec![0u8; 32];
        payload[0..2].copy_from_slice(&32u16.to_le_bytes());
        payload[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // No WATCH_TREE
        payload[8..24].copy_from_slice(&[0x66; 16]);
        payload[24..28].copy_from_slice(&0x0000_0003u32.to_le_bytes());

        let msg = parse_one(&build_smb2_message(0x000F, 0, 13, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::ChangeNotify { recursive, .. } => {
                assert!(!*recursive, "should not be recursive without WATCH_TREE");
            }
            other => panic!("expected ChangeNotify, got {:?}", other),
        }
    }

    // ── SetInfo tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_set_info_request() {
        // [MS-SMB2 2.2.39] SET_INFO: StructureSize(2) + InfoType(1) + FileInfoClass(1)
        //   + BufferLength(4) + BufferOffset(2) + Reserved(2) + AdditionalInformation(4) + FileId(16)
        let mut payload = vec![0u8; 32];
        payload[0..2].copy_from_slice(&33u16.to_le_bytes());
        payload[2] = 0x01; // InfoType = FILE
        payload[3] = 0x04; // FileInfoClass = FileBasicInformation
        payload[16..32].copy_from_slice(&[0x77; 16]); // FileId

        let msg = parse_one(&build_smb2_message(0x0011, 0, 14, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::SetInfo(params) => {
                assert_eq!(params.file_id, [0x77; 16]);
                assert_eq!(params.info_type, 0x01);
                assert_eq!(params.file_info_class, 0x04);
                assert!(params.rename_target.is_none());
            }
            other => panic!("expected SetInfo, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_set_info_rename() {
        // SET_INFO with FileRenameInformation (InfoType=0x01, Class=0x0A)
        // Rename buffer: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) + FileNameLength(4) + FileName
        let new_name = encode_utf16le("renamed.txt");
        let mut rename_buf = vec![0u8; 20];
        rename_buf[0] = 0; // ReplaceIfExists = false
        rename_buf[16..20].copy_from_slice(&(new_name.len() as u32).to_le_bytes());
        rename_buf.extend_from_slice(&new_name);

        let buffer_offset = (64 + 32) as u16; // header + fixed SET_INFO struct
        let buffer_length = rename_buf.len() as u32;

        let mut payload = vec![0u8; 32];
        payload[0..2].copy_from_slice(&33u16.to_le_bytes());
        payload[2] = 0x01; // InfoType = FILE
        payload[3] = 0x0A; // FileInfoClass = FileRenameInformation
        payload[4..8].copy_from_slice(&buffer_length.to_le_bytes());
        payload[8..10].copy_from_slice(&buffer_offset.to_le_bytes());
        payload[16..32].copy_from_slice(&[0x88; 16]);
        payload.extend_from_slice(&rename_buf);

        let msg = parse_one(&build_smb2_message(0x0011, 0, 15, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::SetInfo(params) => {
                assert_eq!(params.file_id, [0x88; 16]);
                assert_eq!(params.info_type, 0x01);
                assert_eq!(params.file_info_class, 0x0A);
                assert_eq!(params.rename_target.as_deref(), Some("renamed.txt"));
            }
            other => panic!("expected SetInfo, got {:?}", other),
        }
    }

    // ── OplockBreak test ─────────────────────────────────────────────

    #[test]
    fn test_parse_oplock_break() {
        // [MS-SMB2 2.2.24] OplockBreak: StructureSize(2) + OplockLevel(1) + Reserved(1)
        //   + Reserved2(4) + FileId(16) = 24 bytes
        let mut payload = vec![0u8; 24];
        payload[0..2].copy_from_slice(&24u16.to_le_bytes());
        payload[2] = 0x01; // OplockLevel = LEVEL_II
        payload[8..24].copy_from_slice(&[0x99; 16]); // FileId

        let msg = parse_one(&build_smb2_message(0x0012, 0, 16, 100, 200, 0, &payload));
        match &msg.command {
            SmbCommand::OplockBreak { file_id, oplock_level } => {
                assert_eq!(*file_id, [0x99; 16]);
                assert_eq!(*oplock_level, 0x01);
            }
            other => panic!("expected OplockBreak, got {:?}", other),
        }
    }

    // ── Echo test ────────────────────────────────────────────────────

    #[test]
    fn test_parse_echo() {
        let msg = parse_one(&build_smb2_message(0x000D, 0, 17, 0, 0, 0, &[]));
        assert!(matches!(msg.command, SmbCommand::Echo));
    }

    // ── Cancel test ──────────────────────────────────────────────────

    #[test]
    fn test_parse_cancel() {
        // Cancel = 0x000C. The parser returns Cancel with cancelled_message_id = 0
        // since the actual cancelled message_id comes from the SMB2 header MessageId field,
        // not from the command payload.
        let msg = parse_one(&build_smb2_message(0x000C, 0, 42, 0, 0, 0, &[]));
        match &msg.command {
            SmbCommand::Cancel { cancelled_message_id } => {
                assert_eq!(*cancelled_message_id, 0, "payload-based cancelled_message_id defaults to 0");
            }
            other => panic!("expected Cancel, got {:?}", other),
        }
        assert_eq!(msg.message_id, 42, "message_id from header");
    }

    // ── Logoff / TreeDisconnect tests ────────────────────────────────

    #[test]
    fn test_parse_logoff() {
        let msg = parse_one(&build_smb2_message(0x0002, 0, 20, 100, 0, 0, &[]));
        assert!(matches!(msg.command, SmbCommand::Logoff));
    }

    #[test]
    fn test_parse_tree_disconnect() {
        let msg = parse_one(&build_smb2_message(0x0004, 0, 21, 100, 200, 0, &[]));
        assert!(matches!(msg.command, SmbCommand::TreeDisconnect));
    }

    // ── Helper function tests ────────────────────────────────────────

    #[test]
    fn test_parse_file_id_at() {
        let data = [0u8; 4].iter()
            .chain(&[0xAB; 16])
            .chain(&[0u8; 4])
            .copied()
            .collect::<Vec<u8>>();
        let fid = parse_file_id_at(&data, 4).unwrap();
        assert_eq!(fid, [0xAB; 16]);
    }

    #[test]
    fn test_parse_file_id_at_too_short() {
        let data = [0u8; 10];
        assert!(parse_file_id_at(&data, 0).is_err());
    }

    #[test]
    fn test_decode_utf16le_valid() {
        let encoded = encode_utf16le("hello");
        assert_eq!(decode_utf16le(&encoded), Some("hello".to_string()));
    }

    #[test]
    fn test_decode_utf16le_odd_length() {
        assert_eq!(decode_utf16le(&[0x41, 0x00, 0x42]), None);
    }

    #[test]
    fn test_parse_create_context_tags_function() {
        // Test the standalone parse_create_context_tags function directly
        // Single context with name "DH2Q"
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // Next = 0 (last)
        buf[4..6].copy_from_slice(&16u16.to_le_bytes()); // NameOffset = 16
        buf[6..8].copy_from_slice(&4u16.to_le_bytes()); // NameLength = 4
        buf[16..20].copy_from_slice(b"DH2Q");

        let tags = parse_create_context_tags(&buf);
        assert_eq!(tags, vec!["DH2Q".to_string()]);
    }

    #[test]
    fn test_parse_create_context_tags_empty_buffer() {
        let tags = parse_create_context_tags(&[]);
        assert!(tags.is_empty());
    }
}
