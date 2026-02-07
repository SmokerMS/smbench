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
}

/// Parsed SMB2 command payloads.
#[derive(Debug, Clone)]
pub enum SmbCommand {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect {
        /// Share path (from request) or empty (from response).
        path: String,
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
    },
    Write {
        file_id: FileId,
        offset: u64,
        length: u32,
        data: Vec<u8>,
    },
    Ioctl {
        file_id: FileId,
        ctl_code: u32,
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
    },
    Flush {
        file_id: FileId,
    },
    Lock {
        file_id: FileId,
        locks: Vec<LockElement>,
    },
    OplockBreak,
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
        loop {
            if cursor.len() < 64 {
                break;
            }
            // Validate magic
            if &cursor[0..4] != SMB2_MAGIC {
                break;
            }

            match self.parse_header_and_command(cursor, base_timestamp_us) {
                Ok((next_command_offset, msg)) => {
                    out.push(msg);
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
            SmbCommandCode::SessionSetup => Ok(SmbCommand::SessionSetup),
            SmbCommandCode::Logoff => Ok(SmbCommand::Logoff),
            SmbCommandCode::TreeConnect => {
                if is_response {
                    Ok(SmbCommand::TreeConnect { path: String::new() })
                } else {
                    let path = parse_tree_connect_request(payload).unwrap_or_default();
                    Ok(SmbCommand::TreeConnect { path })
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
                    })
                } else {
                    parse_write_request(payload)
                }
            }
            SmbCommandCode::Ioctl => {
                if payload.len() >= 20 {
                    let ctl_code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let fid = parse_file_id_at(payload, 8)?;
                    Ok(SmbCommand::Ioctl { file_id: fid, ctl_code })
                } else {
                    Ok(SmbCommand::Ioctl { file_id: [0; 16], ctl_code: 0 })
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
                    Ok(SmbCommand::Lock { file_id: fid, locks })
                } else {
                    Ok(SmbCommand::Lock { file_id: [0; 16], locks: Vec::new() })
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
                if !is_response && payload.len() >= 40 {
                    let info_type = payload[2];
                    let info_class = payload[3];
                    let fid = parse_file_id_at(payload, 24)?;
                    Ok(SmbCommand::QueryInfo { file_id: fid, info_type, info_class })
                } else {
                    Ok(SmbCommand::QueryInfo { file_id: [0; 16], info_type: 0, info_class: 0 })
                }
            }
            SmbCommandCode::OplockBreak => Ok(SmbCommand::OplockBreak),
            _ => Ok(SmbCommand::Other { code: code as u16 }),
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
    flags: u32,
    next_command: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
}

fn parse_smb2_header(input: &[u8]) -> IResult<&[u8], RawHeader> {
    let (input, _magic) = take(4usize)(input)?;       //  0..4
    let (input, _struct_size) = le_u16(input)?;        //  4..6
    let (input, _credit_charge) = le_u16(input)?;      //  6..8
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
        }));
    }
    let oplock_level = payload[3];
    let desired_access = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let create_disposition = u32::from_le_bytes([payload[36], payload[37], payload[38], payload[39]]);
    let create_options = u32::from_le_bytes([payload[40], payload[41], payload[42], payload[43]]);
    let name_offset = u16::from_le_bytes([payload[44], payload[45]]) as usize;
    let name_length = u16::from_le_bytes([payload[46], payload[47]]) as usize;

    // name_offset is relative to start of SMB2 header; we have payload starting after 64 bytes.
    let adj = name_offset.saturating_sub(64);
    let path = if adj + name_length <= payload.len() {
        decode_utf16le(&payload[adj..adj + name_length]).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(SmbCommand::Create(CreateParams {
        file_id: [0; 16],
        path,
        desired_access,
        create_disposition,
        oplock_level,
        create_options,
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
        }));
    }
    let oplock_level = payload[2];
    let file_id = parse_file_id_at(payload, 64)?;
    Ok(SmbCommand::Create(CreateParams {
        file_id,
        path: String::new(),
        desired_access: 0,
        create_disposition: 0,
        oplock_level,
        create_options: 0,
    }))
}

/// [MS-SMB2 2.2.19] READ Request
fn parse_read_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + Padding (1) + Flags (1) + Length (4)
    // + Offset (8) + FileId (16) + ...
    if payload.len() < 32 {
        return Err(anyhow!("READ request too short"));
    }
    let length = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let offset = u64::from_le_bytes([
        payload[8], payload[9], payload[10], payload[11],
        payload[12], payload[13], payload[14], payload[15],
    ]);
    let file_id = parse_file_id_at(payload, 16)?;
    Ok(SmbCommand::Read { file_id, offset, length })
}

/// [MS-SMB2 2.2.21] WRITE Request
fn parse_write_request(payload: &[u8]) -> Result<SmbCommand> {
    // StructureSize (2) + DataOffset (2) + Length (4) + Offset (8)
    // + FileId (16) + ...
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

    // DataOffset is relative to the start of the SMB2 header.
    let adj = data_offset_field.saturating_sub(64);
    let data = if adj + length as usize <= payload.len() {
        payload[adj..adj + length as usize].to_vec()
    } else {
        Vec::new()
    };

    Ok(SmbCommand::Write { file_id, offset, length, data })
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
        let mut msg = Vec::new();
        msg.extend_from_slice(SMB2_MAGIC);           //  0..4
        msg.extend_from_slice(&64u16.to_le_bytes());  //  4..6  StructureSize
        msg.extend_from_slice(&1u16.to_le_bytes());   //  6..8  CreditCharge
        msg.extend_from_slice(&status.to_le_bytes()); //  8..12
        msg.extend_from_slice(&command.to_le_bytes()); // 12..14
        msg.extend_from_slice(&1u16.to_le_bytes());   // 14..16 Credits
        msg.extend_from_slice(&flags.to_le_bytes());  // 16..20
        msg.extend_from_slice(&0u32.to_le_bytes());   // 20..24 NextCommand
        msg.extend_from_slice(&message_id.to_le_bytes()); // 24..32
        msg.extend_from_slice(&0u32.to_le_bytes());   // 32..36 Reserved
        msg.extend_from_slice(&tree_id.to_le_bytes()); // 36..40
        msg.extend_from_slice(&session_id.to_le_bytes()); // 40..48
        msg.extend_from_slice(&[0u8; 16]);            // 48..64 Signature
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

    #[test]
    fn test_parse_negotiate() {
        let smb = build_smb2_message(0x0000, 0, 0, 0, 0, 0, &[]);
        let stream_data = frame_netbios(&smb);
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
        assert_eq!(msgs.len(), 1);
        assert!(matches!(msgs[0].command, SmbCommand::Negotiate));
        assert_eq!(msgs[0].message_id, 0);
    }

    #[test]
    fn test_parse_response_flag() {
        let smb = build_smb2_message(0x0000, SMB2_FLAGS_SERVER_TO_REDIR, 1, 0, 0, 0, &[]);
        let stream_data = frame_netbios(&smb);
        let stream = super::super::tcp_reassembly::TcpStream {
            id: super::super::tcp_reassembly::StreamId {
                src_ip: "10.0.0.2".parse().unwrap(),
                src_port: 445,
                dst_ip: "10.0.0.1".parse().unwrap(),
                dst_port: 50000,
            },
            data: stream_data,
            start_time_us: 2000,
        };
        let mut parser = SmbParser::new();
        let msgs = parser.parse_stream(&stream).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].is_response);
    }

    #[test]
    fn test_parse_read_request() {
        // Build a minimal READ request payload.
        let mut payload = vec![0u8; 49]; // StructureSize = 49
        payload[0] = 49; payload[1] = 0; // StructureSize
        // Length = 4096
        payload[4..8].copy_from_slice(&4096u32.to_le_bytes());
        // Offset = 1024
        payload[8..16].copy_from_slice(&1024u64.to_le_bytes());
        // FileId at offset 16 (16 bytes)
        payload[16..32].copy_from_slice(&[0xAA; 16]);

        let smb = build_smb2_message(0x0008, 0, 5, 100, 200, 0, &payload);
        let stream_data = frame_netbios(&smb);
        let stream = super::super::tcp_reassembly::TcpStream {
            id: super::super::tcp_reassembly::StreamId {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 50000,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 445,
            },
            data: stream_data,
            start_time_us: 5000,
        };
        let mut parser = SmbParser::new();
        let msgs = parser.parse_stream(&stream).unwrap();
        assert_eq!(msgs.len(), 1);
        match &msgs[0].command {
            SmbCommand::Read { file_id, offset, length } => {
                assert_eq!(*file_id, [0xAA; 16]);
                assert_eq!(*offset, 1024);
                assert_eq!(*length, 4096);
            }
            other => panic!("expected Read, got {:?}", other),
        }
    }
}
