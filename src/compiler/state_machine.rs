//! SMB protocol state machine.
//!
//! Tracks connections, sessions, tree connections and open files across
//! request/response pairs. Each completed request→response pair generates
//! a `TrackedOperation` that the downstream `OperationExtractor` converts
//! into an IR `Operation`.
//!
//! ## References
//!
//! - [MS-SMB2 3.2] Client-side protocol details (state machines)
//! - [MS-SMB2 3.3] Server-side protocol details (state machines)

use super::smb_parser::{FileId, SmbCommand, SmbMessage};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for generating unique handle references.
static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_handle_ref() -> String {
    let n = HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("h_{}", n)
}

// ── public types ──

/// Represents an SMB connection (identified by a client IP or equivalent).
#[derive(Debug, Clone)]
pub struct SmbConnection {
    /// Identifier for the client (e.g. IP address).
    pub client_id: String,
    /// Sessions within this connection.
    pub sessions: HashMap<u64, SessionState>,
    /// All completed operations on this connection.
    pub operations: Vec<TrackedOperation>,
}

/// Per-session state.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: u64,
    pub trees: HashMap<u32, TreeState>,
}

/// Per-tree-connect state.
#[derive(Debug, Clone)]
pub struct TreeState {
    pub tree_id: u32,
    pub share_name: String,
    pub open_files: HashMap<FileId, FileState>,
}

/// Per-open-file state.
#[derive(Debug, Clone)]
pub struct FileState {
    pub file_id: FileId,
    pub path: String,
    pub handle_ref: String,
    pub create_time_us: u64,
}

/// A completed operation extracted from a request→response pair.
#[derive(Debug, Clone)]
pub struct TrackedOperation {
    /// Microsecond timestamp of the *request*.
    pub timestamp_us: u64,
    /// SMB operation type name (Open, Read, Write, Close, Rename, Delete, ...).
    pub operation_type: String,
    /// Client identifier.
    pub client_id: String,
    /// Associated file_id (if applicable).
    pub file_id: Option<FileId>,
    /// Handle reference for the IR.
    pub handle_ref: Option<String>,
    /// File / share path.
    pub path: Option<String>,
    /// Read/Write offset.
    pub offset: Option<u64>,
    /// Read/Write length.
    pub length: Option<u32>,
    /// Write data (captured from the request).
    pub data: Option<Vec<u8>>,
    /// DesiredAccess mask (for CREATE).
    pub desired_access: Option<u32>,
    /// CreateDisposition (for CREATE).
    pub create_disposition: Option<u32>,
    /// Oplock level.
    pub oplock_level: Option<u8>,
    /// Rename target path.
    pub rename_target: Option<String>,
    /// IOCTL control code.
    pub ctl_code: Option<u32>,
    /// QueryDirectory search pattern.
    pub pattern: Option<String>,
    /// QueryInfo / QueryDirectory info class.
    pub info_class: Option<u8>,
    /// QueryInfo info type (1=File, 2=FS, 3=Security).
    pub info_type: Option<u8>,
    /// Lock/Unlock offset.
    pub lock_offset: Option<u64>,
    /// Lock/Unlock length.
    pub lock_length: Option<u64>,
    /// Lock exclusive flag.
    pub lock_exclusive: Option<bool>,
    /// ChangeNotify completion filter.
    pub notify_filter: Option<u32>,
    /// ChangeNotify recursive (watch_tree) flag.
    pub notify_recursive: Option<bool>,
    /// CreateOptions flags (for mkdir/rmdir extraction).
    pub create_options: Option<u32>,
    /// SetInfo info type.
    pub set_info_type: Option<u8>,
    /// SetInfo file info class.
    pub set_info_class: Option<u8>,
    /// Cancel target message_id.
    pub cancel_message_id: Option<u64>,
    /// Whether this is a pipe (named pipe) path.
    pub is_pipe: Option<bool>,
    /// Source handle ref for server-copy operations.
    pub source_handle_ref: Option<String>,
    /// Destination handle ref for server-copy operations.
    pub dest_handle_ref: Option<String>,
    /// Copy offset.
    pub copy_offset: Option<u64>,
    /// Copy length.
    pub copy_length: Option<u64>,
    /// ShareAccess flags from CREATE request.
    pub share_access: Option<u32>,
    /// FileAttributes from CREATE request/response.
    pub file_attributes: Option<u32>,
    /// CreateAction from CREATE response (FILE_SUPERSEDED=0, FILE_OPENED=1, FILE_CREATED=2, FILE_OVERWRITTEN=3).
    pub create_action: Option<u32>,
    /// Create context tags from CREATE request (e.g., ["MxAc", "QFid"]).
    pub create_context_tags: Option<Vec<String>>,
    /// READ flags (SMB2_READFLAG_READ_UNBUFFERED=0x01, etc.).
    pub read_flags: Option<u8>,
    /// WRITE flags (SMB2_WRITEFLAG_WRITE_THROUGH=0x01, etc.).
    pub write_flags: Option<u32>,
    /// NT status code from the response (for error tracking).
    pub nt_status: Option<u32>,
    /// Credit charge from the request header (for multi-credit tracking).
    pub credit_charge: Option<u16>,
}

// ── state machine ──

/// Pending request stored while waiting for the matching response.
#[derive(Debug, Clone)]
struct PendingRequest {
    message: SmbMessage,
}

/// The state machine that processes SMB messages in order and tracks
/// sessions → trees → files.
pub struct SmbStateMachine {
    /// All tracked connections, keyed by client_id.
    connections: HashMap<String, SmbConnection>,
    /// Pending requests waiting for a response, keyed by (session_id, message_id).
    pending: HashMap<(u64, u64), PendingRequest>,
    /// Current client identifier (set per-stream).
    current_client: String,
}

impl SmbStateMachine {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            pending: HashMap::new(),
            current_client: String::new(),
        }
    }

    /// Set the current client identifier (call before feeding a stream's messages).
    pub fn set_client_id(&mut self, client_id: impl Into<String>) {
        self.current_client = client_id.into();
    }

    /// Process a single SMB message.
    pub fn process_message(&mut self, message: SmbMessage) -> Result<()> {
        let client_id = self.current_client.clone();

        // Ensure the connection entry exists.
        self.connections.entry(client_id.clone()).or_insert_with(|| SmbConnection {
            client_id: client_id.clone(),
            sessions: HashMap::new(),
            operations: Vec::new(),
        });

        if message.is_response {
            self.process_response(message, &client_id)?;
        } else {
            self.process_request(message, &client_id)?;
        }
        Ok(())
    }

    fn process_request(&mut self, message: SmbMessage, _client_id: &str) -> Result<()> {
        // For TreeConnect requests, extract the path before storing.
        let key = (message.session_id, message.message_id);
        self.pending.insert(key, PendingRequest { message });
        Ok(())
    }

    fn process_response(&mut self, response: SmbMessage, client_id: &str) -> Result<()> {
        // Skip STATUS_PENDING interim responses — the request stays pending until the
        // final response arrives.
        if response.is_async && response.status == 0x0000_0103 {
            return Ok(());
        }

        let key = (response.session_id, response.message_id);
        let request_opt = self.pending.remove(&key);

        let conn = self.connections.get_mut(client_id).unwrap();

        // Ensure session exists.
        conn.sessions.entry(response.session_id).or_insert_with(|| SessionState {
            session_id: response.session_id,
            trees: HashMap::new(),
        });

        // Helper: successful responses have status 0 (STATUS_SUCCESS) or
        // STATUS_BUFFER_OVERFLOW (0x80000005) for partial reads, etc.
        let success = response.status == 0 || response.status == 0x80000005;

        match (&response.command, request_opt) {
            // ── LOGOFF ── session cleanup
            (SmbCommand::Logoff, _) => {
                if success {
                    conn.sessions.remove(&response.session_id);
                }
            }

            // ── TREE_DISCONNECT ── tree cleanup
            (SmbCommand::TreeDisconnect, _) => {
                if success {
                    if let Some(session) = conn.sessions.get_mut(&response.session_id) {
                        session.trees.remove(&response.tree_id);
                    }
                }
            }

            // ── TREE_CONNECT ──
            (SmbCommand::TreeConnect { .. }, Some(req)) => {
                if success {
                    let path = match &req.message.command {
                        SmbCommand::TreeConnect { path, .. } => path.clone(),
                        _ => String::new(),
                    };
                    let session = conn.sessions.get_mut(&response.session_id).unwrap();
                    session.trees.entry(response.tree_id).or_insert_with(|| TreeState {
                        tree_id: response.tree_id,
                        share_name: path,
                        open_files: HashMap::new(),
                    });
                }
            }

            // ── CREATE ──
            (SmbCommand::Create(resp_params), Some(req)) => {
                if success {
                    let (req_path, desired_access, create_disposition, req_oplock, create_options,
                     share_access, file_attributes_req, create_context_tags) =
                        match &req.message.command {
                            SmbCommand::Create(p) => (
                                p.path.clone(),
                                p.desired_access,
                                p.create_disposition,
                                p.oplock_level,
                                p.create_options,
                                p.share_access,
                                p.file_attributes,
                                p.create_context_tags.clone(),
                            ),
                            _ => (String::new(), 0, 0, 0, 0, 0, 0, Vec::new()),
                        };

                    let handle_ref = next_handle_ref();
                    let file_state = FileState {
                        file_id: resp_params.file_id,
                        path: req_path.clone(),
                        handle_ref: handle_ref.clone(),
                        create_time_us: req.message.timestamp_us,
                    };

                    // Register the file in the tree.
                    if let Some(session) = conn.sessions.get_mut(&response.session_id) {
                        if let Some(tree) = session.trees.get_mut(&response.tree_id) {
                            tree.open_files.insert(resp_params.file_id, file_state);
                        }
                    }

                    let mut tracked = new_tracked(req.message.timestamp_us, "Open", client_id);
                    tracked.file_id = Some(resp_params.file_id);
                    tracked.handle_ref = Some(handle_ref);
                    tracked.path = Some(req_path);
                    tracked.desired_access = Some(desired_access);
                    tracked.create_disposition = Some(create_disposition);
                    tracked.oplock_level = Some(req_oplock);
                    tracked.create_options = Some(create_options);
                    tracked.share_access = Some(share_access);
                    // Use response file_attributes if available, else request
                    tracked.file_attributes = if resp_params.file_attributes != 0 {
                        Some(resp_params.file_attributes)
                    } else {
                        Some(file_attributes_req)
                    };
                    tracked.create_action = resp_params.create_action;
                    if !create_context_tags.is_empty() {
                        tracked.create_context_tags = Some(create_context_tags);
                    }
                    conn.operations.push(tracked);
                }
            }

            // ── CLOSE ──
            (SmbCommand::Close { file_id }, Some(req)) => {
                let req_fid = match &req.message.command {
                    SmbCommand::Close { file_id } => *file_id,
                    _ => *file_id,
                };
                let (handle_ref, path) = lookup_file(
                    conn, response.session_id, response.tree_id, &req_fid,
                );

                let mut tracked = new_tracked(req.message.timestamp_us, "Close", client_id);
                tracked.file_id = Some(req_fid);
                tracked.handle_ref = Some(handle_ref);
                tracked.path = path;
                conn.operations.push(tracked);

                // Remove file from tree state.
                if let Some(session) = conn.sessions.get_mut(&response.session_id) {
                    if let Some(tree) = session.trees.get_mut(&response.tree_id) {
                        tree.open_files.remove(&req_fid);
                    }
                }
            }

            // ── READ ──
            (SmbCommand::Read { length: resp_len, .. }, Some(req)) => {
                let (req_fid, req_offset, req_length, r_flags) = match &req.message.command {
                    SmbCommand::Read { file_id, offset, length, flags } => (*file_id, *offset, *length, *flags),
                    _ => ([0; 16], 0, *resp_len, 0),
                };
                let (handle_ref, path) = lookup_file(
                    conn, response.session_id, req.message.tree_id, &req_fid,
                );
                let mut tracked = new_tracked(req.message.timestamp_us, "Read", client_id);
                tracked.file_id = Some(req_fid);
                tracked.handle_ref = Some(handle_ref);
                tracked.path = path;
                tracked.offset = Some(req_offset);
                tracked.length = Some(req_length);
                if r_flags != 0 {
                    tracked.read_flags = Some(r_flags);
                }
                conn.operations.push(tracked);
            }

            // ── WRITE ──
            (SmbCommand::Write { .. }, Some(req)) => {
                let (req_fid, req_offset, req_length, req_data, w_flags) = match &req.message.command {
                    SmbCommand::Write { file_id, offset, length, data, flags } => {
                        (*file_id, *offset, *length, data.clone(), *flags)
                    }
                    _ => ([0; 16], 0, 0, Vec::new(), 0),
                };
                let (handle_ref, path) = lookup_file(
                    conn, response.session_id, req.message.tree_id, &req_fid,
                );
                let mut tracked = new_tracked(req.message.timestamp_us, "Write", client_id);
                tracked.file_id = Some(req_fid);
                tracked.handle_ref = Some(handle_ref);
                tracked.path = path;
                tracked.offset = Some(req_offset);
                tracked.length = Some(req_length);
                tracked.data = Some(req_data);
                if w_flags != 0 {
                    tracked.write_flags = Some(w_flags);
                }
                conn.operations.push(tracked);
            }

            // ── SET_INFO (legacy rename/delete detection + new SetInfo tracking) ──
            (SmbCommand::SetInfo(_), Some(req)) => {
                if success {
                    if let SmbCommand::SetInfo(params) = &req.message.command {
                        if params.info_type == 0x01 && params.file_info_class == 0x0A {
                            // FileRenameInformation → Rename
                            let (handle_ref, path) = lookup_file(
                                conn, response.session_id, req.message.tree_id, &params.file_id,
                            );
                            let mut tracked = new_tracked(req.message.timestamp_us, "Rename", client_id);
                            tracked.file_id = Some(params.file_id);
                            tracked.handle_ref = Some(handle_ref);
                            tracked.path = path;
                            tracked.rename_target = params.rename_target.clone();
                            conn.operations.push(tracked);
                        } else if params.info_type == 0x01 && params.file_info_class == 0x0D {
                            // FileDispositionInformation → Delete
                            let (handle_ref, path) = lookup_file(
                                conn, response.session_id, req.message.tree_id, &params.file_id,
                            );
                            let mut tracked = new_tracked(req.message.timestamp_us, "Delete", client_id);
                            tracked.file_id = Some(params.file_id);
                            tracked.handle_ref = Some(handle_ref);
                            tracked.path = path;
                            conn.operations.push(tracked);
                        } else {
                            // All other SetInfo classes → generic SetInfo operation
                            let (handle_ref, path) = lookup_file(
                                conn, response.session_id, req.message.tree_id, &params.file_id,
                            );
                            let mut tracked = new_tracked(req.message.timestamp_us, "SetInfo", client_id);
                            tracked.file_id = Some(params.file_id);
                            tracked.handle_ref = Some(handle_ref);
                            tracked.path = path;
                            tracked.set_info_type = Some(params.info_type);
                            tracked.set_info_class = Some(params.file_info_class);
                            conn.operations.push(tracked);
                        }
                    }
                }
            }

            // ── QUERY_DIRECTORY ──
            (SmbCommand::QueryDirectory { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::QueryDirectory { file_id, pattern, info_class } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "QueryDirectory", client_id);
                        tracked.file_id = Some(*file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        tracked.pattern = Some(pattern.clone());
                        tracked.info_class = Some(*info_class);
                        conn.operations.push(tracked);
                    }
                }
            }

            // ── QUERY_INFO ──
            (SmbCommand::QueryInfo { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::QueryInfo { file_id, info_type, info_class, .. } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "QueryInfo", client_id);
                        tracked.file_id = Some(*file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        tracked.info_type = Some(*info_type);
                        tracked.info_class = Some(*info_class);
                        conn.operations.push(tracked);
                    }
                }
            }

            // ── FLUSH ──
            (SmbCommand::Flush { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::Flush { file_id } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "Flush", client_id);
                        tracked.file_id = Some(*file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        conn.operations.push(tracked);
                    }
                }
            }

            // ── LOCK ──
            (SmbCommand::Lock { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::Lock { file_id, locks, .. } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        for lock_elem in locks {
                            let is_unlock = (lock_elem.flags & 0x0000_0004) != 0;
                            let is_exclusive = (lock_elem.flags & 0x0000_0002) != 0;
                            let op_type = if is_unlock { "Unlock" } else { "Lock" };
                            let mut tracked = new_tracked(req.message.timestamp_us, op_type, client_id);
                            tracked.file_id = Some(*file_id);
                            tracked.handle_ref = Some(handle_ref.clone());
                            tracked.path = path.clone();
                            tracked.lock_offset = Some(lock_elem.offset);
                            tracked.lock_length = Some(lock_elem.length);
                            tracked.lock_exclusive = Some(is_exclusive);
                            conn.operations.push(tracked);
                        }
                    }
                }
            }

            // ── IOCTL ──
            (SmbCommand::Ioctl { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::Ioctl { file_id, ctl_code, .. } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        // Detect special IOCTL subtypes
                        const FSCTL_PIPE_TRANSACT: u32 = 0x0011C017;
                        const FSCTL_SRV_COPYCHUNK: u32 = 0x001440F2;
                        const FSCTL_SRV_COPYCHUNK_WRITE: u32 = 0x001480F2;
                        match *ctl_code {
                            FSCTL_PIPE_TRANSACT => {
                                let mut tracked = new_tracked(req.message.timestamp_us, "TransactPipe", client_id);
                                tracked.file_id = Some(*file_id);
                                tracked.handle_ref = Some(handle_ref);
                                tracked.path = path;
                                tracked.is_pipe = Some(true);
                                conn.operations.push(tracked);
                            }
                            FSCTL_SRV_COPYCHUNK | FSCTL_SRV_COPYCHUNK_WRITE => {
                                let mut tracked = new_tracked(req.message.timestamp_us, "ServerCopy", client_id);
                                tracked.file_id = Some(*file_id);
                                // The dest handle_ref is the file the IOCTL targets
                                tracked.dest_handle_ref = Some(handle_ref);
                                // We don't have the source handle from the IOCTL payload here
                                tracked.source_handle_ref = None;
                                tracked.path = path;
                                tracked.ctl_code = Some(*ctl_code);
                                conn.operations.push(tracked);
                            }
                            _ => {
                                let mut tracked = new_tracked(req.message.timestamp_us, "Ioctl", client_id);
                                tracked.file_id = Some(*file_id);
                                tracked.handle_ref = Some(handle_ref);
                                tracked.path = path;
                                tracked.ctl_code = Some(*ctl_code);
                                conn.operations.push(tracked);
                            }
                        }
                    }
                }
            }

            // ── CHANGE_NOTIFY ──
            (SmbCommand::ChangeNotify { .. }, Some(req)) => {
                // ChangeNotify may return STATUS_NOTIFY_ENUM_DIR (0x010C) or STATUS_SUCCESS
                if let SmbCommand::ChangeNotify { file_id, filter, recursive } = &req.message.command {
                    let (handle_ref, path) = lookup_file(
                        conn, response.session_id, req.message.tree_id, file_id,
                    );
                    let mut tracked = new_tracked(req.message.timestamp_us, "ChangeNotify", client_id);
                    tracked.file_id = Some(*file_id);
                    tracked.handle_ref = Some(handle_ref);
                    tracked.path = path;
                    tracked.notify_filter = Some(*filter);
                    tracked.notify_recursive = Some(*recursive);
                    conn.operations.push(tracked);
                }
            }

            // ── ECHO ──
            (SmbCommand::Echo, Some(req)) => {
                if success {
                    let tracked = new_tracked(req.message.timestamp_us, "Echo", client_id);
                    conn.operations.push(tracked);
                }
            }

            // ── CANCEL ──
            (SmbCommand::Cancel { .. }, _) => {
                // Cancel doesn't require a response; it's fire-and-forget.
                // The message_id in the header was set to the cancelled request's message_id.
                let mut tracked = new_tracked(response.timestamp_us, "Cancel", client_id);
                tracked.cancel_message_id = Some(response.message_id);
                conn.operations.push(tracked);
            }

            // ── OPLOCK_BREAK ──
            (SmbCommand::OplockBreak { .. }, Some(req)) => {
                if success {
                    if let SmbCommand::OplockBreak { file_id, oplock_level: req_level } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, response.tree_id, file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "OplockBreakAck", client_id);
                        tracked.file_id = Some(*file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        tracked.oplock_level = Some(*req_level);
                        conn.operations.push(tracked);
                    }
                }
            }

            // ── Everything else: no-op ──
            _ => {}
        }

        Ok(())
    }

    /// Consume the state machine and return all connections.
    pub fn finalize(self) -> Result<Vec<SmbConnection>> {
        Ok(self.connections.into_values().collect())
    }
}

/// Create a new TrackedOperation with all fields defaulting to None.
fn new_tracked(
    timestamp_us: u64,
    operation_type: &str,
    client_id: &str,
) -> TrackedOperation {
    TrackedOperation {
        timestamp_us,
        operation_type: operation_type.to_string(),
        client_id: client_id.to_string(),
        file_id: None,
        handle_ref: None,
        path: None,
        offset: None,
        length: None,
        data: None,
        desired_access: None,
        create_disposition: None,
        oplock_level: None,
        rename_target: None,
        ctl_code: None,
        pattern: None,
        info_class: None,
        info_type: None,
        lock_offset: None,
        lock_length: None,
        lock_exclusive: None,
        notify_filter: None,
        notify_recursive: None,
        create_options: None,
        set_info_type: None,
        set_info_class: None,
        cancel_message_id: None,
        is_pipe: None,
        source_handle_ref: None,
        dest_handle_ref: None,
        copy_offset: None,
        copy_length: None,
        share_access: None,
        file_attributes: None,
        create_action: None,
        create_context_tags: None,
        read_flags: None,
        write_flags: None,
        nt_status: None,
        credit_charge: None,
    }
}

/// Look up handle_ref and path for a file_id in the connection's tree state.
fn lookup_file(
    conn: &SmbConnection,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
) -> (String, Option<String>) {
    if let Some(session) = conn.sessions.get(&session_id) {
        if let Some(tree) = session.trees.get(&tree_id) {
            if let Some(fs) = tree.open_files.get(file_id) {
                return (fs.handle_ref.clone(), Some(fs.path.clone()));
            }
        }
    }
    // Unknown file; generate a synthetic handle_ref.
    (next_handle_ref(), None)
}

impl Default for SmbStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::smb_parser::{SmbCommand, SmbMessage, CreateParams, SetInfoParams, LockElement};

    fn make_msg(
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        command: SmbCommand,
        is_response: bool,
        status: u32,
    ) -> SmbMessage {
        make_msg_ex(message_id, session_id, tree_id, command, is_response, status, 1, false)
    }

    fn make_msg_ex(
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        command: SmbCommand,
        is_response: bool,
        status: u32,
        credit_charge: u16,
        is_async: bool,
    ) -> SmbMessage {
        SmbMessage {
            timestamp_us: message_id * 1000,
            message_id,
            session_id,
            tree_id,
            command,
            is_response,
            status,
            credit_charge,
            compound_index: 0,
            compound_last: true,
            is_async,
        }
    }

    /// Setup a state machine with a tree connect already established.
    fn setup_with_tree(client: &str, session_id: u64, tree_id: u32) -> SmbStateMachine {
        let mut sm = SmbStateMachine::new();
        sm.set_client_id(client);
        sm.process_message(make_msg(
            1, session_id, 0,
            SmbCommand::TreeConnect { path: "\\\\srv\\share".into(), share_type: None, share_flags: None, share_capabilities: None },
            false, 0,
        )).unwrap();
        sm.process_message(make_msg(
            1, session_id, tree_id,
            SmbCommand::TreeConnect { path: String::new(), share_type: None, share_flags: None, share_capabilities: None },
            true, 0,
        )).unwrap();
        sm
    }

    /// Open a file in the state machine and return the file_id.
    fn open_file(sm: &mut SmbStateMachine, msg_id: u64, session_id: u64, tree_id: u32, path: &str) -> FileId {
        let fid = {
            let mut f = [0u8; 16];
            f[0] = msg_id as u8;
            f[1] = 0xAA;
            f
        };
        sm.process_message(make_msg(msg_id, session_id, tree_id, SmbCommand::Create(CreateParams {
            file_id: [0; 16],
            path: path.to_string(),
            desired_access: 0x0012_0089,
            create_disposition: 1,
            oplock_level: 0,
            create_options: 0,
            share_access: 0,
            file_attributes: 0,
            create_action: None,
            create_context_tags: Vec::new(),
        }), false, 0)).unwrap();
        sm.process_message(make_msg(msg_id, session_id, tree_id, SmbCommand::Create(CreateParams {
            file_id: fid,
            path: String::new(),
            desired_access: 0,
            create_disposition: 0,
            oplock_level: 0,
            create_options: 0,
            share_access: 0,
            file_attributes: 0,
            create_action: None,
            create_context_tags: Vec::new(),
        }), true, 0)).unwrap();
        fid
    }

    // ── Original test (preserved) ────────────────────────────────────

    #[test]
    fn test_create_close_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "test.txt");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Close { file_id: fid }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Close { file_id: fid }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        assert_eq!(conns.len(), 1);
        let ops = &conns[0].operations;
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].operation_type, "Open");
        assert_eq!(ops[0].path.as_deref(), Some("test.txt"));
        assert_eq!(ops[1].operation_type, "Close");
    }

    // ── CREATE enriched fields ───────────────────────────────────────

    #[test]
    fn test_create_enriched_fields() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        // Create request with enriched fields
        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0; 16],
            path: "enriched.txt".to_string(),
            desired_access: 0x8012_0089,
            create_disposition: 2, // FILE_CREATE
            oplock_level: 0x02,
            create_options: 0x0000_0040, // NON_DIRECTORY
            share_access: 0x0000_0007,   // R|W|D
            file_attributes: 0x0000_0020, // ARCHIVE
            create_action: None,
            create_context_tags: vec!["MxAc".to_string(), "QFid".to_string()],
        }), false, 0)).unwrap();

        // Create response with create_action and file_attributes
        let fid = [0xBB; 16];
        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: fid,
            path: String::new(),
            desired_access: 0,
            create_disposition: 0,
            oplock_level: 0x01, // LEVEL_II
            create_options: 0,
            share_access: 0,
            file_attributes: 0x0000_0080, // NORMAL
            create_action: Some(2), // FILE_CREATED
            create_context_tags: Vec::new(),
        }), true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let ops = &conns[0].operations;
        let open = &ops[ops.len() - 1];
        assert_eq!(open.operation_type, "Open");
        assert_eq!(open.share_access, Some(0x0000_0007));
        assert_eq!(open.file_attributes, Some(0x0000_0080)); // response takes precedence
        assert_eq!(open.create_action, Some(2));
        assert_eq!(open.create_context_tags, Some(vec!["MxAc".to_string(), "QFid".to_string()]));
        assert_eq!(open.desired_access, Some(0x8012_0089));
        assert_eq!(open.create_disposition, Some(2));
        assert_eq!(open.create_options, Some(0x0000_0040));
        assert_eq!(open.oplock_level, Some(0x02)); // request oplock is used
    }

    #[test]
    fn test_create_file_attributes_from_request_when_response_is_zero() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0; 16], path: "f.txt".to_string(),
            desired_access: 0x8000_0000, create_disposition: 1,
            oplock_level: 0, create_options: 0,
            share_access: 0, file_attributes: 0x0000_0020, // ARCHIVE from request
            create_action: None, create_context_tags: Vec::new(),
        }), false, 0)).unwrap();

        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0xCC; 16], path: String::new(),
            desired_access: 0, create_disposition: 0, oplock_level: 0,
            create_options: 0, share_access: 0,
            file_attributes: 0, // zero in response → fall back to request
            create_action: None, create_context_tags: Vec::new(),
        }), true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let ops = &conns[0].operations;
        let open = ops.iter().find(|o| o.operation_type == "Open").unwrap();
        assert_eq!(open.file_attributes, Some(0x0000_0020), "should use request file_attributes when response is 0");
    }

    // ── READ / WRITE flags ───────────────────────────────────────────

    #[test]
    fn test_read_flags_propagation() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "data.bin");

        // READ request with UNBUFFERED flag
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: fid, offset: 0, length: 4096, flags: 0x01,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: [0; 16], offset: 0, length: 4096, flags: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let ops = &conns[0].operations;
        let read = ops.iter().find(|o| o.operation_type == "Read").unwrap();
        assert_eq!(read.read_flags, Some(0x01), "READ_UNBUFFERED flag");
    }

    #[test]
    fn test_read_flags_not_set_when_zero() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "data.bin");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: fid, offset: 0, length: 1024, flags: 0,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: [0; 16], offset: 0, length: 1024, flags: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let read = conns[0].operations.iter().find(|o| o.operation_type == "Read").unwrap();
        assert_eq!(read.read_flags, None, "read_flags should be None when zero");
    }

    #[test]
    fn test_write_flags_propagation() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "data.bin");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Write {
            file_id: fid, offset: 512, length: 256, data: vec![0x42; 256],
            flags: 0x0000_0001, // WRITE_THROUGH
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Write {
            file_id: [0; 16], offset: 0, length: 256, data: Vec::new(), flags: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let write = conns[0].operations.iter().find(|o| o.operation_type == "Write").unwrap();
        assert_eq!(write.write_flags, Some(0x0000_0001), "WRITE_THROUGH flag");
        assert_eq!(write.offset, Some(512));
        assert_eq!(write.length, Some(256));
    }

    // ── SetInfo sub-type detection ───────────────────────────────────

    #[test]
    fn test_set_info_rename_detection() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "old.txt");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: fid, info_type: 0x01, file_info_class: 0x0A,
            rename_target: Some("new.txt".to_string()),
        }), false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: [0; 16], info_type: 0, file_info_class: 0, rename_target: None,
        }), true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let rename = conns[0].operations.iter().find(|o| o.operation_type == "Rename").unwrap();
        assert_eq!(rename.path.as_deref(), Some("old.txt"));
        assert_eq!(rename.rename_target.as_deref(), Some("new.txt"));
    }

    #[test]
    fn test_set_info_delete_detection() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "todelete.txt");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: fid, info_type: 0x01, file_info_class: 0x0D, // FileDispositionInformation
            rename_target: None,
        }), false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: [0; 16], info_type: 0, file_info_class: 0, rename_target: None,
        }), true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let del = conns[0].operations.iter().find(|o| o.operation_type == "Delete").unwrap();
        assert_eq!(del.path.as_deref(), Some("todelete.txt"));
    }

    #[test]
    fn test_set_info_generic() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "meta.txt");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: fid, info_type: 0x01, file_info_class: 0x04, // FileBasicInformation
            rename_target: None,
        }), false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::SetInfo(SetInfoParams {
            file_id: [0; 16], info_type: 0, file_info_class: 0, rename_target: None,
        }), true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let si = conns[0].operations.iter().find(|o| o.operation_type == "SetInfo").unwrap();
        assert_eq!(si.set_info_type, Some(0x01));
        assert_eq!(si.set_info_class, Some(0x04));
    }

    // ── Lock / Unlock ────────────────────────────────────────────────

    #[test]
    fn test_lock_and_unlock() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "locked.dat");

        // LOCK request with one exclusive lock and one unlock
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Lock {
            file_id: fid,
            locks: vec![
                LockElement { offset: 0, length: 100, flags: 0x02 },    // EXCLUSIVE
                LockElement { offset: 200, length: 50, flags: 0x04 },   // UNLOCK
            ],
            lock_sequence: 0x42,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Lock {
            file_id: [0; 16], locks: Vec::new(), lock_sequence: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let ops = &conns[0].operations;
        let lock = ops.iter().find(|o| o.operation_type == "Lock").unwrap();
        assert_eq!(lock.lock_offset, Some(0));
        assert_eq!(lock.lock_length, Some(100));
        assert_eq!(lock.lock_exclusive, Some(true));
        assert_eq!(lock.path.as_deref(), Some("locked.dat"));

        let unlock = ops.iter().find(|o| o.operation_type == "Unlock").unwrap();
        assert_eq!(unlock.lock_offset, Some(200));
        assert_eq!(unlock.lock_length, Some(50));
        assert_eq!(unlock.lock_exclusive, Some(false)); // UNLOCK flag doesn't set EXCLUSIVE
    }

    // ── IOCTL sub-type detection ─────────────────────────────────────

    #[test]
    fn test_ioctl_generic() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "ioctl.dat");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: fid, ctl_code: 0x00090028, input_count: 128, output_count: 0,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: [0; 16], ctl_code: 0, input_count: 0, output_count: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let ioctl = conns[0].operations.iter().find(|o| o.operation_type == "Ioctl").unwrap();
        assert_eq!(ioctl.ctl_code, Some(0x00090028));
    }

    #[test]
    fn test_ioctl_pipe_transact() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "\\pipe\\svcctl");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: fid, ctl_code: 0x0011C017, // FSCTL_PIPE_TRANSACT
            input_count: 256, output_count: 0,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: [0; 16], ctl_code: 0, input_count: 0, output_count: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let pipe = conns[0].operations.iter().find(|o| o.operation_type == "TransactPipe").unwrap();
        assert!(pipe.is_pipe == Some(true));
    }

    #[test]
    fn test_ioctl_server_copy() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "dest.dat");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: fid, ctl_code: 0x001440F2, // FSCTL_SRV_COPYCHUNK
            input_count: 48, output_count: 0,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Ioctl {
            file_id: [0; 16], ctl_code: 0, input_count: 0, output_count: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let copy = conns[0].operations.iter().find(|o| o.operation_type == "ServerCopy").unwrap();
        assert!(copy.dest_handle_ref.is_some());
        assert_eq!(copy.ctl_code, Some(0x001440F2));
    }

    // ── Echo and Cancel ──────────────────────────────────────────────

    #[test]
    fn test_echo_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        sm.process_message(make_msg(10, 1, 100, SmbCommand::Echo, false, 0)).unwrap();
        sm.process_message(make_msg(10, 1, 100, SmbCommand::Echo, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let echo = conns[0].operations.iter().find(|o| o.operation_type == "Echo");
        assert!(echo.is_some(), "Echo should be tracked");
    }

    #[test]
    fn test_cancel_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        // Cancel is fire-and-forget: just the response triggers tracking
        sm.process_message(make_msg(10, 1, 100, SmbCommand::Cancel { cancelled_message_id: 0 }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let cancel = conns[0].operations.iter().find(|o| o.operation_type == "Cancel").unwrap();
        assert_eq!(cancel.cancel_message_id, Some(10), "cancel_message_id comes from header message_id");
    }

    // ── OplockBreakAck with handle_ref ───────────────────────────────

    #[test]
    fn test_oplock_break_ack_with_handle() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "oplocked.dat");

        // OplockBreak request (client acknowledging)
        sm.process_message(make_msg(3, 1, 100, SmbCommand::OplockBreak {
            file_id: fid, oplock_level: 0x01,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::OplockBreak {
            file_id: fid, oplock_level: 0x01,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let obreak = conns[0].operations.iter().find(|o| o.operation_type == "OplockBreakAck").unwrap();
        assert_eq!(obreak.oplock_level, Some(0x01));
        assert_eq!(obreak.file_id, Some(fid));
        assert!(obreak.handle_ref.is_some(), "should have handle_ref from file lookup");
        assert_eq!(obreak.path.as_deref(), Some("oplocked.dat"));
    }

    // ── QueryDirectory / QueryInfo / Flush / ChangeNotify ────────────

    #[test]
    fn test_query_directory_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "somedir");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::QueryDirectory {
            file_id: fid, pattern: "*.txt".to_string(), info_class: 0x25,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::QueryDirectory {
            file_id: [0; 16], pattern: String::new(), info_class: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let qd = conns[0].operations.iter().find(|o| o.operation_type == "QueryDirectory").unwrap();
        assert_eq!(qd.pattern.as_deref(), Some("*.txt"));
        assert_eq!(qd.info_class, Some(0x25));
        assert_eq!(qd.path.as_deref(), Some("somedir"));
    }

    #[test]
    fn test_query_info_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "info.dat");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::QueryInfo {
            file_id: fid, info_type: 0x01, info_class: 0x05, output_buffer_length: 1024,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::QueryInfo {
            file_id: [0; 16], info_type: 0, info_class: 0, output_buffer_length: 48,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let qi = conns[0].operations.iter().find(|o| o.operation_type == "QueryInfo").unwrap();
        assert_eq!(qi.info_type, Some(0x01));
        assert_eq!(qi.info_class, Some(0x05));
    }

    #[test]
    fn test_flush_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "flushed.dat");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Flush { file_id: fid }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Flush { file_id: [0; 16] }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let flush = conns[0].operations.iter().find(|o| o.operation_type == "Flush").unwrap();
        assert_eq!(flush.path.as_deref(), Some("flushed.dat"));
    }

    #[test]
    fn test_change_notify_tracking() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "watched");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::ChangeNotify {
            file_id: fid, filter: 0x0000_0017, recursive: true,
        }, false, 0)).unwrap();
        sm.process_message(make_msg(3, 1, 100, SmbCommand::ChangeNotify {
            file_id: [0; 16], filter: 0, recursive: false,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let cn = conns[0].operations.iter().find(|o| o.operation_type == "ChangeNotify").unwrap();
        assert_eq!(cn.notify_filter, Some(0x0000_0017));
        assert_eq!(cn.notify_recursive, Some(true));
        assert_eq!(cn.path.as_deref(), Some("watched"));
    }

    // ── STATUS_PENDING skip ──────────────────────────────────────────

    #[test]
    fn test_status_pending_skipped() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "pending.dat");

        // Send a read request
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: fid, offset: 0, length: 4096, flags: 0,
        }, false, 0)).unwrap();

        // Interim STATUS_PENDING response (should be skipped)
        sm.process_message(make_msg_ex(
            3, 1, 100,
            SmbCommand::Read { file_id: [0; 16], offset: 0, length: 0, flags: 0 },
            true,
            0x0000_0103, // STATUS_PENDING
            1,
            true, // is_async
        )).unwrap();

        // Final successful response
        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: [0; 16], offset: 0, length: 4096, flags: 0,
        }, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let reads: Vec<_> = conns[0].operations.iter()
            .filter(|o| o.operation_type == "Read")
            .collect();
        assert_eq!(reads.len(), 1, "STATUS_PENDING should not produce a duplicate operation");
    }

    #[test]
    fn test_status_pending_not_skipped_if_not_async() {
        // If is_async is false even with STATUS_PENDING status, it should NOT be skipped
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);
        let fid = open_file(&mut sm, 2, 1, 100, "data.dat");

        sm.process_message(make_msg(3, 1, 100, SmbCommand::Read {
            file_id: fid, offset: 0, length: 4096, flags: 0,
        }, false, 0)).unwrap();

        // Non-async response with STATUS_PENDING status (unusual, but tests the guard)
        sm.process_message(make_msg_ex(
            3, 1, 100,
            SmbCommand::Read { file_id: [0; 16], offset: 0, length: 0, flags: 0 },
            true,
            0x0000_0103,
            1,
            false, // NOT async
        )).unwrap();

        let conns = sm.finalize().unwrap();
        let reads: Vec<_> = conns[0].operations.iter()
            .filter(|o| o.operation_type == "Read")
            .collect();
        assert_eq!(reads.len(), 1, "non-async STATUS_PENDING should still produce an operation");
    }

    // ── Logoff / TreeDisconnect cleanup ──────────────────────────────

    #[test]
    fn test_logoff_cleans_session() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        sm.process_message(make_msg(5, 1, 0, SmbCommand::Logoff, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let conn = &conns[0];
        assert!(conn.sessions.is_empty(), "logoff should remove session");
    }

    #[test]
    fn test_tree_disconnect_cleans_tree() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        sm.process_message(make_msg(5, 1, 100, SmbCommand::TreeDisconnect, true, 0)).unwrap();

        let conns = sm.finalize().unwrap();
        let session = conns[0].sessions.get(&1).unwrap();
        assert!(session.trees.is_empty(), "tree_disconnect should remove tree");
    }

    // ── Failed operations not tracked ────────────────────────────────

    #[test]
    fn test_failed_create_not_tracked() {
        let mut sm = setup_with_tree("10.0.0.1", 1, 100);

        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0; 16], path: "fail.txt".to_string(),
            desired_access: 0x8000_0000, create_disposition: 1,
            oplock_level: 0, create_options: 0, share_access: 0,
            file_attributes: 0, create_action: None, create_context_tags: Vec::new(),
        }), false, 0)).unwrap();

        // Create response with ACCESS_DENIED
        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0; 16], path: String::new(),
            desired_access: 0, create_disposition: 0, oplock_level: 0,
            create_options: 0, share_access: 0, file_attributes: 0,
            create_action: None, create_context_tags: Vec::new(),
        }), true, 0xC000_0022)).unwrap(); // STATUS_ACCESS_DENIED

        let conns = sm.finalize().unwrap();
        let opens: Vec<_> = conns[0].operations.iter()
            .filter(|o| o.operation_type == "Open")
            .collect();
        assert!(opens.is_empty(), "failed create should not produce Open operation");
    }
}
