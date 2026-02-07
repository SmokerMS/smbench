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
                        SmbCommand::TreeConnect { path } => path.clone(),
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
                    let (req_path, desired_access, create_disposition, req_oplock, create_options) =
                        match &req.message.command {
                            SmbCommand::Create(p) => (
                                p.path.clone(),
                                p.desired_access,
                                p.create_disposition,
                                p.oplock_level,
                                p.create_options,
                            ),
                            _ => (String::new(), 0, 0, 0, 0),
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
                let (req_fid, req_offset, req_length) = match &req.message.command {
                    SmbCommand::Read { file_id, offset, length } => (*file_id, *offset, *length),
                    _ => ([0; 16], 0, *resp_len),
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
                conn.operations.push(tracked);
            }

            // ── WRITE ──
            (SmbCommand::Write { .. }, Some(req)) => {
                let (req_fid, req_offset, req_length, req_data) = match &req.message.command {
                    SmbCommand::Write { file_id, offset, length, data } => {
                        (*file_id, *offset, *length, data.clone())
                    }
                    _ => ([0; 16], 0, 0, Vec::new()),
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
                conn.operations.push(tracked);
            }

            // ── SET_INFO (rename detection) ──
            (SmbCommand::SetInfo(_), Some(req)) => {
                if let SmbCommand::SetInfo(params) = &req.message.command {
                    if params.info_type == 0x01 && params.file_info_class == 0x0A {
                        // FileRenameInformation
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, &params.file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "Rename", client_id);
                        tracked.file_id = Some(params.file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        tracked.rename_target = params.rename_target.clone();
                        conn.operations.push(tracked);
                    }
                    // FileDispositionInformation (class 13/0x0D) → Delete
                    if params.info_type == 0x01 && params.file_info_class == 0x0D {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, &params.file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "Delete", client_id);
                        tracked.file_id = Some(params.file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        conn.operations.push(tracked);
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
                    if let SmbCommand::QueryInfo { file_id, info_type, info_class } = &req.message.command {
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
                    if let SmbCommand::Lock { file_id, locks } = &req.message.command {
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
                    if let SmbCommand::Ioctl { file_id, ctl_code } = &req.message.command {
                        let (handle_ref, path) = lookup_file(
                            conn, response.session_id, req.message.tree_id, file_id,
                        );
                        let mut tracked = new_tracked(req.message.timestamp_us, "Ioctl", client_id);
                        tracked.file_id = Some(*file_id);
                        tracked.handle_ref = Some(handle_ref);
                        tracked.path = path;
                        tracked.ctl_code = Some(*ctl_code);
                        conn.operations.push(tracked);
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
    use crate::compiler::smb_parser::{SmbCommand, SmbMessage, CreateParams};

    fn make_msg(
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        command: SmbCommand,
        is_response: bool,
        status: u32,
    ) -> SmbMessage {
        SmbMessage {
            timestamp_us: message_id * 1000,
            message_id,
            session_id,
            tree_id,
            command,
            is_response,
            status,
        }
    }

    #[test]
    fn test_create_close_tracking() {
        let mut sm = SmbStateMachine::new();
        sm.set_client_id("10.0.0.1");

        // Tree connect
        sm.process_message(make_msg(1, 1, 0, SmbCommand::TreeConnect { path: "\\\\srv\\share".to_string() }, false, 0)).unwrap();
        sm.process_message(make_msg(1, 1, 100, SmbCommand::TreeConnect { path: String::new() }, true, 0)).unwrap();

        // Create request
        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: [0; 16],
            path: "test.txt".to_string(),
            desired_access: 0x0012_0089, // GENERIC_READ
            create_disposition: 1, // FILE_OPEN
            oplock_level: 0,
            create_options: 0,
        }), false, 0)).unwrap();

        // Create response
        let fid = [1u8; 16];
        sm.process_message(make_msg(2, 1, 100, SmbCommand::Create(CreateParams {
            file_id: fid,
            path: String::new(),
            desired_access: 0,
            create_disposition: 0,
            oplock_level: 0,
            create_options: 0,
        }), true, 0)).unwrap();

        // Close request
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
}
