//! Operation extraction – converts `TrackedOperation` records from the
//! state machine into IR `Operation` values.
//!
//! ## Mapping
//!
//! | SMB2 Command            | IR Operation |
//! |-------------------------|-------------|
//! | CREATE (success)        | `Open`      |
//! | CLOSE                   | `Close`     |
//! | READ                    | `Read`      |
//! | WRITE                   | `Write`     |
//! | SET_INFO (rename)       | `Rename`    |
//! | SET_INFO (delete)       | `Delete`    |

use super::smb_parser::fsctl_name;
use super::state_machine::{SmbConnection, TrackedOperation};
use crate::ir::{OpenMode, Operation};
use crate::protocol::ntstatus::NtStatus;
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};

static OP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_op_id() -> String {
    let n = OP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("op_{}", n)
}

/// Converts tracked SMB operations into IR operations.
pub struct OperationExtractor;

impl OperationExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract IR operations from all connections.
    pub fn extract(&self, connections: &[SmbConnection]) -> Result<Vec<Operation>> {
        let mut operations = Vec::new();

        for conn in connections {
            for tracked in &conn.operations {
                if let Some(op) = self.convert(tracked)? {
                    operations.push(op);
                }
            }
        }

        // Sort by timestamp to produce a deterministic, chronological IR.
        operations.sort_by_key(|op| op.timestamp_us());
        Ok(operations)
    }

    fn convert(&self, t: &TrackedOperation) -> Result<Option<Operation>> {
        let op = match t.operation_type.as_str() {
            "Open" => {
                let create_options = t.create_options.unwrap_or(0);
                let create_disposition = t.create_disposition.unwrap_or(0);
                let is_directory = (create_options & 0x0000_0001) != 0; // FILE_DIRECTORY_FILE
                let is_delete_on_close = (create_options & 0x0000_1000) != 0; // FILE_DELETE_ON_CLOSE

                if is_directory && is_delete_on_close {
                    // Directory opened with delete-on-close → Rmdir
                    return Ok(Some(Operation::Rmdir {
                        op_id: next_op_id(),
                        client_id: t.client_id.clone(),
                        timestamp_us: t.timestamp_us,
                        path: t.path.clone().unwrap_or_default(),
                    }));
                }

                if is_directory && (create_disposition == 2 || create_disposition == 3) {
                    // FILE_CREATE (2) or FILE_OPEN_IF (3) on a directory → Mkdir
                    return Ok(Some(Operation::Mkdir {
                        op_id: next_op_id(),
                        client_id: t.client_id.clone(),
                        timestamp_us: t.timestamp_us,
                        path: t.path.clone().unwrap_or_default(),
                    }));
                }

                let mode = infer_open_mode(t.desired_access.unwrap_or(0));
                Operation::Open {
                    op_id: next_op_id(),
                    client_id: t.client_id.clone(),
                    timestamp_us: t.timestamp_us,
                    path: t.path.clone().unwrap_or_default(),
                    mode,
                    handle_ref: t.handle_ref.clone().unwrap_or_default(),
                    extensions: build_extensions(t),
                }
            }
            "Close" => Operation::Close {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
            },
            "Read" => Operation::Read {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                offset: t.offset.unwrap_or(0),
                length: t.length.unwrap_or(0) as u64,
            },
            "Write" => Operation::Write {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                offset: t.offset.unwrap_or(0),
                length: t.length.unwrap_or(0) as u64,
                // blob_path is set later by the IrGenerator when it writes blob files.
                blob_path: String::new(),
            },
            "Rename" => Operation::Rename {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                source_path: t.path.clone().unwrap_or_default(),
                dest_path: t.rename_target.clone().unwrap_or_default(),
            },
            "Delete" => Operation::Delete {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                path: t.path.clone().unwrap_or_default(),
            },
            "QueryDirectory" => Operation::QueryDirectory {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                pattern: t.pattern.clone().unwrap_or_else(|| "*".to_string()),
                info_class: t.info_class.unwrap_or(0),
            },
            "QueryInfo" => Operation::QueryInfo {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                info_type: t.info_type.unwrap_or(0),
                info_class: t.info_class.unwrap_or(0),
            },
            "Flush" => Operation::Flush {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
            },
            "Lock" => Operation::Lock {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                offset: t.lock_offset.unwrap_or(0),
                length: t.lock_length.unwrap_or(0),
                exclusive: t.lock_exclusive.unwrap_or(true),
            },
            "Unlock" => Operation::Unlock {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                offset: t.lock_offset.unwrap_or(0),
                length: t.lock_length.unwrap_or(0),
            },
            "Ioctl" => Operation::Ioctl {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                ctl_code: t.ctl_code.unwrap_or(0),
                input_blob_path: None,
            },
            "ChangeNotify" => Operation::ChangeNotify {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                filter: t.notify_filter.unwrap_or(0),
                recursive: t.notify_recursive.unwrap_or(false),
            },
            "SetInfo" => Operation::SetInfo {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                info_type: t.set_info_type.unwrap_or(0),
                info_class: t.set_info_class.unwrap_or(0),
                input_blob_path: None,
            },
            "Echo" => Operation::Echo {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
            },
            "Cancel" => Operation::Cancel {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                target_message_id: t.cancel_message_id.unwrap_or(0),
            },
            "OplockBreakAck" => Operation::OplockBreakAck {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                oplock_level: t.oplock_level.unwrap_or(0),
            },
            "TransactPipe" => Operation::TransactPipe {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                handle_ref: t.handle_ref.clone().unwrap_or_default(),
                input_blob_path: None,
            },
            "Negotiate" => {
                // Negotiate operations are tracked for metadata but don't map to a replay IR op.
                // We skip them since they're handled at connection setup.
                return Ok(None);
            }
            "ServerCopy" => Operation::ServerCopy {
                op_id: next_op_id(),
                client_id: t.client_id.clone(),
                timestamp_us: t.timestamp_us,
                source_handle_ref: t.source_handle_ref.clone().unwrap_or_default(),
                dest_handle_ref: t.dest_handle_ref.clone().unwrap_or_default(),
                offset: t.copy_offset.unwrap_or(0),
                length: t.copy_length.unwrap_or(0),
            },
            _ => return Ok(None),
        };
        Ok(Some(op))
    }
}

impl Default for OperationExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Infer `OpenMode` from the DesiredAccess mask.
///
/// [MS-SMB2 2.2.13] DesiredAccess bits:
/// - FILE_READ_DATA  = 0x0000_0001
/// - FILE_WRITE_DATA = 0x0000_0002
/// - GENERIC_READ    = 0x8000_0000
/// - GENERIC_WRITE   = 0x4000_0000
fn infer_open_mode(access: u32) -> OpenMode {
    let read = (access & 0x0000_0001) != 0 || (access & 0x8000_0000) != 0;
    let write = (access & 0x0000_0002) != 0 || (access & 0x4000_0000) != 0;
    match (read, write) {
        (true, true) | (false, false) => OpenMode::ReadWrite,
        (true, false) => OpenMode::Read,
        (false, true) => OpenMode::Write,
    }
}

/// Build optional JSON extensions from tracked operation metadata.
fn build_extensions(t: &TrackedOperation) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    if let Some(oplock) = t.oplock_level {
        if oplock != 0 {
            map.insert(
                "oplock_level".to_string(),
                serde_json::Value::Number(oplock.into()),
            );
        }
    }
    if let Some(disp) = t.create_disposition {
        map.insert(
            "create_disposition".to_string(),
            serde_json::Value::Number(disp.into()),
        );
    }
    if let Some(sa) = t.share_access {
        if sa != 0 {
            map.insert(
                "share_access".to_string(),
                serde_json::Value::Number(sa.into()),
            );
        }
    }
    if let Some(fa) = t.file_attributes {
        if fa != 0 {
            map.insert(
                "file_attributes".to_string(),
                serde_json::Value::Number(fa.into()),
            );
        }
    }
    if let Some(ca) = t.create_action {
        map.insert(
            "create_action".to_string(),
            serde_json::Value::Number(ca.into()),
        );
    }
    if let Some(rf) = t.read_flags {
        if rf != 0 {
            map.insert(
                "read_flags".to_string(),
                serde_json::Value::Number(rf.into()),
            );
        }
    }
    if let Some(wf) = t.write_flags {
        if wf != 0 {
            map.insert(
                "write_flags".to_string(),
                serde_json::Value::Number(wf.into()),
            );
        }
    }
    if let Some(ref tags) = t.create_context_tags {
        if !tags.is_empty() {
            let arr: Vec<serde_json::Value> = tags.iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect();
            map.insert(
                "create_contexts".to_string(),
                serde_json::Value::Array(arr),
            );
        }
    }
    if let Some(status) = t.nt_status {
        map.insert(
            "nt_status".to_string(),
            serde_json::Value::Number(status.into()),
        );
        let nt = NtStatus::from_u32(status);
        if let Some(name) = nt.name() {
            map.insert(
                "nt_status_name".to_string(),
                serde_json::Value::String(name.to_string()),
            );
        }
    }
    if let Some(cc) = t.credit_charge {
        if cc > 1 {
            map.insert(
                "credit_charge".to_string(),
                serde_json::Value::Number(cc.into()),
            );
        }
    }
    if let Some(ctl) = t.ctl_code {
        if let Some(name) = fsctl_name(ctl) {
            map.insert(
                "fsctl_name".to_string(),
                serde_json::Value::String(name.to_string()),
            );
        }
    }
    if let Some(dialect) = t.negotiate_dialect {
        map.insert(
            "negotiate_dialect".to_string(),
            serde_json::Value::Number(dialect.into()),
        );
    }
    if let Some(caps) = t.negotiate_capabilities {
        map.insert(
            "negotiate_capabilities".to_string(),
            serde_json::Value::Number(caps.into()),
        );
    }
    if map.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::state_machine::{SmbConnection, TrackedOperation};

    fn make_tracked(op_type: &str, client: &str) -> TrackedOperation {
        TrackedOperation {
            timestamp_us: 1000,
            operation_type: op_type.to_string(),
            client_id: client.to_string(),
            file_id: Some([0xAA; 16]),
            handle_ref: Some("h_1".to_string()),
            path: Some("test.txt".to_string()),
            offset: Some(0),
            length: Some(1024),
            data: Some(vec![0x42; 1024]),
            desired_access: Some(0x0012_0089),
            create_disposition: Some(1),
            oplock_level: Some(0),
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
            negotiate_dialect: None,
            negotiate_capabilities: None,
        }
    }

    fn make_conn(ops: Vec<TrackedOperation>) -> SmbConnection {
        SmbConnection {
            client_id: "10.0.0.1".to_string(),
            sessions: Default::default(),
            operations: ops,
        }
    }

    fn extract_one(t: TrackedOperation) -> Operation {
        let extractor = OperationExtractor::new();
        let ops = extractor.extract(&[make_conn(vec![t])]).unwrap();
        assert_eq!(ops.len(), 1);
        ops.into_iter().next().unwrap()
    }

    // ── Original tests (preserved) ───────────────────────────────────

    #[test]
    fn test_extract_open() {
        let op = extract_one(make_tracked("Open", "10.0.0.1"));
        assert!(matches!(op, Operation::Open { .. }));
    }

    #[test]
    fn test_infer_open_mode_read() {
        assert!(matches!(infer_open_mode(0x0000_0001), OpenMode::Read));
    }

    #[test]
    fn test_infer_open_mode_write() {
        assert!(matches!(infer_open_mode(0x0000_0002), OpenMode::Write));
    }

    #[test]
    fn test_infer_open_mode_readwrite() {
        assert!(matches!(infer_open_mode(0x0000_0003), OpenMode::ReadWrite));
    }

    // ── infer_open_mode additional coverage ──────────────────────────

    #[test]
    fn test_infer_open_mode_generic_read() {
        assert!(matches!(infer_open_mode(0x8000_0000), OpenMode::Read));
    }

    #[test]
    fn test_infer_open_mode_generic_write() {
        assert!(matches!(infer_open_mode(0x4000_0000), OpenMode::Write));
    }

    #[test]
    fn test_infer_open_mode_generic_readwrite() {
        assert!(matches!(infer_open_mode(0xC000_0000), OpenMode::ReadWrite));
    }

    #[test]
    fn test_infer_open_mode_no_access_defaults_readwrite() {
        assert!(matches!(infer_open_mode(0), OpenMode::ReadWrite));
    }

    // ── build_extensions tests ───────────────────────────────────────

    #[test]
    fn test_build_extensions_empty_when_all_none_or_zero() {
        let t = make_tracked("Open", "10.0.0.1");
        // oplock_level is 0, share_access/file_attributes/etc. are None
        let ext = build_extensions(&t);
        // Should only contain create_disposition (which is Some(1))
        assert!(ext.is_some());
        let obj = ext.unwrap();
        assert!(obj.get("create_disposition").is_some());
        // But no share_access, file_attributes, etc. since they're None
        assert!(obj.get("share_access").is_none());
        assert!(obj.get("file_attributes").is_none());
        assert!(obj.get("read_flags").is_none());
        assert!(obj.get("write_flags").is_none());
        assert!(obj.get("create_contexts").is_none());
    }

    #[test]
    fn test_build_extensions_returns_none_when_truly_empty() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.oplock_level = None;
        t.create_disposition = None;
        t.share_access = None;
        t.file_attributes = None;
        t.create_action = None;
        t.create_context_tags = None;
        t.read_flags = None;
        t.write_flags = None;
        let ext = build_extensions(&t);
        assert!(ext.is_none(), "should be None when all enrichments are absent");
    }

    #[test]
    fn test_build_extensions_share_access() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.share_access = Some(0x0000_0007); // R|W|D
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["share_access"], 0x0000_0007);
    }

    #[test]
    fn test_build_extensions_share_access_zero_omitted() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.share_access = Some(0);
        let ext = build_extensions(&t).unwrap();
        assert!(ext.get("share_access").is_none(), "share_access=0 should be omitted");
    }

    #[test]
    fn test_build_extensions_file_attributes() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.file_attributes = Some(0x0000_0020); // ARCHIVE
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["file_attributes"], 0x0000_0020);
    }

    #[test]
    fn test_build_extensions_create_action() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.create_action = Some(2); // FILE_CREATED
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["create_action"], 2);
    }

    #[test]
    fn test_build_extensions_create_contexts() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.create_context_tags = Some(vec!["MxAc".to_string(), "DH2Q".to_string()]);
        let ext = build_extensions(&t).unwrap();
        let contexts = ext["create_contexts"].as_array().unwrap();
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0], "MxAc");
        assert_eq!(contexts[1], "DH2Q");
    }

    #[test]
    fn test_build_extensions_create_contexts_empty_vec_omitted() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.create_context_tags = Some(Vec::new());
        let ext = build_extensions(&t).unwrap();
        assert!(ext.get("create_contexts").is_none(), "empty create_contexts should be omitted");
    }

    #[test]
    fn test_build_extensions_read_flags() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.read_flags = Some(0x01); // UNBUFFERED
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["read_flags"], 0x01);
    }

    #[test]
    fn test_build_extensions_write_flags() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.write_flags = Some(0x01); // WRITE_THROUGH
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["write_flags"], 0x01);
    }

    #[test]
    fn test_build_extensions_oplock_level_nonzero() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.oplock_level = Some(0x08); // BATCH
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["oplock_level"], 0x08);
    }

    #[test]
    fn test_build_extensions_oplock_level_zero_omitted() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.oplock_level = Some(0);
        let ext = build_extensions(&t).unwrap();
        assert!(ext.get("oplock_level").is_none(), "oplock_level=0 should be omitted");
    }

    #[test]
    fn test_build_extensions_all_fields() {
        let mut t = make_tracked("Open", "10.0.0.1");
        t.oplock_level = Some(0x08);
        t.create_disposition = Some(2);
        t.share_access = Some(0x07);
        t.file_attributes = Some(0x80);
        t.create_action = Some(1);
        t.create_context_tags = Some(vec!["MxAc".to_string()]);
        t.read_flags = Some(0x01);
        t.write_flags = Some(0x01);
        let ext = build_extensions(&t).unwrap();
        let obj = ext.as_object().unwrap();
        // 8 original enrichments + nt_status/nt_status_name/credit_charge may be added
        // depending on their values, so we just check the core enrichments are present
        assert!(obj.len() >= 8, "at least 8 enrichment fields should be present");
    }

    // ── New operation type extraction tests ──────────────────────────

    #[test]
    fn test_extract_close() {
        let op = extract_one(make_tracked("Close", "c1"));
        match op {
            Operation::Close { handle_ref, .. } => {
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected Close"),
        }
    }

    #[test]
    fn test_extract_read() {
        let op = extract_one(make_tracked("Read", "c1"));
        match op {
            Operation::Read { offset, length, handle_ref, .. } => {
                assert_eq!(offset, 0);
                assert_eq!(length, 1024);
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected Read"),
        }
    }

    #[test]
    fn test_extract_write() {
        let op = extract_one(make_tracked("Write", "c1"));
        match op {
            Operation::Write { offset, length, handle_ref, .. } => {
                assert_eq!(offset, 0);
                assert_eq!(length, 1024);
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected Write"),
        }
    }

    #[test]
    fn test_extract_rename() {
        let mut t = make_tracked("Rename", "c1");
        t.rename_target = Some("new.txt".to_string());
        let op = extract_one(t);
        match op {
            Operation::Rename { source_path, dest_path, .. } => {
                assert_eq!(source_path, "test.txt");
                assert_eq!(dest_path, "new.txt");
            }
            _ => panic!("expected Rename"),
        }
    }

    #[test]
    fn test_extract_delete() {
        let op = extract_one(make_tracked("Delete", "c1"));
        match op {
            Operation::Delete { path, .. } => {
                assert_eq!(path, "test.txt");
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn test_extract_set_info() {
        let mut t = make_tracked("SetInfo", "c1");
        t.set_info_type = Some(0x01);
        t.set_info_class = Some(0x04);
        let op = extract_one(t);
        match op {
            Operation::SetInfo { info_type, info_class, .. } => {
                assert_eq!(info_type, 0x01);
                assert_eq!(info_class, 0x04);
            }
            _ => panic!("expected SetInfo"),
        }
    }

    #[test]
    fn test_extract_echo() {
        let op = extract_one(make_tracked("Echo", "c1"));
        assert!(matches!(op, Operation::Echo { .. }));
    }

    #[test]
    fn test_extract_cancel() {
        let mut t = make_tracked("Cancel", "c1");
        t.cancel_message_id = Some(42);
        let op = extract_one(t);
        match op {
            Operation::Cancel { target_message_id, .. } => {
                assert_eq!(target_message_id, 42);
            }
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn test_extract_oplock_break_ack() {
        let mut t = make_tracked("OplockBreakAck", "c1");
        t.oplock_level = Some(0x01);
        let op = extract_one(t);
        match op {
            Operation::OplockBreakAck { oplock_level, handle_ref, .. } => {
                assert_eq!(oplock_level, 0x01);
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected OplockBreakAck"),
        }
    }

    #[test]
    fn test_extract_transact_pipe() {
        let op = extract_one(make_tracked("TransactPipe", "c1"));
        match op {
            Operation::TransactPipe { handle_ref, .. } => {
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected TransactPipe"),
        }
    }

    #[test]
    fn test_extract_server_copy() {
        let mut t = make_tracked("ServerCopy", "c1");
        t.source_handle_ref = Some("src_h".to_string());
        t.dest_handle_ref = Some("dst_h".to_string());
        t.copy_offset = Some(4096);
        t.copy_length = Some(65536);
        let op = extract_one(t);
        match op {
            Operation::ServerCopy { source_handle_ref, dest_handle_ref, offset, length, .. } => {
                assert_eq!(source_handle_ref, "src_h");
                assert_eq!(dest_handle_ref, "dst_h");
                assert_eq!(offset, 4096);
                assert_eq!(length, 65536);
            }
            _ => panic!("expected ServerCopy"),
        }
    }

    #[test]
    fn test_extract_query_directory() {
        let mut t = make_tracked("QueryDirectory", "c1");
        t.pattern = Some("*.log".to_string());
        t.info_class = Some(0x25);
        let op = extract_one(t);
        match op {
            Operation::QueryDirectory { pattern, info_class, handle_ref, .. } => {
                assert_eq!(pattern, "*.log");
                assert_eq!(info_class, 0x25);
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected QueryDirectory"),
        }
    }

    #[test]
    fn test_extract_query_info() {
        let mut t = make_tracked("QueryInfo", "c1");
        t.info_type = Some(0x01);
        t.info_class = Some(0x05);
        let op = extract_one(t);
        match op {
            Operation::QueryInfo { info_type, info_class, .. } => {
                assert_eq!(info_type, 0x01);
                assert_eq!(info_class, 0x05);
            }
            _ => panic!("expected QueryInfo"),
        }
    }

    #[test]
    fn test_extract_flush() {
        let op = extract_one(make_tracked("Flush", "c1"));
        match op {
            Operation::Flush { handle_ref, .. } => {
                assert_eq!(handle_ref, "h_1");
            }
            _ => panic!("expected Flush"),
        }
    }

    #[test]
    fn test_extract_lock() {
        let mut t = make_tracked("Lock", "c1");
        t.lock_offset = Some(0);
        t.lock_length = Some(100);
        t.lock_exclusive = Some(true);
        let op = extract_one(t);
        match op {
            Operation::Lock { offset, length, exclusive, .. } => {
                assert_eq!(offset, 0);
                assert_eq!(length, 100);
                assert!(exclusive);
            }
            _ => panic!("expected Lock"),
        }
    }

    #[test]
    fn test_extract_unlock() {
        let mut t = make_tracked("Unlock", "c1");
        t.lock_offset = Some(200);
        t.lock_length = Some(50);
        let op = extract_one(t);
        match op {
            Operation::Unlock { offset, length, .. } => {
                assert_eq!(offset, 200);
                assert_eq!(length, 50);
            }
            _ => panic!("expected Unlock"),
        }
    }

    #[test]
    fn test_extract_ioctl() {
        let mut t = make_tracked("Ioctl", "c1");
        t.ctl_code = Some(0x00090028);
        let op = extract_one(t);
        match op {
            Operation::Ioctl { ctl_code, .. } => {
                assert_eq!(ctl_code, 0x00090028);
            }
            _ => panic!("expected Ioctl"),
        }
    }

    #[test]
    fn test_extract_change_notify() {
        let mut t = make_tracked("ChangeNotify", "c1");
        t.notify_filter = Some(0x17);
        t.notify_recursive = Some(true);
        let op = extract_one(t);
        match op {
            Operation::ChangeNotify { filter, recursive, .. } => {
                assert_eq!(filter, 0x17);
                assert!(recursive);
            }
            _ => panic!("expected ChangeNotify"),
        }
    }

    // ── Mkdir/Rmdir detection from Open ──────────────────────────────

    #[test]
    fn test_extract_mkdir() {
        let mut t = make_tracked("Open", "c1");
        t.create_options = Some(0x0000_0001); // FILE_DIRECTORY_FILE
        t.create_disposition = Some(2);        // FILE_CREATE
        let op = extract_one(t);
        assert!(matches!(op, Operation::Mkdir { .. }));
    }

    #[test]
    fn test_extract_rmdir() {
        let mut t = make_tracked("Open", "c1");
        t.create_options = Some(0x0000_1001); // FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE
        t.create_disposition = Some(1);
        let op = extract_one(t);
        assert!(matches!(op, Operation::Rmdir { .. }));
    }

    // ── Unknown operation type ───────────────────────────────────────

    #[test]
    fn test_extract_unknown_returns_none() {
        let t = make_tracked("SomeFutureCommand", "c1");
        let extractor = OperationExtractor::new();
        let ops = extractor.extract(&[make_conn(vec![t])]).unwrap();
        assert!(ops.is_empty(), "unknown operation type should be skipped");
    }

    // ── Timestamp ordering ───────────────────────────────────────────

    #[test]
    fn test_extract_orders_by_timestamp() {
        let mut t1 = make_tracked("Read", "c1");
        t1.timestamp_us = 3000;
        let mut t2 = make_tracked("Write", "c1");
        t2.timestamp_us = 1000;
        let mut t3 = make_tracked("Close", "c1");
        t3.timestamp_us = 2000;

        let extractor = OperationExtractor::new();
        let ops = extractor.extract(&[make_conn(vec![t1, t2, t3])]).unwrap();
        assert_eq!(ops.len(), 3);
        assert!(ops[0].timestamp_us() <= ops[1].timestamp_us());
        assert!(ops[1].timestamp_us() <= ops[2].timestamp_us());
    }

    // ── Open mode with extensions ────────────────────────────────────

    #[test]
    fn test_extract_open_with_all_extensions() {
        let mut t = make_tracked("Open", "c1");
        t.desired_access = Some(0x8000_0000); // GENERIC_READ
        t.oplock_level = Some(0x08); // BATCH
        t.create_disposition = Some(3); // FILE_OPEN_IF
        t.share_access = Some(0x07);
        t.file_attributes = Some(0x80);
        t.create_action = Some(1); // FILE_OPENED
        t.create_context_tags = Some(vec!["MxAc".to_string()]);
        let op = extract_one(t);
        match op {
            Operation::Open { mode, extensions, .. } => {
                assert!(matches!(mode, OpenMode::Read));
                let ext = extensions.unwrap();
                assert_eq!(ext["oplock_level"], 0x08);
                assert_eq!(ext["create_disposition"], 3);
                assert_eq!(ext["share_access"], 0x07);
                assert_eq!(ext["file_attributes"], 0x80);
                assert_eq!(ext["create_action"], 1);
                assert_eq!(ext["create_contexts"][0], "MxAc");
            }
            _ => panic!("expected Open"),
        }
    }

    // ── Phase A6: NTSTATUS and credit_charge extension tests ─────────

    #[test]
    fn test_extensions_include_nt_status() {
        let mut t = make_tracked("Open", "c1");
        t.nt_status = Some(0x0000_0000); // STATUS_SUCCESS
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["nt_status"], 0);
        assert_eq!(ext["nt_status_name"], "STATUS_SUCCESS");
    }

    #[test]
    fn test_extensions_include_nt_status_error() {
        let mut t = make_tracked("Open", "c1");
        t.nt_status = Some(0xC000_0022); // STATUS_ACCESS_DENIED
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["nt_status"], 0xC000_0022u32);
        assert_eq!(ext["nt_status_name"], "STATUS_ACCESS_DENIED");
    }

    #[test]
    fn test_extensions_credit_charge_above_1() {
        let mut t = make_tracked("Open", "c1");
        t.credit_charge = Some(8);
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["credit_charge"], 8);
    }

    #[test]
    fn test_extensions_credit_charge_1_omitted() {
        let mut t = make_tracked("Open", "c1");
        t.credit_charge = Some(1); // == 1, should be omitted
        let ext = build_extensions(&t).unwrap();
        assert!(ext.get("credit_charge").is_none());
    }

    // ── Phase A6: Negotiate skip test ────────────────────────────────

    #[test]
    fn test_negotiate_is_skipped_by_extractor() {
        let mut t = make_tracked("Negotiate", "c1");
        t.negotiate_dialect = Some(0x0311);
        t.negotiate_capabilities = Some(0x3F);
        let extractor = OperationExtractor::new();
        let ops = extractor.extract(&[make_conn(vec![t])]).unwrap();
        assert!(ops.is_empty(), "Negotiate ops should be skipped by extractor");
    }

    // ── Phase A6: Negotiate extensions test ──────────────────────────

    #[test]
    fn test_extensions_negotiate_dialect_and_caps() {
        let mut t = make_tracked("Open", "c1");
        t.negotiate_dialect = Some(0x0311);
        t.negotiate_capabilities = Some(0x7F);
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["negotiate_dialect"], 0x0311);
        assert_eq!(ext["negotiate_capabilities"], 0x7F);
    }

    // ── Phase A6: FSCTL name in extensions test ──────────────────────

    #[test]
    fn test_extensions_include_fsctl_name() {
        let mut t = make_tracked("Open", "c1");
        t.ctl_code = Some(0x0014_0204); // FSCTL_VALIDATE_NEGOTIATE_INFO
        let ext = build_extensions(&t).unwrap();
        assert_eq!(ext["fsctl_name"], "FSCTL_VALIDATE_NEGOTIATE_INFO");
    }

    #[test]
    fn test_extensions_unknown_fsctl_no_name() {
        let mut t = make_tracked("Open", "c1");
        t.ctl_code = Some(0xFFFF_FFFF); // unknown FSCTL
        t.create_disposition = None;
        t.oplock_level = None;
        t.desired_access = None;
        let ext = build_extensions(&t);
        // No other enrichments are set besides unknown FSCTL, so extensions may be None
        if let Some(ext) = ext {
            assert!(ext.get("fsctl_name").is_none(), "unknown FSCTL should not have fsctl_name");
        }
    }
}
