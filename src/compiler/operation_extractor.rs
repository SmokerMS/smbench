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

use super::state_machine::{SmbConnection, TrackedOperation};
use crate::ir::{OpenMode, Operation};
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
        }
    }

    #[test]
    fn test_extract_open() {
        let conn = SmbConnection {
            client_id: "10.0.0.1".to_string(),
            sessions: Default::default(),
            operations: vec![make_tracked("Open", "10.0.0.1")],
        };
        let extractor = OperationExtractor::new();
        let ops = extractor.extract(&[conn]).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], Operation::Open { .. }));
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
}
