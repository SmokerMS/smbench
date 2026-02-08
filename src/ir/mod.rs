use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkloadIr {
    pub version: u32,
    pub metadata: Metadata,
    pub clients: Vec<ClientSpec>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub source: String,
    pub duration_seconds: f64,
    pub client_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientSpec {
    pub client_id: String,
    pub operation_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Operation {
    Open {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
        mode: OpenMode,
        handle_ref: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<serde_json::Value>,
    },
    Read {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
    },
    Write {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
        blob_path: String,
    },
    Close {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
    },
    Rename {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        source_path: String,
        dest_path: String,
    },
    Delete {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
    },
    Mkdir {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
    },
    Rmdir {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
    },
    QueryDirectory {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        pattern: String,
        info_class: u8,
    },
    QueryInfo {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        info_type: u8,
        info_class: u8,
    },
    Flush {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
    },
    Lock {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
        exclusive: bool,
    },
    Unlock {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
    },
    Ioctl {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        ctl_code: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_blob_path: Option<String>,
    },
    ChangeNotify {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        filter: u32,
        recursive: bool,
    },
    SetInfo {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        info_type: u8,
        info_class: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_blob_path: Option<String>,
    },
    Echo {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
    },
    Cancel {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        target_message_id: u64,
    },
    OplockBreakAck {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        oplock_level: u8,
    },
    TransactPipe {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_blob_path: Option<String>,
    },
    ServerCopy {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        source_handle_ref: String,
        dest_handle_ref: String,
        offset: u64,
        length: u64,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
}

impl Operation {
    pub fn op_id(&self) -> &str {
        match self {
            Operation::Open { op_id, .. }
            | Operation::Read { op_id, .. }
            | Operation::Write { op_id, .. }
            | Operation::Close { op_id, .. }
            | Operation::Rename { op_id, .. }
            | Operation::Delete { op_id, .. }
            | Operation::Mkdir { op_id, .. }
            | Operation::Rmdir { op_id, .. }
            | Operation::QueryDirectory { op_id, .. }
            | Operation::QueryInfo { op_id, .. }
            | Operation::Flush { op_id, .. }
            | Operation::Lock { op_id, .. }
            | Operation::Unlock { op_id, .. }
            | Operation::Ioctl { op_id, .. }
            | Operation::ChangeNotify { op_id, .. }
            | Operation::SetInfo { op_id, .. }
            | Operation::Echo { op_id, .. }
            | Operation::Cancel { op_id, .. }
            | Operation::OplockBreakAck { op_id, .. }
            | Operation::TransactPipe { op_id, .. }
            | Operation::ServerCopy { op_id, .. } => op_id,
        }
    }

    pub fn client_id(&self) -> &str {
        match self {
            Operation::Open { client_id, .. }
            | Operation::Read { client_id, .. }
            | Operation::Write { client_id, .. }
            | Operation::Close { client_id, .. }
            | Operation::Rename { client_id, .. }
            | Operation::Delete { client_id, .. }
            | Operation::Mkdir { client_id, .. }
            | Operation::Rmdir { client_id, .. }
            | Operation::QueryDirectory { client_id, .. }
            | Operation::QueryInfo { client_id, .. }
            | Operation::Flush { client_id, .. }
            | Operation::Lock { client_id, .. }
            | Operation::Unlock { client_id, .. }
            | Operation::Ioctl { client_id, .. }
            | Operation::ChangeNotify { client_id, .. }
            | Operation::SetInfo { client_id, .. }
            | Operation::Echo { client_id, .. }
            | Operation::Cancel { client_id, .. }
            | Operation::OplockBreakAck { client_id, .. }
            | Operation::TransactPipe { client_id, .. }
            | Operation::ServerCopy { client_id, .. } => client_id,
        }
    }

    pub fn timestamp_us(&self) -> u64 {
        match self {
            Operation::Open { timestamp_us, .. }
            | Operation::Read { timestamp_us, .. }
            | Operation::Write { timestamp_us, .. }
            | Operation::Close { timestamp_us, .. }
            | Operation::Rename { timestamp_us, .. }
            | Operation::Delete { timestamp_us, .. }
            | Operation::Mkdir { timestamp_us, .. }
            | Operation::Rmdir { timestamp_us, .. }
            | Operation::QueryDirectory { timestamp_us, .. }
            | Operation::QueryInfo { timestamp_us, .. }
            | Operation::Flush { timestamp_us, .. }
            | Operation::Lock { timestamp_us, .. }
            | Operation::Unlock { timestamp_us, .. }
            | Operation::Ioctl { timestamp_us, .. }
            | Operation::ChangeNotify { timestamp_us, .. }
            | Operation::SetInfo { timestamp_us, .. }
            | Operation::Echo { timestamp_us, .. }
            | Operation::Cancel { timestamp_us, .. }
            | Operation::OplockBreakAck { timestamp_us, .. }
            | Operation::TransactPipe { timestamp_us, .. }
            | Operation::ServerCopy { timestamp_us, .. } => *timestamp_us,
        }
    }

    pub fn handle_ref(&self) -> Option<&str> {
        match self {
            Operation::Open { handle_ref, .. }
            | Operation::Read { handle_ref, .. }
            | Operation::Write { handle_ref, .. }
            | Operation::Close { handle_ref, .. }
            | Operation::QueryDirectory { handle_ref, .. }
            | Operation::QueryInfo { handle_ref, .. }
            | Operation::Flush { handle_ref, .. }
            | Operation::Lock { handle_ref, .. }
            | Operation::Unlock { handle_ref, .. }
            | Operation::Ioctl { handle_ref, .. }
            | Operation::ChangeNotify { handle_ref, .. }
            | Operation::SetInfo { handle_ref, .. }
            | Operation::OplockBreakAck { handle_ref, .. }
            | Operation::TransactPipe { handle_ref, .. } => Some(handle_ref),
            Operation::ServerCopy { source_handle_ref, .. } => Some(source_handle_ref),
            Operation::Rename { .. }
            | Operation::Delete { .. }
            | Operation::Mkdir { .. }
            | Operation::Rmdir { .. }
            | Operation::Echo { .. }
            | Operation::Cancel { .. } => None,
        }
    }

    pub fn extensions(&self) -> Option<&serde_json::Value> {
        match self {
            Operation::Open { extensions, .. } => extensions.as_ref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkloadSummary {
    pub client_count: usize,
    pub operation_count: usize,
    pub open_ops: usize,
    pub read_ops: usize,
    pub write_ops: usize,
    pub close_ops: usize,
    pub rename_ops: usize,
    pub delete_ops: usize,
    pub mkdir_ops: usize,
    pub rmdir_ops: usize,
    pub query_directory_ops: usize,
    pub query_info_ops: usize,
    pub flush_ops: usize,
    pub lock_ops: usize,
    pub unlock_ops: usize,
    pub ioctl_ops: usize,
    pub change_notify_ops: usize,
    pub set_info_ops: usize,
    pub echo_ops: usize,
    pub cancel_ops: usize,
    pub oplock_break_ack_ops: usize,
    pub transact_pipe_ops: usize,
    pub server_copy_ops: usize,
}

impl WorkloadIr {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("Unsupported IR version: {}", self.version));
        }
        if self.metadata.client_count as usize != self.clients.len() {
            return Err(format!(
                "metadata.client_count {} does not match clients length {}",
                self.metadata.client_count,
                self.clients.len()
            ));
        }
        let mut client_counts = std::collections::HashMap::new();
        for client in &self.clients {
            if client.client_id.trim().is_empty() {
                return Err("client_id must be non-empty".to_string());
            }
            client_counts.insert(client.client_id.clone(), 0usize);
        }
        for op in &self.operations {
            let entry = client_counts
                .get_mut(op.client_id())
                .ok_or_else(|| format!("Unknown client_id in op: {}", op.client_id()))?;
            *entry += 1;
        }
        for client in &self.clients {
            let observed = client_counts.get(&client.client_id).copied().unwrap_or(0);
            if observed != client.operation_count as usize {
                return Err(format!(
                    "client {} operation_count {} does not match observed {}",
                    client.client_id, client.operation_count, observed
                ));
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> WorkloadSummary {
        let mut summary = WorkloadSummary {
            client_count: self.clients.len(),
            operation_count: self.operations.len(),
            open_ops: 0,
            read_ops: 0,
            write_ops: 0,
            close_ops: 0,
            rename_ops: 0,
            delete_ops: 0,
            mkdir_ops: 0,
            rmdir_ops: 0,
            query_directory_ops: 0,
            query_info_ops: 0,
            flush_ops: 0,
            lock_ops: 0,
            unlock_ops: 0,
            ioctl_ops: 0,
            change_notify_ops: 0,
            set_info_ops: 0,
            echo_ops: 0,
            cancel_ops: 0,
            oplock_break_ack_ops: 0,
            transact_pipe_ops: 0,
            server_copy_ops: 0,
        };
        for op in &self.operations {
            match op {
                Operation::Open { .. } => summary.open_ops += 1,
                Operation::Read { .. } => summary.read_ops += 1,
                Operation::Write { .. } => summary.write_ops += 1,
                Operation::Close { .. } => summary.close_ops += 1,
                Operation::Rename { .. } => summary.rename_ops += 1,
                Operation::Delete { .. } => summary.delete_ops += 1,
                Operation::Mkdir { .. } => summary.mkdir_ops += 1,
                Operation::Rmdir { .. } => summary.rmdir_ops += 1,
                Operation::QueryDirectory { .. } => summary.query_directory_ops += 1,
                Operation::QueryInfo { .. } => summary.query_info_ops += 1,
                Operation::Flush { .. } => summary.flush_ops += 1,
                Operation::Lock { .. } => summary.lock_ops += 1,
                Operation::Unlock { .. } => summary.unlock_ops += 1,
                Operation::Ioctl { .. } => summary.ioctl_ops += 1,
                Operation::ChangeNotify { .. } => summary.change_notify_ops += 1,
                Operation::SetInfo { .. } => summary.set_info_ops += 1,
                Operation::Echo { .. } => summary.echo_ops += 1,
                Operation::Cancel { .. } => summary.cancel_ops += 1,
                Operation::OplockBreakAck { .. } => summary.oplock_break_ack_ops += 1,
                Operation::TransactPipe { .. } => summary.transact_pipe_ops += 1,
                Operation::ServerCopy { .. } => summary.server_copy_ops += 1,
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_counts() {
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "test".to_string(),
                duration_seconds: 1.0,
                client_count: 1,
            },
            clients: vec![ClientSpec {
                client_id: "client_1".to_string(),
                operation_count: 1,
            }],
            operations: vec![Operation::Delete {
                op_id: "op_1".to_string(),
                client_id: "client_1".to_string(),
                timestamp_us: 0,
                path: "/tmp/file".to_string(),
            }],
        };
        assert!(ir.validate().is_ok());
    }

    #[test]
    fn test_new_ops_round_trip() {
        let ops = vec![
            Operation::QueryDirectory {
                op_id: "qd_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 1000,
                handle_ref: "h_1".to_string(),
                pattern: "*.txt".to_string(),
                info_class: 37,
            },
            Operation::QueryInfo {
                op_id: "qi_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 2000,
                handle_ref: "h_1".to_string(),
                info_type: 1,
                info_class: 5,
            },
            Operation::Flush {
                op_id: "fl_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 3000,
                handle_ref: "h_1".to_string(),
            },
            Operation::Lock {
                op_id: "lk_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 4000,
                handle_ref: "h_1".to_string(),
                offset: 0,
                length: 1024,
                exclusive: true,
            },
            Operation::Unlock {
                op_id: "ul_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 5000,
                handle_ref: "h_1".to_string(),
                offset: 0,
                length: 1024,
            },
            Operation::Ioctl {
                op_id: "io_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 6000,
                handle_ref: "h_1".to_string(),
                ctl_code: 0x00060194,
                input_blob_path: None,
            },
            Operation::ChangeNotify {
                op_id: "cn_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 7000,
                handle_ref: "h_1".to_string(),
                filter: 0x17,
                recursive: true,
            },
        ];

        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "test".to_string(),
                duration_seconds: 1.0,
                client_count: 1,
            },
            clients: vec![ClientSpec {
                client_id: "c1".to_string(),
                operation_count: 7,
            }],
            operations: ops,
        };

        // Serialize and deserialize
        let json = serde_json::to_string_pretty(&ir).unwrap();
        let ir2: WorkloadIr = serde_json::from_str(&json).unwrap();

        assert!(ir2.validate().is_ok());
        assert_eq!(ir2.operations.len(), 7);

        // Verify summary
        let summary = ir2.summary();
        assert_eq!(summary.query_directory_ops, 1);
        assert_eq!(summary.query_info_ops, 1);
        assert_eq!(summary.flush_ops, 1);
        assert_eq!(summary.lock_ops, 1);
        assert_eq!(summary.unlock_ops, 1);
        assert_eq!(summary.ioctl_ops, 1);
        assert_eq!(summary.change_notify_ops, 1);

        // Verify accessor methods
        assert_eq!(ir2.operations[0].op_id(), "qd_1");
        assert_eq!(ir2.operations[0].client_id(), "c1");
        assert_eq!(ir2.operations[0].timestamp_us(), 1000);
        assert_eq!(ir2.operations[0].handle_ref(), Some("h_1"));
        assert_eq!(ir2.operations[3].handle_ref(), Some("h_1"));
        assert_eq!(ir2.operations[5].handle_ref(), Some("h_1"));
    }

    #[test]
    fn test_validate_unknown_client() {
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "test".to_string(),
                duration_seconds: 1.0,
                client_count: 1,
            },
            clients: vec![ClientSpec {
                client_id: "client_1".to_string(),
                operation_count: 1,
            }],
            operations: vec![Operation::Delete {
                op_id: "op_1".to_string(),
                client_id: "missing".to_string(),
                timestamp_us: 0,
                path: "/tmp/file".to_string(),
            }],
        };
        assert!(ir.validate().is_err());
    }
}
