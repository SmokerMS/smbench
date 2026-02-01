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
            | Operation::Delete { op_id, .. } => op_id,
        }
    }

    pub fn client_id(&self) -> &str {
        match self {
            Operation::Open { client_id, .. }
            | Operation::Read { client_id, .. }
            | Operation::Write { client_id, .. }
            | Operation::Close { client_id, .. }
            | Operation::Rename { client_id, .. }
            | Operation::Delete { client_id, .. } => client_id,
        }
    }

    pub fn timestamp_us(&self) -> u64 {
        match self {
            Operation::Open { timestamp_us, .. }
            | Operation::Read { timestamp_us, .. }
            | Operation::Write { timestamp_us, .. }
            | Operation::Close { timestamp_us, .. }
            | Operation::Rename { timestamp_us, .. }
            | Operation::Delete { timestamp_us, .. } => *timestamp_us,
        }
    }

    pub fn handle_ref(&self) -> Option<&str> {
        match self {
            Operation::Open { handle_ref, .. }
            | Operation::Read { handle_ref, .. }
            | Operation::Write { handle_ref, .. }
            | Operation::Close { handle_ref, .. } => Some(handle_ref),
            Operation::Rename { .. } | Operation::Delete { .. } => None,
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
        };
        for op in &self.operations {
            match op {
                Operation::Open { .. } => summary.open_ops += 1,
                Operation::Read { .. } => summary.read_ops += 1,
                Operation::Write { .. } => summary.write_ops += 1,
                Operation::Close { .. } => summary.close_ops += 1,
                Operation::Rename { .. } => summary.rename_ops += 1,
                Operation::Delete { .. } => summary.delete_ops += 1,
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
