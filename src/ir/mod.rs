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
