use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkerRequest {
    Connect {
        request_id: String,
        server: String,
        share: String,
        username: String,
        password: String,
    },
    Open {
        request_id: String,
        connection_id: String,
        path: String,
        mode: String,
    },
    Write {
        request_id: String,
        handle_id: String,
        offset: u64,
        data_base64: String,
    },
    WriteFromBlob {
        request_id: String,
        handle_id: String,
        offset: u64,
        blob_path: String,
    },
    Read {
        request_id: String,
        handle_id: String,
        offset: u64,
        length: u64,
    },
    Close {
        request_id: String,
        handle_id: String,
    },
    Rename {
        request_id: String,
        connection_id: String,
        source_path: String,
        dest_path: String,
    },
    Delete {
        request_id: String,
        connection_id: String,
        path: String,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkerResponse {
    Connected {
        request_id: String,
        connection_id: String,
        success: bool,
        error: Option<String>,
    },
    Opened {
        request_id: String,
        handle_id: String,
        success: bool,
        error: Option<String>,
    },
    ReadResult {
        request_id: String,
        data_base64: String,
        success: bool,
        error: Option<String>,
    },
    WriteResult {
        request_id: String,
        bytes_written: u64,
        success: bool,
        error: Option<String>,
    },
    Closed {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    Renamed {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    Deleted {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    Error {
        request_id: String,
        error: String,
    },
}

pub fn validate_blob_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(anyhow!("Blob path must be absolute"));
    }
    if path.contains("..") {
        return Err(anyhow!("Blob path must not contain .."));
    }
    if !std::path::Path::new(path).exists() {
        return Err(anyhow!("Blob path does not exist"));
    }
    Ok(())
}

pub fn serialize_request(request: &WorkerRequest) -> Result<String> {
    let json_str = serde_json::to_string(request)?;
    if json_str.len() > MAX_MESSAGE_BYTES {
        return Err(anyhow!("Message too large: {} bytes", json_str.len()));
    }
    if json_str.contains('\n') {
        return Err(anyhow!("Message contains newline"));
    }
    Ok(json_str)
}
