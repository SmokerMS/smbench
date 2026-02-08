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
        #[serde(skip_serializing_if = "Option::is_none")]
        desired_access: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        create_disposition: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        create_options: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        share_access: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_attributes: Option<u32>,
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
    Mkdir {
        request_id: String,
        connection_id: String,
        path: String,
    },
    Rmdir {
        request_id: String,
        connection_id: String,
        path: String,
    },
    QueryDirectory {
        request_id: String,
        handle_id: String,
        pattern: String,
        info_class: u8,
    },
    QueryInfo {
        request_id: String,
        handle_id: String,
        info_type: u8,
        info_class: u8,
    },
    Flush {
        request_id: String,
        handle_id: String,
    },
    Lock {
        request_id: String,
        handle_id: String,
        offset: u64,
        length: u64,
        exclusive: bool,
    },
    Unlock {
        request_id: String,
        handle_id: String,
        offset: u64,
        length: u64,
    },
    Ioctl {
        request_id: String,
        handle_id: String,
        ctl_code: u32,
    },
    ChangeNotify {
        request_id: String,
        handle_id: String,
        filter: u32,
        recursive: bool,
    },
    SetInfo {
        request_id: String,
        handle_id: String,
        info_type: u8,
        info_class: u8,
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
    MkdirResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    RmdirResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    QueryDirectoryResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    QueryInfoResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    FlushResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    LockResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    UnlockResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    IoctlResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    ChangeNotifyResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
    SetInfoResult {
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

pub fn serialize_request_line(request: &WorkerRequest) -> Result<String> {
    let json_str = serialize_request(request)?;
    if json_str.len() + 1 > MAX_MESSAGE_BYTES {
        return Err(anyhow!(
            "Message too large with newline: {} bytes",
            json_str.len() + 1
        ));
    }
    Ok(format!("{json_str}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_request_line_newline() {
        let request = WorkerRequest::Shutdown;
        let line = serialize_request_line(&request).unwrap();
        assert!(line.ends_with('\n'));
        assert!(!line[..line.len() - 1].contains('\n'));
    }

    #[test]
    fn test_new_request_variants_round_trip() {
        let requests = vec![
            WorkerRequest::QueryDirectory {
                request_id: "r1".to_string(),
                handle_id: "h1".to_string(),
                pattern: "*.txt".to_string(),
                info_class: 37,
            },
            WorkerRequest::QueryInfo {
                request_id: "r2".to_string(),
                handle_id: "h1".to_string(),
                info_type: 1,
                info_class: 5,
            },
            WorkerRequest::Flush {
                request_id: "r3".to_string(),
                handle_id: "h1".to_string(),
            },
            WorkerRequest::Lock {
                request_id: "r4".to_string(),
                handle_id: "h1".to_string(),
                offset: 0,
                length: 1024,
                exclusive: true,
            },
            WorkerRequest::Unlock {
                request_id: "r5".to_string(),
                handle_id: "h1".to_string(),
                offset: 0,
                length: 1024,
            },
            WorkerRequest::Ioctl {
                request_id: "r6".to_string(),
                handle_id: "h1".to_string(),
                ctl_code: 0x00060194,
            },
            WorkerRequest::ChangeNotify {
                request_id: "r7".to_string(),
                handle_id: "h1".to_string(),
                filter: 0x17,
                recursive: true,
            },
        ];

        for req in &requests {
            let line = serialize_request_line(req).unwrap();
            assert!(line.ends_with('\n'));
            assert!(!line[..line.len() - 1].contains('\n'));
            // Verify it can be parsed back
            let _parsed: WorkerRequest = serde_json::from_str(&line).unwrap();
            // Verify the type tag is preserved
            let json: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(json.get("type").is_some());
        }
    }

    #[test]
    fn test_new_response_variants_round_trip() {
        let responses = vec![
            (r#"{"type":"QueryDirectoryResult","request_id":"r1","success":true,"error":null}"#, "QueryDirectoryResult"),
            (r#"{"type":"QueryInfoResult","request_id":"r2","success":true,"error":null}"#, "QueryInfoResult"),
            (r#"{"type":"FlushResult","request_id":"r3","success":true,"error":null}"#, "FlushResult"),
            (r#"{"type":"LockResult","request_id":"r4","success":true,"error":null}"#, "LockResult"),
            (r#"{"type":"UnlockResult","request_id":"r5","success":true,"error":null}"#, "UnlockResult"),
            (r#"{"type":"IoctlResult","request_id":"r6","success":true,"error":null}"#, "IoctlResult"),
            (r#"{"type":"ChangeNotifyResult","request_id":"r7","success":true,"error":null}"#, "ChangeNotifyResult"),
        ];

        for (json_str, expected_type) in responses {
            let resp: WorkerResponse = serde_json::from_str(json_str).unwrap();
            // Re-serialize and verify type tag is preserved
            let re_serialized = serde_json::to_string(&resp).unwrap();
            let val: serde_json::Value = serde_json::from_str(&re_serialized).unwrap();
            assert_eq!(val["type"].as_str().unwrap(), expected_type);
        }
    }

    #[test]
    fn test_serialize_request_line_size_limit() {
        let base = WorkerRequest::WriteFromBlob {
            request_id: "req".to_string(),
            handle_id: "h".to_string(),
            offset: 0,
            blob_path: "x".to_string(),
        };
        let mut line = serialize_request_line(&base).unwrap();
        let pad_len = MAX_MESSAGE_BYTES - line.len();
        line.push_str(&"x".repeat(pad_len));
        assert_eq!(line.len(), MAX_MESSAGE_BYTES);

        let over = WorkerRequest::WriteFromBlob {
            request_id: "req".to_string(),
            handle_id: "h".to_string(),
            offset: 0,
            blob_path: "x".repeat(MAX_MESSAGE_BYTES),
        };
        assert!(serialize_request_line(&over).is_err());
    }
}
