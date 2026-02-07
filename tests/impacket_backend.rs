//! Tests for the Impacket subprocess backend using a mock Python worker.
//!
//! These tests verify the JSON-line protocol round-trip without requiring
//! Impacket or an actual SMB server.

#![cfg(feature = "impacket-backend")]

use smbench::backend::impacket::{ImpacketBackend, ImpacketConfig};
use smbench::backend::SMBBackend;
use smbench::ir::OpenMode;

fn mock_config() -> ImpacketConfig {
    ImpacketConfig {
        worker_script: "tests/mock_worker.py".to_string(),
        python: "python3".to_string(),
        server: "mock-server".to_string(),
        share: "mock-share".to_string(),
        user: "mock-user".to_string(),
        pass: "mock-pass".to_string(),
    }
}

#[tokio::test]
async fn test_impacket_connect() {
    let backend = ImpacketBackend::new(mock_config());
    let conn = backend.connect("test_client").await;
    assert!(conn.is_ok(), "Connect should succeed: {:?}", conn.err());
}

#[tokio::test]
async fn test_impacket_open_close() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Open
    let op = smbench::ir::Operation::Open {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        path: "test/file.txt".to_string(),
        mode: OpenMode::ReadWrite,
        handle_ref: "h_1".to_string(),
        extensions: None,
    };
    let result = conn.execute(&op).await;
    assert!(result.is_ok(), "Open should succeed: {:?}", result.err());

    // Close
    let close_op = smbench::ir::Operation::Close {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        handle_ref: "h_1".to_string(),
    };
    let result = conn.execute(&close_op).await;
    assert!(result.is_ok(), "Close should succeed: {:?}", result.err());
}

#[tokio::test]
async fn test_impacket_read_write() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Open
    let open_op = smbench::ir::Operation::Open {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        path: "test/data.bin".to_string(),
        mode: OpenMode::ReadWrite,
        handle_ref: "h_1".to_string(),
        extensions: None,
    };
    conn.execute(&open_op).await.unwrap();

    // Write - need a blob file
    let blob_dir = std::env::temp_dir().join("smbench_impacket_test");
    std::fs::create_dir_all(&blob_dir).unwrap();
    let blob_path = blob_dir.join("test_blob.bin");
    std::fs::write(&blob_path, b"test data payload").unwrap();

    let write_op = smbench::ir::Operation::Write {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        handle_ref: "h_1".to_string(),
        offset: 0,
        length: 17,
        blob_path: blob_path.to_string_lossy().to_string(),
    };
    let result = conn.execute(&write_op).await;
    assert!(result.is_ok(), "Write should succeed: {:?}", result.err());

    // Read
    let read_op = smbench::ir::Operation::Read {
        op_id: "op_3".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 200,
        handle_ref: "h_1".to_string(),
        offset: 0,
        length: 1024,
    };
    let result = conn.execute(&read_op).await;
    assert!(result.is_ok(), "Read should succeed: {:?}", result.err());

    // Close
    let close_op = smbench::ir::Operation::Close {
        op_id: "op_4".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 300,
        handle_ref: "h_1".to_string(),
    };
    conn.execute(&close_op).await.unwrap();

    // Cleanup
    let _ = std::fs::remove_dir_all(&blob_dir);
}

#[tokio::test]
async fn test_impacket_rename_delete() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Rename
    let rename_op = smbench::ir::Operation::Rename {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        source_path: "old.txt".to_string(),
        dest_path: "new.txt".to_string(),
    };
    let result = conn.execute(&rename_op).await;
    assert!(result.is_ok(), "Rename should succeed: {:?}", result.err());

    // Delete
    let delete_op = smbench::ir::Operation::Delete {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        path: "new.txt".to_string(),
    };
    let result = conn.execute(&delete_op).await;
    assert!(result.is_ok(), "Delete should succeed: {:?}", result.err());
}

#[tokio::test]
async fn test_impacket_flush_lock_unlock() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Open a file first
    let open_op = smbench::ir::Operation::Open {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        path: "test/lockfile.bin".to_string(),
        mode: OpenMode::ReadWrite,
        handle_ref: "h_1".to_string(),
        extensions: None,
    };
    conn.execute(&open_op).await.unwrap();

    // Flush
    let flush_op = smbench::ir::Operation::Flush {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        handle_ref: "h_1".to_string(),
    };
    let result = conn.execute(&flush_op).await;
    assert!(result.is_ok(), "Flush should succeed: {:?}", result.err());

    // Lock
    let lock_op = smbench::ir::Operation::Lock {
        op_id: "op_3".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 200,
        handle_ref: "h_1".to_string(),
        offset: 0,
        length: 1024,
        exclusive: true,
    };
    let result = conn.execute(&lock_op).await;
    assert!(result.is_ok(), "Lock should succeed: {:?}", result.err());

    // Unlock
    let unlock_op = smbench::ir::Operation::Unlock {
        op_id: "op_4".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 300,
        handle_ref: "h_1".to_string(),
        offset: 0,
        length: 1024,
    };
    let result = conn.execute(&unlock_op).await;
    assert!(result.is_ok(), "Unlock should succeed: {:?}", result.err());

    // Close
    let close_op = smbench::ir::Operation::Close {
        op_id: "op_5".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 400,
        handle_ref: "h_1".to_string(),
    };
    conn.execute(&close_op).await.unwrap();
}

#[tokio::test]
async fn test_impacket_query_directory_info() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Open a file first (acts as dir handle)
    let open_op = smbench::ir::Operation::Open {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        path: "test/dir".to_string(),
        mode: OpenMode::Read,
        handle_ref: "h_1".to_string(),
        extensions: None,
    };
    conn.execute(&open_op).await.unwrap();

    // QueryDirectory
    let qd_op = smbench::ir::Operation::QueryDirectory {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        handle_ref: "h_1".to_string(),
        pattern: "*.txt".to_string(),
        info_class: 37,
    };
    let result = conn.execute(&qd_op).await;
    assert!(result.is_ok(), "QueryDirectory should succeed: {:?}", result.err());

    // QueryInfo
    let qi_op = smbench::ir::Operation::QueryInfo {
        op_id: "op_3".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 200,
        handle_ref: "h_1".to_string(),
        info_type: 1,
        info_class: 5,
    };
    let result = conn.execute(&qi_op).await;
    assert!(result.is_ok(), "QueryInfo should succeed: {:?}", result.err());

    // Close
    let close_op = smbench::ir::Operation::Close {
        op_id: "op_4".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 300,
        handle_ref: "h_1".to_string(),
    };
    conn.execute(&close_op).await.unwrap();
}

#[tokio::test]
async fn test_impacket_ioctl_change_notify() {
    let backend = ImpacketBackend::new(mock_config());
    let mut conn = backend.connect("test_client").await.unwrap();

    // Open a file first
    let open_op = smbench::ir::Operation::Open {
        op_id: "op_1".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 0,
        path: "test/notify.txt".to_string(),
        mode: OpenMode::ReadWrite,
        handle_ref: "h_1".to_string(),
        extensions: None,
    };
    conn.execute(&open_op).await.unwrap();

    // Ioctl
    let ioctl_op = smbench::ir::Operation::Ioctl {
        op_id: "op_2".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 100,
        handle_ref: "h_1".to_string(),
        ctl_code: 0x00060194,
        input_blob_path: None,
    };
    let result = conn.execute(&ioctl_op).await;
    assert!(result.is_ok(), "Ioctl should succeed: {:?}", result.err());

    // ChangeNotify
    let cn_op = smbench::ir::Operation::ChangeNotify {
        op_id: "op_3".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 200,
        handle_ref: "h_1".to_string(),
        filter: 0x17,
        recursive: true,
    };
    let result = conn.execute(&cn_op).await;
    assert!(result.is_ok(), "ChangeNotify should succeed: {:?}", result.err());

    // Close
    let close_op = smbench::ir::Operation::Close {
        op_id: "op_4".to_string(),
        client_id: "test_client".to_string(),
        timestamp_us: 300,
        handle_ref: "h_1".to_string(),
    };
    conn.execute(&close_op).await.unwrap();
}

#[tokio::test]
async fn test_impacket_capabilities() {
    let backend = ImpacketBackend::new(mock_config());
    let caps = backend.capabilities();
    assert_eq!(caps.name, "impacket");
    assert!(!caps.supports_oplocks);
    assert!(!caps.is_dev_only);
}

#[tokio::test]
async fn test_impacket_multiple_connections() {
    let backend = ImpacketBackend::new(mock_config());

    // Each connect spawns a new subprocess
    let conn1 = backend.connect("client_1").await;
    let conn2 = backend.connect("client_2").await;

    assert!(conn1.is_ok(), "First connect should succeed");
    assert!(conn2.is_ok(), "Second connect should succeed");
}
