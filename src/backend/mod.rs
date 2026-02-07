use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::ir::{OpenMode, Operation};

#[cfg(feature = "smb-rs-backend")]
pub mod smbrs;

#[cfg(feature = "impacket-backend")]
pub mod impacket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    Development,
    Production,
}

#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    pub name: String,
    pub supports_oplocks: bool,
    pub is_dev_only: bool,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }
}

#[async_trait]
pub trait SMBBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    async fn connect(&self, client_id: &str) -> Result<ConnectionState>;
}

#[async_trait]
pub trait SMBConnectionInner: Send + Sync {
    async fn open_simple(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>>;
    async fn open_extended(
        &self,
        path: &str,
        extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>>;
    async fn execute_misc(&self, op: &Operation) -> Result<()>;
}

#[async_trait]
pub trait SMBFileHandle: Send + Sync {
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>>;
    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64>;
    async fn close(self: Box<Self>) -> Result<()>;
    fn file_id(&self) -> Option<String> {
        None
    }
    fn lease_key(&self) -> Option<String> {
        None
    }
    fn granted_oplock(&self) -> Option<OplockLevel> {
        None
    }
    async fn acknowledge_oplock_break(&self, _new_level: OplockLevel) -> Result<()> {
        Err(anyhow!("Oplocks not supported"))
    }
    async fn acknowledge_lease_break(
        &self,
        _lease_key: &str,
        _lease_state: LeaseState,
    ) -> Result<()> {
        Err(anyhow!("Leases not supported"))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OplockLevel {
    None,
    Read,
    Batch,
}

#[derive(Debug, Clone, Copy)]
pub struct LeaseState {
    pub read: bool,
    pub write: bool,
    pub handle: bool,
}

struct HandleEntry {
    handle: Box<dyn SMBFileHandle>,
    oplock_state: OplockState,
    #[allow(dead_code)]
    path: String,
}

#[derive(Debug)]
enum OplockState {
    None,
    BreakPending { waiters: Vec<tokio::sync::oneshot::Sender<()>> },
    Broken,
}

pub struct ConnectionState {
    inner: Box<dyn SMBConnectionInner>,
    handles: HashMap<String, HandleEntry>,
    file_id_map: HashMap<String, String>,
    lease_key_map: HashMap<String, String>,
    oplock_break_rx: Option<mpsc::Receiver<OplockBreak>>,
    oplock_wait_timeout: tokio::time::Duration,
}

#[derive(Debug, Clone)]
pub struct OplockBreak {
    pub handle_ref: String,
    pub file_id: Option<String>,
    pub lease_key: Option<String>,
    pub new_level: OplockLevel,
    pub lease_state: Option<LeaseState>,
}

impl ConnectionState {
    pub fn new(inner: Box<dyn SMBConnectionInner>) -> Self {
        Self {
            inner,
            handles: HashMap::new(),
            file_id_map: HashMap::new(),
            lease_key_map: HashMap::new(),
            oplock_break_rx: None,
            oplock_wait_timeout: tokio::time::Duration::from_secs(30),
        }
    }

    pub fn with_oplock_wait_timeout(mut self, timeout: tokio::time::Duration) -> Self {
        self.oplock_wait_timeout = timeout;
        self
    }

    pub fn with_oplock_channel(mut self, rx: mpsc::Receiver<OplockBreak>) -> Self {
        self.oplock_break_rx = Some(rx);
        self
    }

    pub fn take_oplock_receiver(&mut self) -> Option<mpsc::Receiver<OplockBreak>> {
        self.oplock_break_rx.take()
    }

    /// Close all open handles. Used during scheduler cleanup after workload completion.
    pub async fn close_all_handles(&mut self) {
        let refs: Vec<String> = self.handles.keys().cloned().collect();
        for handle_ref in refs {
            if let Some(entry) = self.handles.remove(&handle_ref) {
                if let Some(file_id) = entry.handle.file_id() {
                    self.file_id_map.remove(&file_id);
                }
                if let Some(lease_key) = entry.handle.lease_key() {
                    self.lease_key_map.remove(&lease_key);
                }
                if let Err(err) = entry.handle.close().await {
                    tracing::warn!(
                        handle_ref = handle_ref,
                        error = %err,
                        "Failed to close handle during cleanup"
                    );
                }
            }
        }
    }

    pub async fn execute(&mut self, op: &Operation) -> Result<()> {
        match op {
            Operation::Open {
                path,
                mode,
                handle_ref,
                extensions,
                ..
            } => {
                let handle = if let Some(details) = extensions {
                    self.inner.open_extended(path, details).await?
                } else {
                    self.inner.open_simple(path, *mode).await?
                };
                let oplock_state = if handle.granted_oplock().is_some() {
                    OplockState::Broken
                } else {
                    OplockState::None
                };
                self.handles.insert(
                    handle_ref.clone(),
                    HandleEntry {
                        handle,
                        oplock_state,
                        path: path.clone(),
                    },
                );
                if let Some(entry) = self.handles.get(handle_ref) {
                    if let Some(file_id) = entry.handle.file_id() {
                        self.file_id_map.insert(file_id, handle_ref.clone());
                    }
                    if let Some(lease_key) = entry.handle.lease_key() {
                        self.lease_key_map.insert(lease_key, handle_ref.clone());
                    }
                }
                Ok(())
            }
            Operation::Read {
                handle_ref,
                offset,
                length,
                ..
            } => {
                self.wait_if_blocked_by_handle(handle_ref).await?;
                let entry = self
                    .handles
                    .get(handle_ref)
                    .ok_or_else(|| anyhow!("Unknown handle_ref: {}", handle_ref))?;
                entry.handle.read(*offset, *length).await?;
                Ok(())
            }
            Operation::Write {
                handle_ref,
                offset,
                blob_path,
                length,
                ..
            } => {
                self.wait_if_blocked_by_handle(handle_ref).await?;
                let entry = self
                    .handles
                    .get(handle_ref)
                    .ok_or_else(|| anyhow!("Unknown handle_ref: {}", handle_ref))?;
                let data = tokio::fs::read(blob_path).await?;
                let expected_len = (*length) as usize;
                if expected_len > data.len() {
                    return Err(anyhow!(
                        "Write length {} exceeds blob size {}",
                        expected_len,
                        data.len()
                    ));
                }
                let slice = &data[..expected_len];
                entry.handle.write(*offset, slice).await?;
                Ok(())
            }
            Operation::Close { handle_ref, .. } => {
                if let Some(entry) = self.handles.remove(handle_ref) {
                    if let Some(file_id) = entry.handle.file_id() {
                        self.file_id_map.remove(&file_id);
                    }
                    if let Some(lease_key) = entry.handle.lease_key() {
                        self.lease_key_map.remove(&lease_key);
                    }
                    entry.handle.close().await?;
                }
                Ok(())
            }
            _ => self.inner.execute_misc(op).await,
        }
    }

    async fn wait_if_blocked_by_handle(&mut self, handle_ref: &str) -> Result<()> {
        let entry = self
            .handles
            .get_mut(handle_ref)
            .ok_or_else(|| anyhow!("Unknown handle_ref: {}", handle_ref))?;
        match &mut entry.oplock_state {
            OplockState::BreakPending { waiters } => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                waiters.push(tx);
                tokio::time::timeout(self.oplock_wait_timeout, rx)
                    .await
                    .map_err(|_| anyhow!("Oplock wait timed out"))?
                    .map_err(|_| anyhow!("Oplock wait canceled"))?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn handle_oplock_break(&mut self, break_msg: OplockBreak) {
        if break_msg.handle_ref.is_empty()
            && break_msg.file_id.is_none()
            && break_msg.lease_key.is_none()
        {
            return;
        }
        let handle_ref = if self.handles.contains_key(&break_msg.handle_ref) {
            Some(break_msg.handle_ref.clone())
        } else if let Some(file_id) = &break_msg.file_id {
            self.file_id_map.get(file_id).cloned()
        } else if let Some(lease_key) = &break_msg.lease_key {
            self.lease_key_map.get(lease_key).cloned()
        } else {
            None
        };

        if let Some(handle_ref) = handle_ref {
            if let Some(entry) = self.handles.get_mut(&handle_ref) {
                let mut waiters = Vec::new();
                if let OplockState::BreakPending { waiters: existing } = &mut entry.oplock_state {
                    waiters.append(existing);
                }
                entry.oplock_state = OplockState::BreakPending { waiters };

                if let Some(lease_state) = break_msg.lease_state {
                    if let Some(lease_key) = &break_msg.lease_key {
                        if let Err(err) = entry
                            .handle
                            .acknowledge_lease_break(lease_key, lease_state)
                            .await
                        {
                            tracing::error!(error = %err, "Failed to ACK lease break");
                        }
                    }
                } else if let Err(err) = entry
                    .handle
                    .acknowledge_oplock_break(break_msg.new_level)
                    .await
                {
                    tracing::error!(error = %err, "Failed to ACK oplock break");
                }
                if let OplockState::BreakPending { waiters } = &mut entry.oplock_state {
                    for tx in waiters.drain(..) {
                        tx.send(()).ok();
                    }
                    entry.oplock_state = OplockState::Broken;
                }
            }
        } else {
            tracing::warn!(
                handle_ref = break_msg.handle_ref,
                file_id = ?break_msg.file_id,
                "Received oplock break for unknown handle"
            );
        }
    }
}

pub fn ensure_backend_allowed(
    backend: &dyn SMBBackend,
    mode: BackendMode,
) -> Result<()> {
    let caps = backend.capabilities();
    if mode == BackendMode::Production && caps.is_dev_only {
        return Err(anyhow!(
            "Backend {} is dev-only and cannot be used in production",
            caps.name
        ));
    }
    Ok(())
}

pub struct NullBackend;

#[async_trait]
impl SMBBackend for NullBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "null".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        Ok(ConnectionState::new(Box::new(NullConnection)))
    }
}

struct NullConnection;

#[async_trait]
impl SMBConnectionInner for NullConnection {
    async fn open_simple(&self, _path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NullHandle))
    }

    async fn open_extended(
        &self,
        _path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        Ok(Box::new(NullHandle))
    }

    async fn execute_misc(&self, _op: &Operation) -> Result<()> {
        Ok(())
    }
}

struct NullHandle;

#[async_trait]
impl SMBFileHandle for NullHandle {
    async fn read(&self, _offset: u64, _length: u64) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn write(&self, _offset: u64, data: &[u8]) -> Result<u64> {
        Ok(data.len() as u64)
    }

    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicUsizeOrdering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestHandle {
        file_id: String,
        lease_key: Option<String>,
        ack_called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl SMBFileHandle for TestHandle {
        async fn read(&self, _offset: u64, _length: u64) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn write(&self, _offset: u64, data: &[u8]) -> Result<u64> {
            Ok(data.len() as u64)
        }

        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }

        fn file_id(&self) -> Option<String> {
            Some(self.file_id.clone())
        }

        fn lease_key(&self) -> Option<String> {
            self.lease_key.clone()
        }

        async fn acknowledge_oplock_break(&self, _new_level: OplockLevel) -> Result<()> {
            self.ack_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct TestConn;

    #[async_trait]
    impl SMBConnectionInner for TestConn {
        async fn open_simple(&self, _path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
            Err(anyhow!("not used"))
        }

        async fn open_extended(
            &self,
            _path: &str,
            _extensions: &serde_json::Value,
        ) -> Result<Box<dyn SMBFileHandle>> {
            Err(anyhow!("not used"))
        }

        async fn execute_misc(&self, _op: &Operation) -> Result<()> {
            Ok(())
        }
    }

    struct TestWriteHandle {
        last_len: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SMBFileHandle for TestWriteHandle {
        async fn read(&self, _offset: u64, _length: u64) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn write(&self, _offset: u64, data: &[u8]) -> Result<u64> {
            self.last_len
                .store(data.len(), AtomicUsizeOrdering::SeqCst);
            Ok(data.len() as u64)
        }

        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_handle_oplock_break_by_file_id() {
        let ack_called = Arc::new(AtomicBool::new(false));
        let file_id = "file-id-1".to_string();
        let handle_ref = "handle-1".to_string();

        let mut state = ConnectionState::new(Box::new(TestConn));
        state.handles.insert(
            handle_ref.clone(),
            HandleEntry {
                handle: Box::new(TestHandle {
                    file_id: file_id.clone(),
                    lease_key: None,
                    ack_called: ack_called.clone(),
                }),
                oplock_state: OplockState::None,
                path: "/tmp/file".to_string(),
            },
        );
        state.file_id_map.insert(file_id.clone(), handle_ref.clone());

        state
            .handle_oplock_break(OplockBreak {
                handle_ref: String::new(),
                file_id: Some(file_id),
                lease_key: None,
                new_level: OplockLevel::Read,
                lease_state: None,
            })
            .await;

        let entry = state.handles.get(&handle_ref).unwrap();
        match entry.oplock_state {
            OplockState::Broken => {}
            _ => panic!("Expected Broken oplock state"),
        }
        assert!(ack_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_oplock_break_preserves_waiters() {
        let ack_called = Arc::new(AtomicBool::new(false));
        let file_id = "file-id-2".to_string();
        let handle_ref = "handle-2".to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();

        let mut state = ConnectionState::new(Box::new(TestConn));
        state.handles.insert(
            handle_ref.clone(),
            HandleEntry {
                handle: Box::new(TestHandle {
                    file_id: file_id.clone(),
                    lease_key: None,
                    ack_called,
                }),
                oplock_state: OplockState::BreakPending { waiters: vec![tx] },
                path: "/tmp/file".to_string(),
            },
        );
        state.file_id_map.insert(file_id.clone(), handle_ref.clone());

        state
            .handle_oplock_break(OplockBreak {
                handle_ref,
                file_id: Some(file_id),
                lease_key: None,
                new_level: OplockLevel::Read,
                lease_state: None,
            })
            .await;

        tokio::time::timeout(tokio::time::Duration::from_secs(1), rx)
            .await
            .expect("waiter should be released")
            .expect("waiter should receive");
    }

    #[tokio::test]
    async fn test_write_respects_length() {
        let last_len = Arc::new(AtomicUsize::new(0));
        let handle_ref = "handle-3".to_string();
        let mut state = ConnectionState::new(Box::new(TestConn));
        state.handles.insert(
            handle_ref.clone(),
            HandleEntry {
                handle: Box::new(TestWriteHandle {
                    last_len: last_len.clone(),
                }),
                oplock_state: OplockState::None,
                path: "/tmp/file".to_string(),
            },
        );

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let blob_path = std::env::temp_dir().join(format!("smbench_blob_{unique}.bin"));
        std::fs::write(&blob_path, b"hello world").expect("write blob");

        let op = Operation::Write {
            op_id: "op_1".to_string(),
            client_id: "client_1".to_string(),
            timestamp_us: 0,
            handle_ref: handle_ref.clone(),
            offset: 0,
            length: 5,
            blob_path: blob_path.to_string_lossy().to_string(),
        };

        state.execute(&op).await.expect("write ok");
        assert_eq!(last_len.load(AtomicUsizeOrdering::SeqCst), 5);

        let _ = std::fs::remove_file(&blob_path);
    }

    #[tokio::test]
    async fn test_break_pending_blocks_io() {
        let handle_ref = "handle-5".to_string();
        let mut state = ConnectionState::new(Box::new(TestConn))
            .with_oplock_wait_timeout(tokio::time::Duration::from_millis(50));
        state.handles.insert(
            handle_ref.clone(),
            HandleEntry {
                handle: Box::new(TestHandle {
                    file_id: "file-id-5".to_string(),
                    lease_key: None,
                    ack_called: Arc::new(AtomicBool::new(false)),
                }),
                oplock_state: OplockState::BreakPending { waiters: Vec::new() },
                path: "/tmp/file".to_string(),
            },
        );

        let op = Operation::Read {
            op_id: "op_1".to_string(),
            client_id: "client_1".to_string(),
            timestamp_us: 0,
            handle_ref,
            offset: 0,
            length: 4,
        };

        let err = state.execute(&op).await.unwrap_err();
        assert!(err.to_string().contains("Oplock wait timed out"));
    }

    #[tokio::test]
    async fn test_lease_break_by_lease_key() {
        let ack_called = Arc::new(AtomicBool::new(false));
        let lease_key = "lease-key-1".to_string();
        let handle_ref = "handle-4".to_string();

        struct LeaseHandle {
            lease_key: String,
            ack_called: Arc<AtomicBool>,
        }

        #[async_trait]
        impl SMBFileHandle for LeaseHandle {
            async fn read(&self, _offset: u64, _length: u64) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }

            async fn write(&self, _offset: u64, data: &[u8]) -> Result<u64> {
                Ok(data.len() as u64)
            }

            async fn close(self: Box<Self>) -> Result<()> {
                Ok(())
            }

            fn lease_key(&self) -> Option<String> {
                Some(self.lease_key.clone())
            }

            async fn acknowledge_lease_break(
                &self,
                _lease_key: &str,
                _lease_state: LeaseState,
            ) -> Result<()> {
                self.ack_called.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let mut state = ConnectionState::new(Box::new(TestConn));
        state.handles.insert(
            handle_ref.clone(),
            HandleEntry {
                handle: Box::new(LeaseHandle {
                    lease_key: lease_key.clone(),
                    ack_called: ack_called.clone(),
                }),
                oplock_state: OplockState::None,
                path: "/tmp/file".to_string(),
            },
        );
        state.lease_key_map.insert(lease_key.clone(), handle_ref);

        state
            .handle_oplock_break(OplockBreak {
                handle_ref: String::new(),
                file_id: None,
                lease_key: Some(lease_key),
                new_level: OplockLevel::None,
                lease_state: Some(LeaseState {
                    read: true,
                    write: false,
                    handle: true,
                }),
            })
            .await;

        assert!(ack_called.load(Ordering::SeqCst));
    }
}

pub struct OSMountBackend {
    #[allow(dead_code)]
    mount_point: Arc<String>,
}

impl OSMountBackend {
    pub fn new(mount_point: impl Into<String>) -> Self {
        Self {
            mount_point: Arc::new(mount_point.into()),
        }
    }
}

#[async_trait]
impl SMBBackend for OSMountBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "osmount (DEV ONLY)".to_string(),
            supports_oplocks: false,
            is_dev_only: true,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        #[cfg(target_os = "linux")]
        {
            Ok(ConnectionState::new(Box::new(OSMountConnection {
                mount_point: self.mount_point.clone(),
                open_files: HashMap::new(),
            })))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("OS mount backend requires Linux"))
        }
    }
}

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
struct OSMountConnection {
    mount_point: Arc<String>,
    open_files: HashMap<String, tokio::fs::File>,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl SMBConnectionInner for OSMountConnection {
    async fn open_simple(&self, path: &str, _mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        let full_path = Path::new(&*self.mount_point).join(path);
        let file = tokio::fs::File::open(&full_path).await?;
        Ok(Box::new(OSMountHandle { file }))
    }

    async fn open_extended(
        &self,
        path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        self.open_simple(path, OpenMode::ReadWrite).await
    }

    async fn execute_misc(&self, _op: &Operation) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct OSMountHandle {
    file: tokio::fs::File,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl SMBFileHandle for OSMountHandle {
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = self.file.try_clone().await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; length as usize];
        let bytes = file.read(&mut buf).await?;
        buf.truncate(bytes);
        Ok(buf)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        let mut file = self.file.try_clone().await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write_all(data).await?;
        Ok(data.len() as u64)
    }

    async fn close(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}
