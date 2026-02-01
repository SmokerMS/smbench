use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::ir::{OpenMode, Operation};

#[cfg(feature = "smb-rs-backend")]
pub mod smbrs;

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
    fn granted_oplock(&self) -> Option<OplockLevel> {
        None
    }
    async fn acknowledge_oplock_break(&self, _new_level: OplockLevel) -> Result<()> {
        Err(anyhow!("Oplocks not supported"))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OplockLevel {
    None,
    Read,
    Batch,
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
    oplock_break_rx: Option<mpsc::Receiver<OplockBreak>>,
    oplock_wait_timeout: tokio::time::Duration,
}

#[derive(Debug, Clone)]
pub struct OplockBreak {
    pub handle_ref: String,
    pub file_id: Option<String>,
    pub new_level: OplockLevel,
}

impl ConnectionState {
    pub fn new(inner: Box<dyn SMBConnectionInner>) -> Self {
        Self {
            inner,
            handles: HashMap::new(),
            file_id_map: HashMap::new(),
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
                ..
            } => {
                self.wait_if_blocked_by_handle(handle_ref).await?;
                let entry = self
                    .handles
                    .get(handle_ref)
                    .ok_or_else(|| anyhow!("Unknown handle_ref: {}", handle_ref))?;
                let data = tokio::fs::read(blob_path).await?;
                entry.handle.write(*offset, &data).await?;
                Ok(())
            }
            Operation::Close { handle_ref, .. } => {
                if let Some(entry) = self.handles.remove(handle_ref) {
                    if let Some(file_id) = entry.handle.file_id() {
                        self.file_id_map.remove(&file_id);
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
        if break_msg.handle_ref.is_empty() && break_msg.file_id.is_none() {
            return;
        }
        let handle_ref = if self.handles.contains_key(&break_msg.handle_ref) {
            Some(break_msg.handle_ref.clone())
        } else if let Some(file_id) = &break_msg.file_id {
            self.file_id_map.get(file_id).cloned()
        } else {
            None
        };

        if let Some(handle_ref) = handle_ref {
            if let Some(entry) = self.handles.get_mut(&handle_ref) {
                entry.oplock_state = OplockState::BreakPending { waiters: Vec::new() };
                if let Err(err) = entry
                    .handle
                    .acknowledge_oplock_break(break_msg.new_level)
                    .await
                {
                    tracing::error!(error = %err, "Failed to ACK oplock break");
                    return;
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
