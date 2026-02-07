//! Impacket subprocess backend.
//!
//! Spawns a Python worker process that communicates via JSON lines on stdin/stdout.
//! The worker uses Impacket's `SMBConnection` for actual SMB operations.
//!
//! Gated behind the `impacket-backend` feature flag.

use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::backend::{
    BackendCapabilities, ConnectionState, SMBConnectionInner, SMBFileHandle, SMBBackend,
};
use crate::ir::{OpenMode, Operation};
use crate::protocol::impacket::{
    serialize_request_line, WorkerRequest, WorkerResponse,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    format!("req_{}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Configuration for the Impacket backend.
#[derive(Clone, Debug)]
pub struct ImpacketConfig {
    /// Path to the Python worker script.
    pub worker_script: String,
    /// Python interpreter (default: "python3").
    pub python: String,
    /// SMB server hostname/IP.
    pub server: String,
    /// SMB share name.
    pub share: String,
    /// Username for authentication.
    pub user: String,
    /// Password for authentication.
    pub pass: String,
}

impl ImpacketConfig {
    pub fn from_env() -> Result<Self> {
        let server = std::env::var("SMBENCH_SMB_SERVER")
            .map_err(|_| anyhow!("SMBENCH_SMB_SERVER not set"))?;
        let share = std::env::var("SMBENCH_SMB_SHARE")
            .map_err(|_| anyhow!("SMBENCH_SMB_SHARE not set"))?;
        let user = std::env::var("SMBENCH_SMB_USER")
            .map_err(|_| anyhow!("SMBENCH_SMB_USER not set"))?;
        let pass = std::env::var("SMBENCH_SMB_PASS")
            .map_err(|_| anyhow!("SMBENCH_SMB_PASS not set"))?;
        let worker_script = std::env::var("SMBENCH_IMPACKET_WORKER")
            .unwrap_or_else(|_| "control/worker.py".to_string());
        let python = std::env::var("SMBENCH_PYTHON")
            .unwrap_or_else(|_| "python3".to_string());
        Ok(Self {
            worker_script,
            python,
            server,
            share,
            user,
            pass,
        })
    }
}

/// Backend that spawns Python/Impacket worker subprocesses.
pub struct ImpacketBackend {
    config: ImpacketConfig,
}

impl ImpacketBackend {
    pub fn new(config: ImpacketConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl SMBBackend for ImpacketBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "impacket".to_string(),
            supports_oplocks: false,
            is_dev_only: false,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        let mut child = Command::new(&self.config.python)
            .arg(&self.config.worker_script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn worker: {}", e))?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("No stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("No stdout"))?;

        let worker = Arc::new(Mutex::new(WorkerProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            connection_id: None,
        }));

        // Send Connect request
        let request_id = next_request_id();
        let req = WorkerRequest::Connect {
            request_id: request_id.clone(),
            server: self.config.server.clone(),
            share: self.config.share.clone(),
            username: self.config.user.clone(),
            password: self.config.pass.clone(),
        };

        let mut w = worker.lock().await;
        w.send_request(&req).await?;
        let resp = w.read_response().await?;

        match resp {
            WorkerResponse::Connected {
                connection_id,
                success,
                error,
                ..
            } => {
                if !success {
                    return Err(anyhow!(
                        "Connect failed: {}",
                        error.unwrap_or_else(|| "unknown".to_string())
                    ));
                }
                w.connection_id = Some(connection_id);
            }
            WorkerResponse::Error { error, .. } => {
                return Err(anyhow!("Connect error: {}", error));
            }
            _ => {
                return Err(anyhow!("Unexpected response to Connect"));
            }
        }
        drop(w);

        Ok(ConnectionState::new(Box::new(ImpacketConnection {
            worker,
        })))
    }
}

struct WorkerProcess {
    #[allow(dead_code)]
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    connection_id: Option<String>,
}

impl WorkerProcess {
    async fn send_request(&mut self, req: &WorkerRequest) -> Result<()> {
        let line = serialize_request_line(req)?;
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<WorkerResponse> {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("Worker process closed stdout"));
        }
        let resp: WorkerResponse = serde_json::from_str(line.trim())?;
        Ok(resp)
    }

    async fn request_response(&mut self, req: &WorkerRequest) -> Result<WorkerResponse> {
        self.send_request(req).await?;
        self.read_response().await
    }
}

struct ImpacketConnection {
    worker: Arc<Mutex<WorkerProcess>>,
}

#[async_trait]
impl SMBConnectionInner for ImpacketConnection {
    async fn open_simple(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        let mut w = self.worker.lock().await;
        let conn_id = w
            .connection_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let req = WorkerRequest::Open {
            request_id: next_request_id(),
            connection_id: conn_id,
            path: path.to_string(),
            mode: match mode {
                OpenMode::Read => "Read".to_string(),
                OpenMode::Write => "Write".to_string(),
                OpenMode::ReadWrite => "ReadWrite".to_string(),
            },
        };
        let resp = w.request_response(&req).await?;
        match resp {
            WorkerResponse::Opened {
                handle_id,
                success,
                error,
                ..
            } => {
                if !success {
                    return Err(anyhow!(
                        "Open failed: {}",
                        error.unwrap_or_else(|| "unknown".to_string())
                    ));
                }
                Ok(Box::new(ImpacketFileHandle {
                    handle_id,
                    worker: self.worker.clone(),
                }))
            }
            WorkerResponse::Error { error, .. } => Err(anyhow!("Open error: {}", error)),
            _ => Err(anyhow!("Unexpected response to Open")),
        }
    }

    async fn open_extended(
        &self,
        path: &str,
        _extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        // Impacket doesn't support the full extension set; fall back to simple open
        self.open_simple(path, OpenMode::ReadWrite).await
    }

    async fn execute_misc(&self, op: &Operation) -> Result<()> {
        let mut w = self.worker.lock().await;
        let conn_id = w
            .connection_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        match op {
            Operation::Rename {
                source_path,
                dest_path,
                ..
            } => {
                let req = WorkerRequest::Rename {
                    request_id: next_request_id(),
                    connection_id: conn_id,
                    source_path: source_path.clone(),
                    dest_path: dest_path.clone(),
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "Rename")
            }
            Operation::Delete { path, .. } => {
                let req = WorkerRequest::Delete {
                    request_id: next_request_id(),
                    connection_id: conn_id,
                    path: path.clone(),
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "Delete")
            }
            Operation::Mkdir { path, .. } => {
                let req = WorkerRequest::Mkdir {
                    request_id: next_request_id(),
                    connection_id: conn_id,
                    path: path.clone(),
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "Mkdir")
            }
            Operation::Rmdir { path, .. } => {
                let req = WorkerRequest::Rmdir {
                    request_id: next_request_id(),
                    connection_id: conn_id,
                    path: path.clone(),
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "Rmdir")
            }
            Operation::QueryDirectory { handle_ref, pattern, info_class, .. } => {
                let req = WorkerRequest::QueryDirectory {
                    request_id: next_request_id(),
                    handle_id: handle_ref.clone(),
                    pattern: pattern.clone(),
                    info_class: *info_class,
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "QueryDirectory")
            }
            Operation::QueryInfo { handle_ref, info_type, info_class, .. } => {
                let req = WorkerRequest::QueryInfo {
                    request_id: next_request_id(),
                    handle_id: handle_ref.clone(),
                    info_type: *info_type,
                    info_class: *info_class,
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "QueryInfo")
            }
            Operation::Ioctl { handle_ref, ctl_code, .. } => {
                let req = WorkerRequest::Ioctl {
                    request_id: next_request_id(),
                    handle_id: handle_ref.clone(),
                    ctl_code: *ctl_code,
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "Ioctl")
            }
            Operation::ChangeNotify { handle_ref, filter, recursive, .. } => {
                let req = WorkerRequest::ChangeNotify {
                    request_id: next_request_id(),
                    handle_id: handle_ref.clone(),
                    filter: *filter,
                    recursive: *recursive,
                };
                let resp = w.request_response(&req).await?;
                check_success_response(&resp, "ChangeNotify")
            }
            _ => Ok(()),
        }
    }
}

struct ImpacketFileHandle {
    handle_id: String,
    worker: Arc<Mutex<WorkerProcess>>,
}

#[async_trait]
impl SMBFileHandle for ImpacketFileHandle {
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let mut w = self.worker.lock().await;
        let req = WorkerRequest::Read {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
            offset,
            length,
        };
        let resp = w.request_response(&req).await?;
        match resp {
            WorkerResponse::ReadResult {
                data_base64,
                success,
                error,
                ..
            } => {
                if !success {
                    return Err(anyhow!(
                        "Read failed: {}",
                        error.unwrap_or_else(|| "unknown".to_string())
                    ));
                }
                use base64::Engine;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(&data_base64)
                    .map_err(|e| anyhow!("Base64 decode error: {}", e))?;
                Ok(data)
            }
            WorkerResponse::Error { error, .. } => Err(anyhow!("Read error: {}", error)),
            _ => Err(anyhow!("Unexpected response to Read")),
        }
    }

    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64> {
        let mut w = self.worker.lock().await;
        use base64::Engine;
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(data);
        let req = WorkerRequest::Write {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
            offset,
            data_base64,
        };
        let resp = w.request_response(&req).await?;
        match resp {
            WorkerResponse::WriteResult {
                bytes_written,
                success,
                error,
                ..
            } => {
                if !success {
                    return Err(anyhow!(
                        "Write failed: {}",
                        error.unwrap_or_else(|| "unknown".to_string())
                    ));
                }
                Ok(bytes_written)
            }
            WorkerResponse::Error { error, .. } => Err(anyhow!("Write error: {}", error)),
            _ => Err(anyhow!("Unexpected response to Write")),
        }
    }

    async fn close(self: Box<Self>) -> Result<()> {
        let mut w = self.worker.lock().await;
        let req = WorkerRequest::Close {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
        };
        let resp = w.request_response(&req).await?;
        check_success_response(&resp, "Close")
    }

    async fn flush(&self) -> Result<()> {
        let mut w = self.worker.lock().await;
        let req = WorkerRequest::Flush {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
        };
        let resp = w.request_response(&req).await?;
        check_success_response(&resp, "Flush")
    }

    async fn lock(&self, offset: u64, length: u64, exclusive: bool) -> Result<()> {
        let mut w = self.worker.lock().await;
        let req = WorkerRequest::Lock {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
            offset,
            length,
            exclusive,
        };
        let resp = w.request_response(&req).await?;
        check_success_response(&resp, "Lock")
    }

    async fn unlock(&self, offset: u64, length: u64) -> Result<()> {
        let mut w = self.worker.lock().await;
        let req = WorkerRequest::Unlock {
            request_id: next_request_id(),
            handle_id: self.handle_id.clone(),
            offset,
            length,
        };
        let resp = w.request_response(&req).await?;
        check_success_response(&resp, "Unlock")
    }
}

fn check_success_response(resp: &WorkerResponse, operation: &str) -> Result<()> {
    match resp {
        WorkerResponse::Closed { success, error, .. }
        | WorkerResponse::Renamed { success, error, .. }
        | WorkerResponse::Deleted { success, error, .. }
        | WorkerResponse::MkdirResult { success, error, .. }
        | WorkerResponse::RmdirResult { success, error, .. }
        | WorkerResponse::QueryDirectoryResult { success, error, .. }
        | WorkerResponse::QueryInfoResult { success, error, .. }
        | WorkerResponse::FlushResult { success, error, .. }
        | WorkerResponse::LockResult { success, error, .. }
        | WorkerResponse::UnlockResult { success, error, .. }
        | WorkerResponse::IoctlResult { success, error, .. }
        | WorkerResponse::ChangeNotifyResult { success, error, .. } => {
            if !*success {
                return Err(anyhow!(
                    "{} failed: {}",
                    operation,
                    error.as_deref().unwrap_or("unknown")
                ));
            }
            Ok(())
        }
        WorkerResponse::Error { error, .. } => Err(anyhow!("{} error: {}", operation, error)),
        _ => Err(anyhow!("Unexpected response to {}", operation)),
    }
}
