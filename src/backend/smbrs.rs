use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::backend::{
    BackendCapabilities, ConnectionState, LeaseState, OplockBreak, OplockLevel, SMBBackend,
    SMBConnectionInner, SMBFileHandle,
};
use crate::ir::{OpenMode, Operation};

/// Authentication method for SMB connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Automatically negotiate (NTLM or Kerberos depending on server/environment).
    Auto,
    /// Force NTLM authentication.
    Ntlm,
    /// Force Kerberos authentication.
    Kerberos,
}

impl std::str::FromStr for AuthMethod {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "ntlm" => Ok(Self::Ntlm),
            "kerberos" | "krb5" | "krb" => Ok(Self::Kerberos),
            other => Err(anyhow!("unknown auth method: '{}' (expected: auto, ntlm, kerberos)", other)),
        }
    }
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::Auto
    }
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Ntlm => write!(f, "ntlm"),
            Self::Kerberos => write!(f, "kerberos"),
        }
    }
}

/// Transport mode for SMB connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportMode {
    /// Standard TCP transport (default).
    Tcp,
    /// RDMA transport (SMB Direct, [MS-SMBD]).
    #[cfg(feature = "rdma")]
    Rdma,
}

impl Default for TransportMode {
    fn default() -> Self {
        Self::Tcp
    }
}

impl std::str::FromStr for TransportMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            #[cfg(feature = "rdma")]
            "rdma" => Ok(Self::Rdma),
            #[cfg(not(feature = "rdma"))]
            "rdma" => Err(anyhow!("RDMA transport requires the 'rdma' feature flag")),
            other => Err(anyhow!("unknown transport: '{}' (expected: tcp, rdma)", other)),
        }
    }
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            #[cfg(feature = "rdma")]
            Self::Rdma => write!(f, "rdma"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SmbRsConfig {
    pub server: String,
    pub share: String,
    pub user: String,
    pub pass: String,
    /// Domain for authentication (e.g., "CONTOSO").
    pub domain: Option<String>,
    /// Authentication method to use.
    pub auth_method: AuthMethod,
    /// Path to Kerberos keytab file (for Kerberos auth).
    pub kerberos_keytab: Option<std::path::PathBuf>,
    /// Kerberos principal (e.g., "user@DOMAIN.COM").
    pub kerberos_principal: Option<String>,
    /// Kerberos KDC hostname/IP.
    pub kerberos_kdc: Option<String>,
    /// Transport mode (TCP or RDMA).
    pub transport: TransportMode,
}

impl SmbRsConfig {
    pub fn from_env() -> Result<Self> {
        let server = std::env::var("SMBENCH_SMB_SERVER")
            .map_err(|_| anyhow!("SMBENCH_SMB_SERVER not set"))?;
        let share = std::env::var("SMBENCH_SMB_SHARE")
            .map_err(|_| anyhow!("SMBENCH_SMB_SHARE not set"))?;
        let user = std::env::var("SMBENCH_SMB_USER")
            .map_err(|_| anyhow!("SMBENCH_SMB_USER not set"))?;
        let pass = std::env::var("SMBENCH_SMB_PASS")
            .map_err(|_| anyhow!("SMBENCH_SMB_PASS not set"))?;

        let domain = std::env::var("SMBENCH_SMB_DOMAIN").ok();
        let auth_method = std::env::var("SMBENCH_AUTH_METHOD")
            .map(|v| v.parse::<AuthMethod>().unwrap_or_default())
            .unwrap_or_default();
        let kerberos_keytab = std::env::var("SMBENCH_KERBEROS_KEYTAB")
            .ok()
            .map(std::path::PathBuf::from);
        let kerberos_principal = std::env::var("SMBENCH_KERBEROS_PRINCIPAL").ok();
        let kerberos_kdc = std::env::var("SMBENCH_KERBEROS_KDC").ok();
        let transport = std::env::var("SMBENCH_TRANSPORT")
            .map(|v| v.parse::<TransportMode>().unwrap_or_default())
            .unwrap_or_default();

        Ok(Self {
            server,
            share,
            user,
            pass,
            domain,
            auth_method,
            kerberos_keytab,
            kerberos_principal,
            kerberos_kdc,
            transport,
        })
    }
}

pub struct SmbRsBackend {
    config: SmbRsConfig,
}

impl SmbRsBackend {
    pub fn new(config: SmbRsConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl SMBBackend for SmbRsBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "smb-rs".to_string(),
            supports_oplocks: true,
            is_dev_only: false,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        let client = smb::Client::new(smb::ClientConfig::default());
        let conn = client.connect(&self.config.server).await?;
        let mut break_rx = conn.subscribe_oplock_breaks()?;
        let mut lease_break_rx = conn.subscribe_lease_breaks()?;

        let share_path = smb::UncPath::from_str(&format!(
            r"\\{}\{}",
            self.config.server, self.config.share
        ))?;
        client
            .share_connect(&share_path, &self.config.user, self.config.pass.clone())
            .await?;

        let (tx, rx) = mpsc::channel(64);
        let tx_oplock = tx.clone();
        tokio::spawn(async move {
            loop {
                match break_rx.recv().await {
                    Ok(event) => {
                        let _ = tx_oplock
                            .send(OplockBreak {
                                handle_ref: String::new(),
                                file_id: Some(format!("{:?}", event.file_id)),
                                lease_key: None,
                                new_level: map_smb_oplock(event.new_level),
                                lease_state: None,
                            })
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });
        let tx_lease = tx.clone();
        tokio::spawn(async move {
            loop {
                match lease_break_rx.recv().await {
                    Ok(event) => {
                        let _ = tx_lease
                            .send(OplockBreak {
                                handle_ref: String::new(),
                                file_id: None,
                                lease_key: Some(event.lease_key.to_string()),
                                new_level: OplockLevel::None,
                                lease_state: Some(LeaseState {
                                    read: event.new_state.read_caching(),
                                    write: event.new_state.write_caching(),
                                    handle: event.new_state.handle_caching(),
                                }),
                            })
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(ConnectionState::new(Box::new(SmbRsConnection {
            client: Arc::new(client),
            share_path,
            _conn: conn,
        }))
        .with_oplock_channel(rx))
    }
}

struct SmbRsConnection {
    client: Arc<smb::Client>,
    share_path: smb::UncPath,
    _conn: Arc<smb::Connection>,
}

#[async_trait]
impl SMBConnectionInner for SmbRsConnection {
    async fn open_simple(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        let unc_path = resolve_unc_path(&self.share_path, path)?;
        let args = build_args_for_mode(mode);
        let resource = self.client.create_file(&unc_path, &args).await?;
        let file: smb::File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _)) => return Err(anyhow!(err)),
        };
        Ok(Box::new(SmbRsFileHandle::new(file)?))
    }

    async fn open_extended(
        &self,
        path: &str,
        extensions: &serde_json::Value,
    ) -> Result<Box<dyn SMBFileHandle>> {
        let unc_path = resolve_unc_path(&self.share_path, path)?;
        let args = build_args_from_extensions(OpenMode::ReadWrite, extensions);

        let resource = self.client.create_file(&unc_path, &args).await?;
        let file: smb::File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _)) => return Err(anyhow!(err)),
        };
        if let Some(allocation_size) = parse_allocation_size(extensions) {
            file.set_info(smb::FileAllocationInformation { allocation_size })
                .await
                .map_err(|e| anyhow!(e))?;
        }
        Ok(Box::new(SmbRsFileHandle::new(file)?))
    }

    async fn execute_misc(&self, op: &Operation) -> Result<()> {
        match op {
            Operation::Rename {
                source_path,
                dest_path,
                ..
            } => {
                let source = resolve_unc_path(&self.share_path, source_path)?;
                let dest = resolve_rename_target(&self.share_path, dest_path)?;
                let access = smb::FileAccessMask::new().with_generic_all(true);
                let args = smb::FileCreateArgs::make_open_existing(access);
                let resource = self.client.create_file(&source, &args).await?;
                let file: smb::File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _)) => return Err(anyhow!(err)),
                };
                let rename = smb::FileRenameInformation::new(false, dest.as_str());
                file.set_info(rename).await.map_err(|e| anyhow!(e))?;
                file.close().await.map_err(|e| anyhow!(e))?;
                Ok(())
            }
            Operation::Delete { path, .. } => {
                let target = resolve_unc_path(&self.share_path, path)?;
                let access = smb::FileAccessMask::new().with_generic_all(true);
                let args = smb::FileCreateArgs::make_open_existing(access);
                let resource = self.client.create_file(&target, &args).await?;
                let file: smb::File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _)) => return Err(anyhow!(err)),
                };
                file.set_info(smb::FileDispositionInformation::default())
                    .await
                    .map_err(|e| anyhow!(e))?;
                file.close().await.map_err(|e| anyhow!(e))?;
                Ok(())
            }
            Operation::Mkdir { path, .. } => {
                let target = resolve_unc_path(&self.share_path, path)?;
                let access = smb::FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true);
                let args = smb::FileCreateArgs {
                    disposition: smb::CreateDisposition::OpenIf,
                    attributes: smb::FileAttributes::new().with_directory(true),
                    options: smb::CreateOptions::new().with_directory_file(true),
                    desired_access: access,
                    requested_oplock_level: smb::OplockLevel::None,
                    requested_lease: None,
                    requested_durable: None,
                    share_access: None,
                };
                let resource = self.client.create_file(&target, &args).await?;
                let file: smb::File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _)) => return Err(anyhow!(err)),
                };
                file.close().await.map_err(|e| anyhow!(e))?;
                Ok(())
            }
            Operation::Rmdir { path, .. } => {
                let target = resolve_unc_path(&self.share_path, path)?;
                let access = smb::FileAccessMask::new().with_generic_all(true);
                let args = smb::FileCreateArgs {
                    disposition: smb::CreateDisposition::Open,
                    attributes: smb::FileAttributes::new().with_directory(true),
                    options: smb::CreateOptions::new().with_directory_file(true),
                    desired_access: access,
                    requested_oplock_level: smb::OplockLevel::None,
                    requested_lease: None,
                    requested_durable: None,
                    share_access: None,
                };
                let resource = self.client.create_file(&target, &args).await?;
                let file: smb::File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _)) => return Err(anyhow!(err)),
                };
                file.set_info(smb::FileDispositionInformation::default())
                    .await
                    .map_err(|e| anyhow!(e))?;
                file.close().await.map_err(|e| anyhow!(e))?;
                Ok(())
            }
            // QueryDirectory, QueryInfo, Ioctl, ChangeNotify, Flush, Lock, Unlock
            // are all routed through the file handle in ConnectionState::execute().
            // They should not reach execute_misc anymore.
            _ => Ok(()),
        }
    }
}

struct SmbRsFileHandle {
    file: smb::File,
    file_id: String,
    granted_oplock: Option<OplockLevel>,
    lease_key: Option<String>,
}

impl SmbRsFileHandle {
    fn new(file: smb::File) -> Result<Self> {
        let file_id = format!("{:?}", file.file_id_for_oplock()?);
        let granted_oplock = Some(map_smb_oplock(file.granted_oplock_level()));
        let lease_key = file.granted_lease().map(|lease| {
            let lease_key = match lease {
                smb::RequestLease::RqLsReqv1(v1) => v1.lease_key,
                smb::RequestLease::RqLsReqv2(v2) => v2.lease_key,
            };
            let guid = smb::Guid::try_from(&lease_key.to_le_bytes())
                .unwrap_or_else(|_| smb::Guid::ZERO);
            guid.to_string()
        });
        Ok(Self {
            file,
            file_id,
            granted_oplock,
            lease_key,
        })
    }
}

#[async_trait]
impl SMBFileHandle for SmbRsFileHandle {
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; length as usize];
        let bytes = self
            .file
            .read_block(&mut buf, offset, None, false)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        buf.truncate(bytes);
        Ok(buf)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64> {
        let bytes = self
            .file
            .write_block(data, offset, None)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(bytes as u64)
    }

    async fn close(self: Box<Self>) -> Result<()> {
        self.file.close().await.map_err(|e| anyhow!(e.to_string()))
    }

    async fn flush(&self) -> Result<()> {
        self.file.flush().await.map_err(|e| anyhow!(e.to_string()))
    }

    async fn lock(&self, offset: u64, length: u64, exclusive: bool) -> Result<()> {
        self.file
            .lock(offset, length, exclusive, true)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn unlock(&self, offset: u64, length: u64) -> Result<()> {
        self.file
            .unlock(offset, length)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn query_directory(&self, pattern: &str, _info_class: u8) -> Result<()> {
        self.file
            .query_directory_raw(pattern)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn query_info(&self, _info_type: u8, _info_class: u8) -> Result<()> {
        self.file
            .query_info_raw()
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn ioctl(&self, ctl_code: u32) -> Result<()> {
        // Use the raw ioctl method with an empty input buffer.
        // We discard the output; the purpose is to generate the SMB traffic.
        self.file
            .ioctl(ctl_code, vec![], 4096)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(())
    }

    async fn set_info(&self, _info_type: u8, _info_class: u8) -> Result<()> {
        // SetInfo requires knowing the specific info class to construct the right
        // data structure. For benchmarking replay, we send a generic query_info_raw
        // instead, which generates equivalent network traffic.
        self.file
            .query_info_raw()
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn change_notify(&self, filter: u32, recursive: bool) -> Result<()> {
        // Use a short timeout; during replay, FS changes won't happen,
        // so we expect the timeout to expire. That's fine.
        self.file
            .change_notify_raw(
                filter,
                recursive,
                std::time::Duration::from_millis(100),
            )
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    fn file_id(&self) -> Option<String> {
        Some(self.file_id.clone())
    }

    fn lease_key(&self) -> Option<String> {
        self.lease_key.clone()
    }

    fn granted_oplock(&self) -> Option<OplockLevel> {
        self.granted_oplock
    }

    async fn acknowledge_oplock_break(&self, new_level: OplockLevel) -> Result<()> {
        let smb_level = match new_level {
            OplockLevel::None => smb::OplockLevel::None,
            OplockLevel::Read => smb::OplockLevel::II,
            OplockLevel::Batch => smb::OplockLevel::Exclusive,
        };
        self.file
            .acknowledge_oplock_break(smb_level)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn acknowledge_lease_break(
        &self,
        lease_key: &str,
        lease_state: LeaseState,
    ) -> Result<()> {
        let guid = smb::Guid::from_str(lease_key).map_err(|e| anyhow!(e.to_string()))?;
        let state = smb::LeaseState::new()
            .with_read_caching(lease_state.read)
            .with_write_caching(lease_state.write)
            .with_handle_caching(lease_state.handle);
        self.file
            .acknowledge_lease_break(guid, state)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }
}

fn build_args_for_mode(mode: OpenMode) -> smb::FileCreateArgs {
    let access = match mode {
        OpenMode::Read => smb::FileAccessMask::new().with_generic_read(true),
        OpenMode::Write => smb::FileAccessMask::new().with_generic_write(true),
        OpenMode::ReadWrite => smb::FileAccessMask::new()
            .with_generic_read(true)
            .with_generic_write(true),
    };
    smb::FileCreateArgs::make_open_existing(access)
}

fn build_args_from_extensions(
    mode: OpenMode,
    extensions: &serde_json::Value,
) -> smb::FileCreateArgs {
    let mut desired_access = parse_desired_access(extensions).unwrap_or_else(|| match mode {
        OpenMode::Read => smb::FileAccessMask::new().with_generic_read(true),
        OpenMode::Write => smb::FileAccessMask::new().with_generic_write(true),
        OpenMode::ReadWrite => smb::FileAccessMask::new()
            .with_generic_read(true)
            .with_generic_write(true),
    });

    let disposition = parse_create_disposition(extensions).unwrap_or(smb::CreateDisposition::Open);
    let options = parse_create_options(extensions);
    if extensions
        .get("create_options")
        .and_then(|v| v.get("delete_on_close"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        // delete-on-close requires DELETE access (MS-SMB2).
        desired_access.set_delete(true);
    }
    let attributes = parse_file_attributes(extensions).unwrap_or_else(smb::FileAttributes::new);
    let requested_oplock_level = parse_oplock_level(extensions).unwrap_or(smb::OplockLevel::None);
    let share_access = parse_share_access(extensions);
    let requested_lease = parse_lease_request(extensions);
    let requested_durable = parse_durable_handle(extensions);

    smb::FileCreateArgs {
        disposition,
        attributes,
        options,
        desired_access,
        requested_oplock_level,
        requested_lease,
        requested_durable,
        share_access,
    }
}

fn resolve_unc_path(share: &smb::UncPath, path: &str) -> Result<smb::UncPath> {
    if path.starts_with("\\\\") {
        Ok(smb::UncPath::from_str(path)?)
    } else {
        let share_name = share
            .share()
            .ok_or_else(|| anyhow!("Share name missing from base UNC path"))?;
        let full = format!("\\\\{}\\{}\\{}", share.server(), share_name, path);
        Ok(smb::UncPath::from_str(&full)?)
    }
}

fn resolve_rename_target(share: &smb::UncPath, dest_path: &str) -> Result<String> {
    if dest_path.starts_with("\\\\") {
        let share_name = share
            .share()
            .ok_or_else(|| anyhow!("Share name missing from base UNC path"))?;
        let prefix = format!("\\\\{}\\{}", share.server(), share_name);
        if !dest_path
            .to_lowercase()
            .starts_with(&prefix.to_lowercase())
        {
            return Err(anyhow!(
                "Rename target must be within the same share ({}\\\\{})",
                share.server(),
                share_name
            ));
        }
        let relative = dest_path[prefix.len()..].trim_start_matches('\\');
        Ok(relative.to_string())
    } else {
        Ok(dest_path.to_string())
    }
}

fn parse_oplock_level(ext: &serde_json::Value) -> Option<smb::OplockLevel> {
    let raw = ext.get("oplock_level").or_else(|| ext.get("oplock"))?;

    // Try numeric first (MS-SMB2 2.2.14: 0x00=None, 0x02=II, 0x08=Batch, 0x09=Lease)
    if let Some(n) = raw.as_u64() {
        return match n {
            0x00 => Some(smb::OplockLevel::None),
            0x02 => Some(smb::OplockLevel::II),
            0x08 => Some(smb::OplockLevel::Exclusive), // Batch → maps to Exclusive in smb-rs
            0x09 => Some(smb::OplockLevel::Lease),
            _ => None,
        };
    }

    // String values
    let value = raw.as_str()?.to_lowercase();
    match value.as_str() {
        "none" | "0" => Some(smb::OplockLevel::None),
        "read" | "ii" | "2" => Some(smb::OplockLevel::II),
        "exclusive" => Some(smb::OplockLevel::Exclusive),
        "batch" | "8" => Some(smb::OplockLevel::Exclusive), // Batch → Exclusive
        "lease" | "9" => Some(smb::OplockLevel::Lease),
        _ => None,
    }
}

fn parse_lease_request(ext: &serde_json::Value) -> Option<smb::RequestLease> {
    let value = ext.get("lease_request")?;
    let version = value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("v2")
        .to_lowercase();
    let state_value = value
        .get("state")
        .or_else(|| value.get("lease_state"))
        .unwrap_or(value);

    let lease_state = smb::LeaseState::new()
        .with_read_caching(
            state_value
                .get("read")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        )
        .with_write_caching(
            state_value
                .get("write")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        )
        .with_handle_caching(
            state_value
                .get("handle")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        );

    let lease_key = if let Some(key) = value.get("lease_key").and_then(|v| v.as_str()) {
        guid_to_u128(key).ok()?
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u128
    };

    if version == "v1" || version == "1" {
        Some(smb::RequestLease::RqLsReqv1(smb::RequestLeaseV1::new(
            lease_key, lease_state,
        )))
    } else {
        let mut flags = smb::LeaseFlags::new();
        let mut parent_key = 0u128;
        if let Some(parent) = value.get("parent_lease_key").and_then(|v| v.as_str()) {
            if let Ok(parent_val) = guid_to_u128(parent) {
                parent_key = parent_val;
                flags.set_parent_lease_key_set(true);
            }
        }
        let epoch = value
            .get("epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        Some(smb::RequestLease::RqLsReqv2(smb::RequestLeaseV2::new(
            lease_key, lease_state, flags, parent_key, epoch,
        )))
    }
}

fn parse_durable_handle(ext: &serde_json::Value) -> Option<smb::DurableHandleRequestV2> {
    let value = ext.get("durable_handle")?;
    let obj = if value.is_object() { value } else { &serde_json::json!({}) };
    let timeout = obj
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let persistent = obj
        .get("persistent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut flags = smb::DurableHandleV2Flags::new();
    if persistent {
        flags.set_persistent(true);
    }
    Some(smb::DurableHandleRequestV2::new(
        timeout,
        flags,
        smb::Guid::generate(),
    ))
}

fn guid_to_u128(input: &str) -> Result<u128> {
    let guid = smb::Guid::from_str(input).map_err(|e| anyhow!(e.to_string()))?;
    let bytes: [u8; 16] = guid.into();
    Ok(u128::from_le_bytes(bytes))
}

fn parse_desired_access(ext: &serde_json::Value) -> Option<smb::FileAccessMask> {
    let value = ext.get("desired_access")?;
    let mut access = smb::FileAccessMask::new();
    if value.get("generic_read").and_then(|v| v.as_bool()).unwrap_or(false) {
        access.set_generic_read(true);
    }
    if value
        .get("generic_write")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_generic_write(true);
    }
    if value
        .get("generic_execute")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_generic_execute(true);
    }
    if value.get("generic_all").and_then(|v| v.as_bool()).unwrap_or(false) {
        access.set_generic_all(true);
    }
    if value
        .get("file_read_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_read_data(true);
    }
    if value
        .get("file_write_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_write_data(true);
    }
    if value
        .get("file_append_data")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_append_data(true);
    }
    if value
        .get("file_read_attributes")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_read_attributes(true);
    }
    if value
        .get("file_write_attributes")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_write_attributes(true);
    }
    if value
        .get("file_read_ea")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_read_ea(true);
    }
    if value
        .get("file_write_ea")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_write_ea(true);
    }
    if value
        .get("file_execute")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_file_execute(true);
    }
    Some(access)
}

fn parse_create_disposition(ext: &serde_json::Value) -> Option<smb::CreateDisposition> {
    let raw = ext.get("create_disposition")?;

    // Try numeric first (MS-SMB2 2.2.13: 0-5)
    if let Some(n) = raw.as_u64() {
        return match n {
            0 => Some(smb::CreateDisposition::Superseded),
            1 => Some(smb::CreateDisposition::Open),
            2 => Some(smb::CreateDisposition::Create),
            3 => Some(smb::CreateDisposition::OpenIf),
            4 => Some(smb::CreateDisposition::Overwrite),
            5 => Some(smb::CreateDisposition::OverwriteIf),
            _ => None,
        };
    }

    // String values
    let value = raw.as_str()?.to_lowercase();
    match value.as_str() {
        "supersede" | "0" => Some(smb::CreateDisposition::Superseded),
        "open" | "1" => Some(smb::CreateDisposition::Open),
        "create" | "2" => Some(smb::CreateDisposition::Create),
        "open_if" | "3" => Some(smb::CreateDisposition::OpenIf),
        "overwrite" | "4" => Some(smb::CreateDisposition::Overwrite),
        "overwrite_if" | "5" => Some(smb::CreateDisposition::OverwriteIf),
        _ => None,
    }
}

fn parse_create_options(ext: &serde_json::Value) -> smb::CreateOptions {
    let mut options = smb::CreateOptions::new();
    let value = ext.get("create_options");
    if let Some(value) = value {
        if value
            .get("directory_file")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_directory_file(true);
        }
        if value
            .get("write_through")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_write_through(true);
        }
        if value
            .get("sequential_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_sequential_only(true);
        }
        if value
            .get("non_directory_file")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_non_directory_file(true);
        }
        if value
            .get("no_intermediate_buffering")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_no_intermediate_buffering(true);
        }
        if value
            .get("random_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_random_access(true);
        }
        if value
            .get("delete_on_close")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_delete_on_close(true);
        }
        if value
            .get("open_for_backup_intent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_open_for_backup_intent(true);
        }
        if value
            .get("no_compression")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_no_compression(true);
        }
        if value
            .get("open_requiring_oplock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_open_requiring_oplock(true);
        }
        if value
            .get("open_reparse_point")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_open_reparse_point(true);
        }
        if value
            .get("open_no_recall")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_open_no_recall(true);
        }
        if value
            .get("open_for_free_space_query")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            options.set_open_for_free_space_query(true);
        }
    }
    options
}

fn parse_file_attributes(ext: &serde_json::Value) -> Option<smb::FileAttributes> {
    let value = ext.get("file_attributes")?;
    let mut attrs = smb::FileAttributes::new();
    if value.get("readonly").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_readonly(true);
    }
    if value.get("hidden").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_hidden(true);
    }
    if value.get("system").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_system(true);
    }
    if value.get("directory").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_directory(true);
    }
    if value.get("archive").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_archive(true);
    }
    if value.get("normal").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_normal(true);
    }
    if value.get("temporary").and_then(|v| v.as_bool()).unwrap_or(false) {
        attrs.set_temporary(true);
    }
    if value
        .get("not_content_indexed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        attrs.set_not_content_indexed(true);
    }
    Some(attrs)
}

fn parse_allocation_size(ext: &serde_json::Value) -> Option<u64> {
    ext.get("allocation_size").and_then(|v| v.as_u64())
}

fn parse_share_access(ext: &serde_json::Value) -> Option<smb::ShareAccessFlags> {
    let value = ext.get("share_access")?;
    let mut access = smb::ShareAccessFlags::new();
    if value.get("read").and_then(|v| v.as_bool()).unwrap_or(false) {
        access.set_read(true);
    }
    if value
        .get("write")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_write(true);
    }
    if value
        .get("delete")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        access.set_delete(true);
    }
    Some(access)
}

fn map_smb_oplock(level: smb::OplockLevel) -> OplockLevel {
    match level {
        smb::OplockLevel::None => OplockLevel::None,
        smb::OplockLevel::II => OplockLevel::Read,
        smb::OplockLevel::Exclusive => OplockLevel::Batch,
        smb::OplockLevel::Lease => OplockLevel::Batch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oplock_level() {
        let ext = serde_json::json!({"oplock_level": "exclusive"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Exclusive));

        let ext = serde_json::json!({"oplock": "ii"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::II));

        let ext = serde_json::json!({"oplock_level": "unknown"});
        assert_eq!(parse_oplock_level(&ext), None);

        // Batch string maps to Exclusive
        let ext = serde_json::json!({"oplock_level": "batch"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Exclusive));

        // Lease string
        let ext = serde_json::json!({"oplock_level": "lease"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Lease));
    }

    #[test]
    fn test_parse_oplock_level_numeric() {
        // MS-SMB2 2.2.14 numeric values
        let ext = serde_json::json!({"oplock_level": 0});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::None));

        let ext = serde_json::json!({"oplock_level": 2});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::II));

        let ext = serde_json::json!({"oplock_level": 8});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Exclusive));

        let ext = serde_json::json!({"oplock_level": 9});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Lease));

        let ext = serde_json::json!({"oplock_level": 99});
        assert_eq!(parse_oplock_level(&ext), None);
    }

    #[test]
    fn test_parse_share_access() {
        let ext = serde_json::json!({
            "share_access": {"read": true, "write": false, "delete": true}
        });
        let access = parse_share_access(&ext).unwrap();
        assert!(access.read());
        assert!(!access.write());
        assert!(access.delete());
    }

    #[test]
    fn test_parse_desired_access() {
        let ext = serde_json::json!({
            "desired_access": {
                "generic_read": true,
                "generic_write": true,
                "file_read_data": true
            }
        });
        let access = parse_desired_access(&ext).unwrap();
        assert!(access.generic_read());
        assert!(access.generic_write());
        assert!(access.file_read_data());
        assert!(!access.generic_execute());
    }

    #[test]
    fn test_parse_create_disposition() {
        let ext = serde_json::json!({"create_disposition": "open_if"});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::OpenIf)
        );
    }

    #[test]
    fn test_parse_create_disposition_numeric() {
        // MS-SMB2 2.2.13 numeric values
        let ext = serde_json::json!({"create_disposition": 0});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::Superseded)
        );

        let ext = serde_json::json!({"create_disposition": 1});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::Open)
        );

        let ext = serde_json::json!({"create_disposition": 2});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::Create)
        );

        let ext = serde_json::json!({"create_disposition": 3});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::OpenIf)
        );

        let ext = serde_json::json!({"create_disposition": 4});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::Overwrite)
        );

        let ext = serde_json::json!({"create_disposition": 5});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::OverwriteIf)
        );

        let ext = serde_json::json!({"create_disposition": 99});
        assert_eq!(parse_create_disposition(&ext), None);
    }

    #[test]
    fn test_parse_create_disposition_string_numeric() {
        // Numeric strings should also work
        let ext = serde_json::json!({"create_disposition": "3"});
        assert_eq!(
            parse_create_disposition(&ext),
            Some(smb::CreateDisposition::OpenIf)
        );
    }

    #[test]
    fn test_parse_create_options() {
        let ext = serde_json::json!({
            "create_options": {
                "write_through": true,
                "non_directory_file": true,
                "random_access": true
            }
        });
        let options = parse_create_options(&ext);
        assert!(options.write_through());
        assert!(options.non_directory_file());
        assert!(options.random_access());
    }

    #[test]
    fn test_parse_file_attributes() {
        let ext = serde_json::json!({
            "file_attributes": {"readonly": true, "hidden": true, "archive": true}
        });
        let attrs = parse_file_attributes(&ext).unwrap();
        assert!(attrs.readonly());
        assert!(attrs.hidden());
        assert!(attrs.archive());
    }

    #[test]
    fn test_parse_allocation_size() {
        let ext = serde_json::json!({"allocation_size": 4096});
        assert_eq!(parse_allocation_size(&ext), Some(4096));
    }

    #[test]
    fn test_build_args_from_extensions() {
        let ext = serde_json::json!({
            "desired_access": {
                "generic_read": true,
                "file_write_data": true
            },
            "create_disposition": "overwrite_if",
            "create_options": {"write_through": true, "non_directory_file": true},
            "file_attributes": {"readonly": true},
            "lease_request": {"version": "v1", "read": true},
            "durable_handle": {"timeout_ms": 1000}
        });
        let args = build_args_from_extensions(OpenMode::ReadWrite, &ext);
        assert_eq!(args.disposition, smb::CreateDisposition::OverwriteIf);
        assert!(args.options.write_through());
        assert!(args.options.non_directory_file());
        assert!(args.attributes.readonly());
        assert!(args.desired_access.generic_read());
        assert!(args.desired_access.file_write_data());
        assert!(args.requested_lease.is_some());
        assert!(args.requested_durable.is_some());
    }

    #[test]
    fn test_parse_durable_handle() {
        let ext = serde_json::json!({
            "durable_handle": {"timeout_ms": 500, "persistent": true}
        });
        let durable = parse_durable_handle(&ext).unwrap();
        assert_eq!(durable.timeout, 500);
        assert!(durable.flags.persistent());
    }

    #[test]
    fn test_parse_lease_request_v1() {
        let ext = serde_json::json!({
            "lease_request": {
                "version": "v1",
                "state": {"read": true}
            }
        });
        let lease = parse_lease_request(&ext).unwrap();
        match lease {
            smb::RequestLease::RqLsReqv1(v1) => {
                assert!(v1.lease_state.read_caching());
            }
            _ => panic!("Expected v1 lease request"),
        }
    }

    #[test]
    fn test_parse_lease_request_v2_parent() {
        let ext = serde_json::json!({
            "lease_request": {
                "version": "v2",
                "state": {"read": true, "handle": true},
                "parent_lease_key": "b69d8fd8-184b-7c4d-a359-40c8a53cd2b7"
            }
        });
        let lease = parse_lease_request(&ext).unwrap();
        match lease {
            smb::RequestLease::RqLsReqv2(v2) => {
                assert!(v2.lease_state.read_caching());
                assert!(v2.lease_state.handle_caching());
                assert!(v2.lease_flags.parent_lease_key_set());
            }
            _ => panic!("Expected v2 lease request"),
        }
    }

    #[test]
    fn test_resolve_rename_target() {
        let share = smb::UncPath::from_str(r"\\server\share").unwrap();
        let target = resolve_rename_target(&share, "dir\\file.txt").unwrap();
        assert_eq!(target, "dir\\file.txt");

        let target = resolve_rename_target(&share, r"\\server\share\dir\file.txt").unwrap();
        assert_eq!(target, "dir\\file.txt");

        let err = resolve_rename_target(&share, r"\\other\share\x.txt").unwrap_err();
        assert!(err.to_string().contains("same share"));
    }

    #[test]
    fn test_resolve_unc_path() {
        let share = smb::UncPath::from_str(r"\\server\share").unwrap();
        let relative = resolve_unc_path(&share, "dir\\file.txt").unwrap();
        assert_eq!(relative.server(), "server");
        assert_eq!(relative.share(), Some("share"));
        assert_eq!(relative.path(), Some("dir\\file.txt"));

        let absolute = resolve_unc_path(&share, r"\\server\share\dir\file.txt").unwrap();
        assert_eq!(absolute.server(), "server");
        assert_eq!(absolute.share(), Some("share"));
        assert_eq!(absolute.path(), Some("dir\\file.txt"));
    }

    // ── Phase B4: AuthMethod tests ───────────────────────────────────

    #[test]
    fn test_auth_method_parse_auto() {
        assert_eq!("auto".parse::<AuthMethod>().unwrap(), AuthMethod::Auto);
        assert_eq!("AUTO".parse::<AuthMethod>().unwrap(), AuthMethod::Auto);
        assert_eq!("Auto".parse::<AuthMethod>().unwrap(), AuthMethod::Auto);
    }

    #[test]
    fn test_auth_method_parse_ntlm() {
        assert_eq!("ntlm".parse::<AuthMethod>().unwrap(), AuthMethod::Ntlm);
        assert_eq!("NTLM".parse::<AuthMethod>().unwrap(), AuthMethod::Ntlm);
    }

    #[test]
    fn test_auth_method_parse_kerberos() {
        assert_eq!("kerberos".parse::<AuthMethod>().unwrap(), AuthMethod::Kerberos);
        assert_eq!("krb5".parse::<AuthMethod>().unwrap(), AuthMethod::Kerberos);
        assert_eq!("krb".parse::<AuthMethod>().unwrap(), AuthMethod::Kerberos);
    }

    #[test]
    fn test_auth_method_parse_invalid() {
        assert!("invalid".parse::<AuthMethod>().is_err());
        assert!("".parse::<AuthMethod>().is_err());
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(AuthMethod::Auto.to_string(), "auto");
        assert_eq!(AuthMethod::Ntlm.to_string(), "ntlm");
        assert_eq!(AuthMethod::Kerberos.to_string(), "kerberos");
    }

    #[test]
    fn test_auth_method_default() {
        assert_eq!(AuthMethod::default(), AuthMethod::Auto);
    }

    #[test]
    fn test_auth_method_roundtrip() {
        for method in [AuthMethod::Auto, AuthMethod::Ntlm, AuthMethod::Kerberos] {
            let s = method.to_string();
            let parsed: AuthMethod = s.parse().unwrap();
            assert_eq!(method, parsed);
        }
    }

    // ── Phase D3: TransportMode tests ────────────────────────────────

    #[test]
    fn test_transport_mode_parse_tcp() {
        assert_eq!("tcp".parse::<TransportMode>().unwrap(), TransportMode::Tcp);
        assert_eq!("TCP".parse::<TransportMode>().unwrap(), TransportMode::Tcp);
    }

    #[test]
    fn test_transport_mode_rdma_without_feature() {
        // Without the "rdma" feature, parsing "rdma" should fail
        #[cfg(not(feature = "rdma"))]
        {
            let result = "rdma".parse::<TransportMode>();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("rdma"));
        }
    }

    #[test]
    fn test_transport_mode_parse_invalid() {
        assert!("invalid".parse::<TransportMode>().is_err());
        assert!("quic".parse::<TransportMode>().is_err());
    }

    #[test]
    fn test_transport_mode_default() {
        assert_eq!(TransportMode::default(), TransportMode::Tcp);
    }

    #[test]
    fn test_transport_mode_display() {
        assert_eq!(TransportMode::Tcp.to_string(), "tcp");
    }
}
