use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::backend::{
    BackendCapabilities, ConnectionState, OplockBreak, OplockLevel, SMBBackend, SMBConnectionInner,
    SMBFileHandle,
};
use crate::ir::{OpenMode, Operation};

#[derive(Clone, Debug)]
pub struct SmbRsConfig {
    pub server: String,
    pub share: String,
    pub user: String,
    pub pass: String,
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
        Ok(Self {
            server,
            share,
            user,
            pass,
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

        let share_path = smb::UncPath::from_str(&format!(
            r"\\{}\\{}",
            self.config.server, self.config.share
        ))?;
        client
            .share_connect(&share_path, &self.config.user, self.config.pass.clone())
            .await?;

        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                match break_rx.recv().await {
                    Ok(event) => {
                        let _ = tx
                            .send(OplockBreak {
                                handle_ref: String::new(),
                                file_id: Some(format!("{:?}", event.file_id)),
                                new_level: map_smb_oplock(event.new_level),
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

        Ok(ConnectionState::new(Box::new(SmbRsConnection {
            client: Arc::new(client),
            share_path,
        }))
        .with_oplock_channel(rx))
    }
}

struct SmbRsConnection {
    client: Arc<smb::Client>,
    share_path: smb::UncPath,
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
        let mut args = build_args_for_mode(OpenMode::ReadWrite);

        if let Some(oplock) = parse_oplock_level(extensions) {
            args = args.with_oplock_level(oplock);
        }
        if let Some(share_access) = parse_share_access(extensions) {
            args = args.with_share_access(share_access);
        }

        let resource = self.client.create_file(&unc_path, &args).await?;
        let file: smb::File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _)) => return Err(anyhow!(err)),
        };
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
            _ => Ok(()),
        }
    }
}

struct SmbRsFileHandle {
    file: smb::File,
    file_id: String,
    granted_oplock: Option<OplockLevel>,
}

impl SmbRsFileHandle {
    fn new(file: smb::File) -> Result<Self> {
        let file_id = format!("{:?}", file.file_id_for_oplock()?);
        let granted_oplock = map_smb_oplock(file.granted_oplock_level());
        Ok(Self {
            file,
            file_id,
            granted_oplock,
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

    fn file_id(&self) -> Option<String> {
        Some(self.file_id.clone())
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

fn resolve_unc_path(share: &smb::UncPath, path: &str) -> Result<smb::UncPath> {
    if path.starts_with("\\\\") {
        Ok(smb::UncPath::from_str(path)?)
    } else {
        Ok(share.with_path(path))
    }
}

fn resolve_rename_target(share: &smb::UncPath, dest_path: &str) -> Result<String> {
    if dest_path.starts_with("\\\\") {
        let unc = smb::UncPath::from_str(dest_path)?;
        if unc.server() != share.server() || unc.share() != share.share() {
            return Err(anyhow!(
                "Rename target must be within the same share ({}\\\\{})",
                share.server(),
                share.share().unwrap_or_default()
            ));
        }
        Ok(unc.path().unwrap_or(dest_path).to_string())
    } else {
        Ok(dest_path.to_string())
    }
}

fn parse_oplock_level(ext: &serde_json::Value) -> Option<smb::OplockLevel> {
    let value = ext.get("oplock_level").or_else(|| ext.get("oplock"))?;
    let value = value.as_str()?.to_lowercase();
    match value.as_str() {
        "none" => Some(smb::OplockLevel::None),
        "read" | "ii" => Some(smb::OplockLevel::II),
        "exclusive" => Some(smb::OplockLevel::Exclusive),
        _ => None,
    }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oplock_level() {
        let ext = serde_json::json!({\"oplock_level\": \"exclusive\"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::Exclusive));

        let ext = serde_json::json!({\"oplock\": \"ii\"});
        assert_eq!(parse_oplock_level(&ext), Some(smb::OplockLevel::II));

        let ext = serde_json::json!({\"oplock_level\": \"unknown\"});
        assert_eq!(parse_oplock_level(&ext), None);
    }

    #[test]
    fn test_parse_share_access() {
        let ext = serde_json::json!({
            \"share_access\": {\"read\": true, \"write\": false, \"delete\": true}
        });
        let access = parse_share_access(&ext).unwrap();
        assert!(access.read());
        assert!(!access.write());
        assert!(access.delete());
    }

    #[test]
    fn test_resolve_rename_target() {
        let share = smb::UncPath::from_str(r"\\server\\share").unwrap();
        let target = resolve_rename_target(&share, "dir\\file.txt").unwrap();
        assert_eq!(target, "dir\\file.txt");

        let target = resolve_rename_target(&share, r"\\server\\share\\dir\\file.txt").unwrap();
        assert_eq!(target, "dir\\file.txt");

        let err = resolve_rename_target(&share, r"\\other\\share\\x.txt").unwrap_err();
        assert!(err.to_string().contains("same share"));
    }
}
