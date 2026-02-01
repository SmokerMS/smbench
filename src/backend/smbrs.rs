use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::backend::{
    BackendCapabilities, ConnectionState, LeaseState, OplockBreak, OplockLevel, SMBBackend,
    SMBConnectionInner, SMBFileHandle,
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
        let mut lease_break_rx = conn.subscribe_lease_breaks()?;

        let share_path = smb::UncPath::from_str(&format!(
            r"\\{}\\{}",
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
    let desired_access = parse_desired_access(extensions).unwrap_or_else(|| match mode {
        OpenMode::Read => smb::FileAccessMask::new().with_generic_read(true),
        OpenMode::Write => smb::FileAccessMask::new().with_generic_write(true),
        OpenMode::ReadWrite => smb::FileAccessMask::new()
            .with_generic_read(true)
            .with_generic_write(true),
    });

    let disposition = parse_create_disposition(extensions).unwrap_or(smb::CreateDisposition::Open);
    let options = parse_create_options(extensions);
    let attributes = parse_file_attributes(extensions).unwrap_or_else(smb::FileAttributes::new);
    let requested_oplock_level = parse_oplock_level(extensions).unwrap_or(smb::OplockLevel::None);
    let share_access = parse_share_access(extensions);

    smb::FileCreateArgs {
        disposition,
        attributes,
        options,
        desired_access,
        requested_oplock_level,
        requested_lease: None,
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
    let value = ext.get("oplock_level").or_else(|| ext.get("oplock"))?;
    let value = value.as_str()?.to_lowercase();
    match value.as_str() {
        "none" => Some(smb::OplockLevel::None),
        "read" | "ii" => Some(smb::OplockLevel::II),
        "exclusive" => Some(smb::OplockLevel::Exclusive),
        _ => None,
    }
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
    let value = ext.get("create_disposition")?.as_str()?.to_lowercase();
    match value.as_str() {
        "supersede" => Some(smb::CreateDisposition::Superseded),
        "open" => Some(smb::CreateDisposition::Open),
        "create" => Some(smb::CreateDisposition::Create),
        "open_if" => Some(smb::CreateDisposition::OpenIf),
        "overwrite" => Some(smb::CreateDisposition::Overwrite),
        "overwrite_if" => Some(smb::CreateDisposition::OverwriteIf),
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
            "file_attributes": {"readonly": true}
        });
        let args = build_args_from_extensions(OpenMode::ReadWrite, &ext);
        assert_eq!(args.disposition, smb::CreateDisposition::OverwriteIf);
        assert!(args.options.write_through());
        assert!(args.options.non_directory_file());
        assert!(args.attributes.readonly());
        assert!(args.desired_access.generic_read());
        assert!(args.desired_access.file_write_data());
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
}
