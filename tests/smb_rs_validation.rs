#[cfg(feature = "smb-rs-backend")]
mod smb_rs_validation {
    use std::cmp::min;
    use std::env;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use smbench::backend::smbrs::{SmbRsBackend, SmbRsConfig};
    use smbench::backend::SMBBackend;
    use futures_util::StreamExt;
    use smb::{
        Client, ClientConfig, ConnectionConfig, CreateOptions, Dialect, Directory, File,
        FileAccessMask, FileAttributes, FileCreateArgs, GetLen, LeaseState, OplockLevel,
        RequestLease, RequestLeaseV1, RequestLeaseV2, UncPath,
    };
    use smb::connection::config::MultiChannelConfig;
    use smb::resource::file_util::{SetLen, block_copy};
    use smb_msg::{
        EchoRequest, NotifyFilter, OffloadReadRequest, PipePeekRequest, PipeWaitRequest,
        QueryAllocRangesItem, RequestContent, SetReparsePointRequest,
        SrvCopyChunkCopyWrite, SrvCopychunkCopy, SrvCopychunkItem, SrvEnumerateSnapshotsRequest,
        SrvHashRetrievalType, SrvReadHashReq, SrvRequestResumeKeyRequest,
    };
    use smb_msg::dfsc::{ReferralLevel, ReqGetDfsReferralEx};
    use smb_msg::{
        FileLevelTrimRange, FileLevelTrimRequest, NetworkResiliencyRequest,
        ValidateNegotiateInfoRequest,
    };
    use smb_dtyp::binrw_util::prelude::Boolean;
    use smb_fscc::{
        DirAccessMask, FileBasicInformation, FileDirectoryInformation, FileFsAttributeInformation,
        FileFsSectorSizeInformation, FileFsSizeInformation, FileStandardInformation,
    };
    use smb_rpc::interface::SrvSvc;
    use tokio_util::sync::CancellationToken;
    use std::sync::Arc;

    fn smb_env() -> Option<(String, String, String, String)> {
        let server = env::var("SMBENCH_SMB_SERVER").ok()?;
        let share = env::var("SMBENCH_SMB_SHARE").ok()?;
        let user = env::var("SMBENCH_SMB_USER").ok()?;
        let pass = env::var("SMBENCH_SMB_PASS").ok()?;
        Some((server, share, user, pass))
    }

    fn unique_name(prefix: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{}_{}.txt", prefix, ts)
    }

    fn strict_env(name: &str) -> bool {
        env::var(name)
            .ok()
            .as_deref()
            .map(|val| val != "0")
            .unwrap_or(false)
    }

    fn fsctl_strict() -> bool {
        strict_env("SMBENCH_STRICT_FSCTL")
    }

    fn smb_client_config() -> ClientConfig {
        let mut config = ClientConfig::default();
        config.connection.timeout = Some(std::time::Duration::from_secs(30));
        config
    }

    fn new_client() -> Client {
        Client::new(smb_client_config())
    }

    fn new_client_with_dialect(dialect: Dialect) -> Client {
        let mut config = smb_client_config();
        config.connection.min_dialect = Some(dialect);
        config.connection.max_dialect = Some(dialect);
        Client::new(config)
    }

    async fn create_file_with_data(
        client: &Client,
        share_path: &UncPath,
        name: &str,
        data: &[u8],
    ) -> Result<File> {
        let file_path = share_path.clone().with_path(name);
        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client
            .create_file(&file_path, &create_args)
            .await?
            .unwrap_file();
        if !data.is_empty() {
            file.write_block(data, 0, None).await?;
            file.set_len(data.len() as u64).await?;
            file.flush().await?;
        }
        Ok(file)
    }

    fn build_symlink_reparse_data(target: &str, relative: bool) -> Vec<u8> {
        let (substitute, print, flags) = if relative {
            (target.to_string(), target.to_string(), 1u32)
        } else {
            let substitute = if target.starts_with(r"\\") {
                format!(r"\??\UNC\{}", &target[2..])
            } else {
                format!(r"\??\{}", target)
            };
            (substitute, target.to_string(), 0u32)
        };
        let substitute_utf16: Vec<u16> = substitute.encode_utf16().collect();
        let print_utf16: Vec<u16> = print.encode_utf16().collect();

        let substitute_len = (substitute_utf16.len() * 2) as u16;
        let print_len = (print_utf16.len() * 2) as u16;
        let print_offset = substitute_len;

        let mut data = Vec::with_capacity(12 + substitute_len as usize + print_len as usize);
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute offset
        data.extend_from_slice(&substitute_len.to_le_bytes());
        data.extend_from_slice(&print_offset.to_le_bytes());
        data.extend_from_slice(&print_len.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        for c in substitute_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }
        for c in print_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data
    }

    #[tokio::test]
    async fn test_smb_rs_connection() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs connection test");
            return Ok(());
        };

        let client = new_client();
        let target_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&target_path, &user, pass).await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_file_ops() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs file ops test");
            return Ok(());
        };

        let client = new_client_with_dialect(Dialect::Smb0302);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let file_name = unique_name("smbench_phase0");
        let file_path = share_path.clone().with_path(&file_name);

        let mut options = CreateOptions::new();
        options.set_write_through(true);
        options.set_non_directory_file(true);
        let create_args = FileCreateArgs::make_overwrite(FileAttributes::new(), options);
        let resource = match client.create_file(&file_path, &create_args).await {
            Ok(resource) => resource,
            Err(err) => {
                // Some servers reject extra options; fall back to minimal create args.
                eprintln!("Create with options failed: {err}; retrying with minimal options");
                let create_args =
                    FileCreateArgs::make_overwrite(FileAttributes::new(), CreateOptions::new());
                client.create_file(&file_path, &create_args).await?
            }
        };
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let data = b"smbench-phase0";
        let written = file.write_block(data, 0, None).await?;
        assert_eq!(written, data.len(), "write returned {written}");
        file.set_len(data.len() as u64).await?;
        file.flush().await?;
        file.close().await?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let read_access = FileAccessMask::new().with_generic_read(true);
        let read_args = FileCreateArgs::make_open_existing(read_access);
        let resource = client.create_file(&file_path, &read_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let len = file.get_len().await?;
        assert!(
            len >= data.len() as u64,
            "file length {} smaller than {}",
            len,
            data.len()
        );

        let mut buf = vec![0u8; data.len()];
        let read = file.read_block(&mut buf, 0, None, true).await?;
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);

        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_oplocks() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs lease test");
            return Ok(());
        };

        let mut connection = ConnectionConfig::default();
        connection.min_dialect = Some(Dialect::Smb030);
        connection.max_dialect = Some(Dialect::Smb0311);
        connection.disable_notifications = false;
        connection.timeout = Some(std::time::Duration::from_secs(60));
        let client_config = ClientConfig {
            connection,
            ..ClientConfig::default()
        };

        let client1 = Client::new(client_config.clone());
        let client2 = Client::new(client_config);

        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let conn1 = client1.get_connection(&server).await?;
        let mut lease_break_rx = conn1.subscribe_lease_breaks()?;
        let mut oplock_break_rx = conn1.subscribe_oplock_breaks()?;
        if let Some(info) = conn1.conn_info() {
            eprintln!(
                "server_caps: leasing={} directory_leasing={} notifications={}",
                info.negotiation.caps.leasing(),
                info.negotiation.caps.directory_leasing(),
                info.negotiation.caps.notifications()
            );
        }

        let file_name = unique_name("smbench_lease");
        let file_path = share_path.clone().with_path(&file_name);

        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = client1.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;

        let mut lease_options = CreateOptions::new();
        lease_options.set_non_directory_file(true);

        let lease_key = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u128;
        let lease_key_guid = smb::Guid::try_from(&lease_key.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("invalid lease key guid: {e}"))?;
        let lease_state = LeaseState::new()
            .with_read_caching(true)
            .with_write_caching(true)
            .with_handle_caching(true);
        let lease_request_v2 = RequestLease::RqLsReqv2(RequestLeaseV2::new(
            lease_key,
            lease_state,
            Default::default(),
            0,
            0,
        ));
        let lease_request_v1 = RequestLease::RqLsReqv1(RequestLeaseV1::new(lease_key, lease_state));

        let share_access = smb::ShareAccessFlags::new()
            .with_read(true)
            .with_write(true)
            .with_delete(true);
        let mut create_args = FileCreateArgs::make_open_existing(
            FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true),
        );
        create_args.options = lease_options;
        create_args = create_args
            .with_lease_request(lease_request_v1.clone())
            .with_share_access(share_access);

        let file1_resource = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client1.create_file(&file_path, &create_args),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for create (lease v1)"))??;
        let mut file1: File = match file1_resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let mut lease_granted = file1.granted_lease().is_some();
        eprintln!(
            "lease_granted_v1={lease_granted} oplock_granted={:?}",
            file1.granted_oplock_level()
        );
        if !lease_granted {
            file1.close().await?;
            create_args = create_args.with_lease_request(lease_request_v2);
            let file1_resource = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                client1.create_file(&file_path, &create_args),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for create (lease v2)"))??;
            file1 = match file1_resource.try_into() {
                Ok(file) => file,
                Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
            };
            lease_granted = file1.granted_lease().is_some();
            eprintln!(
                "lease_granted_v2={lease_granted} oplock_granted={:?}",
                file1.granted_oplock_level()
            );
        }

        if !lease_granted {
            file1.close().await?;
            let mut oplock_args = FileCreateArgs::make_open_existing(
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            );
            let mut oplock_options = CreateOptions::new();
            oplock_options.set_non_directory_file(true);
            oplock_options.set_write_through(true);
            oplock_options.set_open_requiring_oplock(true);
            oplock_args.options = oplock_options;
            let oplock_args = oplock_args
                .with_oplock_level(OplockLevel::Exclusive)
                .with_share_access(share_access);
            let file1_resource = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                client1.create_file(&file_path, &oplock_args),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for create (oplock)"))??;
            file1 = match file1_resource.try_into() {
                Ok(file) => file,
                Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
            };

            if matches!(file1.granted_oplock_level(), OplockLevel::None) {
                if std::env::var("SMBENCH_STRICT_OPLOCKS").ok().as_deref() == Some("1") {
            return Err(anyhow::anyhow!(
                        "Lease not granted and oplock not granted"
                    ));
                }
                eprintln!("Lease/oplock not granted by server; skipping break validation");
                file1.close().await?;
                client1.close().await?;
                return Ok(());
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let breaker = tokio::spawn({
            let file_path = file_path.clone();
            async move {
                let mut open_options = CreateOptions::new();
                open_options.set_non_directory_file(true);
                let mut access = FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true);
                access.set_delete(true);
                let open_args = FileCreateArgs::make_open_existing(access);
                let open_args = FileCreateArgs {
                    options: open_options,
                    ..open_args
                }
                .with_share_access(
                    smb::ShareAccessFlags::new()
                        .with_read(true)
                        .with_write(true)
                        .with_delete(true),
                );
                let resource2 = tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    client2.create_file(&file_path, &open_args),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for breaker open"))??;
                let file2: File = match resource2.try_into() {
                    Ok(file) => file,
                    Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
                };
                let _ = file2.write_block(b"x", 0, None).await?;
                file2.flush().await?;
                file2.close().await?;
                client2.close().await?;
                Ok::<(), anyhow::Error>(())
            }
        });

        if lease_granted {
            let event =
                tokio::time::timeout(std::time::Duration::from_secs(45), lease_break_rx.recv())
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for lease break"))??;

        assert_eq!(event.lease_key, lease_key_guid);

        if event.ack_required {
                file1
                .acknowledge_lease_break(event.lease_key, event.new_state)
                    .await
                    .context("lease break ack")?;
            }
        } else {
            let event = tokio::time::timeout(std::time::Duration::from_secs(45), oplock_break_rx.recv())
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for oplock break"))??;
            let expected_file_id = file1.file_id_for_oplock()?;
            assert_eq!(event.file_id, expected_file_id);
            file1.acknowledge_oplock_break(event.new_level).await?;
        }
        breaker.await.context("breaker task join")??;

        file1.close().await?;
        client1.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_rename_delete() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs rename/delete test");
            return Ok(());
        };

        let client = new_client_with_dialect(Dialect::Smb0302);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let file_name = unique_name("smbench_rename_src");
        let file_path = share_path.clone().with_path(&file_name);

        let mut options = CreateOptions::new();
        options.set_non_directory_file(true);
        let create_args = FileCreateArgs::make_overwrite(FileAttributes::new(), options);
        let resource = client.create_file(&file_path, &create_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let new_name = unique_name("smbench_rename_dst");
        let rename_info = smb::FileRenameInformation::new(false, &new_name);
        file.set_info(rename_info).await?;
        file.close().await?;

        let renamed_path = share_path.with_path(&new_name);
        let open_access = FileAccessMask::new().with_generic_all(true);
        let open_args = FileCreateArgs::make_open_existing(open_access);
        let resource = client.create_file(&renamed_path, &open_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        file.set_info(smb::FileDispositionInformation::default())
                .await?;
        file.close().await?;

        let deleted = client.create_file(&renamed_path, &open_args).await;
        assert!(deleted.is_err(), "expected delete to remove file");

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_share_mode_conflict() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs share mode test");
            return Ok(());
        };

        let client1 = new_client();
        let client2 = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let file_name = unique_name("smbench_share_mode");
        let file_path = share_path.clone().with_path(&file_name);

        let share_read_only = smb::ShareAccessFlags::new().with_read(true);
        let create_args = FileCreateArgs::make_overwrite(FileAttributes::new(), CreateOptions::new())
            .with_share_access(share_read_only);
        let resource = client1.create_file(&file_path, &create_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let write_access = FileAccessMask::new().with_generic_write(true);
        let write_args = FileCreateArgs::make_open_existing(write_access)
            .with_share_access(share_read_only);
        let second_open = client2.create_file(&file_path, &write_args).await;
        assert!(second_open.is_err(), "expected share-mode conflict");

        file.close().await?;
        client1.close().await?;
        client2.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_access_mask_enforced() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs access mask test");
            return Ok(());
        };

        let client = new_client_with_dialect(Dialect::Smb0302);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let file_name = unique_name("smbench_access_mask");
        let file_path = share_path.clone().with_path(&file_name);
        let create_args = FileCreateArgs::make_overwrite(FileAttributes::new(), CreateOptions::new());
        let resource = client.create_file(&file_path, &create_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        file.close().await?;

        let read_access = FileAccessMask::new().with_generic_read(true);
        let read_args = FileCreateArgs::make_open_existing(read_access);
        let resource = client.create_file(&file_path, &read_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let write_result = file.write_block(b"x", 0, None).await;
        assert!(write_result.is_err(), "expected write to be denied");

        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_delete_on_close() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs delete-on-close test");
            return Ok(());
        };

        let client = new_client_with_dialect(Dialect::Smb0302);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let file_name = unique_name("smbench_delete_on_close");
        let file_path = share_path.clone().with_path(&file_name);

        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = client.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;

        let mut options = CreateOptions::new();
        options.set_non_directory_file(true);
        options.set_delete_on_close(true);
        let mut desired_access = FileAccessMask::new().with_generic_all(true);
        desired_access.set_delete(true);
        let delete_args = FileCreateArgs {
            disposition: smb::CreateDisposition::Open,
            attributes: FileAttributes::new(),
            options,
            desired_access,
            requested_oplock_level: OplockLevel::None,
            requested_lease: None,
            requested_durable: None,
            share_access: Some(
                smb::ShareAccessFlags::new()
                    .with_read(true)
                    .with_write(true)
                    .with_delete(true),
            ),
        };
        let resource = client.create_file(&file_path, &delete_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        file.close().await?;

        let open_access = FileAccessMask::new().with_generic_read(true);
        let open_args = FileCreateArgs::make_open_existing(open_access);
        let reopened = client.create_file(&file_path, &open_args).await;
        assert!(reopened.is_err(), "expected delete-on-close to remove file");

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_extensions_lease_break() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs extensions lease test");
            return Ok(());
        };

        let seed_client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        seed_client
            .share_connect(&share_path, &user, pass.clone())
            .await?;

        let file_name = unique_name("smbench_lease_ext");
        let file_path = share_path.clone().with_path(&file_name);
        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = seed_client.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;
        seed_client.close().await?;

        let backend = SmbRsBackend::new(SmbRsConfig {
            server: server.clone(),
            share: share.clone(),
            user: user.clone(),
            pass: pass.clone(),
        });
        let mut conn_state: smbench::backend::ConnectionState =
            backend.connect("client-lease").await?;
        let mut break_rx = conn_state
            .take_oplock_receiver()
            .context("missing break receiver")?;

        let extensions = serde_json::json!({
            "lease_request": {
                "version": "v1",
                "state": {"read": true, "write": true, "handle": true}
            }
        });
        let open = smbench::ir::Operation::Open {
            op_id: "op_open".to_string(),
            client_id: "client-lease".to_string(),
            timestamp_us: 0,
            path: file_name.clone(),
            mode: smbench::ir::OpenMode::ReadWrite,
            handle_ref: "h1".to_string(),
            extensions: Some(extensions),
        };
        conn_state.execute(&open).await?;

        let breaker = tokio::spawn({
            let server = server.clone();
            let share = share.clone();
            let user = user.clone();
            let pass = pass.clone();
            let file_path = file_path.clone();
            async move {
                let client = new_client();
                let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
                client.share_connect(&share_path, &user, pass).await?;
                let mut access = FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true);
                access.set_delete(true);
                let open_args = FileCreateArgs::make_open_existing(access)
                    .with_share_access(
                        smb::ShareAccessFlags::new()
                            .with_read(true)
                            .with_write(true)
                            .with_delete(true),
                    );
                let resource = client.create_file(&file_path, &open_args).await?;
                let file: File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
                };
                let _ = file.write_block(b"x", 0, None).await?;
                file.flush().await?;
                file.close().await?;
                client.close().await?;
                Ok::<(), anyhow::Error>(())
            }
        });

        let break_msg = tokio::time::timeout(std::time::Duration::from_secs(45), break_rx.recv())
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for lease break"))?
            .ok_or_else(|| anyhow::anyhow!("Break channel closed"))?;
        conn_state.handle_oplock_break(break_msg).await;

        let read = smbench::ir::Operation::Read {
            op_id: "op_read".to_string(),
            client_id: "client-lease".to_string(),
            timestamp_us: 1,
            handle_ref: "h1".to_string(),
            offset: 0,
            length: 1,
        };
        conn_state.execute(&read).await?;
        let close = smbench::ir::Operation::Close {
            op_id: "op_close".to_string(),
            client_id: "client-lease".to_string(),
            timestamp_us: 2,
            handle_ref: "h1".to_string(),
        };
        conn_state.execute(&close).await?;

        breaker.await.context("breaker task join")??;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_extensions_delete_on_close() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs extensions delete test");
            return Ok(());
        };

        let backend = SmbRsBackend::new(SmbRsConfig {
            server: server.clone(),
            share: share.clone(),
            user: user.clone(),
            pass: pass.clone(),
        });
        let mut conn_state: smbench::backend::ConnectionState =
            backend.connect("client-delete").await?;

        let file_name = unique_name("smbench_ext_delete");
        let extensions = serde_json::json!({
            "create_disposition": "open_if",
            "create_options": {
                "non_directory_file": true,
                "delete_on_close": true
            },
            "desired_access": {
                "generic_all": true
            },
            "share_access": {"read": true, "write": true, "delete": true}
        });

        let open = smbench::ir::Operation::Open {
            op_id: "op_open".to_string(),
            client_id: "client-delete".to_string(),
            timestamp_us: 0,
            path: file_name.clone(),
            mode: smbench::ir::OpenMode::ReadWrite,
            handle_ref: "hdel".to_string(),
            extensions: Some(extensions),
        };
        conn_state.execute(&open).await?;

        let close = smbench::ir::Operation::Close {
            op_id: "op_close".to_string(),
            client_id: "client-delete".to_string(),
            timestamp_us: 1,
            handle_ref: "hdel".to_string(),
        };
        conn_state.execute(&close).await?;

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;
        let open_access = FileAccessMask::new().with_generic_read(true);
        let open_args = FileCreateArgs::make_open_existing(open_access);
        let target = share_path.with_path(&file_name);
        let reopened = client.create_file(&target, &open_args).await;
        assert!(reopened.is_err(), "expected delete-on-close to remove file");
        client.close().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_extensions_allocation_size() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs extensions allocation test");
            return Ok(());
        };

        let seed_client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        seed_client
            .share_connect(&share_path, &user, pass.clone())
            .await?;

        let file_name = unique_name("smbench_ext_alloc");
        let file_path = share_path.clone().with_path(&file_name);
        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = seed_client.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;
        seed_client.close().await?;

        let backend = SmbRsBackend::new(SmbRsConfig {
            server: server.clone(),
            share: share.clone(),
            user: user.clone(),
            pass: pass.clone(),
        });
        let mut conn_state: smbench::backend::ConnectionState =
            backend.connect("client-alloc").await?;

        let extensions = serde_json::json!({
            "allocation_size": 4096,
            "desired_access": {"generic_all": true},
            "share_access": {"read": true, "write": true, "delete": true}
        });
        let open = smbench::ir::Operation::Open {
            op_id: "op_open".to_string(),
            client_id: "client-alloc".to_string(),
            timestamp_us: 0,
            path: file_name.clone(),
            mode: smbench::ir::OpenMode::ReadWrite,
            handle_ref: "halloc".to_string(),
            extensions: Some(extensions),
        };
        conn_state.execute(&open).await?;
        let close = smbench::ir::Operation::Close {
            op_id: "op_close".to_string(),
            client_id: "client-alloc".to_string(),
            timestamp_us: 1,
            handle_ref: "halloc".to_string(),
        };
        conn_state.execute(&close).await?;

        let client = new_client();
        client.share_connect(&share_path, &user, pass.clone()).await?;
        let open_access = FileAccessMask::new().with_generic_read(true);
        let open_args = FileCreateArgs::make_open_existing(open_access);
        let resource = client.create_file(&file_path, &open_args).await?;
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        let len = file.get_len().await?;
        assert_eq!(len, 0, "expected empty file after allocation");
        file.close().await?;
        client.close().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_extensions_access_enforced() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs extensions access test");
            return Ok(());
        };

        let seed_client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        seed_client
            .share_connect(&share_path, &user, pass.clone())
            .await?;

        let file_name = unique_name("smbench_ext_access");
        let file_path = share_path.clone().with_path(&file_name);
        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = seed_client.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;
        seed_client.close().await?;

        let backend = SmbRsBackend::new(SmbRsConfig {
            server: server.clone(),
            share: share.clone(),
            user: user.clone(),
            pass: pass.clone(),
        });
        let mut conn_state: smbench::backend::ConnectionState =
            backend.connect("client-access").await?;

        let extensions = serde_json::json!({
            "desired_access": {"generic_read": true},
            "share_access": {"read": true}
        });
        let open = smbench::ir::Operation::Open {
            op_id: "op_open".to_string(),
            client_id: "client-access".to_string(),
            timestamp_us: 0,
            path: file_name.clone(),
            mode: smbench::ir::OpenMode::Read,
            handle_ref: "hread".to_string(),
            extensions: Some(extensions),
        };
        conn_state.execute(&open).await?;

        let blob_path = std::env::temp_dir().join("smbench_ext_access_blob");
        std::fs::write(&blob_path, b"x").expect("write blob");
        let write = smbench::ir::Operation::Write {
            op_id: "op_write".to_string(),
            client_id: "client-access".to_string(),
            timestamp_us: 1,
            handle_ref: "hread".to_string(),
            offset: 0,
            length: 1,
            blob_path: blob_path.to_string_lossy().to_string(),
        };
        let err = conn_state.execute(&write).await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("access")
                || err.to_string().to_lowercase().contains("denied"),
            "unexpected error: {err}"
        );

        let close = smbench::ir::Operation::Close {
            op_id: "op_close".to_string(),
            client_id: "client-access".to_string(),
            timestamp_us: 2,
            handle_ref: "hread".to_string(),
        };
        conn_state.execute(&close).await?;
        let _ = std::fs::remove_file(&blob_path);

        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_lease_downgrade() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs lease downgrade test");
            return Ok(());
        };

        let mut connection = ConnectionConfig::default();
        connection.min_dialect = Some(Dialect::Smb030);
        connection.max_dialect = Some(Dialect::Smb0311);
        let client_config = ClientConfig {
            connection,
            ..ClientConfig::default()
        };

        let client1 = Client::new(client_config.clone());
        let client2 = Client::new(client_config);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let conn1 = client1.get_connection(&server).await?;
        let mut lease_break_rx = conn1.subscribe_lease_breaks()?;

        let file_name = unique_name("smbench_lease_downgrade");
        let file_path = share_path.clone().with_path(&file_name);
        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = client1.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;

        let lease_key = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u128;
        let lease_key_guid = smb::Guid::try_from(&lease_key.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("invalid lease key guid: {e}"))?;
        let lease_state = LeaseState::new()
            .with_read_caching(true)
            .with_write_caching(true)
            .with_handle_caching(true);
        let lease_request = RequestLease::RqLsReqv1(RequestLeaseV1::new(lease_key, lease_state));

        let share_access = smb::ShareAccessFlags::new()
            .with_read(true)
            .with_write(true)
            .with_delete(true);
        let mut create_args = FileCreateArgs::make_open_existing(
            FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true),
        );
        create_args.options = CreateOptions::new().with_non_directory_file(true);
        create_args = create_args
            .with_lease_request(lease_request)
            .with_share_access(share_access);
        let resource = client1.create_file(&file_path, &create_args).await?;
        let file1: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let breaker = tokio::spawn({
            let file_path = file_path.clone();
            async move {
                let mut access = FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true);
                access.set_delete(true);
                let open_args = FileCreateArgs::make_open_existing(access)
                    .with_share_access(
                        smb::ShareAccessFlags::new()
                            .with_read(true)
                            .with_write(true)
                            .with_delete(true),
                    );
                let resource = client2.create_file(&file_path, &open_args).await?;
                let file2: File = match resource.try_into() {
                    Ok(file) => file,
                    Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
                };
                let _ = file2.write_block(b"x", 0, None).await?;
                file2.flush().await?;
                file2.close().await?;
                client2.close().await?;
                Ok::<(), anyhow::Error>(())
            }
        });

        let event = tokio::time::timeout(std::time::Duration::from_secs(45), lease_break_rx.recv())
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for lease break"))??;
        assert_eq!(event.lease_key, lease_key_guid);
        if std::env::var("SMBENCH_STRICT_LEASE_DOWNGRADE")
            .ok()
            .as_deref()
            == Some("1")
        {
            assert!(
                !event.new_state.write_caching(),
                "expected write caching to be revoked"
            );
        }
        if event.ack_required {
            file1
                .acknowledge_lease_break(event.lease_key, event.new_state)
                .await
                .context("lease break ack")?;
        }

        breaker.await.context("breaker task join")??;
        file1.close().await?;
        client1.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_durable_handle_v2() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs durable handle test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let file_name = unique_name("smbench_durable");
        let file_path = share_path.clone().with_path(&file_name);
        let mut seed_options = CreateOptions::new();
        seed_options.set_non_directory_file(true);
        let seed_args = FileCreateArgs::make_overwrite(FileAttributes::new(), seed_options);
        let seed = client.create_file(&file_path, &seed_args).await?;
        let seed: File = match seed.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        seed.close().await?;

        let access = FileAccessMask::new()
            .with_generic_read(true)
            .with_generic_write(true);
        let mut args = FileCreateArgs::make_open_existing(access);
        let mut flags = smb::DurableHandleV2Flags::new();
        let persistent = std::env::var("SMBENCH_DURABLE_PERSISTENT")
            .ok()
            .as_deref()
            == Some("1");
        if persistent {
            flags.set_persistent(true);
        }
        let durable =
            smb::DurableHandleRequestV2::new(60_000, flags, smb::Guid::generate());
        args = args.with_durable_handle_v2(durable);
        args.options.set_non_directory_file(true);

        let resource = match client.create_file(&file_path, &args).await {
            Ok(resource) => resource,
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("Invalid Parameter") {
                    if std::env::var("SMBENCH_STRICT_DURABLE").ok().as_deref() == Some("1") {
                        return Err(anyhow::anyhow!(msg));
                    }
                    eprintln!("Durable handle v2 request rejected by server; skipping strict assertion");
                    client.close().await?;
                    return Ok(());
                }
                return Err(anyhow::anyhow!(msg));
            }
        };
        let file: File = match resource.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };
        let durable_granted = file.durable_handle().is_some();
        if !durable_granted {
            if std::env::var("SMBENCH_STRICT_DURABLE").ok().as_deref() == Some("1") {
                return Err(anyhow::anyhow!("durable handle not granted by server"));
            }
            eprintln!("Durable handle not granted by server; skipping strict assertion");
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_change_notify() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs change notify test");
            return Ok(());
        };

        let client1 = new_client();
        let client2 = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let dir_name = unique_name("smbench_notify_dir");
        let dir_path = share_path.clone().with_path(&dir_name);
        let create_dir_args = FileCreateArgs::make_create_new(
            FileAttributes::new().with_directory(true),
            CreateOptions::new().with_directory_file(true),
        );
        let dir_resource = client1.create_file(&dir_path, &create_dir_args).await?;
        let dir_resource = dir_resource.unwrap_dir();

        let watch_handle: Directory = dir_resource;
        let notify_task = tokio::spawn(async move {
            watch_handle
                .watch_timeout(NotifyFilter::all(), false, std::time::Duration::from_secs(10))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let file_name = format!("{dir_name}\\notify.txt");
        let file_path = share_path.clone().with_path(&file_name);
        let file_args = FileCreateArgs::make_create_new(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client2.create_file(&file_path, &file_args).await?;
        file.unwrap_file().close().await?;

        let notify_result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            notify_task,
        )
        .await??
        ?;
        assert!(
            !notify_result.is_empty(),
            "expected at least one notify event"
        );

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(file) = client2.create_file(&file_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }
        if let Ok(dir) = client1.create_file(&dir_path, &cleanup_open).await {
            let dir = dir.unwrap_dir();
            let _ = dir
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = dir.close().await;
        }

        client1.close().await?;
        client2.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_change_notify_stream() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs change notify stream test");
            return Ok(());
        };

        let client1 = new_client();
        let client2 = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let dir_name = unique_name("smbench_notify_stream_dir");
        let dir_path = share_path.clone().with_path(&dir_name);
        let create_dir_args = FileCreateArgs::make_create_new(
            FileAttributes::new().with_directory(true),
            CreateOptions::new().with_directory_file(true),
        );
        client1
            .create_file(&dir_path, &create_dir_args)
            .await?
            .unwrap_dir()
            .close()
            .await?;

        let directory = client1
            .create_file(
                &dir_path,
                &FileCreateArgs::make_open_existing(
                    DirAccessMask::new().with_list_directory(true).into(),
                ),
            )
            .await?
            .unwrap_dir();
        let directory = Arc::new(directory);
        let mut stream = Directory::watch_stream(&directory, NotifyFilter::all(), false)?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let file_name = format!("{dir_name}\\notify_stream.txt");
        let file_path = share_path.clone().with_path(&file_name);
        let file_args = FileCreateArgs::make_create_new(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        client2
            .create_file(&file_path, &file_args)
            .await?
            .unwrap_file()
            .close()
            .await?;

        let _event = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stream.next(),
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("notify stream ended"))??;

        directory.close().await?;

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(file) = client2.create_file(&file_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }
        if let Ok(dir) = client1.create_file(&dir_path, &cleanup_open).await {
            let dir = dir.unwrap_dir();
            let _ = dir
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = dir.close().await;
        }

        client1.close().await?;
        client2.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_change_notify_cancel() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs change notify cancel test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let dir_name = unique_name("smbench_notify_cancel_dir");
        let dir_path = share_path.clone().with_path(&dir_name);
        let create_dir_args = FileCreateArgs::make_create_new(
            FileAttributes::new().with_directory(true),
            CreateOptions::new().with_directory_file(true),
        );
        client
            .create_file(&dir_path, &create_dir_args)
            .await?
            .unwrap_dir()
            .close()
            .await?;

        let directory = client
            .create_file(
                &dir_path,
                &FileCreateArgs::make_open_existing(
                    DirAccessMask::new().with_list_directory(true).into(),
                ),
            )
            .await?
            .unwrap_dir();
        let directory = Arc::new(directory);

        let cancel = CancellationToken::new();
        let mut stream =
            Directory::watch_stream_cancellable(&directory, NotifyFilter::all(), false, cancel.clone())?;
        // Give the watch loop a moment to send its request before cancelling.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();

        let next = tokio::time::timeout(std::time::Duration::from_secs(15), stream.next()).await;
        match next {
            Ok(next) => {
                if let Some(result) = next {
                    if let Err(err) = result {
                        let msg = err.to_string().to_lowercase();
                        assert!(
                            msg.contains("cancel"),
                            "unexpected cancellation error: {msg}"
                        );
                    }
                }
            }
            Err(err) => {
                if strict_env("SMBENCH_STRICT_NOTIFY_CANCEL") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("Change notify cancel timed out: {err}");
            }
        }

        directory.close().await?;

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(dir) = client.create_file(&dir_path, &cleanup_open).await {
            let dir = dir.unwrap_dir();
            let _ = dir
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = dir.close().await;
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_share_capabilities() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs share capabilities test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let conn = client.get_connection(&server).await?;
        if let Some(info) = conn.conn_info() {
            assert!(
                info.negotiation.caps.notifications(),
                "server should advertise notify capability"
            );
        }

        let ipc_path = UncPath::ipc_share(&server)?;
        client.share_connect(&ipc_path, &user, pass.clone()).await?;
        let tree = client.get_tree(&ipc_path).await?;
        if std::env::var("SMBENCH_STRICT_ENCRYPT_SHARE")
            .ok()
            .as_deref()
            == Some("1")
        {
            assert!(
                tree.share_flags()?.encrypt_data(),
                "expected share encryption flag to be set"
            );
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_query_directory() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs query directory test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let dir_name = unique_name("smbench_query_dir");
        let dir_path = share_path.clone().with_path(&dir_name);
        let create_dir_args = FileCreateArgs::make_create_new(
            FileAttributes::new().with_directory(true),
            CreateOptions::new().with_directory_file(true),
        );
        client
            .create_file(&dir_path, &create_dir_args)
            .await?
            .unwrap_dir()
            .close()
            .await?;

        let file_name = format!("{dir_name}\\query.txt");
        let file_path = share_path.clone().with_path(&file_name);
        let file_args = FileCreateArgs::make_create_new(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        client
            .create_file(&file_path, &file_args)
            .await?
            .unwrap_file()
            .close()
            .await?;

        let directory = client
            .create_file(
                &dir_path,
                &FileCreateArgs::make_open_existing(
                    DirAccessMask::new().with_list_directory(true).into(),
                ),
            )
            .await?
            .unwrap_dir();
        let directory = Arc::new(directory);

        let mut found = false;
        let stream = Directory::query::<FileDirectoryInformation>(&directory, "query.txt").await?;
        stream
            .for_each(|entry| {
                if let Ok(entry) = entry {
                    if entry.file_name.to_string() == "query.txt" {
                        found = true;
                    }
                }
                async {}
            })
            .await;

        assert!(found, "query directory did not return expected file");
        directory.close().await?;

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(file) = client.create_file(&file_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }
        if let Ok(dir) = client.create_file(&dir_path, &cleanup_open).await {
            let dir = dir.unwrap_dir();
            let _ = dir
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = dir.close().await;
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_query_file_info() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs query file info test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let file_name = unique_name("smbench_query_info");
        let file_path = share_path.clone().with_path(&file_name);
        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client
            .create_file(&file_path, &create_args)
            .await?
            .unwrap_file();

        let data = b"query-info";
        file.write_block(data, 0, None).await?;
        file.set_len(data.len() as u64).await?;
        file.flush().await?;

        let basic: FileBasicInformation = file.query_info().await?;
        assert!(
            !basic.file_attributes.directory(),
            "expected non-directory attributes"
        );

        let standard: FileStandardInformation = file.query_info().await?;
        assert!(
            standard.end_of_file >= data.len() as u64,
            "end_of_file too small: {}",
            standard.end_of_file
        );
        assert!(
            !bool::from(standard.directory),
            "expected non-directory standard info"
        );

        file.close().await?;

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(file) = client.create_file(&file_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_query_fs_info() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs query fs info test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let directory = client
            .create_file(
                &share_path,
                &FileCreateArgs::make_open_existing(
                    DirAccessMask::new().with_list_directory(true).into(),
                ),
            )
            .await?
            .unwrap_dir();

        let fs_info: FileFsSizeInformation = directory.query_fs_info().await?;
        assert!(fs_info.bytes_per_sector > 0, "invalid bytes_per_sector");
        assert!(
            fs_info.sectors_per_allocation_unit > 0,
            "invalid sectors_per_allocation_unit"
        );

        let fs_attrs: FileFsAttributeInformation = directory.query_fs_info().await?;
        assert!(
            !fs_attrs.file_system_name.to_string().is_empty(),
            "expected file system name"
        );

        directory.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_block_copy() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs block copy test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let src_name = unique_name("smbench_block_copy_src");
        let dst_name = unique_name("smbench_block_copy_dst");
        let src_path = share_path.clone().with_path(&src_name);
        let dst_path = share_path.clone().with_path(&dst_name);

        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let src = client
            .create_file(&src_path, &create_args)
            .await?
            .unwrap_file();
        let dst = client
            .create_file(&dst_path, &create_args)
            .await?
            .unwrap_file();

        let data = vec![0x5a; 128 * 1024];
        src.write_block(&data, 0, None).await?;
        src.set_len(data.len() as u64).await?;
        src.flush().await?;

        block_copy(src, dst, 4).await?;

        let read_args = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_read(true),
        );
        let file = client.create_file(&dst_path, &read_args).await?;
        let file = file.unwrap_file();
        let mut buf = vec![0u8; data.len()];
        let read = file.read_block(&mut buf, 0, None, true).await?;
        assert_eq!(read, data.len());
        assert_eq!(buf, data);
        file.close().await?;

        let cleanup_open = FileCreateArgs::make_open_existing(
            FileAccessMask::new().with_generic_all(true),
        );
        if let Ok(file) = client.create_file(&src_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }
        if let Ok(file) = client.create_file(&dst_path, &cleanup_open).await {
            let file = file.unwrap_file();
            let _ = file
                .set_info(smb::FileDispositionInformation::default())
                .await;
            let _ = file.close().await;
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_compound_echo() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs compound echo test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let tree = client.get_tree(&share_path).await?;
        let responses = tree
            .send_compound(
                vec![
                    RequestContent::Echo(EchoRequest::default()),
                    RequestContent::Echo(EchoRequest::default()),
                ],
                false,
            )
            .await?;

        assert_eq!(responses.len(), 2);
        for response in responses {
            response.message.content.as_echo()?;
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_multichannel_capability() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs multichannel test");
            return Ok(());
        };

        let enable_multichannel = std::env::var("SMBENCH_ENABLE_MULTICHANNEL")
            .ok()
            .as_deref()
            == Some("1");
        let strict_multichannel = std::env::var("SMBENCH_STRICT_MULTICHANNEL")
            .ok()
            .as_deref()
            == Some("1");

        let mut client_config = ClientConfig::default();
        if enable_multichannel {
            client_config.connection.multichannel = MultiChannelConfig::Always;
        }
        let client = Client::new(client_config);
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let conn = client.get_connection(&server).await?;
        let caps = conn
            .conn_info()
            .map(|info| info.negotiation.caps.multi_channel())
            .unwrap_or(false);

        if enable_multichannel && caps {
            let channels = client.get_channels(&share_path).await?;
            if strict_multichannel {
                assert!(
                    !channels.is_empty(),
                    "expected multichannel connections"
                );
            }
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_ipc_query_network_interfaces() -> Result<()> {
        let Some((server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs IPC interface query test");
            return Ok(());
        };

        let enable_multichannel = std::env::var("SMBENCH_ENABLE_MULTICHANNEL")
            .ok()
            .as_deref()
            == Some("1");
        if !enable_multichannel {
            eprintln!("SMBENCH_ENABLE_MULTICHANNEL not set; skipping IPC interface query test");
            return Ok(());
        }
        let strict_multichannel = std::env::var("SMBENCH_STRICT_MULTICHANNEL")
            .ok()
            .as_deref()
            == Some("1");

        let mut client_config = ClientConfig::default();
        client_config.connection.multichannel = MultiChannelConfig::Always;
        let client = Client::new(client_config);
        client.ipc_connect(&server, &user, pass.clone()).await?;
        let ipc_path = UncPath::ipc_share(&server)?;
        client.share_connect(&ipc_path, &user, pass.clone()).await?;
        let tree = client.get_tree(&ipc_path).await?;
        let ipc_tree = tree.as_ipc_tree()?;
        match ipc_tree.query_network_interfaces().await {
            Ok(interfaces) => {
                assert!(!interfaces.is_empty(), "IPC interface list is empty");
            }
            Err(err) => {
                if strict_multichannel {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("IPC interface query not supported: {err}");
            }
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_ipc_list_shares() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs IPC list shares test");
            return Ok(());
        };

        let client = new_client();
        client.ipc_connect(&server, &user, pass).await?;
        let shares = client.list_shares(&server).await?;
        let share_found = shares.iter().any(|s| {
            s.netname
                .as_ref()
                .map(|name| name.to_string())
                .map(|name| name.trim_end_matches('\0').eq_ignore_ascii_case(&share))
                .unwrap_or(false)
        });
        assert!(share_found, "Share {share} not found in IPC list");
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_dfs_referral() -> Result<()> {
        let Some((_server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs DFS referral test");
            return Ok(());
        };
        let Some(dfs_path) = env::var("SMBENCH_DFS_PATH").ok() else {
            eprintln!("SMBENCH_DFS_PATH not set; skipping smb-rs DFS referral test");
            return Ok(());
        };

        let strict_dfs = std::env::var("SMBENCH_STRICT_DFS")
            .ok()
            .as_deref()
            == Some("1");

        let client = new_client();
        let unc = UncPath::from_str(&dfs_path)?;
        client.share_connect(&unc, &user, pass).await?;
        let tree = client.get_tree(&unc).await?;
        if !tree.is_dfs_root()? {
            if strict_dfs {
                return Err(anyhow::anyhow!(
                    "Tree {} is not marked as DFS root",
                    unc
                ));
            }
            eprintln!("DFS not enabled for {}; skipping referral validation", unc);
            client.close().await?;
            return Ok(());
        }

        let dfs_root = tree.as_dfs_tree()?;
        let referrals = dfs_root.dfs_get_referrals(&dfs_path).await?;
        assert!(
            !referrals.referral_entries.is_empty(),
            "DFS referral response is empty"
        );
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_dfs_referral_ex() -> Result<()> {
        let Some((_server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs DFS referral ex test");
            return Ok(());
        };
        let Some(dfs_path) = env::var("SMBENCH_DFS_PATH").ok() else {
            eprintln!("SMBENCH_DFS_PATH not set; skipping smb-rs DFS referral ex test");
            return Ok(());
        };

        let strict_dfs = std::env::var("SMBENCH_STRICT_DFS")
            .ok()
            .as_deref()
            == Some("1");

        let client = new_client();
        let unc = UncPath::from_str(&dfs_path)?;
        client.share_connect(&unc, &user, pass).await?;
        let tree = client.get_tree(&unc).await?;
        if !tree.is_dfs_root()? {
            if strict_dfs {
                return Err(anyhow::anyhow!(
                    "Tree {} is not marked as DFS root",
                    unc
                ));
            }
            eprintln!("DFS not enabled for {}; skipping referral ex validation", unc);
            client.close().await?;
            return Ok(());
        }

        let dfs_root = tree.as_dfs_tree()?;
        let request = ReqGetDfsReferralEx::new(ReferralLevel::V4, dfs_path.as_str(), "");
        let referrals = dfs_root.dfs_get_referrals(&dfs_path).await?;
        assert!(
            !referrals.referral_entries.is_empty(),
            "DFS referral response is empty"
        );

        // Validate the EX request is accepted by the server (if supported).
        match dfs_root.dfs_get_referrals_ex(request).await {
            Ok(resp) => {
                assert!(
                    !resp.referral_entries.is_empty(),
                    "DFS referral ex response is empty"
                );
            }
            Err(err) => {
                if strict_dfs {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("DFS referral ex not supported: {err}");
            }
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_pipe_peek() -> Result<()> {
        let Some((server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL pipe peek test");
            return Ok(());
        };

        let client = new_client();
        client.ipc_connect(&server, &user, pass).await?;
        let pipe = client.open_pipe(&server, "srvsvc").await?;
        match pipe.fsctl(PipePeekRequest(())).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL pipe peek not supported: {err}");
            }
        }
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_pipe_wait() -> Result<()> {
        let Some((server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL pipe wait test");
            return Ok(());
        };

        let client = new_client();
        client.ipc_connect(&server, &user, pass).await?;
        let ipc_path = UncPath::ipc_share(&server)?;
        let tree = client.get_tree(&ipc_path).await?;
        let request = PipeWaitRequest {
            timeout: 0,
            timeout_specified: Boolean::from(false),
            name: "srvsvc".into(),
        };
        match tree.fsctl(request).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL pipe wait not supported: {err}");
            }
        }
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_pipe_transceive() -> Result<()> {
        let Some((server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL pipe transceive test");
            return Ok(());
        };

        let client = new_client();
        client.ipc_connect(&server, &user, pass).await?;
        let pipe = client.open_pipe(&server, "srvsvc").await?;
        let mut srvsvc: SrvSvc<_> = pipe.bind().await?;
        let shares: Vec<smb_rpc::interface::ShareInfo1> =
            srvsvc.netr_share_enum(&server).await?;
        assert!(!shares.is_empty(), "srvsvc returned empty share list");
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_srv_enumerate_snapshots() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL enumerate snapshots test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let file = create_file_with_data(
            &client,
            &share_path,
            &unique_name("smbench_fsctl_snapshots"),
            b"smbench-snapshots",
        )
        .await?;
        match file.fsctl(SrvEnumerateSnapshotsRequest(())).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL enumerate snapshots not supported: {err}");
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_srv_read_hash() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL read hash test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
        let file_name = unique_name("smbench_fsctl_read_hash");
        let _file = create_file_with_data(&client, &share_path, &file_name, b"smbench-read-hash")
            .await?;

        let fsctl_access = FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_read_attributes(true);
        let mut open_args = FileCreateArgs::make_open_existing(fsctl_access);
        open_args.options.set_non_directory_file(true);
        let file = client
            .create_file(&share_path.clone().with_path(&file_name), &open_args)
            .await?
            .unwrap_file();

        let req = SrvReadHashReq::new(1, SrvHashRetrievalType::HashBased, 0, 4096);
        match file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_READ_HASH") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL read hash not supported: {err}");
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_lmr_request_resiliency() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL resiliency test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
        let file = create_file_with_data(
            &client,
            &share_path,
            &unique_name("smbench_fsctl_resiliency"),
            b"smbench-resiliency",
        )
        .await?;

        let req = NetworkResiliencyRequest::new(1000);
        match file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL resiliency not supported: {err}");
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_validate_negotiate_info() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL validate negotiate test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let conn = client.get_connection(&server).await?;
        let Some(conn_info) = conn.conn_info() else {
            return Err(anyhow::anyhow!("Missing connection info for validate negotiate"));
        };
        let req = ValidateNegotiateInfoRequest {
            capabilities: u32::from_le_bytes(conn_info.client_capabilities.into_bytes()),
            guid: conn_info.client_guid,
            security_mode: conn_info.client_security_mode,
            dialects: conn_info.client_dialects.clone(),
        };

        let tree = client.get_tree(&share_path).await?;
        match tree.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_VALIDATE_NEGOTIATE") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL validate negotiate not supported: {err}");
                let _ = client.close().await;
                return Ok(());
            }
        }
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_offload_read() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL offload read test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
        let file_name = unique_name("smbench_fsctl_offload");
        let _file =
            create_file_with_data(&client, &share_path, &file_name, &vec![0x7a; 8192]).await?;

        let fsctl_access = FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_read_attributes(true);
        let mut open_args = FileCreateArgs::make_open_existing(fsctl_access);
        open_args.options.set_non_directory_file(true);
        let file = client
            .create_file(&share_path.clone().with_path(&file_name), &open_args)
            .await?
            .unwrap_file();

        let sector_info: FileFsSectorSizeInformation = match file.query_fs_info().await {
            Ok(info) => info,
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_OFFLOAD_READ") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL offload read preflight failed: {err}");
                let _ = file.close().await;
                let _ = client.close().await;
                return Ok(());
            }
        };
        let alignment = sector_info
            .effective_physical_bytes_per_sector_for_atomicity
            .max(512) as u64;
        let copy_len = alignment * 4;
        if let Err(err) = file.set_len(copy_len).await {
            if fsctl_strict() || strict_env("SMBENCH_STRICT_OFFLOAD_READ") {
                return Err(anyhow::anyhow!(err));
            }
            eprintln!("FSCTL offload read preflight failed: {err}");
            let _ = file.close().await;
            let _ = client.close().await;
            return Ok(());
        }

        let req = OffloadReadRequest {
            flags: 0,
            token_time_to_live: 0,
            file_offset: 0,
            copy_length: copy_len,
        };
        match file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_OFFLOAD_READ") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL offload read not supported: {err}");
                let _ = file.close().await;
                let _ = client.close().await;
                return Ok(());
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_file_level_trim() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL file level trim test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
        let file_name = unique_name("smbench_fsctl_trim");
        let _file =
            create_file_with_data(&client, &share_path, &file_name, &vec![0xaa; 8192]).await?;

        let fsctl_access = FileAccessMask::new()
            .with_file_write_data(true)
            .with_file_write_attributes(true)
            .with_file_read_attributes(true);
        let mut open_args = FileCreateArgs::make_open_existing(fsctl_access);
        open_args.options.set_non_directory_file(true);
        open_args.options.set_no_intermediate_buffering(true);
        open_args.options.set_write_through(true);
        let file = client
            .create_file(&share_path.clone().with_path(&file_name), &open_args)
            .await?
            .unwrap_file();

        let sector_info: FileFsSectorSizeInformation = file.query_fs_info().await?;
        assert!(
            sector_info.flags.trim_enabled(),
            "FSCTL file level trim requires trim support"
        );
        let alignment = sector_info
            .effective_physical_bytes_per_sector_for_atomicity
            .max(512) as u64;
        let trim_len = alignment * 2;
        file.set_len(trim_len).await?;

        let req = FileLevelTrimRequest {
            ranges: vec![FileLevelTrimRange {
                offset: 0,
                length: trim_len,
            }],
        };
        match file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_FILE_LEVEL_TRIM") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL file level trim not supported: {err}");
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_set_reparse_point() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL set reparse test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let target_name = unique_name("smbench_reparse_target");
        let link_name = unique_name("smbench_reparse_link");
        let link_path = share_path.clone().with_path(&link_name);

        create_file_with_data(&client, &share_path, &target_name, b"reparse-target").await?;
        let link_file = client
            .create_file(
                &link_path,
                &FileCreateArgs::make_overwrite(
                    FileAttributes::new().with_reparse_point(true),
                    CreateOptions::new()
                        .with_non_directory_file(true)
                        .with_open_reparse_point(true),
                ),
            )
            .await?
            .unwrap_file();
        link_file.close().await?;

        let fsctl_access = FileAccessMask::new()
            .with_file_write_data(true)
            .with_file_write_attributes(true)
            .with_file_read_attributes(true);
        let mut open_args = FileCreateArgs::make_open_existing(fsctl_access);
        open_args.options = CreateOptions::new()
            .with_non_directory_file(true)
            .with_open_reparse_point(true);
        let link_file = client
            .create_file(&link_path, &open_args)
            .await?
            .unwrap_file();

        let target_unc = format!(r"\\{}\{}\{}", server, share, target_name);
        let reparse_data = build_symlink_reparse_data(&target_unc, false);
        let req = SetReparsePointRequest::new(0xA000000C, None, reparse_data);
        match link_file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_REPARSE") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL set reparse point not supported: {err}");
            }
        }
        link_file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_srv_copychunk() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL copychunk test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let src_name = unique_name("smbench_fsctl_copychunk_src");
        let dst_name = unique_name("smbench_fsctl_copychunk_dst");
        let src = create_file_with_data(&client, &share_path, &src_name, b"copychunk")
            .await?;
        let dst = create_file_with_data(&client, &share_path, &dst_name, &[]).await?;

        let resume_key = src.fsctl(SrvRequestResumeKeyRequest(())).await?;
        let chunks = vec![SrvCopychunkItem {
            source_offset: 0,
            target_offset: 0,
            length: 9,
        }];
        let req = SrvCopychunkCopy {
            source_key: resume_key.resume_key,
            chunks,
        };
        match dst.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL copychunk not supported: {err}");
            }
        }
        src.close().await?;
        dst.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_srv_copychunk_write() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL copychunk write test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let src_name = unique_name("smbench_fsctl_copychunkw_src");
        let dst_name = unique_name("smbench_fsctl_copychunkw_dst");
        let src = create_file_with_data(&client, &share_path, &src_name, b"copychunkw")
            .await?;
        let dst = create_file_with_data(&client, &share_path, &dst_name, &[]).await?;

        let resume_key = src.fsctl(SrvRequestResumeKeyRequest(())).await?;
        let chunks = vec![SrvCopychunkItem {
            source_offset: 0,
            target_offset: 0,
            length: 10,
        }];
        let req = SrvCopychunkCopy {
            source_key: resume_key.resume_key,
            chunks,
        };
        match dst.fsctl(SrvCopyChunkCopyWrite(req)).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL copychunk write not supported: {err}");
            }
        }
        src.close().await?;
        dst.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_srv_copy_api() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs srv_copy API test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let src_name = unique_name("smbench_srv_copy_src");
        let dst_name = unique_name("smbench_srv_copy_dst");
        let src = create_file_with_data(&client, &share_path, &src_name, b"srv-copy").await?;
        let dst = create_file_with_data(&client, &share_path, &dst_name, &[]).await?;

        match dst.srv_copy(&src).await {
            Ok(()) => {}
            Err(err) => {
                if fsctl_strict() {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("srv_copy not supported: {err}");
            }
        }

        src.close().await?;
        dst.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_srv_read_hash_v2() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL read hash v2 test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
        let conn = client.get_connection(&server).await?;
        let Some(conn_info) = conn.conn_info() else {
            return Err(anyhow::anyhow!("Missing connection info for read hash v2"));
        };
        if conn_info.negotiation.dialect_rev < Dialect::Smb030 {
            eprintln!("Dialect < SMB 3.0; skipping read hash v2 test");
            client.close().await?;
            return Ok(());
        }

        let file_name = unique_name("smbench_fsctl_read_hash_v2");
        let _file = create_file_with_data(
            &client,
            &share_path,
            &file_name,
            b"smbench-read-hash-v2",
        )
        .await?;

        let fsctl_access = FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_read_attributes(true);
        let mut open_args = FileCreateArgs::make_open_existing(fsctl_access);
        open_args.options.set_non_directory_file(true);
        let file = client
            .create_file(&share_path.clone().with_path(&file_name), &open_args)
            .await?
            .unwrap_file();

        let req = SrvReadHashReq::new(2, SrvHashRetrievalType::HashBased, 0, 4096);
        match file.fsctl(req).await {
            Ok(_resp) => {}
            Err(err) => {
                if fsctl_strict() || strict_env("SMBENCH_STRICT_READ_HASH") {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL read hash v2 not supported: {err}");
            }
        }
        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_dfs_referral_ex_with_site() -> Result<()> {
        let Some((_server, _share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs DFS referral ex site test");
            return Ok(());
        };
        let Some(dfs_path) = env::var("SMBENCH_DFS_PATH").ok() else {
            eprintln!("SMBENCH_DFS_PATH not set; skipping smb-rs DFS referral ex site test");
            return Ok(());
        };
        let Some(site_name) = env::var("SMBENCH_DFS_SITE").ok() else {
            eprintln!("SMBENCH_DFS_SITE not set; skipping smb-rs DFS referral ex site test");
            return Ok(());
        };

        let strict_dfs = std::env::var("SMBENCH_STRICT_DFS")
            .ok()
            .as_deref()
            == Some("1");

        let client = new_client();
        let unc = UncPath::from_str(&dfs_path)?;
        client.share_connect(&unc, &user, pass).await?;
        let tree = client.get_tree(&unc).await?;
        if !tree.is_dfs_root()? {
            if strict_dfs {
                return Err(anyhow::anyhow!(
                    "Tree {} is not marked as DFS root",
                    unc
                ));
            }
            eprintln!("DFS not enabled for {}; skipping referral ex site validation", unc);
            client.close().await?;
            return Ok(());
        }

        let dfs_root = tree.as_dfs_tree()?;
        let request = ReqGetDfsReferralEx::new(ReferralLevel::V4, dfs_path.as_str(), &site_name);
        match dfs_root.dfs_get_referrals_ex(request).await {
            Ok(resp) => {
                assert!(
                    !resp.referral_entries.is_empty(),
                    "DFS referral ex site response is empty"
                );
            }
            Err(err) => {
                if strict_dfs {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("DFS referral ex site not supported: {err}");
            }
        }

        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_resume_key() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL resume key test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let file_name = unique_name("smbench_fsctl_resume_key");
        let file_path = share_path.clone().with_path(&file_name);
        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client
            .create_file(&file_path, &create_args)
            .await?
            .unwrap_file();
        let data = b"smbench-fsctl";
        file.write_block(data, 0, None).await?;
        file.set_len(data.len() as u64).await?;
        file.flush().await?;

        let resume_key = file.fsctl(SrvRequestResumeKeyRequest(())).await?;
        assert!(
            resume_key.context.is_empty(),
            "FSCTL resume key context expected empty"
        );

        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_fsctl_query_allocated_ranges() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs FSCTL allocated ranges test");
            return Ok(());
        };

        let strict_fsctl = std::env::var("SMBENCH_STRICT_FSCTL")
            .ok()
            .as_deref()
            == Some("1");

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let file_name = unique_name("smbench_fsctl_ranges");
        let file_path = share_path.clone().with_path(&file_name);
        let create_args = FileCreateArgs::make_overwrite(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client
            .create_file(&file_path, &create_args)
            .await?
            .unwrap_file();
        let data = vec![0x4f; 64 * 1024];
        file.write_block(&data, 0, None).await?;
        file.set_len(data.len() as u64).await?;
        file.flush().await?;

        let req = QueryAllocRangesItem {
            offset: 0,
            len: data.len() as u64,
        };
        match file.fsctl(req).await {
            Ok(ranges) => {
                assert!(
                    !ranges.is_empty(),
                    "FSCTL allocated ranges returned empty list"
                );
            }
            Err(err) => {
                if strict_fsctl {
                    return Err(anyhow::anyhow!(err));
                }
                eprintln!("FSCTL allocated ranges not supported: {err}");
            }
        }

        file.close().await?;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_smb_rs_negotiated_io_limits() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs negotiated I/O limits test");
            return Ok(());
        };

        let client = new_client();
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass.clone()).await?;

        let conn = client.get_connection(&server).await?;
        let Some(info) = conn.conn_info() else {
            return Err(anyhow::anyhow!("Missing connection info for negotiated limits"));
        };
        assert!(info.negotiation.max_read_size > 0);
        assert!(info.negotiation.max_write_size > 0);

        let io_len = min(
            info.negotiation.max_write_size.min(info.negotiation.max_read_size) as usize,
            256 * 1024,
        );
        let data = vec![0x5a; io_len];

        let file_name = unique_name("smbench_negotiated_io");
        let file_path = share_path.clone().with_path(&file_name);
        let file = client
            .create_file(
                &file_path,
                &FileCreateArgs::make_overwrite(
                    FileAttributes::new(),
                    CreateOptions::new().with_non_directory_file(true),
                ),
            )
            .await?
            .unwrap_file();

        let written = file.write_block(&data, 0, None).await?;
        assert_eq!(written, data.len(), "short write");
        file.flush().await?;

        let mut read_buf = vec![0u8; data.len()];
        let read = file.read_block(&mut read_buf, 0, None, false).await?;
        assert_eq!(read, data.len(), "short read");
        assert_eq!(read_buf, data);

        file.close().await?;
        client.close().await?;
        Ok(())
    }
}
