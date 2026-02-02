#[cfg(feature = "smb-rs-backend")]
mod smb_rs_validation {
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
    use smb_msg::{EchoRequest, NotifyFilter, RequestContent};
    use smb_fscc::{
        DirAccessMask, FileBasicInformation, FileDirectoryInformation, FileFsAttributeInformation,
        FileFsSizeInformation, FileStandardInformation,
    };
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

    #[tokio::test]
    async fn test_smb_rs_connection() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs connection test");
            return Ok(());
        };

        let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

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

        let client1 = Client::new(ClientConfig::default());
        let client2 = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

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

        let seed_client = Client::new(ClientConfig::default());
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
                let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;
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

        let seed_client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
        client.share_connect(&share_path, &user, pass).await?;
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

        let seed_client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

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
            smb::DurableHandleRequestV2::new(0, flags, smb::Guid::generate());
        args = args.with_durable_handle_v2(durable);

        let resource = client.create_file(&file_path, &args).await?;
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

        let client1 = Client::new(ClientConfig::default());
        let client2 = Client::new(ClientConfig::default());
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

        let file_name = format!("{dir_name}\\notify.txt");
        let file_path = share_path.clone().with_path(&file_name);
        let file_args = FileCreateArgs::make_create_new(
            FileAttributes::new(),
            CreateOptions::new().with_non_directory_file(true),
        );
        let file = client2.create_file(&file_path, &file_args).await?;
        file.unwrap_file().close().await?;

        let notify_result = notify_task.await??;
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

        let client1 = Client::new(ClientConfig::default());
        let client2 = Client::new(ClientConfig::default());
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
            std::time::Duration::from_secs(10),
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
    async fn test_smb_rs_share_capabilities() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs share capabilities test");
            return Ok(());
        };

        let client = Client::new(ClientConfig::default());
        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client.share_connect(&share_path, &user, pass).await?;

        let conn = client.get_connection(&server).await?;
        if let Some(info) = conn.conn_info() {
            assert!(
                info.negotiation.caps.notifications(),
                "server should advertise notify capability"
            );
        }

        let tree = client.get_tree(&share_path).await?;
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

        let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
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

        let client = Client::new(ClientConfig::default());
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
}
