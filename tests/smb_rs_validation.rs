#[cfg(feature = "smb-rs-backend")]
mod smb_rs_validation {
    use std::env;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::Result;
    use smb::{
        Client, ClientConfig, ConnectionConfig, CreateOptions, Dialect, File, FileAccessMask,
        FileAttributes, FileCreateArgs, GetLen, LeaseState, OplockLevel, RequestLease,
        RequestLeaseV1, RequestLeaseV2, UncPath,
    };
    use smb::resource::file_util::SetLen;

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
    #[ignore]
    async fn test_smb_rs_oplocks() -> Result<()> {
        let Some((server, share, user, pass)) = smb_env() else {
            eprintln!("SMB env not set; skipping smb-rs lease test");
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

        let conn1 = client1.connect(&server).await?;
        let mut lease_break_rx = conn1.subscribe_lease_breaks()?;
        let mut oplock_break_rx = conn1.subscribe_oplock_breaks()?;

        let share_path = UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        client1.share_connect(&share_path, &user, pass.clone()).await?;
        client2.share_connect(&share_path, &user, pass).await?;

        let mut options = CreateOptions::new();
        options.set_non_directory_file(true);
        options.set_write_through(true);
        let file_name = unique_name("smbench_lease");
        let file_path = share_path.clone().with_path(&file_name);

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

        let share_access = smb::ShareAccessFlags::new().with_read(true);
        let mut create_args = FileCreateArgs::make_overwrite(FileAttributes::new(), options)
            .with_oplock_level(OplockLevel::Exclusive)
            .with_lease_request(lease_request_v2.clone())
            .with_share_access(share_access);

        let mut file1: File = match client1.create_file(&file_path, &create_args).await?.try_into() {
            Ok(file) => file,
            Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
        };

        let mut lease_granted = file1.granted_lease().is_some();
        if !lease_granted {
            file1.close().await?;
            create_args = create_args.with_lease_request(lease_request_v1);
            file1 = match client1.create_file(&file_path, &create_args).await?.try_into() {
                Ok(file) => file,
                Err((err, _resource)) => return Err(anyhow::anyhow!(err)),
            };
            lease_granted = file1.granted_lease().is_some();
        }

        if !lease_granted {
            file1.close().await?;
            let oplock_args = FileCreateArgs::make_overwrite(FileAttributes::new(), options)
                .with_oplock_level(OplockLevel::Exclusive)
                .with_share_access(share_access);
            file1 = match client1.create_file(&file_path, &oplock_args).await?.try_into() {
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
                let open_args = FileCreateArgs::make_overwrite(FileAttributes::new(), open_options)
                    .with_share_access(smb::ShareAccessFlags::new());
                let resource2 = client2.create_file(&file_path, &open_args).await?;
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
        let event = tokio::time::timeout(std::time::Duration::from_secs(15), lease_break_rx.recv())
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for lease break"))??;

            assert_eq!(event.lease_key, lease_key_guid);

            if event.ack_required {
                conn1
                    .acknowledge_lease_break(event.lease_key, event.new_state)
                    .await?;
            }
        } else {
        let event = tokio::time::timeout(std::time::Duration::from_secs(15), oplock_break_rx.recv())
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for oplock break"))??;
            let expected_file_id = file1.file_id_for_oplock()?;
            assert_eq!(event.file_id, expected_file_id);
            file1.acknowledge_oplock_break(event.new_level).await?;
        }
        breaker.await??;

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
}
