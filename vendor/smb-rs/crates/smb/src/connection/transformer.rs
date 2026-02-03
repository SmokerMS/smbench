use crate::session::{SessionAndChannel, SessionInfo};
use crate::sync_helpers::*;
use crate::{compression::*, msg_handler::*};
use binrw::prelude::*;
use maybe_async::*;
use smb_msg::*;
use smb_transport::IoVec;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use super::connection_info::ConnectionInfo;

/// The [`Transformer`] structure is responsible for transforming messages to and from bytes,
/// send over NetBios TCP connection.
///
/// See [`Transformer::transform_outgoing`] and [`Transformer::transform_incoming`] for transformation functions.
#[derive(Default)]
pub struct Transformer {
    /// Sessions opened from this connection.
    // This structure is performance-critical, so it uses RwLock to allow concurrent reads.
    // Writes are only done when a session is started or ended - which is *very* rare in high-performance scenarios.
    sessions: RwLock<HashMap<u64, Arc<RwLock<SessionAndChannel>>>>,

    config: RwLock<TransformerConfig>,
}

#[derive(Default, Debug)]
struct TransformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,
}

#[maybe_async(AFIT)]
impl Transformer {
    /// Notifies that the connection negotiation has been completed,
    /// with the given [`ConnectionInfo`].
    pub async fn negotiated(&self, neg_info: &ConnectionInfo) -> crate::Result<()> {
        {
            let config = self.config.read().await?;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await?;
        if neg_info.dialect.supports_compression() && neg_info.config.compression_enabled {
            let compress = neg_info
                .negotiation
                .compression
                .as_ref()
                .map(|c| (Compressor::new(c), Decompressor::new(c)));
            config.compress = compress;
        }

        config.negotiated = true;

        Ok(())
    }

    /// Notifies that a session has started.
    pub async fn session_started(
        &self,
        session: &Arc<RwLock<SessionAndChannel>>,
    ) -> crate::Result<()> {
        let rconfig = self.config.read().await?;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = { session.read().await?.session_id };
        self.sessions
            .write()
            .await?
            .insert(session_id, session.clone());

        log::trace!(
            "Session {} started and inserted to worker {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// Notifies that a session has ended.
    pub async fn session_ended(
        &self,
        session: &Arc<RwLock<SessionAndChannel>>,
    ) -> crate::Result<()> {
        let session_id = { session.read().await?.session_id };
        self.sessions
            .write()
            .await?
            .remove(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;

        log::trace!(
            "Session {} ended and removed from worker {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// (Internal)
    ///
    /// Locates the current channel per the provded session ID,
    /// and invokes the provided closure with the channel information.
    ///
    /// Note: this function WILL deadlock if any lock attempt is performed within the closure on `self.sessions`.
    #[maybe_async]
    #[inline]
    async fn _with_channel<F, R>(&self, session_id: u64, f: F) -> crate::Result<R>
    where
        F: FnOnce(&SessionAndChannel) -> crate::Result<R>,
    {
        let sessions = self.sessions.read().await?;
        let session = sessions
            .get(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;
        let session = session.read().await?;
        f(&session)
    }

    /// (Internal)
    ///
    /// Locates the current session per the provided session ID,
    /// and invokes the provided closure with the session information.
    ///
    /// Note: this function WILL deadlock if any lock attempt is performed within the closure on `self.sessions`.
    #[maybe_async]
    #[inline]
    async fn _with_session<F, R>(&self, session_id: u64, f: F) -> crate::Result<R>
    where
        F: FnOnce(&SessionInfo) -> crate::Result<R>,
    {
        let sessions = self.sessions.read().await?;
        let session = sessions
            .get(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;
        let session = session.read().await?;
        let session_info = session.session.read().await?;
        f(&session_info)
    }

    /// Transforms an outgoing message to a raw SMB message.
    pub async fn transform_outgoing(&self, mut msg: OutgoingMessage) -> crate::Result<IoVec> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let session_id = msg.message.header.session_id;

        let mut outgoing_data = IoVec::default();
        // Plain header + content
        {
            let buffer = outgoing_data.add_owned(Vec::with_capacity(Header::STRUCT_SIZE));
            msg.message.write(&mut Cursor::new(buffer))?;
        }
        // Additional data, if any
        if msg.additional_data.as_ref().is_some_and(|d| !d.is_empty()) {
            outgoing_data.add_shared(msg.additional_data.unwrap().clone());
        }

        // 1. Sign
        if should_sign {
            debug_assert!(
                !should_encrypt,
                "Should not sign and encrypt at the same time!"
            );

            let mut signer = self
                ._with_channel(session_id, |session| {
                    let channel_info =
                        session
                            .channel
                            .as_ref()
                            .ok_or(crate::Error::TranformFailed(TransformError {
                                outgoing: true,
                                phase: TransformPhase::SignVerify,
                                session_id: Some(session_id),
                                why: "Message is required to be signed, but no channel is set up!",
                                msg_id: Some(msg.message.header.message_id),
                            }))?;

                    Ok(channel_info.signer()?.clone())
                })
                .await?;

            signer.sign_message(&mut msg.message.header, &mut outgoing_data)?;

            log::debug!(
                "Message #{} signed (signature={}).",
                msg.message.header.message_id,
                msg.message.header.signature
            );
        };

        // 2. Compress
        const COMPRESSION_THRESHOLD: usize = 1024;
        outgoing_data = {
            if msg.compress && outgoing_data.total_size() > COMPRESSION_THRESHOLD {
                let rconfig = self.config.read().await?;
                if let Some(compress) = &rconfig.compress {
                    // Build a vector of the entire data. In the future, this may be optimized to avoid copying.
                    // currently, there's not chained compression, and copy will occur anyway.
                    outgoing_data.consolidate();
                    let compressed = compress.0.compress(outgoing_data.first().unwrap())?;

                    let mut compressed_result = IoVec::default();
                    let write_compressed =
                        compressed_result.add_owned(Vec::with_capacity(compressed.total_size()));
                    compressed.write(&mut Cursor::new(write_compressed))?;
                    compressed_result
                } else {
                    outgoing_data
                }
            } else {
                outgoing_data
            }
        };

        // 3. Encrypt
        if should_encrypt {
            let mut encryptor = self
                ._with_session(session_id, |session| {
                    let encryptor = session.encryptor()?.ok_or(crate::Error::TranformFailed(
                        TransformError {
                            outgoing: true,
                            phase: TransformPhase::EncryptDecrypt,
                            session_id: Some(session_id),
                            why: "Message is required to be encrypted, but no encryptor is set up!",
                            msg_id: Some(msg.message.header.message_id),
                        },
                    ))?;
                    Ok(encryptor.clone())
                })
                .await?;

            debug_assert!(should_encrypt && !should_sign);

            let encrypted_header = encryptor.encrypt_message(&mut outgoing_data, session_id)?;

            let write_encryption_header =
                outgoing_data.insert_owned(0, Vec::with_capacity(EncryptedHeader::STRUCTURE_SIZE));

            encrypted_header.write(&mut Cursor::new(write_encryption_header))?;
        }

        Ok(outgoing_data)
    }

    /// Transforms multiple outgoing messages to a single compounded SMB message buffer.
    pub async fn transform_outgoing_compound(
        &self,
        mut msgs: Vec<OutgoingMessage>,
    ) -> crate::Result<IoVec> {
        if msgs.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "Compound message list is empty".to_string(),
            ));
        }

        let should_encrypt = msgs[0].encrypt;
        let should_compress = msgs[0].compress;
        for msg in &msgs {
            if msg.encrypt != should_encrypt || msg.compress != should_compress {
                return Err(crate::Error::InvalidArgument(
                    "Compound messages must share encrypt/compress settings".to_string(),
                ));
            }
        }

        let session_id = msgs[0].message.header.session_id;
        let mut message_sizes = Vec::with_capacity(msgs.len());

        for msg in msgs.iter_mut() {
            msg.message.header.next_command = 0;
            let raw = Self::serialize_plain_request(&msg.message, msg.additional_data.as_deref())?;
            message_sizes.push(raw.len());
        }

        let mut offsets = Vec::with_capacity(msgs.len());
        let mut total_len = 0usize;
        for (idx, size) in message_sizes.iter().enumerate() {
            offsets.push(total_len);
            let padded = if idx + 1 == message_sizes.len() {
                *size
            } else {
                Self::align8(*size)
            };
            total_len += padded;
        }

        let msg_count = msgs.len();
        let mut compound = Vec::with_capacity(total_len);
        for (idx, msg) in msgs.iter_mut().enumerate() {
            let is_last = idx + 1 == msg_count;
            let next_command = if is_last {
                0
            } else {
                Self::align8(message_sizes[idx]) as u32
            };
            msg.message.header.next_command = next_command;

            let raw = Self::serialize_plain_request(&msg.message, msg.additional_data.as_deref())?;
            let raw_len = raw.len();
            compound.extend_from_slice(&raw);

            if !is_last {
                let padded = Self::align8(raw_len);
                if padded > raw_len {
                    compound.resize(compound.len() + (padded - raw_len), 0);
                }
            }
        }

        if msgs[0].message.header.flags.signed() {
            debug_assert!(
                !should_encrypt,
                "Should not sign and encrypt at the same time!"
            );

            let mut signer = self
                ._with_channel(session_id, |session| {
                    let channel_info =
                        session
                            .channel
                            .as_ref()
                            .ok_or(crate::Error::TranformFailed(TransformError {
                                outgoing: true,
                                phase: TransformPhase::SignVerify,
                                session_id: Some(session_id),
                                why: "Message is required to be signed, but no channel is set up!",
                                msg_id: Some(msgs[0].message.header.message_id),
                            }))?;

                    Ok(channel_info.signer()?.clone())
                })
                .await?;

            for (idx, msg) in msgs.iter_mut().enumerate() {
                let start = offsets[idx];
                let len = if idx + 1 == msg_count {
                    message_sizes[idx]
                } else {
                    Self::align8(message_sizes[idx])
                };
                let mut iovec = IoVec::from(compound[start..start + len].to_vec());
                signer.sign_message(&mut msg.message.header, &mut iovec)?;

                let mut header_writer =
                    Cursor::new(&mut compound[start..start + Header::STRUCT_SIZE]);
                msg.message.header.write(&mut header_writer)?;
            }
        }

        let mut outgoing_data = IoVec::from(compound);
        const COMPRESSION_THRESHOLD: usize = 1024;
        if should_compress && outgoing_data.total_size() > COMPRESSION_THRESHOLD {
            let rconfig = self.config.read().await?;
            if let Some(compress) = &rconfig.compress {
                outgoing_data.consolidate();
                let compressed = compress.0.compress(outgoing_data.first().unwrap())?;

                let mut compressed_result = IoVec::default();
                let write_compressed =
                    compressed_result.add_owned(Vec::with_capacity(compressed.total_size()));
                compressed.write(&mut Cursor::new(write_compressed))?;
                outgoing_data = compressed_result;
            }
        }

        if should_encrypt {
            let mut encryptor = self
                ._with_session(session_id, |session| {
                    let encryptor = session.encryptor()?.ok_or(crate::Error::TranformFailed(
                        TransformError {
                            outgoing: true,
                            phase: TransformPhase::EncryptDecrypt,
                            session_id: Some(session_id),
                            why: "Message is required to be encrypted, but no encryptor is set up!",
                            msg_id: Some(msgs[0].message.header.message_id),
                        },
                    ))?;
                    Ok(encryptor.clone())
                })
                .await?;

            let encrypted_header = encryptor.encrypt_message(&mut outgoing_data, session_id)?;
            let write_encryption_header =
                outgoing_data.insert_owned(0, Vec::with_capacity(EncryptedHeader::STRUCTURE_SIZE));
            encrypted_header.write(&mut Cursor::new(write_encryption_header))?;
        }

        Ok(outgoing_data)
    }

    /// Transforms an incoming message buffer to one or more [`IncomingMessage`] instances.
    pub async fn transform_incoming(&self, data: Vec<u8>) -> crate::Result<Vec<IncomingMessage>> {
        let parsed = Response::try_from(data.as_ref());
        let (raw, form) = match parsed {
            Ok(message) => {
                let mut form = MessageForm::default();

                // 3. Decrypt
                let (message, raw) = if let Response::Encrypted(encrypted_message) = message {
                    let session_id = encrypted_message.header.session_id;

                    let mut decryptor = self
                        ._with_session(session_id, |session| {
                            let decryptor = session.decryptor()?.ok_or(crate::Error::TranformFailed(
                                TransformError {
                                    outgoing: false,
                                    phase: TransformPhase::EncryptDecrypt,
                                    session_id: Some(session_id),
                                    why: "Message is required to be encrypted, but no decryptor is set up!",
                                    msg_id: None,
                                },
                            ))?;
                            Ok(decryptor.clone())
                        })
                        .await?;
                    form.encrypted = true;
                    decryptor.decrypt_message(encrypted_message)?
                } else {
                    (message, data)
                };

                // 2. Decompress
                debug_assert!(!matches!(message, Response::Encrypted(_)));
                let (_message, raw) = if let Response::Compressed(compressed_message) = message {
                    let rconfig = self.config.read().await?;
                    form.compressed = true;
                    match &rconfig.compress {
                        Some(compress) => compress.1.decompress(&compressed_message)?,
                        None => {
                            return Err(crate::Error::TranformFailed(TransformError {
                                outgoing: false,
                                phase: TransformPhase::CompressDecompress,
                                session_id: None,
                                why: "Compression is requested, but no decompressor is set up!",
                                msg_id: None,
                            }));
                        }
                    }
                } else {
                    (message, raw)
                };

                (raw, form)
            }
            Err(err) => {
                if data.len() >= 4 && data[0..4] == [0xFE, b'S', b'M', b'B'] {
                    (data, MessageForm::default())
                } else {
                    return Err(err.into());
                }
            }
        };

        let mut responses = Vec::new();
        for (mut message, raw_msg) in self.split_plain_responses(&raw)? {
            let iovec = IoVec::from(raw_msg);
            let mut msg_form = MessageForm {
                compressed: form.compressed,
                encrypted: form.encrypted,
                signed: false,
            };

            // If fails, return TranformFailed, with message id.
            // this allows to notify the error to the task that was waiting for this message.
            match self
                .verify_plain_incoming(&mut message, &iovec, &mut msg_form)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Failed to verify incoming message: {e:?}",);
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::SignVerify,
                        session_id: Some(message.header.session_id),
                        why: "Failed to verify incoming message!",
                        msg_id: Some(message.header.message_id),
                    }));
                }
            };

            responses.push(IncomingMessage::new(message, iovec, msg_form));
        }

        Ok(responses)
    }

    /// (Internal)
    ///
    /// A helper method to verify the incoming message.
    /// This method is used to verify the signature of the incoming message,
    /// if such verification is required.
    #[maybe_async]
    async fn verify_plain_incoming(
        &self,
        message: &mut PlainResponse,
        raw: &IoVec,
        form: &mut MessageForm,
    ) -> crate::Result<()> {
        // Check if signing check is required.
        if form.encrypted
            || message.header.message_id == u64::MAX
            || message.header.status == Status::Pending as u32
            || !(message.header.flags.signed() || self.is_message_signed_ksmbd(message).await)
        {
            return Ok(());
        }

        // Verify signature (if required, according to the spec)
        let session_id = message.header.session_id;
        let mut signer = self
            ._with_channel(session_id, |session| {
                let channel_info = session
                    .channel
                    .as_ref()
                    .ok_or(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::SignVerify,
                        session_id: Some(session_id),
                        why: "Message is required to be signed, but no channel is set up!",
                        msg_id: Some(message.header.message_id),
                    }))?;

                Ok(channel_info.signer()?.clone())
            })
            .await?;

        signer.verify_signature(&mut message.header, raw)?;
        log::debug!(
            "Message #{} verified (signature={}).",
            message.header.message_id,
            message.header.signature
        );
        form.signed = true;
        Ok(())
    }

    fn align8(size: usize) -> usize {
        (size + 7) & !7
    }

    fn serialize_plain_request(
        msg: &PlainRequest,
        additional_data: Option<&[u8]>,
    ) -> crate::Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(Header::STRUCT_SIZE);
        msg.write(&mut Cursor::new(&mut buffer))?;
        if let Some(data) = additional_data {
            buffer.extend_from_slice(data);
        }
        Ok(buffer)
    }

    fn split_plain_responses(
        &self,
        raw: &[u8],
    ) -> crate::Result<Vec<(PlainResponse, Vec<u8>)>> {
        let mut offset = 0usize;
        let mut responses = Vec::new();

        while offset < raw.len() {
            if raw.len() - offset < Header::STRUCT_SIZE {
                return Err(crate::Error::InvalidMessage(
                    "Compound response too short".to_string(),
                ));
            }

            let mut header_cursor = Cursor::new(&raw[offset..]);
            let header = Header::read(&mut header_cursor)?;
            let next = header.next_command as usize;
            let msg_len = if next == 0 { raw.len() - offset } else { next };

            if msg_len < Header::STRUCT_SIZE || offset + msg_len > raw.len() {
                return Err(crate::Error::InvalidMessage(
                    "Compound response length is invalid".to_string(),
                ));
            }

            let mut msg_cursor = Cursor::new(&raw[offset..offset + msg_len]);
            let message = PlainResponse::read(&mut msg_cursor)?;
            responses.push((message, raw[offset..offset + msg_len].to_vec()));

            offset += msg_len;
            if next == 0 {
                break;
            }
            if msg_len % 8 != 0 {
                return Err(crate::Error::InvalidMessage(
                    "Compound response is not 8-byte aligned".to_string(),
                ));
            }
        }

        if offset < raw.len() {
            return Err(crate::Error::InvalidMessage(
                "Compound response contains trailing bytes".to_string(),
            ));
        }

        Ok(responses)
    }

    /// (Internal)
    ///
    /// ksmbd multichannel setup compatibility check.
    ///
    // ksmbd has a subtle, but irritating bug, where it does not set the "signed" flag
    // for responses during multi channel session setups. To resolve this, we check if the
    // current channel is defined as "binding-only" channel. The feature `ksmbd-multichannel-compat`
    // must also be enabled, or else this code will not be compiled.
    // This behavior is actually against the spec - MS-SMB2 3.2.4.1.1:
    // > "If the client signs the request, it MUST set the SMB2_FLAGS_SIGNED bit in the Flags field of the SMB2 header."
    #[maybe_async]
    async fn is_message_signed_ksmbd(&self, _message: &PlainResponse) -> bool {
        #[cfg(feature = "ksmbd-multichannel-compat")]
        {
            if _message.header.command != Command::SessionSetup || _message.header.signature == 0 {
                return false;
            }

            let session_id = _message.header.session_id;
            let is_binding = self
                ._with_channel(session_id, |session| {
                    let channel_info = session.channel.as_ref().ok_or(crate::Error::Other(
                        "Get channel info for ksmbd sign test failed",
                    ))?;

                    Ok(channel_info.is_binding())
                })
                .await;

            return matches!(is_binding, Ok(true));
        }

        #[cfg(not(feature = "ksmbd-multichannel-compat"))]
        return false;
    }
}

/// An error that can occur during the transformation of messages.
#[derive(Debug)]
pub struct TransformError {
    /// If true, the error occurred while transforming an outgoing message.
    /// If false, it occurred while transforming an incoming message.
    pub outgoing: bool,
    pub phase: TransformPhase,
    pub session_id: Option<u64>,
    pub why: &'static str,
    /// If a message ID is available, it will be set here,
    /// for error-handling purposes.
    pub msg_id: Option<u64>,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.outgoing {
            write!(
                f,
                "Failed to transform outgoing message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        } else {
            write!(
                f,
                "Failed to transform incoming message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        }
    }
}

/// The phase of the transformation process.
#[derive(Debug)]
pub enum TransformPhase {
    /// Initial to/from bytes.
    EncodeDecode,
    /// Signature calculation and verification.
    SignVerify,
    /// Compression and decompression.
    CompressDecompress,
    /// Encryption and decryption.
    EncryptDecrypt,
}
