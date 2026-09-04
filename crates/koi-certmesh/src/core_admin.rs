//! Auth-credential rotation, encrypted backup/restore, and revocation.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    /// Rotate the auth credential - generates new credential, persists, returns setup info.
    ///
    /// If `method` is `None`, keeps the current method. If `Some("totp")`,
    /// switches to that method.
    pub async fn rotate_auth(
        &self,
        passphrase: &str,
        method: Option<&str>,
    ) -> Result<koi_crypto::auth::AuthSetup, CertmeshError> {
        let target = method.unwrap_or("totp").to_string();
        if target != "totp" {
            return Err(CertmeshError::Internal(format!(
                "unknown auth method: {target}"
            )));
        }

        // Reject the common locked/uninitialized case before paying a KDF.
        // The aggregate is checked again after pure preparation is complete.
        if self.state.ca.lock().is_none() {
            return Err(if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            });
        }

        let passphrase = passphrase.to_string();
        let (new_state, json, setup) = self
            .state
            .blocking
            .run(move || {
                let new_secret = koi_crypto::totp::generate_secret();
                let stored = koi_crypto::auth::store_totp(&new_secret, &passphrase)?;
                let uri =
                    koi_crypto::totp::build_totp_uri(&new_secret, "Koi Certmesh", "enrollment");
                let setup = koi_crypto::auth::AuthSetup::Totp { totp_uri: uri };
                let json = serde_json::to_vec_pretty(&stored)
                    .map_err(|error| CertmeshError::Internal(format!("auth serialize: {error}")))?;
                Ok::<_, CertmeshError>((AuthState::Totp(new_secret), json, setup))
            })
            .await??;

        let committed_target = target.clone();
        self.run_blocking_transition(move |domain| {
            // Revalidate after cancellable preparation before admitting mutation.
            if domain.ca.lock().is_none() {
                return Err(if domain.paths.is_ca_initialized() {
                    CertmeshError::CaLocked
                } else {
                    CertmeshError::CaNotInitialized
                });
            }
            let mut transaction = repository::ArtifactTransaction::new();
            transaction.write(domain.paths.auth_path(), json, true);
            transaction.append(
                domain.paths.audit_log_path(),
                audit::render_entry("auth_rotated", &[("method", committed_target.as_str())]),
                true,
            )?;
            let outcome = domain.commit_artifacts_under_transition(transaction)?;
            *domain.auth.lock() = Some(new_state);
            domain.finish_commit_under_transition(outcome)?;
            Ok::<(), CertmeshError>(())
        })
        .await??;

        tracing::info!(method = target, "auth credential rotated");
        Ok(setup)
    }

    // ── Phase 5 - Backup/Restore/Revocation ───────────────────────

    /// Create an encrypted backup bundle for the certmesh state.
    pub async fn backup(
        &self,
        ca_passphrase: &str,
        backup_passphrase: &str,
    ) -> Result<Vec<u8>, CertmeshError> {
        let transition = Arc::clone(&self.state.transition).lock_owned().await;
        let roster = self.state.roster.lock().clone();
        let acme_accounts_json = self.state.acme_accounts.export_json()?;
        let paths = self.state.paths.clone();
        let repository = Arc::clone(&self.state.repository);
        let ca_passphrase = ca_passphrase.to_string();
        let backup_passphrase = backup_passphrase.to_string();
        self.state
            .blocking
            .run(move || {
                let _transition = transition;
                if !paths.is_ca_initialized() {
                    return Err(CertmeshError::CaNotInitialized);
                }

                // Backup observes one serialized aggregate generation. Preparing
                // a legacy migration is harmless here but intentionally not
                // committed: a read-only backup never changes CA storage.
                let ca_state = ca::prepare_ca_load(&ca_passphrase, &paths)?.state;
                let auth_path = paths.auth_path();
                let json = std::fs::read_to_string(&auth_path).map_err(|error| {
                    CertmeshError::Internal(format!("cannot read auth.json: {error}"))
                })?;
                let stored: koi_crypto::auth::StoredAuth =
                    serde_json::from_str(&json).map_err(|error| {
                        CertmeshError::Internal(format!("auth.json parse error: {error}"))
                    })?;
                let auth_state = stored.unlock(&ca_passphrase).map_err(|error| {
                    CertmeshError::Internal(format!("auth unlock failed: {error}"))
                })?;
                let roster_json = serde_json::to_string(&roster).map_err(|error| {
                    CertmeshError::Internal(format!("roster serialization failed: {error}"))
                })?;
                let audit_log =
                    audit::read_log_from(&paths.audit_log_path()).map_err(CertmeshError::Io)?;
                let ca_key_pem = ca_state
                    .key
                    .private_key_pem()
                    .map_err(|error| CertmeshError::Crypto(error.to_string()))?
                    .to_string();
                let payload = backup::BackupPayload::new(
                    ca_key_pem,
                    ca_state.cert_pem,
                    auth_state.method_name().to_string(),
                    auth_state.to_backup_bytes(),
                    roster_json,
                    acme_accounts_json,
                    audit_log,
                );
                let bundle = backup::encode_backup(&payload, &backup_passphrase)?;

                // Audit is the only mutation. It completes on the worker before
                // acknowledgement; status has no audit-derived semantic field.
                let mut transaction = repository::ArtifactTransaction::new();
                transaction.append(
                    paths.audit_log_path(),
                    audit::render_entry("backup_created", &[]),
                    true,
                )?;
                repository.commit_durable(transaction)?;
                Ok(bundle)
            })
            .await?
    }

    /// Restore certmesh state from an encrypted backup bundle.
    pub async fn restore(
        &self,
        backup_bytes: &[u8],
        backup_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), CertmeshError> {
        // Decode and validate the complete recovery set before the first write.
        // A wrong passphrase, malformed roster/auth record, or mismatched CA
        // key/certificate must leave the currently running mesh untouched.
        let backup_bytes = backup_bytes.to_vec();
        let backup_passphrase = backup_passphrase.to_string();
        let new_passphrase = new_passphrase.to_string();
        let issuance_names = self.state.issuance_names.clone();
        let paths = self.state.paths.clone();
        let local_hostname = self.require_local_hostname("restoring the Certmesh authority")?;
        let (
            ca_cert_pem,
            audit_log,
            restored_accounts,
            ca_state,
            encrypted_key,
            slot_table,
            auth_state,
            auth_json,
            restored_roster,
            hostname,
            issued,
            cert_dir,
            machine_fingerprint,
        ) = self
            .state
            .blocking
            .run(move || {
                let payload = backup::decode_backup(&backup_bytes, &backup_passphrase)?;
                let restored_accounts = acme::account::AccountStore::prepare_replacement(
                    payload.acme_accounts_json.as_deref(),
                )?;

                let ca_key = koi_crypto::keys::ca_keypair_from_pem(&payload.ca_key_pem)?;
                let ca_key_der = koi_crypto::keys::ca_keypair_to_der(&ca_key)?;
                let ca_state = ca::build_ca_state_from_material(&ca_key_der, &payload.ca_cert_pem)?;
                let (encrypted_key, slot_table, _master_key) =
                    koi_crypto::unlock_slots::envelope_encrypt_new(&ca_key_der, &new_passphrase)?;

                let auth_state = AuthState::from_backup(&payload.auth_method, payload.auth_data)
                    .map_err(|error| {
                        CertmeshError::Internal(format!("auth restore failed: {error}"))
                    })?;
                let AuthState::Totp(secret) = &auth_state;
                let stored = koi_crypto::auth::store_totp(secret, &new_passphrase)?;
                let auth_json = serde_json::to_string_pretty(&stored)
                    .map_err(|error| CertmeshError::Internal(format!("auth serialize: {error}")))?;
                let mut restored_roster: Roster = serde_json::from_str(&payload.roster_json)
                    .map_err(|error| {
                        CertmeshError::Internal(format!("roster deserialization failed: {error}"))
                    })?;
                let hostname = local_hostname;
                validate_hostname(&hostname)?;
                let sans = issuance_names.self_sans(&hostname, &[])?;
                let issued = ca::issue_certificate(
                    &ca_state,
                    &hostname,
                    &sans,
                    restored_roster.metadata.policy.leaf_lifetime_days,
                )?;
                let cert_dir = paths.certs_dir().join(&hostname);
                if let Some(member) = restored_roster.find_member_mut(&hostname) {
                    member.cert_fingerprint = issued.fingerprint.clone();
                    member.cert_expires = issued.expires;
                    member.cert_sans = sans.clone();
                    member.cert_path = cert_dir.display().to_string();
                    member.status = roster::MemberStatus::Active;
                } else {
                    restored_roster.members.push(roster::RosterMember {
                        hostname: hostname.clone(),
                        role: roster::MemberRole::Primary,
                        enrolled_at: chrono::Utc::now(),
                        enrolled_by: Some("backup-restore".to_string()),
                        cert_fingerprint: issued.fingerprint.clone(),
                        cert_expires: issued.expires,
                        cert_sans: sans,
                        cert_path: cert_dir.display().to_string(),
                        status: roster::MemberStatus::Active,
                        reload_hook: None,
                        last_seen: Some(chrono::Utc::now()),
                        pinned_ca_fingerprint: Some(ca::ca_fingerprint(&ca_state)),
                        proxy_entries: Vec::new(),
                    });
                }
                restored_roster.metadata.seq = restored_roster.metadata.seq.saturating_add(1);

                Ok::<_, CertmeshError>((
                    payload.ca_cert_pem,
                    payload.audit_log,
                    restored_accounts,
                    ca_state,
                    encrypted_key,
                    slot_table,
                    auth_state,
                    auth_json,
                    restored_roster,
                    hostname,
                    issued,
                    cert_dir,
                    koi_crypto::vault::machine_fingerprint(),
                ))
            })
            .await??;

        let permit = self.state.blocking.reserve().await?;
        let transition = Arc::clone(&self.state.transition).lock_owned().await;
        let domain = Arc::clone(&self.state.domain);
        self.state
            .blocking
            .run_with_permit(permit, move || {
                let _transition = transition;
                domain.require_cleanup_complete_under_transition()?;
                let mut transaction = repository::ArtifactTransaction::new();
                transaction.write(
                    domain.paths.ca_key_path(),
                    serde_json::to_vec_pretty(&encrypted_key).map_err(|error| {
                        CertmeshError::Internal(format!("serialize CA key: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    domain.paths.slot_table_path(),
                    serde_json::to_vec_pretty(&slot_table).map_err(|error| {
                        CertmeshError::Internal(format!("serialize unlock slots: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    domain.paths.ca_cert_path(),
                    ca_cert_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(domain.paths.auth_path(), auth_json.into_bytes(), true);
                transaction.write(
                    domain.paths.roster_path(),
                    serde_json::to_vec_pretty(&restored_roster).map_err(|error| {
                        CertmeshError::Internal(format!("serialize roster: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    cert_dir.join("cert.pem"),
                    issued.cert_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(
                    cert_dir.join("key.pem"),
                    issued.key_pem.as_bytes().to_vec(),
                    true,
                );
                transaction.write(
                    cert_dir.join("ca.pem"),
                    issued.ca_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(
                    cert_dir.join("fullchain.pem"),
                    issued.fullchain_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.remove(domain.paths.member_state_path());
                transaction.remove(domain.paths.invites_path());
                transaction.remove(domain.paths.rate_limiter_path());
                transaction.remove(domain.paths.auto_unlock_key_path());
                transaction.remove_tree(&domain.paths.acme_dir())?;
                if let Some(bytes) = restored_accounts.bytes.as_ref() {
                    transaction.write(domain.paths.acme_accounts_path(), bytes.clone(), true);
                }
                if let Some(fingerprint) = machine_fingerprint {
                    transaction.write(
                        domain.paths.machine_bind_path(),
                        fingerprint.into_bytes(),
                        true,
                    );
                } else {
                    transaction.remove(domain.paths.machine_bind_path());
                }
                transaction.write(
                    domain.paths.audit_log_path(),
                    audit_log.into_bytes(),
                    true,
                );
                transaction.append(
                    domain.paths.audit_log_path(),
                    audit::render_entry(
                        "self_enroll",
                        &[
                            ("hostname", hostname.as_str()),
                            ("fingerprint", issued.fingerprint.as_str()),
                        ],
                    ),
                    true,
                )?;
                transaction.append(
                    domain.paths.audit_log_path(),
                    audit::render_entry("backup_restored", &[]),
                    true,
                )?;

                // Restored slot state intentionally disables auto-unlock. Remove
                // the former credential before activating that new generation;
                // restore it if the filesystem transaction fails.
                let previous_auto_unlock = CertmeshCore::read_auto_unlock_key(&domain.paths)?;
                let vault = koi_crypto::vault::Vault::open(domain.paths.data_dir())?;
                vault.delete(CertmeshCore::VAULT_AUTO_UNLOCK_KEY)?;
                let outcome = match domain.commit_artifacts_under_transition(transaction) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        if let Err(rollback_error) = CertmeshCore::restore_auto_unlock_key_at(
                            &domain.paths,
                            previous_auto_unlock,
                        ) {
                            tracing::error!(%rollback_error, "Could not restore prior auto-unlock credential after failed restore");
                        }
                        return Err(error);
                    }
                };

                let sealed_ciphertext = encrypted_key.ciphertext.clone();
                *domain.ca.lock() = Some(ca_state);
                *domain.auth.lock() = Some(auth_state);
                *domain.roster.lock() = restored_roster;
                *domain.rate_limiter.lock() = RateLimiter::new();
                domain.acme_accounts.commit_replacement(restored_accounts);
                domain.finish_commit_under_transition(outcome)?;

                if let Err(error) = remove_empty_tree(&domain.paths.acme_dir()) {
                    tracing::debug!(%error, "Could not remove empty ACME state directory");
                }
                let _ = domain.event_tx.send(CertmeshEvent::MemberJoined {
                    hostname,
                    fingerprint: issued.fingerprint,
                });

                if koi_crypto::tpm::is_available() {
                    if let Err(error) = koi_crypto::tpm::seal_key_material(
                        "koi-certmesh-ca",
                        &sealed_ciphertext,
                    ) {
                        tracing::warn!(%error, "Could not seal restored CA material to this platform");
                    }
                }
                Ok(())
            })
            .await?
    }

    /// Revoke a member and persist the revocation list.
    pub async fn revoke_member(
        &self,
        hostname: &str,
        operator: Option<String>,
        reason: Option<String>,
    ) -> Result<(), CertmeshError> {
        // Membership change → commit_roster bumps `seq` so the revocation
        // propagates in the next trust bundle (ADR-017 F4/F8).
        let hostname = hostname.to_string();
        self.run_blocking_transition(move |domain| {
            let audit_fields = [
                ("hostname", hostname.as_str()),
                ("operator", operator.as_deref().unwrap_or("unknown")),
                ("reason", reason.as_deref().unwrap_or("none")),
            ];
            let ((), outcome) = domain.commit_roster_under_transition(
                true,
                Some(audit::render_entry("member_revoked", &audit_fields)),
                |roster| {
                    roster
                        .revoke_member(&hostname, operator, reason)
                        .map_err(CertmeshError::NotFound)
                },
            )?;
            domain.finish_commit_under_transition(outcome)?;
            let _ = domain
                .event_tx
                .send(CertmeshEvent::MemberRevoked { hostname });
            Ok::<(), CertmeshError>(())
        })
        .await?
    }
}
