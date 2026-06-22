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
        // Verify CA is unlocked
        let ca_guard = self.state.ca.lock().await;
        if ca_guard.is_none() {
            return Err(if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            });
        }
        drop(ca_guard);

        let current_method = self
            .state
            .auth
            .lock()
            .await
            .as_ref()
            .map(|a| a.method_name())
            .unwrap_or("totp");
        let target = method.unwrap_or(current_method);

        let (new_state, stored, setup) = match target {
            "totp" => {
                let new_secret = koi_crypto::totp::generate_secret();
                let stored = koi_crypto::auth::store_totp(&new_secret, passphrase)?;
                let uri =
                    koi_crypto::totp::build_totp_uri(&new_secret, "Koi Certmesh", "enrollment");
                let setup = koi_crypto::auth::AuthSetup::Totp { totp_uri: uri };
                (AuthState::Totp(new_secret), stored, setup)
            }
            other => {
                return Err(CertmeshError::Internal(format!(
                    "unknown auth method: {other}"
                )));
            }
        };

        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        let auth_path = self.state.paths.auth_path();
        tokio::task::spawn_blocking(move || std::fs::write(&auth_path, &json))
            .await
            .map_err(|e| CertmeshError::Internal(format!("file I/O: {e}")))?
            .map_err(CertmeshError::Io)?;
        *self.state.auth.lock().await = Some(new_state);

        tracing::info!(method = target, "auth credential rotated");
        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "auth_rotated",
            &[("method", target)],
        );
        Ok(setup)
    }

    // ── Phase 5 - Backup/Restore/Revocation ───────────────────────

    /// Create an encrypted backup bundle for the certmesh state.
    pub async fn backup(
        &self,
        ca_passphrase: &str,
        backup_passphrase: &str,
    ) -> Result<Vec<u8>, CertmeshError> {
        if !self.state.paths.is_ca_initialized() {
            return Err(CertmeshError::CaNotInitialized);
        }

        let ca_state = ca::load_ca(ca_passphrase, &self.state.paths)?;

        // Load auth state for backup
        let auth_path = self.state.paths.auth_path();
        let json = std::fs::read_to_string(&auth_path)
            .map_err(|e| CertmeshError::Internal(format!("cannot read auth.json: {e}")))?;
        let stored: koi_crypto::auth::StoredAuth = serde_json::from_str(&json)
            .map_err(|e| CertmeshError::Internal(format!("auth.json parse error: {e}")))?;
        let auth_state = stored
            .unlock(ca_passphrase)
            .map_err(|e| CertmeshError::Internal(format!("auth unlock failed: {e}")))?;

        let roster = self.state.roster.lock().await;
        let roster_json = serde_json::to_string(&*roster)
            .map_err(|e| CertmeshError::Internal(format!("roster serialization failed: {e}")))?;

        let audit_log =
            audit::read_log_from(&self.state.paths.audit_log_path()).map_err(CertmeshError::Io)?;

        let ca_key_pem = ca_state
            .key
            .private_key_pem()
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?
            .to_string();
        let payload = backup::BackupPayload::new(
            ca_key_pem,
            ca_state.cert_pem.clone(),
            auth_state.method_name().to_string(),
            auth_state.to_backup_bytes(),
            roster_json,
            audit_log,
        );

        let bundle = backup::encode_backup(&payload, backup_passphrase)?;
        let _ = audit::append_entry_to(&self.state.paths.audit_log_path(), "backup_created", &[]);
        Ok(bundle)
    }

    /// Restore certmesh state from an encrypted backup bundle.
    pub async fn restore(
        &self,
        backup_bytes: &[u8],
        backup_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let payload = backup::decode_backup(backup_bytes, backup_passphrase)?;

        let ca_key = koi_crypto::keys::ca_keypair_from_pem(&payload.ca_key_pem)?;
        let ca_key_der = koi_crypto::keys::ca_keypair_to_der(&ca_key)?;
        let (encrypted_key, slot_table, _master_key) =
            koi_crypto::unlock_slots::envelope_encrypt_new(&ca_key_der, new_passphrase)?;
        std::fs::create_dir_all(self.state.paths.ca_dir())?;
        koi_crypto::keys::save_encrypted_key(&self.state.paths.ca_key_path(), &encrypted_key)?;
        slot_table.save(&self.state.paths.slot_table_path())?;
        std::fs::write(self.state.paths.ca_cert_path(), &payload.ca_cert_pem)?;

        let auth_state = AuthState::from_backup(&payload.auth_method, payload.auth_data)
            .map_err(|e| CertmeshError::Internal(format!("auth restore failed: {e}")))?;

        // Persist restored auth credential
        let AuthState::Totp(secret) = &auth_state;
        let stored = koi_crypto::auth::store_totp(secret, new_passphrase)?;
        let auth_json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        std::fs::write(self.state.paths.auth_path(), auth_json)?;

        if let Some(parent) = self.state.paths.roster_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.state.paths.roster_path(), &payload.roster_json)?;
        if let Some(parent) = self.state.paths.audit_log_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.state.paths.audit_log_path(), &payload.audit_log)?;

        let restored_roster: Roster = serde_json::from_str(&payload.roster_json)
            .map_err(|e| CertmeshError::Internal(format!("roster deserialization failed: {e}")))?;

        let ca_state = ca::load_ca(new_passphrase, &self.state.paths)?;
        *self.state.ca.lock().await = Some(ca_state);
        *self.state.auth.lock().await = Some(auth_state);
        *self.state.roster.lock().await = restored_roster;

        let _ = audit::append_entry_to(&self.state.paths.audit_log_path(), "backup_restored", &[]);
        Ok(())
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
        self.state
            .commit_roster(|roster| {
                roster
                    .revoke_member(hostname, operator.clone(), reason.clone())
                    .map_err(CertmeshError::NotFound)
            })
            .await?;

        let _ = self.state.event_tx.send(CertmeshEvent::MemberRevoked {
            hostname: hostname.to_string(),
        });

        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "member_revoked",
            &[
                ("hostname", hostname),
                ("operator", operator.as_deref().unwrap_or("unknown")),
                ("reason", reason.as_deref().unwrap_or("none")),
            ],
        );
        Ok(())
    }
}
