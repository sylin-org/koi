//! CA lifecycle: create, audit-log read, and destroy.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    /// Initialize a new CA and self-enroll this node as the primary member.
    ///
    /// Full CA-initialization orchestration: decode entropy, create the CA,
    /// generate the TOTP auth credential, create and persist the roster,
    /// self-enroll the CA node, install the CA cert in the OS trust store
    /// (best-effort), configure auto-unlock, and update in-memory state.
    ///
    /// This is the single source of truth for CA creation; the HTTP
    /// `create_handler` is a thin delegate over this method.
    pub async fn create(
        &self,
        req: protocol::CreateCaRequest,
    ) -> Result<protocol::CreateCaResponse, CertmeshError> {
        let state = &self.state;

        // Decode hex entropy (must be exactly 32 bytes)
        let entropy = match decode_hex(&req.entropy_hex) {
            Some(bytes) if bytes.len() == 32 => bytes,
            Some(bytes) => {
                return Err(CertmeshError::InvalidPayload(format!(
                    "entropy must be exactly 32 bytes, got {}",
                    bytes.len()
                )));
            }
            None => {
                return Err(CertmeshError::InvalidPayload(
                    "invalid hex entropy".to_string(),
                ));
            }
        };

        // Reject if CA already initialized
        if state.paths.is_ca_initialized() {
            return Err(CertmeshError::Conflict(
                "CA is already initialized".to_string(),
            ));
        }

        // Create CA (blocking I/O: key gen, file writes, slot table save)
        let passphrase_clone = req.passphrase.clone();
        let paths_clone = state.paths.clone();
        let (ca_state, _master_key) = tokio::task::spawn_blocking(move || {
            ca::create_ca(&passphrase_clone, &entropy, &paths_clone)
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("CA creation task: {e}")))
        .and_then(|r| r)?;
        let ca_fingerprint = ca::ca_fingerprint(&ca_state);

        // Generate auth credential (default=TOTP).
        // If the client provided a ceremony-verified secret, use it;
        // otherwise generate a fresh one.
        let totp_secret = if let Some(ref hex) = req.totp_secret_hex {
            match koi_common::encoding::hex_decode(hex) {
                Ok(bytes) => koi_crypto::totp::TotpSecret::from_bytes(bytes),
                Err(_) => {
                    return Err(CertmeshError::InvalidPayload(
                        "totp_secret_hex: invalid hex encoding".into(),
                    ));
                }
            }
        } else {
            koi_crypto::totp::generate_secret()
        };
        let stored = koi_crypto::auth::store_totp(&totp_secret, &req.passphrase)
            .map_err(|e| CertmeshError::Internal(format!("auth store: {e}")))?;
        let auth_json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        {
            let auth_path = state.paths.auth_path();
            let auth_json_clone = auth_json.clone();
            tokio::task::spawn_blocking(move || std::fs::write(&auth_path, &auth_json_clone))
                .await
                .map_err(|e| std::io::Error::other(format!("file I/O: {e}")))
                .and_then(|r| r)
                .map_err(CertmeshError::Io)?;
        }

        let totp_uri = koi_crypto::totp::build_totp_uri(&totp_secret, "Koi Certmesh", "enrollment");

        // Create roster from the two posture booleans (the named preset, if any,
        // was already resolved to these by the ceremony/CLI).
        let mut new_roster = roster::Roster::new(
            req.enrollment_open,
            req.requires_approval,
            req.operator.clone(),
        );
        let roster_path = state.paths.roster_path();
        roster::persist_roster(&new_roster, &roster_path).await?;

        // Self-enroll the CA node as the first (primary) member.
        // This issues a certificate for the local hostname so applications
        // on this machine can use TLS immediately.
        let local_hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        let sans = vec![
            local_hostname.clone(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        match ca::issue_certificate(
            &ca_state,
            &local_hostname,
            &sans,
            new_roster.metadata.policy.leaf_lifetime_days,
        ) {
            Ok(issued) => {
                let cert_dir_base = state.paths.certs_dir().join(&local_hostname);
                let cert_dir_base_clone = cert_dir_base.clone();
                let issued_for_write = issued.clone();
                let cert_dir = match tokio::task::spawn_blocking(move || {
                    certfiles::write_cert_files_to(&cert_dir_base_clone, &issued_for_write)
                })
                .await
                {
                    Ok(Ok(dir)) => dir,
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "Could not write CA node cert files");
                        cert_dir_base
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Cert file write task panicked");
                        cert_dir_base
                    }
                };
                let ca_fp = ca::ca_fingerprint(&ca_state);
                let member = roster::RosterMember {
                    hostname: local_hostname.clone(),
                    role: roster::MemberRole::Primary,
                    enrolled_at: chrono::Utc::now(),
                    enrolled_by: req.operator.clone(),
                    cert_fingerprint: issued.fingerprint,
                    cert_expires: issued.expires,
                    cert_sans: sans,
                    cert_path: cert_dir.display().to_string(),
                    status: roster::MemberStatus::Active,
                    reload_hook: None,
                    last_seen: Some(chrono::Utc::now()),
                    pinned_ca_fingerprint: Some(ca_fp),
                    proxy_entries: Vec::new(),
                };
                new_roster.members.push(member);
                // Persist updated roster with the self-enrolled member
                if let Err(e) = roster::persist_roster(&new_roster, &roster_path).await {
                    tracing::warn!(error = %e, "Could not save roster after self-enrollment");
                }
                let _ = audit::append_entry_to(
                    &state.paths.audit_log_path(),
                    "member_joined",
                    &[
                        ("hostname", local_hostname.as_str()),
                        ("role", "primary"),
                        ("approved_by", "self-enroll"),
                    ],
                );
                tracing::info!(hostname = %local_hostname, "CA node self-enrolled as primary");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Could not self-enroll CA node - roster will be empty");
            }
        }

        // Install CA cert in OS trust store (best-effort)
        if let Err(e) = os_truststore::Cert::from_pem(&ca_state.cert_pem)
            .and_then(|cert| os_truststore::install(&cert).map(drop))
        {
            tracing::warn!(error = %e, "Could not install CA cert in trust store");
        }

        // Configure auto-unlock from the create-time decision (single source of
        // truth: CertmeshCore::configure_auto_unlock). When `auto_unlock` is true,
        // the passphrase is saved to the koi-crypto vault so the daemon boots
        // unlocked; the slot table is marked. This is what keeps the boot-unlocked
        // path (koi-compose init_certmesh_core) working.
        if let Err(e) = self.configure_auto_unlock(req.auto_unlock, &req.passphrase) {
            tracing::warn!(error = %e, "Could not configure auto-unlock");
        }

        // Record this machine's fingerprint (ADR-017 F11) so a later boot can
        // detect a VM clone / disk restore onto different hardware and refuse to
        // auto-unlock. Best-effort: if the machine-id is unreadable, the CA is
        // simply not machine-checked.
        match koi_crypto::vault::machine_fingerprint() {
            Some(fp) => {
                let path = state.paths.machine_bind_path();
                let r = tokio::task::spawn_blocking(move || write_machine_binding(&path, &fp))
                    .await
                    .map_err(|e| std::io::Error::other(format!("machine-bind task: {e}")))
                    .and_then(|r| r);
                if let Err(e) = r {
                    tracing::warn!(error = %e, "Could not record machine binding");
                }
            }
            None => tracing::debug!(
                "machine-id unavailable; machine binding not recorded (auto-unlock unchecked)"
            ),
        }

        // Update in-memory state
        *state.ca.lock().await = Some(ca_state);
        *state.auth.lock().await = Some(koi_crypto::auth::AuthState::Totp(totp_secret));
        *state.roster.lock().await = new_roster;

        let _ = audit::append_entry_to(
            &state.paths.audit_log_path(),
            "ca_initialized",
            &[
                (
                    "enrollment_open",
                    if req.enrollment_open {
                        "open"
                    } else {
                        "closed"
                    },
                ),
                (
                    "requires_approval",
                    if req.requires_approval { "yes" } else { "no" },
                ),
                ("operator", req.operator.as_deref().unwrap_or("none")),
            ],
        );

        tracing::info!(
            enrollment_open = req.enrollment_open,
            requires_approval = req.requires_approval,
            auto_unlock = req.auto_unlock,
            "CA initialized via service"
        );

        // The CA node self-enrolled a leaf above → Open→Authenticated.
        state.republish_posture();

        Ok(protocol::CreateCaResponse {
            auth_setup: koi_crypto::auth::AuthSetup::Totp { totp_uri },
            ca_fingerprint,
        })
    }

    /// Read the audit log entries.
    pub fn read_audit_log(&self) -> Result<String, CertmeshError> {
        audit::read_log_from(&self.state.paths.audit_log_path()).map_err(CertmeshError::Io)
    }

    /// Destroy all certmesh state - CA key, certs, roster, and audit log.
    ///
    /// Removes all certmesh data from disk and resets in-memory state to
    /// uninitialized. This is irreversible. Used for testing cleanup and
    /// full mesh teardown.
    pub async fn destroy(&self) -> Result<(), CertmeshError> {
        self.state.destroy().await?;
        let _ = self.state.event_tx.send(CertmeshEvent::Destroyed);
        Ok(())
    }
}
