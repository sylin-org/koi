//! CA lifecycle: create, audit-log read, and destroy.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

/// Side-effect-free result of the expensive CA creation phase. A cancelled
/// requester may abandon this value safely: no aggregate state has been
/// admitted, persisted, projected, or announced yet.
struct PreparedCaCreation {
    ca: ca::PreparedCa,
    totp_secret: koi_crypto::totp::TotpSecret,
    auth_json: Vec<u8>,
    totp_uri: String,
    ca_fingerprint: String,
    roster: roster::Roster,
    local_hostname: String,
    issued: ca::IssuedCert,
    machine_fingerprint: Option<String>,
}

impl CertmeshCore {
    /// Initialize a new CA and self-enroll this node as the primary member.
    ///
    /// Full CA-initialization orchestration: decode entropy, create the CA,
    /// generate the TOTP auth credential, create and persist the roster,
    /// self-enroll the CA node, configure auto-unlock, and publish the aggregate.
    /// OS anchor installation belongs to the separate Trust domain, which
    /// consumes Certmesh's CA-anchor projection after this command succeeds.
    ///
    /// This is the single source of truth for CA creation; the HTTP
    /// `create_handler` is a thin delegate over this method.
    pub async fn create(
        &self,
        req: protocol::CreateCaRequest,
    ) -> Result<protocol::CreateCaResponse, CertmeshError> {
        let state = &self.state;

        // Decode and validate everything that does not inspect aggregate state
        // before entering the serialized transition.
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

        if req.auto_unlock && req.passphrase.is_empty() {
            return Err(CertmeshError::InvalidPayload(
                "auto-unlock requires a non-empty CA passphrase".into(),
            ));
        }

        // Avoid paying the KDF/signing cost for an obviously closed aggregate.
        // This is only an optimistic read; the authoritative check is repeated
        // under the transition after preparation.
        if self.status().role != CertmeshRole::Open {
            return Err(CertmeshError::Conflict(
                "node already belongs to a certificate mesh".to_string(),
            ));
        }

        // CA generation, both KDFs, leaf issuance, and serialization are pure
        // preparation. Keep them off the async executor and outside the
        // accepted-mutation gate. If this future is cancelled, Certmesh's owned
        // worker may finish and discard the value; no domain effect can leak.
        let passphrase = req.passphrase.clone();
        let auto_unlock = req.auto_unlock;
        let enrollment_open = req.enrollment_open;
        let requires_approval = req.requires_approval;
        let operator = req.operator.clone();
        let issuance_names = state.issuance_names.clone();
        let paths = state.paths.clone();
        let local_hostname = self.require_local_hostname("creating the Certmesh authority")?;
        let prepared = state
            .blocking
            .run(move || {
                let mut ca = ca::prepare_ca(&passphrase, &entropy)?;
                if auto_unlock {
                    ca.slot_table.add_auto_unlock();
                }
                let ca_fingerprint = ca::ca_fingerprint(&ca.state);

                let stored = koi_crypto::auth::store_totp(&totp_secret, &passphrase)
                    .map_err(|error| CertmeshError::Internal(format!("auth store: {error}")))?;
                let auth_json = serde_json::to_vec_pretty(&stored)
                    .map_err(|error| CertmeshError::Internal(format!("auth serialize: {error}")))?;
                let totp_uri =
                    koi_crypto::totp::build_totp_uri(&totp_secret, "Koi Certmesh", "enrollment");

                let mut roster =
                    roster::Roster::new(enrollment_open, requires_approval, operator.clone());
                validate_hostname(&local_hostname)?;
                let sans = issuance_names.self_sans(&local_hostname, &[])?;
                let issued = ca::issue_certificate(
                    &ca.state,
                    &local_hostname,
                    &sans,
                    roster.metadata.policy.leaf_lifetime_days,
                )?;
                let cert_dir = paths.certs_dir().join(&local_hostname);
                roster.members.push(roster::RosterMember {
                    hostname: local_hostname.clone(),
                    role: roster::MemberRole::Primary,
                    enrolled_at: chrono::Utc::now(),
                    enrolled_by: operator,
                    cert_fingerprint: issued.fingerprint.clone(),
                    cert_expires: issued.expires,
                    cert_sans: sans,
                    cert_path: cert_dir.display().to_string(),
                    status: roster::MemberStatus::Active,
                    reload_hook: None,
                    last_seen: Some(chrono::Utc::now()),
                    pinned_ca_fingerprint: Some(ca_fingerprint.clone()),
                    proxy_entries: Vec::new(),
                });
                roster.metadata.seq = 1;

                Ok::<_, CertmeshError>(PreparedCaCreation {
                    ca,
                    totp_secret,
                    auth_json,
                    totp_uri,
                    ca_fingerprint,
                    roster,
                    local_hostname,
                    issued,
                    machine_fingerprint: koi_crypto::vault::machine_fingerprint(),
                })
            })
            .await??;

        // Reserve the complete accepted mutation before taking the aggregate
        // gate. The worker owns platform intent, persistence, model, projections,
        // and event publication as one cancellation-safe command.
        let permit = state.blocking.reserve().await?;
        let transition = Arc::clone(&state.transition).lock_owned().await;
        let domain = Arc::clone(&state.domain);
        state
            .blocking
            .run_with_permit(permit, move || {
                let _transition = transition;
                domain.require_cleanup_complete_under_transition()?;
                if domain.status.current().role != CertmeshRole::Open {
                    return Err(CertmeshError::Conflict(
                        "node already belongs to a certificate mesh".to_string(),
                    ));
                }

                let local_hostname = prepared.local_hostname.clone();
                let ca_fingerprint = prepared.ca_fingerprint.clone();
                let issued_fingerprint = prepared.issued.fingerprint.clone();
                let cert_dir = domain.paths.certs_dir().join(&local_hostname);
                let sealed_ciphertext = prepared.ca.encrypted_key.ciphertext.clone();
                let mut transaction = repository::ArtifactTransaction::new();
                transaction.write(
                    domain.paths.ca_key_path(),
                    serde_json::to_vec_pretty(&prepared.ca.encrypted_key).map_err(|error| {
                        CertmeshError::Internal(format!("serialize CA key: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    domain.paths.slot_table_path(),
                    serde_json::to_vec_pretty(&prepared.ca.slot_table).map_err(|error| {
                        CertmeshError::Internal(format!("serialize unlock slots: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    domain.paths.ca_cert_path(),
                    prepared.ca.state.cert_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(domain.paths.auth_path(), prepared.auth_json, true);
                transaction.write(
                    domain.paths.roster_path(),
                    serde_json::to_vec_pretty(&prepared.roster).map_err(|error| {
                        CertmeshError::Internal(format!("serialize roster: {error}"))
                    })?,
                    true,
                );
                transaction.write(
                    cert_dir.join("cert.pem"),
                    prepared.issued.cert_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(
                    cert_dir.join("key.pem"),
                    prepared.issued.key_pem.as_bytes().to_vec(),
                    true,
                );
                transaction.write(
                    cert_dir.join("ca.pem"),
                    prepared.issued.ca_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.write(
                    cert_dir.join("fullchain.pem"),
                    prepared.issued.fullchain_pem.as_bytes().to_vec(),
                    false,
                );
                transaction.remove(domain.paths.member_state_path());
                transaction.remove(domain.paths.invites_path());
                transaction.remove(domain.paths.rate_limiter_path());
                transaction.remove(domain.paths.auto_unlock_key_path());
                transaction.remove_tree(&domain.paths.acme_dir())?;
                if let Some(fingerprint) = prepared.machine_fingerprint {
                    transaction.write(
                        domain.paths.machine_bind_path(),
                        fingerprint.into_bytes(),
                        true,
                    );
                } else {
                    transaction.remove(domain.paths.machine_bind_path());
                }
                transaction.append(
                    domain.paths.audit_log_path(),
                    audit::render_entry(
                        "member_joined",
                        &[
                            ("hostname", local_hostname.as_str()),
                            ("role", "primary"),
                            ("approved_by", "self-enroll"),
                        ],
                    ),
                    true,
                )?;
                transaction.append(
                    domain.paths.audit_log_path(),
                    audit::render_entry(
                        "ca_initialized",
                        &[
                            (
                                "enrollment_open",
                                if req.enrollment_open { "open" } else { "closed" },
                            ),
                            (
                                "requires_approval",
                                if req.requires_approval { "yes" } else { "no" },
                            ),
                            ("operator", req.operator.as_deref().unwrap_or("none")),
                        ],
                    ),
                    true,
                )?;

                // Auto-unlock is requested product state, not an optimization.
                // Store the credential first; the durable slot marker activates
                // it. A failed aggregate commit restores the prior inert value.
                let previous_auto_unlock = if req.auto_unlock {
                    let previous = CertmeshCore::read_auto_unlock_key(&domain.paths)?;
                    CertmeshCore::save_auto_unlock_key_at(&domain.paths, &req.passphrase)?;
                    Some(previous)
                } else {
                    None
                };
                let outcome = match domain.commit_artifacts_under_transition(transaction) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        if let Some(previous) = previous_auto_unlock {
                            if let Err(rollback_error) =
                                CertmeshCore::restore_auto_unlock_key_at(&domain.paths, previous)
                            {
                                tracing::error!(%rollback_error, "Could not roll back inactive auto-unlock credential");
                            }
                        }
                        return Err(error);
                    }
                };

                *domain.ca.lock() = Some(prepared.ca.state);
                *domain.auth.lock() = Some(koi_crypto::auth::AuthState::Totp(prepared.totp_secret));
                *domain.roster.lock() = prepared.roster;
                *domain.rate_limiter.lock() = RateLimiter::new();
                domain.acme_accounts.clear();
                domain.finish_commit_under_transition(outcome)?;

                if let Err(error) = remove_empty_tree(&domain.paths.acme_dir()) {
                    tracing::debug!(%error, "Could not remove empty ACME state directory");
                }
                let _ = domain.event_tx.send(CertmeshEvent::MemberJoined {
                    hostname: local_hostname,
                    fingerprint: issued_fingerprint,
                });

                // TPM sealing is explicitly a best-effort hardening layer; the
                // encrypted CA and authoritative status do not depend on it.
                if koi_crypto::tpm::is_available() {
                    if let Err(error) = koi_crypto::tpm::seal_key_material(
                        "koi-certmesh-ca",
                        &sealed_ciphertext,
                    ) {
                        tracing::warn!(%error, "Could not seal Certmesh key material to this platform");
                    }
                }
                tracing::info!(
                    enrollment_open = req.enrollment_open,
                    requires_approval = req.requires_approval,
                    auto_unlock = req.auto_unlock,
                    "CA initialized via service"
                );
                Ok(protocol::CreateCaResponse {
                    auth_setup: koi_crypto::auth::AuthSetup::Totp {
                        totp_uri: prepared.totp_uri,
                    },
                    ca_fingerprint,
                })
            })
            .await?
    }

    /// Read the audit log entries.
    pub async fn read_audit_log(&self) -> Result<String, CertmeshError> {
        let transition = Arc::clone(&self.state.transition).lock_owned().await;
        let path = self.state.paths.audit_log_path();
        let (_transition, result) = self
            .state
            .blocking
            .run(move || {
                let result = audit::read_log_from(&path).map_err(CertmeshError::Io);
                (transition, result)
            })
            .await?;
        result
    }

    /// Destroy all certmesh state - CA key, certs, roster, and audit log.
    ///
    /// Removes all certmesh data from disk and resets in-memory state to
    /// uninitialized. This is irreversible. Used for testing cleanup and
    /// full mesh teardown.
    pub async fn destroy(&self) -> Result<(), CertmeshError> {
        let permit = self.state.blocking.reserve().await?;
        let transition = Arc::clone(&self.state.transition).lock_owned().await;
        let domain = Arc::clone(&self.state.domain);
        self.state
            .blocking
            .run_with_permit(permit, move || {
                let _transition = transition;
                domain.destroy_under_transition()?;
                // `destroy_under_transition` has already published primary and
                // specialized status. The semantic event is the final face.
                let _ = domain.event_tx.send(CertmeshEvent::Destroyed);
                Ok(())
            })
            .await?
    }
}
