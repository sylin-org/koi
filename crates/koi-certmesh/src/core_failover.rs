//! Authority failover commands.
//!
//! Promotion is a two-daemon protocol: the receiving daemon owns the ephemeral
//! secret and all local persistence, while the current authority only prepares
//! encrypted transfer material over mTLS. No CLI process handles a CA key.

use super::*;

const PROMOTION_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

fn accept_promotion_under_transition(
    domain: &CertmeshDomain,
    request: protocol::AcceptPromotionRequest,
) -> Result<protocol::AcceptPromotionResponse, CertmeshError> {
    domain.require_cleanup_complete_under_transition()?;
    if domain.status.current().role != CertmeshRole::Member {
        return Err(CertmeshError::Conflict(
            "only an enrolled member can receive promotion".into(),
        ));
    }
    let pending = {
        let mut slot = domain.pending_promotion.lock();
        let pending = slot
            .as_ref()
            .ok_or_else(|| CertmeshError::PromotionFailed("no pending local session".into()))?;
        if pending.id != request.session_id {
            return Err(CertmeshError::PromotionFailed(
                "promotion session does not match".into(),
            ));
        }
        if tokio::time::Instant::now() > pending.expires_at {
            slot.take();
            return Err(CertmeshError::PromotionFailed(
                "promotion session expired".into(),
            ));
        }
        slot.take().expect("validated pending promotion")
    };

    let ca_cert_pem = request.promotion.ca_cert_pem.clone();
    let (ca_key, auth_state, mut roster, acme_accounts_json) =
        failover::accept_promotion(&request.promotion, pending.keypair)?;
    let promoted_accounts =
        acme::account::AccountStore::prepare_replacement(acme_accounts_json.as_deref())?;
    let ca_key_der = koi_crypto::keys::ca_keypair_to_der(&ca_key)?;
    let ca_state = ca::build_ca_state_from_material(&ca_key_der, &ca_cert_pem)?;
    let (encrypted_key, slot_table, _master_key) =
        koi_crypto::unlock_slots::envelope_encrypt_new(&ca_key_der, &request.passphrase)?;
    let AuthState::Totp(secret) = &auth_state;
    let stored = koi_crypto::auth::store_totp(secret, &request.passphrase)?;

    let hostname = domain.require_local_hostname("accepting Certmesh authority promotion")?;
    validate_hostname(&hostname)?;
    let member = roster
        .find_member_mut(&hostname)
        .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
    if member.status == roster::MemberStatus::Revoked {
        return Err(CertmeshError::Revoked(hostname));
    }
    member.role = roster::MemberRole::Standby;
    roster.metadata.seq = roster.metadata.seq.saturating_add(1);

    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        domain.paths.ca_key_path(),
        serde_json::to_vec_pretty(&encrypted_key)
            .map_err(|error| CertmeshError::Internal(format!("serialize CA key: {error}")))?,
        true,
    );
    transaction.write(
        domain.paths.slot_table_path(),
        serde_json::to_vec_pretty(&slot_table)
            .map_err(|error| CertmeshError::Internal(format!("serialize unlock slots: {error}")))?,
        true,
    );
    transaction.write(
        domain.paths.ca_cert_path(),
        ca_cert_pem.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        domain.paths.auth_path(),
        serde_json::to_vec_pretty(&stored)
            .map_err(|error| CertmeshError::Internal(format!("serialize auth: {error}")))?,
        true,
    );
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&roster)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
        true,
    );
    transaction.remove(domain.paths.member_state_path());
    transaction.remove(domain.paths.invites_path());
    transaction.remove(domain.paths.rate_limiter_path());
    transaction.remove_tree(&domain.paths.acme_dir())?;
    if let Some(bytes) = promoted_accounts.bytes.as_ref() {
        transaction.write(domain.paths.acme_accounts_path(), bytes.clone(), true);
    }
    if let Some(fingerprint) = koi_crypto::vault::machine_fingerprint() {
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
        audit::render_entry("promoted_to_standby", &[("hostname", hostname.as_str())]),
        true,
    )?;
    let outcome = domain.commit_artifacts_under_transition(transaction)?;

    let sealed_ciphertext = encrypted_key.ciphertext.clone();
    *domain.ca.lock() = Some(ca_state);
    *domain.auth.lock() = Some(auth_state);
    *domain.roster.lock() = roster;
    *domain.rate_limiter.lock() = RateLimiter::new();
    domain.acme_accounts.commit_replacement(promoted_accounts);
    domain.finish_commit_under_transition(outcome)?;

    if let Err(error) = remove_empty_tree(&domain.paths.acme_dir()) {
        tracing::debug!(%error, "Could not remove empty ACME state directory");
    }
    let _ = domain.event_tx.send(CertmeshEvent::PromotedToAuthority {
        hostname: hostname.clone(),
    });

    if koi_crypto::tpm::is_available() {
        if let Err(error) =
            koi_crypto::tpm::seal_key_material("koi-certmesh-ca", &sealed_ciphertext)
        {
            tracing::warn!(%error, "Could not seal promoted CA material to this platform");
        }
    }

    Ok(protocol::AcceptPromotionResponse {
        promoted: true,
        role: "standby".into(),
        hostname,
    })
}

fn promote_under_transition(
    domain: &CertmeshDomain,
    authenticated_cn: &str,
    auth: &koi_crypto::auth::AuthResponse,
    client_public_key: &[u8; 32],
) -> Result<protocol::PromoteResponse, CertmeshError> {
    let ca_guard = domain.ca.lock();
    let ca = ca_guard.as_ref().ok_or_else(|| {
        if domain.paths.is_ca_initialized() {
            CertmeshError::CaLocked
        } else {
            CertmeshError::CaNotInitialized
        }
    })?;
    let auth_guard = domain.auth.lock();
    let auth_state = auth_guard.as_ref().ok_or(CertmeshError::CaLocked)?;
    let challenge = domain
        .pending_challenge
        .lock()
        .as_ref()
        .cloned()
        .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
    let roster = domain.roster.lock();

    let rejection = if roster.is_revoked(authenticated_cn) {
        Some(CertmeshError::Revoked(authenticated_cn.to_string()))
    } else {
        match roster.find_member(authenticated_cn) {
            Some(member) if member.status == roster::MemberStatus::Active => None,
            Some(_) => Some(CertmeshError::Forbidden(format!(
                "member '{authenticated_cn}' is not active"
            ))),
            None => Some(CertmeshError::Forbidden(format!(
                "authenticated member '{authenticated_cn}' is not enrolled"
            ))),
        }
    };
    if let Some(error) = rejection {
        let reason = error.to_string();
        drop(roster);
        drop(auth_guard);
        drop(ca_guard);
        let mut transaction = repository::ArtifactTransaction::new();
        transaction.append(
            domain.paths.audit_log_path(),
            audit::render_entry(
                "mtls_promotion_rejected",
                &[("hostname", authenticated_cn), ("reason", reason.as_str())],
            ),
            true,
        )?;
        let outcome = domain.commit_artifacts_under_transition(transaction)?;
        domain.finish_commit_under_transition(outcome)?;
        return Err(error);
    }

    let mut next_rate_limiter = domain.rate_limiter.lock().clone();
    let valid = koi_crypto::auth::adapter_for(auth_state)
        .verify(auth_state, &challenge, auth)
        .unwrap_or(false);
    let auth_result = next_rate_limiter.check_and_record(valid);
    let limiter_json = serde_json::to_vec(&next_rate_limiter)
        .map_err(|error| CertmeshError::Internal(format!("serialize rate limiter: {error}")))?;
    let response = if auth_result.is_ok() {
        Some(failover::prepare_promotion(
            ca,
            auth_state,
            &roster,
            domain.acme_accounts.export_json()?,
            client_public_key,
        )?)
    } else {
        None
    };
    drop(roster);
    drop(auth_guard);
    drop(ca_guard);

    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(domain.paths.rate_limiter_path(), limiter_json, true);
    let audit_event = if response.is_some() {
        "promotion_prepared"
    } else {
        "promotion_auth_rejected"
    };
    transaction.append(
        domain.paths.audit_log_path(),
        audit::render_entry(audit_event, &[("hostname", authenticated_cn)]),
        true,
    )?;
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    *domain.rate_limiter.lock() = next_rate_limiter;
    domain.finish_commit_under_transition(outcome)?;

    match auth_result {
        Ok(()) => response
            .ok_or_else(|| CertmeshError::Internal("promotion response was not prepared".into())),
        Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
            Err(CertmeshError::RateLimited { remaining_secs })
        }
        Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
            Err(CertmeshError::InvalidAuth)
        }
    }
}

impl CertmeshCore {
    /// Create a one-shot local promotion session.
    pub async fn begin_promotion_acceptance(
        &self,
    ) -> Result<protocol::BeginPromotionResponse, CertmeshError> {
        let _transition = self.state.transition.lock().await;
        if self.status().role != CertmeshRole::Member {
            return Err(CertmeshError::Conflict(
                "only an enrolled member can receive promotion".into(),
            ));
        }

        let keypair = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let public = keypair.public_key_bytes();
        let mut random = [0u8; 16];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut random);
        let id = koi_common::encoding::hex_encode(&random);
        *self.state.pending_promotion.lock() = Some(PendingPromotion {
            id: id.clone(),
            keypair,
            expires_at: tokio::time::Instant::now() + PROMOTION_SESSION_TTL,
        });
        Ok(protocol::BeginPromotionResponse {
            session_id: id,
            ephemeral_public: koi_common::encoding::hex_encode(&public),
        })
    }

    /// Relay a promotion request from this local member to an authority over
    /// mTLS. The loopback adapter supplies operator auth; this command supplies
    /// the member certificate and keeps its private key inside the daemon.
    pub async fn relay_promotion(
        &self,
        request: protocol::RelayPromotionRequest,
    ) -> Result<protocol::PromoteResponse, CertmeshError> {
        if request.authority_endpoint.trim().is_empty() {
            return Err(CertmeshError::InvalidPayload(
                "authority endpoint cannot be empty".into(),
            ));
        }
        let session_id = request.session_id.clone();
        let (client_public_key, identity, member_state) = self
            .run_blocking_transition(move |domain| {
                if domain.status.current().role != CertmeshRole::Member {
                    return Err(CertmeshError::Conflict(
                        "only an enrolled member can receive promotion".into(),
                    ));
                }
                let client_public_key = {
                    let pending = domain.pending_promotion.lock();
                    let pending = pending.as_ref().ok_or_else(|| {
                        CertmeshError::PromotionFailed("no pending local session".into())
                    })?;
                    if pending.id != session_id {
                        return Err(CertmeshError::PromotionFailed(
                            "promotion session does not match".into(),
                        ));
                    }
                    if tokio::time::Instant::now() > pending.expires_at {
                        return Err(CertmeshError::PromotionFailed(
                            "promotion session expired".into(),
                        ));
                    }
                    pending.keypair.public_key_bytes()
                };
                if domain.is_self_revoked_under_transition() {
                    return Err(CertmeshError::Revoked(domain.require_local_hostname(
                        "relaying a Certmesh authority promotion",
                    )?));
                }
                let identity = domain.local_identity_under_transition().ok_or_else(|| {
                    CertmeshError::Conflict(
                        "local member identity is missing, expired, or invalid".into(),
                    )
                })?;
                let member_state =
                    member::load(&domain.paths.member_state_path())?.ok_or_else(|| {
                        CertmeshError::Conflict("local member renewal state is unreadable".into())
                    })?;
                Ok((client_public_key, identity, member_state))
            })
            .await??;

        let host = member::host_from_endpoint(&request.authority_endpoint);
        let port = if host == member_state.ca_host {
            member_state.ca_mtls_port
        } else {
            member::DEFAULT_CA_MTLS_PORT
        };
        let body = serde_json::to_string(&protocol::PromoteRequest {
            auth: request.auth,
            ephemeral_public: Some(client_public_key),
        })
        .map_err(|error| CertmeshError::Internal(format!("serialize promotion: {error}")))?;
        let (status, response) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::post_json(
                &host,
                port,
                http::paths::PROMOTE,
                &body,
                &identity.cert_pem,
                &identity.key_pem,
                &identity.ca_cert_pem,
            ),
        )
        .await
        .map_err(|_| {
            CertmeshError::PromotionFailed(format!("promotion request to {host}:{port} timed out"))
        })??;
        if status != 200 {
            return Err(CertmeshError::PromotionFailed(format!(
                "authority returned HTTP {status}: {response}"
            )));
        }
        serde_json::from_str(&response)
            .map_err(|error| CertmeshError::PromotionFailed(format!("invalid response: {error}")))
    }

    /// Install a promotion response as one Certmesh aggregate transaction.
    pub async fn accept_promotion(
        &self,
        request: protocol::AcceptPromotionRequest,
    ) -> Result<protocol::AcceptPromotionResponse, CertmeshError> {
        if request.passphrase.is_empty() {
            return Err(CertmeshError::InvalidPayload(
                "promotion passphrase cannot be empty".into(),
            ));
        }
        self.run_blocking_transition(move |domain| {
            accept_promotion_under_transition(domain, request)
        })
        .await?
    }

    /// Authorize a member and prepare encrypted promotion material on the
    /// current authority.
    ///
    /// The transport proves `authenticated_cn` from mTLS; every remaining
    /// security decision and durable side effect belongs to this command. The
    /// TOTP limiter and audit outcome commit before a response is returned.
    pub async fn promote(
        &self,
        authenticated_cn: &str,
        request: &protocol::PromoteRequest,
    ) -> Result<protocol::PromoteResponse, CertmeshError> {
        let client_public_key = request.ephemeral_public.ok_or_else(|| {
            CertmeshError::InvalidPayload("ephemeral_public is required for promotion".to_string())
        })?;
        let authenticated_cn = authenticated_cn.to_string();
        let auth = request.auth.clone();
        self.run_blocking_transition(move |domain| {
            promote_under_transition(domain, &authenticated_cn, &auth, &client_public_key)
        })
        .await?
    }
}
