//! Member renewal, trust-bundle pull, health, role, and promotion.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    // ── Phase 3 - Lifecycle ────────────────────────────────────────

    /// Member-initiated, rotate-key renewal (ADR-017 F6).
    ///
    /// A no-op ([`RenewOutcome::NotApplicable`]) unless this node has a persisted
    /// [`member::MemberState`] (i.e. it *joined* a mesh). When its local leaf is
    /// within the CA policy's `renew_threshold_days`, it:
    ///
    /// 1. generates a **fresh** keypair + CSR (rotate-on-renewal — the new private
    ///    key is held in memory until the install succeeds, never on the CA),
    /// 2. POSTs only the CSR to the CA's mTLS `/v1/certmesh/renew`, presenting its
    ///    **current** (still-valid) leaf as the client identity,
    /// 3. verifies the returned CA fingerprint matches its pin (anti-CA-swap),
    /// 4. installs the new key + signed leaf locally and runs its reload hook.
    ///
    /// The CA never generates or receives a member private key — on enroll *or*
    /// renew. If the network call fails (CA down, cert lapsed past mTLS validity)
    /// the local files are left untouched and the loop retries next tick.
    pub async fn renew_self_if_due(&self) -> Result<RenewOutcome, CertmeshError> {
        let Some(state) = member::load(&self.state.paths.member_state_path()) else {
            return Ok(RenewOutcome::NotApplicable);
        };

        let cert_dir = self.state.paths.certs_dir().join(&state.hostname);
        // Read the current key + cert + pinned CA off the blocking pool.
        let read_dir = cert_dir.clone();
        let (current_cert, current_key, pinned_ca_pem) =
            tokio::task::spawn_blocking(move || -> std::io::Result<(String, String, String)> {
                Ok((
                    std::fs::read_to_string(read_dir.join("cert.pem"))?,
                    std::fs::read_to_string(read_dir.join("key.pem"))?,
                    std::fs::read_to_string(read_dir.join("ca.pem"))?,
                ))
            })
            .await
            .map_err(|e| CertmeshError::Internal(format!("read member cert task: {e}")))??;

        // Due? Compare the local leaf's not_after against the renew threshold.
        let not_after = leaf_not_after_utc(&current_cert).ok_or_else(|| {
            CertmeshError::Internal("cannot parse local leaf expiry for renewal".into())
        })?;
        let threshold = chrono::Duration::days(i64::from(state.policy.renew_threshold_days));
        if chrono::Utc::now() + threshold < not_after {
            return Ok(RenewOutcome::NotDue { not_after });
        }

        // Rotate: fresh keypair + CSR. The new key lives only in memory until the
        // CA-signed leaf is in hand, so a failed renewal never discards the
        // working key.
        let (new_key_pem, csr_pem) = csr::generate_keypair_and_csr(&state.hostname, &state.sans)?;
        let req_body = serde_json::to_string(&protocol::RenewRequest {
            hostname: state.hostname.clone(),
            csr: csr_pem,
        })
        .map_err(|e| CertmeshError::Internal(format!("serialize renew request: {e}")))?;

        let (host, port) = state.ca_mtls_authority();
        // Bound the network call: a black-holed CA must not stall the loop (or
        // daemon shutdown) for the OS TCP timeout.
        let (status, body) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::post_json(
                &host,
                port,
                http::paths::RENEW,
                &req_body,
                &current_cert,
                &current_key,
                &pinned_ca_pem,
            ),
        )
        .await
        .map_err(|_| CertmeshError::RenewalFailed {
            hostname: state.hostname.clone(),
            reason: format!(
                "renewal request to {host}:{port} timed out after {}s",
                RENEWAL_REQUEST_TIMEOUT.as_secs()
            ),
        })??;

        if status != 200 {
            return Err(CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("CA returned HTTP {status}: {body}"),
            });
        }
        let resp: protocol::RenewResponse =
            serde_json::from_str(&body).map_err(|e| CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("malformed renew response: {e}"),
            })?;

        // Anti-CA-swap: derive the fingerprint from the RETURNED CA cert (the one
        // we are about to install as our new pin) and require it to match the pin.
        // Deriving locally — rather than trusting the asserted `ca_fingerprint`
        // string — is the authoritative check.
        let returned_ca_fp = pem::parse(&resp.ca_cert)
            .map(|der| koi_crypto::pinning::fingerprint_sha256(der.contents()))
            .map_err(|e| CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("returned ca_cert is not valid PEM: {e}"),
            })?;
        if !koi_crypto::pinning::fingerprints_match(&returned_ca_fp, &state.ca_fingerprint) {
            return Err(CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: "returned CA cert does not match the pinned CA fingerprint".into(),
            });
        }

        // Install the new key + leaf atomically (temp → rename per file).
        let new_cert = resp.service_cert.clone();
        let new_ca = resp.ca_cert.clone();
        let fullchain = format!("{new_cert}{new_ca}");
        let dir = cert_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&dir)?;
            write_file_atomic(&dir.join("key.pem"), new_key_pem.as_bytes(), true)?;
            write_file_atomic(&dir.join("cert.pem"), new_cert.as_bytes(), false)?;
            write_file_atomic(&dir.join("ca.pem"), new_ca.as_bytes(), false)?;
            write_file_atomic(&dir.join("fullchain.pem"), fullchain.as_bytes(), false)?;
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write renewed cert task: {e}")))??;

        tracing::info!(hostname = %state.hostname, expires = %resp.expires, "Member certificate renewed (rotated key)");

        // Run the local reload hook, if configured.
        let hook = state
            .reload_hook
            .as_deref()
            .map(lifecycle::execute_reload_hook);

        Ok(RenewOutcome::Renewed {
            expires: resp.expires,
            hook,
        })
    }

    /// Pull, verify, and apply the CA's signed trust bundle (ADR-017 P1/F4).
    ///
    /// A no-op ([`BundleOutcome::NotApplicable`]) unless this node joined a mesh.
    /// Fetches the self-verifying bundle over plain HTTP, verifies the ES256
    /// signature against the **pinned** CA fingerprint, and rejects a strictly
    /// older `seq` (anti-rollback). On a newer bundle it refreshes the member's
    /// cached `policy` and `last_bundle_seq`, and flags whether this node has been
    /// revoked mesh-wide.
    pub async fn pull_trust_bundle(&self) -> Result<BundleOutcome, CertmeshError> {
        let member_path = self.state.paths.member_state_path();
        let Some(mut state) = member::load(&member_path) else {
            return Ok(BundleOutcome::NotApplicable);
        };

        let (host, port) = (state.ca_host.clone(), state.ca_http_port);
        let (status, body) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::get(&host, port, http::paths::TRUST_BUNDLE),
        )
        .await
        .map_err(|_| {
            CertmeshError::Internal(format!("trust-bundle pull from {host}:{port} timed out"))
        })??;

        if status != 200 {
            return Err(CertmeshError::Internal(format!(
                "CA returned HTTP {status} for trust-bundle"
            )));
        }
        let signed: bundle::SignedBundle = serde_json::from_str(&body)
            .map_err(|e| CertmeshError::Internal(format!("malformed trust bundle: {e}")))?;

        // Verify signature against the pinned CA + anti-rollback floor.
        if let Err(e) = bundle::verify(&signed, &state.ca_fingerprint, Some(state.last_bundle_seq))
        {
            // F5 fail-safe: a bundle whose CA fingerprint differs from our pin is
            // rejected, and we KEEP the old pin. There is no supported live CA
            // re-key path today, so a fingerprint change is treated as hostile; an
            // intentional CA replacement is recovered by re-enrolling with a fresh
            // invite (which carries the new fingerprint, F3).
            if matches!(e, bundle::BundleError::PinMismatch) {
                tracing::error!(
                    host = %state.hostname,
                    "Trust bundle CA fingerprint does NOT match the pinned CA — rejecting \
                     (fail-safe). Re-enroll with a fresh invite if the CA was intentionally replaced."
                );
            }
            return Err(CertmeshError::Internal(format!(
                "trust bundle rejected: {e}"
            )));
        }

        // F5 anchor self-heal: the bundle's `ca_cert_pem` provably hashes to our pin
        // (verify enforced it), so writing it keeps the on-disk `ca.pem` — the trust
        // root the mTLS renewal client loads — in sync and repairs drift/corruption.
        // Done on every verified pull (even an unchanged seq) so a wiped anchor is
        // restored promptly; the write is skipped when the file already matches.
        {
            let anchor = self
                .state
                .paths
                .certs_dir()
                .join(&state.hostname)
                .join("ca.pem");
            let want = signed.bundle.ca_cert_pem.clone();
            // Best-effort: the closure logs its own write error, and any JoinError
            // (task panic) is intentionally dropped. A write failure is harmless —
            // the bundle was already pin-verified, and because this heal runs on
            // every verified pull (before the seq short-circuit below) the next pull
            // simply retries it.
            let _ = tokio::task::spawn_blocking(move || {
                let current = std::fs::read_to_string(&anchor).ok();
                if current.as_deref() != Some(want.as_str()) {
                    match write_file_atomic(&anchor, want.as_bytes(), false) {
                        Ok(()) => tracing::info!(
                            path = %anchor.display(),
                            "Refreshed on-disk CA anchor from the verified trust bundle"
                        ),
                        Err(e) => tracing::warn!(error = %e, "Could not refresh on-disk CA anchor"),
                    }
                }
            })
            .await;
        }

        let seq = signed.bundle.seq;
        if seq == state.last_bundle_seq {
            return Ok(BundleOutcome::NoChange { seq });
        }

        let hostname = state.hostname.clone();
        let self_revoked = signed.bundle.is_revoked(&hostname);
        state.last_bundle_seq = seq;
        state.policy = signed.bundle.policy.clone();
        tokio::task::spawn_blocking(move || member::save(&member_path, &state))
            .await
            .map_err(|e| CertmeshError::Internal(format!("member state save task: {e}")))??;

        if self_revoked {
            tracing::error!(
                %hostname,
                "This node has been REVOKED in the mesh trust bundle (seq {seq}); renewal will be refused by the CA"
            );
        } else {
            tracing::debug!(seq, "Trust bundle updated");
        }
        Ok(BundleOutcome::Updated { seq, self_revoked })
    }

    /// Validate a member's health heartbeat.
    pub async fn health_check(
        &self,
        request: &protocol::HealthRequest,
    ) -> Result<protocol::HealthResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let current_fp = ca::ca_fingerprint(ca);
        let valid =
            health::validate_pinned_fingerprint(&current_fp, &request.pinned_ca_fingerprint);
        drop(ca_guard); // release the CA lock before the roster commit (no lock held across disk I/O)

        // Touch last_seen (no seq bump — liveness is not in the bundle); reject a
        // revoked member at the boundary before recording the heartbeat.
        self.state
            .touch_roster(|roster| {
                if roster.is_revoked(&request.hostname) {
                    return Err(CertmeshError::Revoked(request.hostname.clone()));
                }
                roster.touch_member(&request.hostname);
                Ok(())
            })
            .await?;

        Ok(protocol::HealthResponse {
            valid,
            ca_fingerprint: current_fp,
        })
    }

    /// Get the current node's roster role (if any).
    ///
    /// Returns `None` if the roster has no entry matching the local hostname.
    pub async fn node_role(&self) -> Option<roster::MemberRole> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()?;
        let roster = self.state.roster.lock().await;
        roster.find_member(&hostname).map(|m| m.role.clone())
    }

    /// Promote the local member to primary and demote any existing primary.
    /// Returns true if the roster was updated.
    pub async fn promote_self_to_primary(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        // Role changes are not bundle content → touch_roster (no seq bump), but the
        // write still serializes behind the single writer (F8).
        self.state
            .touch_roster(|roster| {
                let already_primary = roster
                    .find_member(&hostname)
                    .map(|m| m.role == roster::MemberRole::Primary)
                    .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
                if already_primary {
                    return Ok(false);
                }
                for m in roster.members.iter_mut() {
                    if m.role == roster::MemberRole::Primary {
                        m.role = roster::MemberRole::Standby;
                    }
                }
                if let Some(member) = roster.find_member_mut(&hostname) {
                    member.role = roster::MemberRole::Primary;
                } else {
                    return Err(CertmeshError::NotFound(hostname.clone()));
                }
                Ok(true)
            })
            .await
    }

    /// Demote the local member to standby. Returns true if the roster changed.
    pub async fn demote_self_to_standby(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        self.state
            .touch_roster(|roster| {
                let member = roster
                    .find_member_mut(&hostname)
                    .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
                if member.role == roster::MemberRole::Standby {
                    return Ok(false);
                }
                member.role = roster::MemberRole::Standby;
                Ok(true)
            })
            .await
    }

    /// Add alias SANs to a member's roster entry (used by DNS alias feedback).
    ///
    /// Returns true if any SANs were added.
    pub async fn add_alias_sans(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<bool, CertmeshError> {
        self.state
            .touch_roster(|roster| {
                let member = roster
                    .find_member_mut(hostname)
                    .ok_or_else(|| CertmeshError::NotFound(hostname.to_string()))?;
                let mut changed = false;
                for san in sans {
                    if !member.cert_sans.iter().any(|s| s == san) {
                        member.cert_sans.push(san.clone());
                        changed = true;
                    }
                }
                Ok(changed)
            })
            .await
    }

    /// Get the local hostname.
    pub fn local_hostname() -> Option<String> {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()
    }

    /// Get the pinned CA fingerprint for the local node (if set).
    pub async fn pinned_ca_fingerprint(&self) -> Option<String> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()?;
        let roster = self.state.roster.lock().await;
        roster
            .find_member(&hostname)
            .and_then(|m| m.pinned_ca_fingerprint.clone())
    }

    /// Prepare promotion material for a standby.
    ///
    /// Called on the primary when a standby requests promotion.
    /// Uses DH key agreement to encrypt the CA key for wire transfer.
    pub async fn promote(
        &self,
        client_public_key: &[u8; 32],
    ) -> Result<protocol::PromoteResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let auth_guard = self.state.auth.lock().await;
        let auth_state = auth_guard.as_ref().ok_or(CertmeshError::CaLocked)?;

        let roster = self.state.roster.lock().await;
        failover::prepare_promotion(ca, auth_state, &roster, client_public_key)
    }
}
