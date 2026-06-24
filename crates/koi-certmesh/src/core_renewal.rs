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
    ///
    /// Emits `CertRenewed`, `CertRenewalFailed`, and `CertExpiringSoon` lifecycle events.
    pub async fn renew_self_if_due(&self) -> Result<RenewOutcome, CertmeshError> {
        // Inner function carries all the real work; this outer shell handles event
        // emission for every failure exit without scattering it across every `?`.
        let days_left_at_attempt = self.cert_days_left_if_member();
        let result = self.renew_self_if_due_inner().await;
        match &result {
            Err(e) => {
                let count = self
                    .state
                    .renewal_failure_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                let _ = self.state.event_tx.send(CertmeshEvent::CertRenewalFailed {
                    reason: e.to_string(),
                    consecutive_failures: count,
                });
                // Only emit CertExpiringSoon when the cert is actually past the renewal
                // threshold (i.e. we attempted renewal, not just "not due").
                if let Some(days) = days_left_at_attempt {
                    let _ = self
                        .state
                        .event_tx
                        .send(CertmeshEvent::CertExpiringSoon { days_left: days });
                }
            }
            Ok(RenewOutcome::Renewed { ref expires, .. }) => {
                self.state
                    .renewal_failure_count
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                let expires_at = expires
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap_or_else(|_| chrono::Utc::now() + chrono::Duration::days(90));
                let _ = self
                    .state
                    .event_tx
                    .send(CertmeshEvent::CertRenewed { expires_at });
            }
            _ => {}
        }
        result
    }

    /// The local member certificate's expiry instant (`not_after`), or `None` when
    /// this node is not a member (never joined a mesh) or the leaf cannot be parsed.
    ///
    /// Exposes the raw expiry so an embedded consumer can derive its own urgency
    /// (days-left, renewal scheduling) without re-implementing leaf parsing
    /// (wishlist I2 / ADR-021). Reachable via `certmesh().core()?.member_cert_expiry()`.
    ///
    /// **This is `member.json`-gated** — it returns `None` for a node that never
    /// armed member state (e.g. an EmbeddedOnly consumer that deliberately does not
    /// arm `member.json`, since that implies the mTLS pull-renewal it doesn't serve).
    /// For this node's own-leaf expiry **independent of member state**, prefer
    /// [`local_identity`](Self::local_identity) → `Identity::renewal` (cert-derived,
    /// works without `member.json`, and carries full renewal health — ADR-022 N5).
    pub fn member_cert_expiry(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let state = member::load(&self.state.paths.member_state_path())?;
        let cert_path = self
            .state
            .paths
            .certs_dir()
            .join(&state.hostname)
            .join("cert.pem");
        let pem = std::fs::read_to_string(cert_path).ok()?;
        leaf_not_after_utc(&pem)
    }

    /// How many days until the local member cert expires. Returns `None` when the
    /// node is not a member or the cert cannot be parsed. Used to populate
    /// `CertExpiringSoon` without re-reading the cert inside the inner function.
    fn cert_days_left_if_member(&self) -> Option<i64> {
        let not_after = self.member_cert_expiry()?;
        Some((not_after - chrono::Utc::now()).num_days())
    }

    async fn renew_self_if_due_inner(&self) -> Result<RenewOutcome, CertmeshError> {
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

    /// CA-side, transport-agnostic member renewal (ADR-021).
    ///
    /// Sign a rotate-key renewal for an **already-authenticated** member. The
    /// caller is responsible for proving `authenticated_cn`:
    ///   - mTLS path: the TLS `ClientCn` extracted from the connection,
    ///   - envelope path: `Assurance::identity()` after [`verify`](Self::verify).
    ///
    /// `authenticated_cn` is a **trusted input** — this method never
    /// re-authenticates; it enforces the CA-side business invariants on a
    /// pre-authenticated identity:
    ///
    /// 1. CA initialized + unlocked,
    /// 2. member enrolled, **active**, and **not revoked** (a revoked member's
    ///    renewal is refused *and audited* at the CA boundary, ADR-017 F9/F14),
    /// 3. **SAN pinning** — every name in the CSR must be covered by the SANs
    ///    recorded at enrollment; a renewal CSR can never expand its SAN set.
    ///    [`csr::sign_csr`] already substitutes the authorized SANs structurally,
    ///    but an expansion attempt is rejected up-front (`InvalidPayload`) so it
    ///    fails loudly rather than silently narrowing,
    /// 4. sign the CSR with the **authorized** SANs + policy lifetime (no key
    ///    generation — the CA never sees a member private key),
    /// 5. record the rotated leaf's fingerprint/expiry in the roster (bumping
    ///    `seq` — a rotation is a membership change the trust bundle reflects, F8),
    /// 6. append a `cert_renewed` audit entry and emit [`CertmeshEvent::CertRenewed`].
    ///
    /// Returns the wire-shaped [`protocol::RenewResponse`] (leaf + CA cert +
    /// fingerprint + expiry); the transport adapter only serializes it.
    pub async fn renew_member(
        &self,
        authenticated_cn: &str,
        csr_pem: &str,
    ) -> Result<protocol::RenewResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        // Authorization FIRST — before the CSR is ever parsed, so an unauthorized
        // (revoked / unknown) caller is refused without inspecting its CSR. The
        // member must be enrolled, active, and not revoked; the authorized SANs
        // are the ones recorded at enrollment.
        let (authorized_sans, policy) = {
            let roster = self.state.roster.lock().await;
            if roster.is_revoked(authenticated_cn) {
                drop(roster);
                let _ = crate::audit::append_entry_to(
                    &self.state.paths.audit_log_path(),
                    "mtls_revoked_rejected",
                    &[("hostname", authenticated_cn), ("op", "renew")],
                );
                return Err(CertmeshError::Revoked(authenticated_cn.to_string()));
            }
            match roster.find_member(authenticated_cn) {
                Some(m) if m.status == crate::roster::MemberStatus::Active => {
                    (m.cert_sans.clone(), roster.metadata.policy.clone())
                }
                Some(_) => {
                    // Non-active (e.g. a status that bypassed is_revoked) → 403,
                    // not a 500; this is an authorization refusal, not a fault.
                    return Err(CertmeshError::Forbidden(format!(
                        "member '{authenticated_cn}' is not active"
                    )));
                }
                None => return Err(CertmeshError::NotFound(authenticated_cn.to_string())),
            }
        };
        // Carry the CA's full policy back to the member (ADR-022 N4) so a member
        // that does not arm member.json can still compute an accurate renewal
        // schedule; the leaf lifetime is the policy's.
        let lifetime_days = policy.leaf_lifetime_days;

        // SAN pinning (the critical invariant): parse the CSR's requested names
        // (only now, after authorization) and reject any name not covered by the
        // enrollment-recorded SANs.
        let requested = crate::csr::requested_sans(csr_pem)?;
        for san in &requested {
            if !authorized_sans
                .iter()
                .any(|a| crate::csr::names_match(a, san))
            {
                return Err(CertmeshError::InvalidPayload(format!(
                    "renewal CSR requests unauthorized identifier '{san}' not in the enrollment record"
                )));
            }
        }

        // Sign the member's CSR — no key generation, authorized SANs only. The CA
        // lock is held through signing (CPU-bound, no I/O) so the key cannot be
        // torn down between authorization and signing; it is released immediately
        // after, before the roster commit.
        let leaf_pem = crate::csr::sign_csr(ca, csr_pem, &authorized_sans, lifetime_days)?;
        let ca_cert = ca.cert_pem.clone();
        let ca_fingerprint = crate::ca::ca_fingerprint(ca);
        drop(ca_guard);

        // Fingerprint + expiry from the issued leaf (same convention as enrollment).
        let fingerprint = pem::parse(&leaf_pem)
            .map(|der| koi_crypto::pinning::fingerprint_sha256(der.contents()))
            .map_err(|e| CertmeshError::Certificate(format!("issued leaf parse: {e}")))?;
        let expires = chrono::Utc::now() + chrono::Duration::days(i64::from(lifetime_days));

        // Update the roster member's fingerprint/expiry/last_seen and bump `seq`
        // (a rotation is a membership change the trust bundle must reflect — F8).
        if let Err(e) = self
            .state
            .commit_roster(|roster| {
                if let Some(member) = roster.find_member_mut(authenticated_cn) {
                    member.cert_fingerprint = fingerprint.clone();
                    member.cert_expires = expires;
                    member.last_seen = Some(chrono::Utc::now());
                }
                Ok(())
            })
            .await
        {
            tracing::warn!(error = %e, "Failed to save roster after renewal");
        }

        let _ = crate::audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "cert_renewed",
            &[
                ("hostname", authenticated_cn),
                ("fingerprint", &fingerprint),
                ("expires", &expires.to_rfc3339()),
            ],
        );

        let _ = self.state.event_tx.send(CertmeshEvent::CertRenewed {
            expires_at: expires,
        });

        Ok(protocol::RenewResponse {
            hostname: authenticated_cn.to_string(),
            service_cert: leaf_pem,
            ca_cert,
            ca_fingerprint,
            expires: expires.to_rfc3339(),
            policy,
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
        let _ = self
            .state
            .event_tx
            .send(CertmeshEvent::BundleUpdated { self_revoked });
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
