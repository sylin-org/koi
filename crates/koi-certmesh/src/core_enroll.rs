//! Enrollment: process member joins and self-enroll the CA node.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    /// Process an enrollment request. Returns the join response on success.
    ///
    /// The joining machine’s hostname comes from the request - not from
    /// `hostname::get()` which would return the CA server’s hostname.
    pub async fn enroll(
        &self,
        request: &protocol::JoinRequest,
    ) -> Result<protocol::JoinResponse, CertmeshError> {
        let hostname = &request.hostname;
        validate_hostname(hostname)?;
        // Default SANs: hostname + hostname.local, plus any extras the joiner sent.
        // Every extra SAN is validated (F15): IP literals pass through; everything
        // else must be a valid RFC 1123 hostname — so a joiner can't slip a wildcard
        // or junk DNS name into its cert. Capped to bound the SAN list.
        const MAX_EXTRA_SANS: usize = 16;
        let mut sans = vec![hostname.clone(), format!("{hostname}.local")];
        for extra in request.sans.iter().take(MAX_EXTRA_SANS) {
            if extra.parse::<std::net::IpAddr>().is_err() {
                validate_hostname(extra)?;
            }
            if !sans.contains(extra) {
                sans.push(extra.clone());
            }
        }

        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let roster = self.state.roster.lock().await;
        let auth_guard = self.state.auth.lock().await;
        // The enrollment auth credential may be absent when the CA was unlocked
        // via a non-passphrase slot (TOTP/auto-unlock master key). Invite-token
        // enrollment (ADR-015 F2) does not need it; the TOTP branch inside
        // `process_enrollment` fails closed (CaLocked) when it does.
        let auth_state = auth_guard.as_ref();
        let challenge_guard = self.state.pending_challenge.lock().await;
        let challenge = challenge_guard
            .as_ref()
            .cloned()
            .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
        let mut rate_limiter = self.state.rate_limiter.lock().await;
        let requires_approval = roster.requires_approval();
        let fallback_operator = roster.metadata.operator.clone();
        drop(roster);

        let approved_by = if requires_approval {
            request_approval(&self.state, hostname, requires_approval).await?
        } else {
            fallback_operator
        };

        // Single-writer commit (ADR-017 F8): process_enrollment validates, signs,
        // and pushes the member under the lock; commit_roster bumps `seq` and
        // persists atomically. On any error it errors *before* mutating, so the
        // roster is left unchanged and nothing is persisted.
        let result = self
            .state
            .commit_roster(|roster| {
                enrollment::process_enrollment(
                    ca,
                    roster,
                    auth_state,
                    &challenge,
                    &mut rate_limiter,
                    request,
                    hostname,
                    &sans,
                    approved_by,
                    &self.state.paths,
                )
            })
            .await;

        // Persist the rate-limiter regardless of outcome (ADR-017 F7): a failed
        // TOTP attempt advances a lockout that must survive a restart. Snapshot +
        // drop the guard before the blocking write (no lock held across I/O).
        // Invite joins never consult the limiter, so this is a no-op for them.
        let limiter_snapshot = rate_limiter.clone();
        drop(rate_limiter);
        if let Err(e) = persist_rate_limiter(&self.state.paths, &limiter_snapshot) {
            tracing::warn!(error = %e, "Could not persist rate-limiter state");
        }

        let (response, _issued) = result?;

        let _ = self.state.event_tx.send(CertmeshEvent::MemberJoined {
            hostname: response.hostname.clone(),
            fingerprint: response.ca_fingerprint.clone(),
        });

        Ok(response)
    }

    /// Self-enroll the daemon as a certmesh member.
    ///
    /// Called automatically after CA creation (and on every daemon start) to get
    /// the server leaf the mTLS + ACME listeners use. This is the **one** issuance
    /// path that key-gens on the CA (the CA's own identity, [`ca::issue_certificate`]
    /// — ADR-017 P3); member leaves only ever come from a member CSR.
    ///
    /// Idempotent **except** when the on-disk leaf is within the CA policy's
    /// `renew_threshold_days`: then it re-issues, so a restart refreshes the
    /// listener cert (the CA self-renews — no live mTLS reload yet; the restart is
    /// the reload point).
    pub async fn self_enroll(&self) -> Result<SelfEnrollment, CertmeshError> {
        let hostname = hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        // Validate hostname before using as certificate SAN (RFC 1123, F15).
        validate_hostname(&hostname)?;

        let sans = vec![
            hostname.clone(),
            format!("{hostname}.local"),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ];

        // Read the CA-held policy (self-leaf lifetime + restart-renewal threshold).
        let policy = {
            let roster = self.state.roster.lock().await;
            roster.metadata.policy.clone()
        };

        // The self leaf always lives at certs_dir()/<hostname> — derived, not read
        // from the roster (cert_path is no longer persisted, F13). Reuse the on-disk
        // leaf unless it is within the renewal threshold.
        {
            let cert_dir = self.state.paths.certs_dir().join(&hostname);
            let on_disk = (
                std::fs::read_to_string(cert_dir.join("cert.pem")).ok(),
                std::fs::read_to_string(cert_dir.join("key.pem")).ok(),
            );
            if let (Some(cert_pem), Some(key_pem)) = on_disk {
                let due = leaf_not_after_utc(&cert_pem)
                    .map(|na| {
                        chrono::Utc::now()
                            + chrono::Duration::days(i64::from(policy.renew_threshold_days))
                            >= na
                    })
                    .unwrap_or(true); // unparseable → re-issue to be safe
                if !due {
                    let ca_guard = self.state.ca.lock().await;
                    let ca = ca_guard.as_ref().ok_or_else(|| {
                        if self.state.paths.is_ca_initialized() {
                            CertmeshError::CaLocked
                        } else {
                            CertmeshError::CaNotInitialized
                        }
                    })?;
                    let ca_cert_pem = ca.cert_pem.clone();
                    drop(ca_guard);
                    tracing::debug!(hostname = %hostname, "already self-enrolled, reusing existing cert");
                    return Ok(SelfEnrollment {
                        cert_pem,
                        key_pem,
                        ca_cert_pem,
                    });
                }
                tracing::info!(hostname = %hostname, "CA self-cert within renewal threshold; re-issuing");
            }
        }

        // Issue a fresh (or renewed) self leaf at the policy lifetime.
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;
        let issued = ca::issue_certificate(ca, &hostname, &sans, policy.leaf_lifetime_days)?;
        let ca_cert_pem = ca.cert_pem.clone();
        drop(ca_guard);

        // Write cert files to the standard path (blocking I/O)
        let cert_path = self.state.paths.certs_dir().join(&hostname);
        let issued_clone = issued.clone();
        let cert_dir = tokio::task::spawn_blocking(move || {
            certfiles::write_cert_files_to(&cert_path, &issued_clone)
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("cert write task: {e}")))??;

        // Update the existing self entry in place, or insert as primary, then
        // commit (ADR-017 F8). The update path covers both restart-renewal and
        // concurrent self_enroll.
        if let Err(e) = self
            .state
            .commit_roster(|roster| {
                if let Some(member) = roster.find_member_mut(&hostname) {
                    member.cert_fingerprint = issued.fingerprint.clone();
                    member.cert_expires = issued.expires;
                    member.cert_path = cert_dir.display().to_string();
                } else {
                    roster.members.push(roster::RosterMember {
                        hostname: hostname.clone(),
                        role: roster::MemberRole::Primary,
                        enrolled_at: chrono::Utc::now(),
                        enrolled_by: Some("self-enrollment".to_string()),
                        cert_fingerprint: issued.fingerprint.clone(),
                        cert_expires: issued.expires,
                        cert_sans: sans.clone(),
                        cert_path: cert_dir.display().to_string(),
                        status: roster::MemberStatus::Active,
                        reload_hook: None,
                        last_seen: Some(chrono::Utc::now()),
                        pinned_ca_fingerprint: None,
                        proxy_entries: Vec::new(),
                    });
                }
                Ok(())
            })
            .await
        {
            tracing::warn!(error = %e, "Failed to save roster after self-enrollment");
        }

        tracing::info!(hostname = %hostname, "Daemon self-enrolled as certmesh member");

        // Audit the self-enroll issuance (ADR-017 F14) — the one issuance path that
        // key-gens on the CA must leave a trail like any other trust decision.
        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "self_enroll",
            &[
                ("hostname", hostname.as_str()),
                ("fingerprint", issued.fingerprint.as_str()),
            ],
        );

        let _ = self.state.event_tx.send(CertmeshEvent::MemberJoined {
            hostname,
            fingerprint: issued.fingerprint,
        });

        // A leaf is now on disk → posture may have flipped Open→Authenticated.
        self.state.republish_posture();

        Ok(SelfEnrollment {
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            ca_cert_pem,
        })
    }
}
