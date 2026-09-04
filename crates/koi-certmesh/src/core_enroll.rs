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
        // One domain policy owns the base names, configured-zone FQDN, validation,
        // deduplication, and cap. The request contains genuine extras only.
        let sans = self
            .state
            .issuance_names
            .member_sans(hostname, &request.sans)?;

        let (requires_approval, fallback_operator) = {
            let roster = self.state.roster.lock();
            (roster.requires_approval(), roster.metadata.operator.clone())
        };

        let approved_by = if requires_approval {
            match request_approval(&self.state, hostname, requires_approval).await {
                Ok(operator) => operator,
                Err(error) => {
                    let event = enrollment_denial_event(request, &error);
                    let hostname = hostname.to_string();
                    self.run_blocking_transition(move |domain| {
                        domain.commit_audit_under_transition(
                            event,
                            &[("hostname", hostname.as_str()), ("result", "denied")],
                        )
                    })
                    .await??;
                    return Err(error);
                }
            }
        } else {
            fallback_operator
        };

        // Human approval is the only unbounded wait and remains outside the
        // aggregate gate. Once admitted, authentication state, invite burn,
        // roster commit, projections, and event settle on the retained worker.
        let request = request.clone();
        let hostname = request.hostname.clone();
        self.run_blocking_transition(move |domain| {
            let ca_guard = domain.ca.lock();
            let ca = ca_guard.as_ref().ok_or_else(|| {
                if domain.paths.is_ca_initialized() {
                    CertmeshError::CaLocked
                } else {
                    CertmeshError::CaNotInitialized
                }
            })?;
            let auth_guard = domain.auth.lock();
            let auth_state = auth_guard.as_ref();
            let challenge = domain
                .pending_challenge
                .lock()
                .as_ref()
                .cloned()
                .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
            let mut rate_limiter = domain.rate_limiter.lock();
            let previous_rate_limiter = rate_limiter.clone();
            let mut roster = domain.roster.lock();
            let previous_roster = roster.clone();
            if roster.requires_approval() && !requires_approval {
                let error = CertmeshError::ApprovalDenied;
                domain.commit_audit_under_transition(
                    enrollment_denial_event(&request, &error),
                    &[("hostname", hostname.as_str()), ("result", "denied")],
                )?;
                return Err(error);
            }
            let prepared_invite = match request.invite_token.as_deref() {
                Some(token) => {
                    invite::prepare_consumption(&domain.paths.invites_path(), token, &hostname)?
                }
                None => None,
            };
            let invited_role = prepared_invite
                .as_ref()
                .map(|prepared| prepared.role.clone());
            let result = enrollment::process_enrollment_prevalidated(
                ca,
                &mut roster,
                auth_state,
                &challenge,
                &mut rate_limiter,
                &request,
                &hostname,
                &sans,
                approved_by,
                invited_role,
            );

            let limiter_json = serde_json::to_vec(&*rate_limiter).map_err(|error| {
                CertmeshError::Internal(format!("serialize rate limiter: {error}"))
            })?;
            let (response, issued) = match result {
                Ok(result) => result,
                Err(error) => {
                    *roster = previous_roster;
                    let mut transaction = repository::ArtifactTransaction::new();
                    transaction.write(domain.paths.rate_limiter_path(), limiter_json, true);
                    if let Some(prepared) = prepared_invite {
                        transaction.write(domain.paths.invites_path(), prepared.store_bytes, true);
                    }
                    transaction.append(
                        domain.paths.audit_log_path(),
                        audit::render_entry(
                            enrollment_denial_event(&request, &error),
                            &[("hostname", hostname.as_str()), ("result", "denied")],
                        ),
                        true,
                    )?;
                    let outcome = match domain.commit_artifacts_under_transition(transaction) {
                        Ok(outcome) => outcome,
                        Err(persist_error) => {
                            *rate_limiter = previous_rate_limiter;
                            return Err(persist_error);
                        }
                    };
                    drop(roster);
                    drop(rate_limiter);
                    drop(auth_guard);
                    drop(ca_guard);
                    domain.finish_commit_under_transition(outcome)?;
                    return Err(error);
                }
            };

            roster.metadata.seq = roster.metadata.seq.saturating_add(1);
            let roster_json = serde_json::to_vec_pretty(&*roster)
                .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?;
            let enrolled = roster
                .find_member(&hostname)
                .expect("successful enrollment inserts the requested member");
            let role = match enrolled.role {
                roster::MemberRole::Primary => "primary",
                roster::MemberRole::Standby => "standby",
                roster::MemberRole::Member => "member",
                roster::MemberRole::Client => "client",
            };
            let operator = enrolled.enrolled_by.as_deref().unwrap_or("self");
            let via = if request.invite_token.is_some() {
                "invite"
            } else {
                "totp"
            };
            let audit_line = audit::render_entry(
                "member_joined",
                &[
                    ("hostname", hostname.as_str()),
                    ("fingerprint", issued.fingerprint.as_str()),
                    ("role", role),
                    ("approved_by", operator),
                    ("via", via),
                ],
            );
            let mut transaction = repository::ArtifactTransaction::new();
            transaction.write(domain.paths.roster_path(), roster_json, true);
            transaction.write(domain.paths.rate_limiter_path(), limiter_json, true);
            if let Some(prepared) = prepared_invite {
                transaction.write(domain.paths.invites_path(), prepared.store_bytes, true);
            }
            transaction.append(domain.paths.audit_log_path(), audit_line, true)?;
            let outcome = match domain.commit_artifacts_under_transition(transaction) {
                Ok(outcome) => outcome,
                Err(error) => {
                    *roster = previous_roster;
                    *rate_limiter = previous_rate_limiter;
                    return Err(error);
                }
            };

            drop(roster);
            drop(rate_limiter);
            drop(auth_guard);
            drop(ca_guard);
            domain.finish_commit_under_transition(outcome)?;
            let _ = domain.event_tx.send(CertmeshEvent::MemberJoined {
                hostname: response.hostname.clone(),
                fingerprint: issued.fingerprint,
            });
            Ok(response)
        })
        .await?
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
        self.self_enroll_with_outcome()
            .await
            .map(|(enrollment, _changed)| enrollment)
    }

    /// Self-enroll and report whether a new leaf generation committed. The
    /// status/event publication stays inside this command's transition; callers
    /// such as the CA renewal scheduler use `changed` instead of synthesizing a
    /// second event after the gate has been released.
    pub(crate) async fn self_enroll_with_outcome(
        &self,
    ) -> Result<(SelfEnrollment, bool), CertmeshError> {
        let hostname = self.require_local_hostname("self-enrolling the Certmesh authority")?;

        // Validate hostname before using as certificate SAN (RFC 1123, F15).
        validate_hostname(&hostname)?;

        let sans = self.state.issuance_names.self_sans(&hostname, &[])?;
        self.run_blocking_transition(move |domain| {
            self_enroll_under_transition(domain, hostname, sans)
        })
        .await?
    }
}

fn self_enroll_under_transition(
    domain: &CertmeshDomain,
    hostname: String,
    sans: Vec<String>,
) -> Result<(SelfEnrollment, bool), CertmeshError> {
    let policy = domain.roster.lock().metadata.policy.clone();
    let cert_dir = domain.paths.certs_dir().join(&hostname);
    let on_disk = (
        std::fs::read_to_string(cert_dir.join("cert.pem")).ok(),
        std::fs::read_to_string(cert_dir.join("key.pem")).ok(),
    );
    if let (Some(cert_pem), Some(key_pem)) = on_disk {
        let due = leaf_not_after_utc(&cert_pem)
            .map(|not_after| {
                chrono::Utc::now() + chrono::Duration::days(i64::from(policy.renew_threshold_days))
                    >= not_after
            })
            .unwrap_or(true);
        let names_current = IssuanceNames::certificate_covers(&cert_pem, &sans);
        let ca_guard = domain.ca.lock();
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if domain.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;
        let ca_cert_pem = ca.cert_pem.clone();
        let material_usable =
            diagnosis::identity_material_is_usable(&cert_pem, &key_pem, &ca_cert_pem);
        if !due && names_current && material_usable {
            tracing::debug!(hostname = %hostname, "already self-enrolled, reusing existing cert");
            return Ok((
                SelfEnrollment {
                    cert_pem,
                    key_pem,
                    ca_cert_pem,
                },
                false,
            ));
        }
        tracing::info!(
            hostname = %hostname,
            due,
            names_current,
            material_usable,
            "CA self-cert requires re-issuance"
        );
    }

    let ca_guard = domain.ca.lock();
    let ca = ca_guard.as_ref().ok_or_else(|| {
        if domain.paths.is_ca_initialized() {
            CertmeshError::CaLocked
        } else {
            CertmeshError::CaNotInitialized
        }
    })?;
    let issued = ca::issue_certificate(ca, &hostname, &sans, policy.leaf_lifetime_days)?;
    let ca_cert_pem = ca.cert_pem.clone();
    drop(ca_guard);

    let mut next_roster = domain.roster.lock().clone();
    let renewing = if let Some(member) = next_roster.find_member_mut(&hostname) {
        member.cert_fingerprint = issued.fingerprint.clone();
        member.cert_expires = issued.expires;
        member.cert_sans = sans.clone();
        member.cert_path = cert_dir.display().to_string();
        true
    } else {
        next_roster.members.push(roster::RosterMember {
            hostname: hostname.clone(),
            role: roster::MemberRole::Primary,
            enrolled_at: chrono::Utc::now(),
            enrolled_by: Some("self-enrollment".to_string()),
            cert_fingerprint: issued.fingerprint.clone(),
            cert_expires: issued.expires,
            cert_sans: sans,
            cert_path: cert_dir.display().to_string(),
            status: roster::MemberStatus::Active,
            reload_hook: None,
            last_seen: Some(chrono::Utc::now()),
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        false
    };
    next_roster.metadata.seq = next_roster.metadata.seq.saturating_add(1);

    let mut transaction = repository::ArtifactTransaction::new();
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
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&next_roster)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
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
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    *domain.roster.lock() = next_roster;
    if renewing {
        domain.clear_renewal_failure_under_transition();
    }
    domain.finish_commit_under_transition(outcome)?;

    if renewing {
        let _ = domain.event_tx.send(CertmeshEvent::CertRenewed {
            expires_at: issued.expires,
        });
    } else {
        let _ = domain.event_tx.send(CertmeshEvent::MemberJoined {
            hostname: hostname.clone(),
            fingerprint: issued.fingerprint.clone(),
        });
    }
    tracing::info!(hostname = %hostname, "Daemon self-enrolled as certmesh member");
    Ok((
        SelfEnrollment {
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            ca_cert_pem,
        },
        true,
    ))
}

fn enrollment_denial_event(request: &protocol::JoinRequest, error: &CertmeshError) -> &'static str {
    match error {
        CertmeshError::EnrollmentClosed => "enroll_closed",
        CertmeshError::CaLocked => "enroll_ca_locked",
        CertmeshError::RateLimited { .. } => "enroll_rate_limited",
        CertmeshError::Revoked(_) => "enroll_revoked_attempt",
        CertmeshError::AlreadyEnrolled(_) => "enroll_already_enrolled",
        CertmeshError::ApprovalDenied => "enroll_approval_denied",
        CertmeshError::InvalidAuth if request.invite_token.is_some() => "enroll_token_invalid",
        CertmeshError::InvalidAuth if request.auth.is_none() => "enroll_auth_missing",
        CertmeshError::InvalidAuth => "enroll_auth_failed",
        CertmeshError::InvalidPayload(_) if request.csr.is_none() => "enroll_no_csr",
        CertmeshError::InvalidPayload(_) => "enroll_profile_refused",
        _ => "enroll_failed",
    }
}
