//! Member renewal, trust-bundle pull, health, role, and promotion.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

struct PreparedSelfRenewal {
    state: member::MemberState,
    original_state: member::MemberState,
    renewal_sans: Vec<String>,
    cert_dir: std::path::PathBuf,
    current_cert: String,
    current_key: String,
    pinned_ca_pem: String,
    new_key_pem: String,
    request_body: String,
    host: String,
    port: u16,
}

enum SelfRenewalPreparation {
    Complete(RenewOutcome),
    Request(Box<PreparedSelfRenewal>),
}

struct CommittedSelfRenewal {
    expires: String,
    reload_completion: Option<tokio::sync::oneshot::Receiver<protocol::HookResult>>,
}

struct ReloadDispatch {
    executor: Arc<lifecycle::ReloadExecutor>,
    permit: blocking_worker::CertmeshBlockingPermit,
    domain: Arc<CertmeshDomain>,
}

fn prepare_self_renewal_under_transition(
    domain: &CertmeshDomain,
    operator_requested: bool,
) -> Result<SelfRenewalPreparation, CertmeshError> {
    let Some(state) = member::load(&domain.paths.member_state_path())? else {
        return Ok(SelfRenewalPreparation::Complete(
            RenewOutcome::NotApplicable,
        ));
    };
    let original_state = state.clone();
    let renewal_sans = domain
        .issuance_names
        .member_sans(&state.hostname, &state.sans)?;
    let cert_dir = domain.paths.certs_dir().join(&state.hostname);
    let current_cert = std::fs::read_to_string(cert_dir.join("cert.pem"))?;
    let current_key = std::fs::read_to_string(cert_dir.join("key.pem"))?;
    let pinned_ca_pem = std::fs::read_to_string(cert_dir.join("ca.pem"))?;

    let not_after = leaf_not_after_utc(&current_cert).ok_or_else(|| {
        CertmeshError::Internal("cannot parse local leaf expiry for renewal".into())
    })?;
    let threshold = chrono::Duration::days(i64::from(state.policy.renew_threshold_days));
    let names_current = IssuanceNames::certificate_covers(&current_cert, &renewal_sans);
    if !operator_requested && chrono::Utc::now() + threshold < not_after && names_current {
        return Ok(SelfRenewalPreparation::Complete(RenewOutcome::NotDue {
            not_after,
        }));
    }

    let (new_key_pem, csr_pem) = csr::generate_keypair_and_csr(&state.hostname, &renewal_sans)?;
    let request_body = serde_json::to_string(&protocol::RenewRequest {
        hostname: state.hostname.clone(),
        csr: csr_pem,
    })
    .map_err(|error| CertmeshError::Internal(format!("serialize renew request: {error}")))?;
    let (host, port) = state.ca_mtls_authority();

    Ok(SelfRenewalPreparation::Request(Box::new(
        PreparedSelfRenewal {
            state,
            original_state,
            renewal_sans,
            cert_dir,
            current_cert,
            current_key,
            pinned_ca_pem,
            new_key_pem,
            request_body,
            host,
            port,
        },
    )))
}

fn commit_self_renewal_under_transition(
    domain: &CertmeshDomain,
    mut prepared: PreparedSelfRenewal,
    response: protocol::RenewResponse,
    reload_dispatch: Option<ReloadDispatch>,
) -> Result<CommittedSelfRenewal, CertmeshError> {
    let expires_at =
        leaf_not_after_utc(&response.service_cert).ok_or_else(|| CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: "returned service certificate has no valid expiry".into(),
        })?;
    let reported_expiry = response
        .expires
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: format!("returned expiry is not RFC 3339: {error}"),
        })?;
    if reported_expiry != expires_at {
        return Err(CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: "returned expiry does not match the signed certificate".into(),
        });
    }
    let returned_ca_fingerprint = pem::parse(&response.ca_cert)
        .map(|der| koi_crypto::pinning::fingerprint_sha256(der.contents()))
        .map_err(|error| CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: format!("returned ca_cert is not valid PEM: {error}"),
        })?;
    if !koi_crypto::pinning::fingerprints_match(
        &returned_ca_fingerprint,
        &prepared.state.ca_fingerprint,
    ) {
        return Err(CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: "returned CA cert does not match the pinned CA fingerprint".into(),
        });
    }

    if member::load(&domain.paths.member_state_path())?.as_ref() != Some(&prepared.original_state)
        || std::fs::read_to_string(prepared.cert_dir.join("cert.pem"))
            .ok()
            .as_deref()
            != Some(prepared.current_cert.as_str())
        || std::fs::read_to_string(prepared.cert_dir.join("key.pem"))
            .ok()
            .as_deref()
            != Some(prepared.current_key.as_str())
    {
        return Err(CertmeshError::Conflict(
            "local identity changed while renewal was in flight; retrying is safe".into(),
        ));
    }

    prepared.state.sans = prepared.renewal_sans;
    let reload_intent = if let Some(command) = prepared.state.reload_hook.clone() {
        let fingerprint = pem::parse(&response.service_cert)
            .map(|certificate| koi_crypto::pinning::fingerprint_sha256(certificate.contents()))
            .map_err(|error| CertmeshError::Certificate(error.to_string()))?;
        Some(lifecycle::ReloadIntent::new(command, fingerprint))
    } else {
        None
    };
    if reload_intent.is_some() != reload_dispatch.is_some() {
        return Err(CertmeshError::Internal(
            "reload execution was not admitted before certificate commit".into(),
        ));
    }
    let fullchain = format!("{}{}", response.service_cert, response.ca_cert);
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        prepared.cert_dir.join("key.pem"),
        prepared.new_key_pem.as_bytes().to_vec(),
        true,
    );
    transaction.write(
        prepared.cert_dir.join("cert.pem"),
        response.service_cert.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        prepared.cert_dir.join("ca.pem"),
        response.ca_cert.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        prepared.cert_dir.join("fullchain.pem"),
        fullchain.into_bytes(),
        false,
    );
    transaction.write(
        domain.paths.member_state_path(),
        serde_json::to_vec_pretty(&prepared.state)
            .map_err(|error| CertmeshError::Internal(format!("serialize member state: {error}")))?,
        true,
    );
    if let Some(intent) = reload_intent.as_ref() {
        transaction.write(
            domain.paths.reload_intent_path(),
            lifecycle::render_intent(intent)?,
            true,
        );
    } else {
        transaction.remove(domain.paths.reload_intent_path());
    }
    transaction.append(
        domain.paths.audit_log_path(),
        audit::render_entry(
            "cert_renewed_local",
            &[
                ("hostname", prepared.state.hostname.as_str()),
                ("expires", response.expires.as_str()),
            ],
        ),
        true,
    )?;
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    domain.clear_renewal_failure_under_transition();
    domain.finish_commit_under_transition(outcome)?;
    let _ = domain
        .event_tx
        .send(CertmeshEvent::CertRenewed { expires_at });

    let reload_completion = reload_intent
        .zip(reload_dispatch)
        .map(|(intent, dispatch)| {
            dispatch
                .executor
                .dispatch(dispatch.permit, dispatch.domain, intent)
        });

    Ok(CommittedSelfRenewal {
        expires: response.expires,
        reload_completion,
    })
}

fn renew_member_under_transition(
    domain: &CertmeshDomain,
    authenticated_cn: &str,
    csr_pem: &str,
) -> Result<protocol::RenewResponse, CertmeshError> {
    let ca_guard = domain.ca.lock();
    let ca = ca_guard.as_ref().ok_or_else(|| {
        if domain.paths.is_ca_initialized() {
            CertmeshError::CaLocked
        } else {
            CertmeshError::CaNotInitialized
        }
    })?;

    let (authorized_sans, policy) = {
        let roster = domain.roster.lock();
        if roster.is_revoked(authenticated_cn) {
            drop(roster);
            drop(ca_guard);
            domain.commit_audit_under_transition(
                "mtls_revoked_rejected",
                &[("hostname", authenticated_cn), ("op", "renew")],
            )?;
            return Err(CertmeshError::Revoked(authenticated_cn.to_string()));
        }
        match roster.find_member(authenticated_cn) {
            Some(member) if member.status == crate::roster::MemberStatus::Active => (
                domain
                    .issuance_names
                    .member_sans(authenticated_cn, &member.cert_sans)?,
                roster.metadata.policy.clone(),
            ),
            Some(_) => {
                return Err(CertmeshError::Forbidden(format!(
                    "member '{authenticated_cn}' is not active"
                )));
            }
            None => return Err(CertmeshError::NotFound(authenticated_cn.to_string())),
        }
    };
    let lifetime_days = policy.leaf_lifetime_days;

    let requested = crate::csr::requested_sans(csr_pem)?;
    for san in &requested {
        if !authorized_sans
            .iter()
            .any(|authorized| crate::csr::names_match(authorized, san))
        {
            return Err(CertmeshError::InvalidPayload(format!(
                "renewal CSR requests unauthorized identifier '{san}' not in the enrollment record"
            )));
        }
    }

    let leaf_pem = crate::csr::sign_csr(ca, csr_pem, &authorized_sans, lifetime_days)?;
    let ca_cert = ca.cert_pem.clone();
    let ca_fingerprint = crate::ca::ca_fingerprint(ca);
    drop(ca_guard);

    let fingerprint = pem::parse(&leaf_pem)
        .map(|der| koi_crypto::pinning::fingerprint_sha256(der.contents()))
        .map_err(|error| CertmeshError::Certificate(format!("issued leaf parse: {error}")))?;
    let expires = leaf_not_after_utc(&leaf_pem).ok_or_else(|| CertmeshError::RenewalFailed {
        hostname: authenticated_cn.to_string(),
        reason: "issued service certificate has no valid expiry".into(),
    })?;
    let mut next_roster = domain.roster.lock().clone();
    let member = next_roster
        .find_member_mut(authenticated_cn)
        .ok_or_else(|| CertmeshError::NotFound(authenticated_cn.to_string()))?;
    member.cert_fingerprint = fingerprint.clone();
    member.cert_expires = expires;
    member.cert_sans = authorized_sans;
    member.last_seen = Some(chrono::Utc::now());
    next_roster.metadata.seq = next_roster.metadata.seq.saturating_add(1);
    let expires_text = expires.to_rfc3339();
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&next_roster)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
        true,
    );
    transaction.append(
        domain.paths.audit_log_path(),
        audit::render_entry(
            "cert_renewed",
            &[
                ("hostname", authenticated_cn),
                ("fingerprint", fingerprint.as_str()),
                ("expires", expires_text.as_str()),
            ],
        ),
        true,
    )?;
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    *domain.roster.lock() = next_roster;
    domain.finish_commit_under_transition(outcome)?;
    let _ = domain.event_tx.send(CertmeshEvent::CertRenewed {
        expires_at: expires,
    });

    Ok(protocol::RenewResponse {
        hostname: authenticated_cn.to_string(),
        service_cert: leaf_pem,
        ca_cert,
        ca_fingerprint,
        expires: expires_text,
        policy,
    })
}

fn apply_trust_bundle_under_transition(
    domain: &CertmeshDomain,
    signed: &bundle::SignedBundle,
) -> Result<BundleOutcome, CertmeshError> {
    let member_path = domain.paths.member_state_path();
    let Some(mut state) = member::load(&member_path)? else {
        return Ok(BundleOutcome::NotApplicable);
    };

    if let Err(error) = bundle::verify(signed, &state.ca_fingerprint, Some(state.last_bundle_seq)) {
        if matches!(error, bundle::BundleError::PinMismatch) {
            tracing::error!(
                host = %state.hostname,
                "Trust bundle CA fingerprint does NOT match the pinned CA — rejecting \
                 (fail-safe). Re-enroll with a fresh invite if the CA was intentionally replaced."
            );
        }
        return Err(CertmeshError::Internal(format!(
            "trust bundle rejected: {error}"
        )));
    }

    let anchor = domain
        .paths
        .certs_dir()
        .join(&state.hostname)
        .join("ca.pem");
    let anchor_dirty = std::fs::read_to_string(&anchor).ok().as_deref()
        != Some(signed.bundle.ca_cert_pem.as_str());
    let hostname = state.hostname.clone();
    let self_revoked = signed.bundle.is_revoked(&hostname);
    let seq = signed.bundle.seq;
    let semantic_digest = signed
        .bundle
        .semantic_digest()
        .map_err(|error| CertmeshError::Internal(format!("canonicalize trust bundle: {error}")))?;
    let seq_advanced = seq != state.last_bundle_seq;
    let revoked = signed.bundle.revoked_fingerprints();

    if !seq_advanced {
        let seed_digest = state.last_bundle_digest.is_none();
        if state
            .last_bundle_digest
            .as_ref()
            .is_some_and(|accepted| accepted != &semantic_digest)
        {
            return Err(CertmeshError::Internal(format!(
                "trust bundle rejected: {}",
                bundle::BundleError::Equivocation { seq }
            )));
        }

        // Older member records predate the semantic digest. Only seed it when
        // every locally enforced fact agrees with the incoming generation; do
        // not let an equal sequence rewrite policy or revocation state.
        if seed_digest {
            if state.policy != signed.bundle.policy
                || state.revoked_fingerprints != revoked
                || state.self_revoked != self_revoked
            {
                return Err(CertmeshError::Internal(format!(
                    "trust bundle rejected: {}",
                    bundle::BundleError::Equivocation { seq }
                )));
            }
            state.last_bundle_digest = Some(semantic_digest);
        }

        let mut transaction = repository::ArtifactTransaction::new();
        if anchor_dirty {
            transaction.write(anchor, signed.bundle.ca_cert_pem.as_bytes().to_vec(), false);
        }
        if seed_digest {
            transaction.write(
                member_path,
                serde_json::to_vec_pretty(&state).map_err(|error| {
                    CertmeshError::Internal(format!("serialize member state: {error}"))
                })?,
                true,
            );
        }
        let outcome = domain.commit_artifacts_under_transition(transaction)?;
        domain.finish_commit_under_transition(outcome)?;
        return Ok(BundleOutcome::NoChange { seq });
    }

    let mut dirty = false;
    if state.revoked_fingerprints != revoked {
        state.revoked_fingerprints = revoked;
        dirty = true;
    }
    if state.self_revoked != self_revoked {
        state.self_revoked = self_revoked;
        dirty = true;
    }
    if seq_advanced {
        state.last_bundle_seq = seq;
        state.last_bundle_digest = Some(semantic_digest);
        state.policy = signed.bundle.policy.clone();
        dirty = true;
    }

    let mut transaction = repository::ArtifactTransaction::new();
    if anchor_dirty {
        transaction.write(anchor, signed.bundle.ca_cert_pem.as_bytes().to_vec(), false);
    }
    if dirty {
        transaction.write(
            member_path,
            serde_json::to_vec_pretty(&state).map_err(|error| {
                CertmeshError::Internal(format!("serialize member state: {error}"))
            })?,
            true,
        );
    }
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    domain.finish_commit_under_transition(outcome)?;

    if self_revoked {
        tracing::error!(
            %hostname,
            "This node has been REVOKED in the mesh trust bundle (seq {seq}); it will stop \
             asserting an authenticated identity (ADR-023 §5) and renewal will be refused by the CA"
        );
    } else {
        tracing::debug!(seq, "Trust bundle updated");
    }
    let _ = domain
        .event_tx
        .send(CertmeshEvent::BundleUpdated { self_revoked });
    Ok(BundleOutcome::Updated { seq, self_revoked })
}

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
        self.renew_self_with_trigger(false).await
    }

    /// Operator-triggered rotate-key renewal for this enrolled member.
    ///
    /// This uses the exact same CSR-only, mTLS-authorized renewal transaction as
    /// [`Self::renew_self_if_due`], but deliberately bypasses only the local
    /// schedule check. CA-side membership, revocation, SAN, and identity policy
    /// remain authoritative. It is useful when an operator needs to rotate a key
    /// immediately after suspected exposure or prove reload behavior on demand.
    pub async fn renew_self(&self) -> Result<RenewOutcome, CertmeshError> {
        self.renew_self_with_trigger(true).await
    }

    async fn renew_self_with_trigger(
        &self,
        operator_requested: bool,
    ) -> Result<RenewOutcome, CertmeshError> {
        // Inner function carries all the real work; this outer shell handles event
        // emission for every failure exit without scattering it across every `?`.
        let days_left_at_attempt = self.cert_days_left_if_member();
        let result = self.renew_self_inner(operator_requested).await;
        match &result {
            Err(e) => {
                // Only emit CertExpiringSoon when the cert is actually past the renewal
                // threshold (i.e. we attempted renewal, not just "not due").
                let expiring = (!operator_requested)
                    .then_some(days_left_at_attempt)
                    .flatten();
                self.publish_local_renewal_failure(e, expiring).await;
            }
            Ok(RenewOutcome::Renewed { .. }) => {}
            _ => {}
        }
        result
    }

    /// CA-side counterpart of [`renew_self_if_due`](Self::renew_self_if_due): keep the
    /// CA's **own** self leaf fresh on the renewal timer.
    ///
    /// The member-pull loop is a no-op on the CA ([`Self::renew_self_if_due`] →
    /// [`RenewOutcome::NotApplicable`]) — a CA cannot pull-renew from itself; its self
    /// leaf comes from the local [`self_enroll`](Self::self_enroll) path instead.
    /// Historically that path ran only at daemon start, so a continuously-up CA (a
    /// "cornerstone") could cross its `renew_threshold_days` and ultimately **expire**
    /// without a restart (ADR-017/ADR-020). This lets the same periodic loop that
    /// renews members also refresh the CA self leaf.
    ///
    /// Returns:
    /// - [`RenewOutcome::NotApplicable`] when this node is not a CA (no local CA key).
    /// - [`RenewOutcome::NotDue`] when the self leaf is outside the renewal threshold
    ///   (the quiet happy path — no event).
    /// - [`RenewOutcome::Renewed`] when the leaf was re-issued (emits
    ///   [`CertmeshEvent::CertRenewed`]).
    ///
    /// Best-effort + observable: a CA that cannot re-issue while its leaf is past the
    /// threshold (most often because it is **locked**) emits
    /// [`CertmeshEvent::CertRenewalFailed`] + [`CertmeshEvent::CertExpiringSoon`] and
    /// returns the error, so the loop logs and retries next tick — the same "silence is
    /// the enemy" contract the member path honors.
    ///
    /// Like [`self_enroll`](Self::self_enroll), this refreshes the leaf on disk and the
    /// envelope/sign plane immediately; the already-bound mTLS/ACME listeners keep the
    /// prior in-memory cert until they are re-spawned (a posture flip or restart) —
    /// there is no live listener reload yet.
    pub async fn renew_ca_self_leaf_if_due(&self) -> Result<RenewOutcome, CertmeshError> {
        // Decide from the immutable domain projection, not an independent set of
        // file/model reads. `self_enroll` performs the authoritative re-check if
        // renewal is due.
        let status = self.status();
        if status.role != CertmeshRole::Authority {
            return Ok(RenewOutcome::NotApplicable);
        }
        let not_after = status
            .identity
            .info
            .as_ref()
            .map(|identity| identity.renewal.expires_at);
        let threshold_days = status.authority.as_ref().map_or(0, |authority| {
            i64::from(authority.policy.renew_threshold_days)
        });

        // Outside the renewal window → nothing to do (and no event: a renewal that did
        // not need to happen is not news).
        if let Some(na) = not_after {
            if chrono::Utc::now() + chrono::Duration::days(threshold_days) < na {
                return Ok(RenewOutcome::NotDue { not_after: na });
            }
        }
        // Within threshold (or a missing/unparseable leaf) → (re)issue.

        let enrollment = self
            .self_enroll_with_outcome()
            .await
            .and_then(|(enrollment, changed)| {
                let expires_at = leaf_not_after_utc(&enrollment.cert_pem).ok_or_else(|| {
                    CertmeshError::Certificate(
                        "self-enrollment returned a certificate with no valid expiry".into(),
                    )
                })?;
                Ok((expires_at, changed))
            });
        match enrollment {
            Ok((expires_at, true)) => Ok(RenewOutcome::Renewed {
                expires: expires_at.to_rfc3339(),
                hook: None,
            }),
            Ok((not_after, false)) => Ok(RenewOutcome::NotDue { not_after }),
            Err(e) => {
                // The CA is within (or past) its threshold but could not re-issue —
                // most likely because it is locked. Surface it loudly, like the member
                // path, then let the loop retry next tick.
                let days_left = not_after.map(|na| (na - chrono::Utc::now()).num_days());
                self.publish_local_renewal_failure(&e, days_left).await;
                Err(e)
            }
        }
    }

    /// Accept execution failure into the authoritative read model before any
    /// best-effort notification leaves the Certmesh boundary.
    async fn publish_local_renewal_failure(&self, error: &CertmeshError, days_left: Option<i64>) {
        let reason = error.to_string();
        let _transition = self.state.transition.lock().await;
        let consecutive_failures = self
            .state
            .record_renewal_failure_under_transition(reason.clone());
        self.state.refresh_status_under_transition();
        let _ = self.state.event_tx.send(CertmeshEvent::CertRenewalFailed {
            reason,
            consecutive_failures,
        });
        if let Some(days_left) = days_left {
            let _ = self
                .state
                .event_tx
                .send(CertmeshEvent::CertExpiringSoon { days_left });
        }
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
        let status = self.status();
        if status.role != CertmeshRole::Member {
            return None;
        }
        status
            .identity
            .info
            .as_ref()
            .map(|identity| identity.renewal.expires_at)
    }

    /// How many days until the local member cert expires. Returns `None` when the
    /// node is not a member or the cert cannot be parsed. Used to populate
    /// `CertExpiringSoon` without re-reading the cert inside the inner function.
    fn cert_days_left_if_member(&self) -> Option<i64> {
        let not_after = self.member_cert_expiry()?;
        Some((not_after - chrono::Utc::now()).num_days())
    }

    async fn renew_self_inner(
        &self,
        operator_requested: bool,
    ) -> Result<RenewOutcome, CertmeshError> {
        let preparation = self
            .run_blocking_transition(move |domain| {
                prepare_self_renewal_under_transition(domain, operator_requested)
            })
            .await??;
        let prepared = match preparation {
            SelfRenewalPreparation::Complete(outcome) => return Ok(outcome),
            SelfRenewalPreparation::Request(prepared) => prepared,
        };

        let host = prepared.host.clone();
        let port = prepared.port;
        // Bound the network call: a black-holed CA must not stall the loop (or
        // daemon shutdown) for the OS TCP timeout.
        let (status, body) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::post_json(
                &host,
                port,
                http::paths::RENEW,
                &prepared.request_body,
                &prepared.current_cert,
                &prepared.current_key,
                &prepared.pinned_ca_pem,
            ),
        )
        .await
        .map_err(|_| CertmeshError::RenewalFailed {
            hostname: prepared.state.hostname.clone(),
            reason: format!(
                "renewal request to {host}:{port} timed out after {}s",
                RENEWAL_REQUEST_TIMEOUT.as_secs()
            ),
        })??;

        if status != 200 {
            return Err(CertmeshError::RenewalFailed {
                hostname: prepared.state.hostname.clone(),
                reason: format!("CA returned HTTP {status}: {body}"),
            });
        }
        let response: protocol::RenewResponse =
            serde_json::from_str(&body).map_err(|error| CertmeshError::RenewalFailed {
                hostname: prepared.state.hostname.clone(),
                reason: format!("malformed renew response: {error}"),
            })?;
        let hostname = prepared.state.hostname.clone();
        let reload_dispatch = if prepared.state.reload_hook.is_some() {
            Some(ReloadDispatch {
                permit: self.state.reloads.reserve().await?,
                executor: Arc::clone(&self.state.reloads),
                domain: Arc::clone(&self.state.domain),
            })
        } else {
            None
        };
        let committed = self
            .run_blocking_transition(move |domain| {
                commit_self_renewal_under_transition(domain, *prepared, response, reload_dispatch)
            })
            .await??;

        tracing::info!(%hostname, expires = %committed.expires, "Member certificate renewed (rotated key)");

        // The separate retained executor already owns this bounded integration;
        // awaiting it only enriches a live caller's response. Dropping this
        // request cannot cancel execution or settlement of the durable intent.
        let hook = if let Some(completion) = committed.reload_completion {
            Some(completion.await.unwrap_or_else(|_| protocol::HookResult {
                success: false,
                command: "<reload executor>".into(),
                output: Some("reload executor stopped before acknowledgement".into()),
            }))
        } else {
            None
        };

        Ok(RenewOutcome::Renewed {
            expires: committed.expires,
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
        let authenticated_cn = authenticated_cn.to_string();
        let csr_pem = csr_pem.to_string();
        self.run_blocking_transition(move |domain| {
            renew_member_under_transition(domain, &authenticated_cn, &csr_pem)
        })
        .await?
    }

    /// Pull, verify, and apply the CA's signed trust bundle (ADR-017 P1/F4).
    ///
    /// A no-op ([`BundleOutcome::NotApplicable`]) unless this node joined a mesh.
    /// Fetches the self-verifying bundle over plain HTTP, then delegates to
    /// [`apply_trust_bundle`](Self::apply_trust_bundle) for verification and
    /// application. Members run this on the role loop (ADR-023): self-management is
    /// intrinsic to membership.
    pub async fn pull_trust_bundle(&self) -> Result<BundleOutcome, CertmeshError> {
        let member_path = self.state.paths.member_state_path();
        let state = self
            .run_blocking_transition(move |_| member::load(&member_path))
            .await??;
        let Some(state) = state else {
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

        self.apply_trust_bundle(&signed).await
    }

    /// Verify and apply a trust bundle obtained over **any** transport (ADR-023 §4).
    ///
    /// The verify+persist core of [`pull_trust_bundle`](Self::pull_trust_bundle),
    /// minus the HTTP fetch — the supported seam for a consumer that carries the
    /// signed bundle over its *own* plane (so it needs no reachability to the CA's
    /// HTTP port). Koi stays the owner of ES256 + anti-rollback verification: this
    /// ingests a `SignedBundle`, never a bare, unverifiable fingerprint list.
    ///
    /// A no-op ([`BundleOutcome::NotApplicable`]) unless this node joined a mesh — a CA
    /// node keeps no `member.json` (it owns the authoritative roster directly), so it
    /// returns `NotApplicable` here rather than ingesting its own bundle.
    /// Verifies the detached ES256 signature against this member's **pinned** CA
    /// fingerprint and rejects a strictly older `seq` (anti-rollback). On a verified
    /// bundle it self-heals the on-disk CA anchor and **applies the bundle's full
    /// cross-member revoked set** into the persisted member-side store that
    /// `verify`/`open` honor — so a pure member rejects *other* revoked members, not
    /// only itself (ADR-023 §3). Full-replace, so an un-revoked entry also clears.
    pub async fn apply_trust_bundle(
        &self,
        signed: &bundle::SignedBundle,
    ) -> Result<BundleOutcome, CertmeshError> {
        let signed = signed.clone();
        self.run_blocking_transition(move |domain| {
            apply_trust_bundle_under_transition(domain, &signed)
        })
        .await?
    }

    /// Validate a member's health heartbeat.
    pub async fn health_check(
        &self,
        request: &protocol::HealthRequest,
    ) -> Result<protocol::HealthResponse, CertmeshError> {
        self.health_check_for(None, request).await
    }

    /// Validate a heartbeat with an optional mTLS principal. Remote callers can
    /// update only their own active member record; local DAT management passes
    /// `None` and is still subject to membership/revocation rules.
    pub async fn health_check_for(
        &self,
        authenticated_cn: Option<&str>,
        request: &protocol::HealthRequest,
    ) -> Result<protocol::HealthResponse, CertmeshError> {
        let authenticated_cn = authenticated_cn.map(str::to_string);
        let hostname = request.hostname.clone();
        let pinned_ca_fingerprint = request.pinned_ca_fingerprint.clone();
        self.run_blocking_transition(move |domain| {
            if authenticated_cn
                .as_deref()
                .is_some_and(|caller| caller != hostname)
            {
                return Err(CertmeshError::Forbidden(format!(
                    "authenticated principal may only report its own health ({hostname})"
                )));
            }
            let ca_guard = domain.ca.lock();
            let ca = ca_guard.as_ref().ok_or_else(|| {
                if domain.paths.is_ca_initialized() {
                    CertmeshError::CaLocked
                } else {
                    CertmeshError::CaNotInitialized
                }
            })?;
            let current_fingerprint = ca::ca_fingerprint(ca);
            let valid =
                health::validate_pinned_fingerprint(&current_fingerprint, &pinned_ca_fingerprint);
            drop(ca_guard);

            let touched = domain.commit_roster_under_transition(false, None, |roster| {
                if roster.is_revoked(&hostname) {
                    return Err(CertmeshError::Revoked(hostname.clone()));
                }
                match roster.find_member_mut(&hostname) {
                    Some(member) if member.status == roster::MemberStatus::Active => {
                        member.last_seen = Some(chrono::Utc::now());
                        Ok(())
                    }
                    Some(_) => Err(CertmeshError::Forbidden(format!(
                        "member '{hostname}' is not active"
                    ))),
                    None => Err(CertmeshError::NotFound(hostname.clone())),
                }
            });
            if matches!(touched, Err(CertmeshError::Revoked(_))) {
                domain.commit_audit_under_transition(
                    "mtls_revoked_rejected",
                    &[("hostname", hostname.as_str()), ("op", "health")],
                )?;
            }
            let ((), outcome) = touched?;
            domain.finish_commit_under_transition(outcome)?;
            Ok(protocol::HealthResponse {
                valid,
                ca_fingerprint: current_fingerprint,
            })
        })
        .await?
    }

    /// Get the current node's roster role (if any).
    ///
    /// Returns `None` if the roster has no entry matching the local hostname.
    pub async fn node_role(&self) -> Option<roster::MemberRole> {
        let hostname = self.state.local_hostname.as_deref()?;
        let _transition = self.state.transition.lock().await;
        let roster = self.state.roster.lock();
        roster.find_member(hostname).map(|m| m.role.clone())
    }

    /// Promote the local member to primary and demote any existing primary.
    /// Returns true if the roster was updated.
    pub async fn promote_self_to_primary(&self) -> Result<bool, CertmeshError> {
        let hostname = self.require_local_hostname("promoting the local Certmesh member")?;

        // Role changes are membership mutations and advance the roster sequence,
        // even though the current public bundle does not expose role names.
        self.run_blocking_transition(move |domain| {
            let already_primary = domain
                .roster
                .lock()
                .find_member(&hostname)
                .map(|member| member.role == roster::MemberRole::Primary)
                .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
            if already_primary {
                return Ok(false);
            }
            let (updated, outcome) =
                domain.commit_roster_under_transition(true, None, |roster| {
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
                })?;
            domain.finish_commit_under_transition(outcome)?;
            Ok(updated)
        })
        .await?
    }

    /// Demote the local member to standby. Returns true if the roster changed.
    pub async fn demote_self_to_standby(&self) -> Result<bool, CertmeshError> {
        let hostname = self.require_local_hostname("demoting the local Certmesh member")?;

        self.run_blocking_transition(move |domain| {
            let current_role = domain
                .roster
                .lock()
                .find_member(&hostname)
                .map(|member| member.role.clone())
                .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
            if current_role == roster::MemberRole::Standby {
                return Ok(false);
            }
            let (updated, outcome) =
                domain.commit_roster_under_transition(true, None, |roster| {
                    let member = roster
                        .find_member_mut(&hostname)
                        .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
                    member.role = roster::MemberRole::Standby;
                    Ok(true)
                })?;
            domain.finish_commit_under_transition(outcome)?;
            Ok(updated)
        })
        .await?
    }

    /// Add alias SANs to a member's roster entry (used by DNS alias feedback).
    ///
    /// Returns true if any SANs were added.
    pub async fn add_alias_sans(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<bool, CertmeshError> {
        let hostname = hostname.to_string();
        let sans = sans.to_vec();
        self.run_blocking_transition(move |domain| {
            let has_new_name = domain
                .roster
                .lock()
                .find_member(&hostname)
                .map(|member| {
                    sans.iter()
                        .any(|san| !member.cert_sans.iter().any(|current| current == san))
                })
                .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
            if !has_new_name {
                return Ok(false);
            }
            let ((), outcome) = domain.commit_roster_under_transition(true, None, |roster| {
                let member = roster
                    .find_member_mut(&hostname)
                    .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
                for san in &sans {
                    if !member.cert_sans.iter().any(|current| current == san) {
                        member.cert_sans.push(san.clone());
                    }
                }
                Ok(())
            })?;
            domain.finish_commit_under_transition(outcome)?;
            Ok(true)
        })
        .await?
    }

    /// The immutable local hostname supplied before this core was shared.
    pub fn configured_local_hostname(&self) -> Option<String> {
        self.state
            .local_hostname
            .as_deref()
            .map(ToString::to_string)
    }

    pub(crate) fn require_local_hostname(&self, operation: &str) -> Result<String, CertmeshError> {
        self.state.require_local_hostname(operation)
    }

    /// Get the pinned CA fingerprint for the local node (if set).
    pub async fn pinned_ca_fingerprint(&self) -> Option<String> {
        let hostname = self.state.local_hostname.as_deref()?;
        let _transition = self.state.transition.lock().await;
        let roster = self.state.roster.lock();
        roster
            .find_member(hostname)
            .and_then(|m| m.pinned_ca_fingerprint.clone())
    }
}

#[cfg(test)]
mod renewal_status_tests {
    use super::*;

    #[tokio::test]
    async fn renewal_failure_is_status_truth_before_its_event() {
        let root = koi_common::test::ensure_data_dir("koi-certmesh-renewal-status-tests")
            .join(koi_common::id::generate_short_id());
        let core =
            CertmeshCore::uninitialized_with_paths(CertmeshPaths::with_data_dir(root.clone()))
                .with_local_hostname("renewal-status-host")
                .unwrap();
        let mut events = core.subscribe();
        let before = core.status();
        let error = CertmeshError::RenewalFailed {
            hostname: "renewal-status-host".to_string(),
            reason: "authority unavailable".to_string(),
        };
        let expected_reason = error.to_string();

        core.publish_local_renewal_failure(&error, Some(2)).await;

        let event = events.recv().await.expect("renewal failure event");
        let current = core.status();
        assert!(current.revision > before.revision);
        assert_eq!(current.renewal.consecutive_failures, 1);
        assert_eq!(
            current.renewal.last_error.as_deref(),
            Some(expected_reason.as_str())
        );
        assert!(matches!(
            event,
            CertmeshEvent::CertRenewalFailed {
                consecutive_failures: 1,
                ..
            }
        ));
        assert!(matches!(
            events.recv().await.expect("expiring event"),
            CertmeshEvent::CertExpiringSoon { days_left: 2 }
        ));

        core.publish_local_renewal_failure(&error, None).await;
        assert_eq!(core.status().renewal.consecutive_failures, 2);
        let _ = std::fs::remove_dir_all(root);
    }
}
