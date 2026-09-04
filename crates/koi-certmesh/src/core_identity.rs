//! Identity, status, and the ADR-020 trust primitives (sign/verify/seal/open/diagnose).
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    /// The CA certificate fingerprint, or `None` when no CA is initialized.
    ///
    /// Reads the in-memory CA when unlocked, else derives it from the on-disk CA
    /// cert (the fingerprint is public). Used by the daemon to advertise the CA's
    /// fingerprint in the `_certmesh._tcp` mDNS TXT (ADR-017 F12) and as a cheap
    /// preflight datum.
    pub async fn ca_fingerprint(&self) -> Option<String> {
        self.status()
            .authority
            .as_ref()
            .and_then(|authority| authority.ca_fingerprint.clone())
    }

    /// This node's current trust posture — the mode oracle every
    /// mode-transparent primitive consults (ADR-020 §0).
    ///
    /// This is a constant-time projection of Certmesh's authoritative immutable
    /// [`CertmeshStatus`], not a filesystem probe. `signed` is true only while
    /// the domain reports a healthy, current, CA-anchored identity. Missing,
    /// incoherent, expired, or revoked identity state fails closed to `false`.
    /// `encrypted` (the Confidential rung) stays false until the `seal`/`open`
    /// encryption rung lands (ADR-020 §4).
    pub fn posture(&self) -> Posture {
        self.status().posture
    }

    /// Whether this node has a durable relationship to a certificate mesh: it
    /// owns a CA or joined one. This is intentionally independent from usable
    /// identity posture, so missing, corrupt, expired, and revoked identities do
    /// not silently turn authentication off.
    ///
    /// This is the supported predicate for a "membership = enforcement" consumer:
    /// gate enforcement on `is_certmesh_member()` — be permissive when `false` (an
    /// Open node), require authenticated envelopes when `true`. Koi keys its own
    /// self-management (renewal, revocation honoring, self-stand-down) on the same
    /// fact, so management is intrinsic to membership rather than a separate switch.
    pub fn is_certmesh_member(&self) -> bool {
        self.status().role.requires_authentication()
    }

    /// Whether this node owns the mesh CA and can serve the trust-plane listeners.
    ///
    /// An enrolled member has an authenticated identity but no CA private key, so
    /// it must not enter the CA self-enrollment/listener retry loop.
    pub fn is_ca_node(&self) -> bool {
        self.status().role == CertmeshRole::Authority
    }

    /// Capture this node's authoritative in-memory identity projection.
    ///
    /// Status and sensitive TLS material are published by the same aggregate
    /// transition. Holding that transition while converting them avoids a
    /// second filesystem-derived read model and returns `None` whenever the
    /// primary status says the identity is absent, invalid, expired, or revoked.
    /// Does not renew or enroll (that is `ensure_identity`'s job).
    pub async fn local_identity(&self) -> Option<Identity> {
        let _transition = self.state.transition.lock().await;
        self.local_identity_under_transition()
    }

    pub(crate) fn local_identity_under_transition(&self) -> Option<Identity> {
        self.state.local_identity_under_transition()
    }

    /// Ensure this node holds a current identity, then return it (`None` if it
    /// cannot — the node is Open with no way to enroll). ADR-020 §7.
    ///
    /// Mode-transparent + idempotent — the consumer calls this without branching:
    /// - **Open** (no CA, not a member): returns `None`.
    /// - **CA node** (CA unlocked): self-enrolls if needed and re-issues a self
    ///   leaf that is within the renewal threshold (local, no network).
    /// - **Joined member**: pull-renews from the CA when the leaf is due
    ///   (`renew_self_if_due`); best-effort — on a network/CA failure it logs and
    ///   returns the current (un-renewed) identity rather than erroring.
    ///
    /// First-join identity acquisition that needs out-of-band authorization (an
    /// invite/TOTP) is *not* performed here — that is the explicit `join` flow.
    pub async fn ensure_identity(&self) -> Option<Identity> {
        let status = self.status();
        if status.role == CertmeshRole::Authority {
            // CA node: self-enroll is idempotent (reuses a fresh leaf, re-issues
            // one within the renewal threshold). Requires the CA unlocked.
            let unlocked = status.authority.as_ref().is_some_and(|ca| !ca.locked);
            if unlocked {
                if let Err(e) = self.self_enroll().await {
                    tracing::warn!(error = %e, "ensure_identity: self-enroll failed");
                }
            }
        } else if status.role == CertmeshRole::Member {
            // Joined member: renew if due (network pull to the CA). Best-effort.
            if let Err(e) = self.renew_self_if_due().await {
                tracing::warn!(error = %e, "ensure_identity: renewal check failed");
            }
        }
        self.local_identity().await
    }

    /// Sign `bytes` into an [`Envelope`](koi_common::envelope::Envelope) (ADR-020 §3).
    ///
    /// Mode-transparent: Open posture → a freshness-stamped passthrough (no
    /// signature); Authenticated → ES256-signed, carrying this node's leaf cert so
    /// any holder of the CA can verify it. The consumer calls this identically in
    /// both postures.
    pub async fn sign(&self, bytes: &[u8]) -> koi_common::envelope::Envelope {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let ts = chrono::Utc::now().timestamp();
        let _transition = self.state.transition.lock().await;
        let identity = self.local_identity_under_transition();
        let self_revoked = self.is_self_revoked_under_transition();
        let signer = self.outbound_signer(&identity, self_revoked);
        envelope::build_envelope(signer, bytes, &nonce, ts)
    }

    /// The signing material for an outbound primitive, applying the ADR-023 §5
    /// **self-gate**: returns the carried `(key_pem, cert_pem)` only when this node
    /// holds a usable identity that has **not** been revoked. A self-revoked node
    /// degrades to the Open/unsigned passthrough (a loud, one-time warning) so it can
    /// no longer assert an authenticated identity — even to peers that have not yet
    /// pulled the revocation. Bounded: it stops *claiming* an identity; it does not
    /// delete the on-disk leaf or exit (the operator owns those).
    fn outbound_signer<'a>(
        &self,
        identity: &'a Option<Identity>,
        self_revoked: bool,
    ) -> Option<(&'a str, &'a str)> {
        let id = identity.as_ref()?;
        if self_revoked {
            static REVOKED_WARNED: std::sync::Once = std::sync::Once::new();
            REVOKED_WARNED.call_once(|| {
                tracing::warn!(
                    "this node is REVOKED in the mesh — signing as an unsigned passthrough; \
                     it can no longer assert an authenticated identity (re-enroll to recover)"
                );
            });
            return None;
        }
        Some((id.key_pem.as_str(), id.cert_pem.as_str()))
    }

    /// Whether this node's own identity has been revoked mesh-wide — **hostname-keyed**
    /// and authoritative (independent of leaf-fingerprint tracking across renewals).
    ///
    /// A member reads the flag persisted from the last accepted trust bundle
    /// (`member.json`); a CA node reads its own roster. A self-revoked node stops
    /// asserting an authenticated identity in [`sign`](Self::sign)/[`seal`](Self::seal)
    /// (ADR-023 §5) and [`diagnose`](Self::diagnose) flags it RED. Exposed so a consumer
    /// can surface "you have been removed from the mesh — rejoin" without re-deriving it.
    pub async fn is_self_revoked(&self) -> bool {
        let _transition = self.state.transition.lock().await;
        self.is_self_revoked_under_transition()
    }

    pub(crate) fn is_self_revoked_under_transition(&self) -> bool {
        self.state.is_self_revoked_under_transition()
    }

    /// Verify an [`Envelope`](koi_common::envelope::Envelope) → an
    /// [`Assurance`](koi_common::envelope::Assurance) (ADR-020 §3).
    ///
    /// Self-contained (carry-cert): validates the carried leaf against this node's
    /// pinned CA + checks freshness + best-effort revocation. Read a trusted
    /// identity only via `Assurance::identity()`. On an Open node (no anchor) any
    /// envelope verifies as `Anonymous`.
    pub async fn verify(
        &self,
        env: &koi_common::envelope::Envelope,
    ) -> koi_common::envelope::Assurance {
        let env = env.clone();
        match self
            .run_blocking_transition(move |domain| {
                let anchor = domain.ca_anchor.current();
                let ca_cert_pem = anchor
                    .anchor()
                    .map_err(|reason| {
                        CertmeshError::Internal(format!(
                            "Certmesh CA anchor is unavailable: {reason}"
                        ))
                    })?
                    .map(|anchor| anchor.certificate_pem.clone());
                let revoked = revoked_fingerprints_under_transition(domain)?;
                Ok(envelope::verify_envelope(
                    &env,
                    ca_cert_pem.as_deref(),
                    &revoked,
                    chrono::Utc::now().timestamp(),
                ))
            })
            .await
        {
            Ok(Ok(assurance)) => assurance,
            Ok(Err(error)) | Err(error) => {
                tracing::error!(%error, "Certmesh verification state unavailable; rejecting envelope");
                koi_common::envelope::Assurance::Rejected {
                    reason: koi_common::envelope::RejectReason::UnknownSigner,
                    signer_cn: None,
                }
            }
        }
    }

    /// Seal `bytes` into a [`Sealed`](koi_common::sealed::Sealed) (ADR-020 §4).
    ///
    /// The confidentiality rung, shipped today as **passthrough**: the bytes are
    /// signed (integrity + freshness) but **not encrypted**. Reuses [`sign`](Self::sign)'s
    /// machinery — a `Sealed` is a signed [`Envelope`](koi_common::envelope::Envelope)
    /// plus a confidentiality version tag. The consumer codes against the final API
    /// now; the group-key rung lands later with no consumer change. A one-time
    /// `warn!` makes the passthrough (un-encrypted) state loud, not silent.
    pub async fn seal(&self, bytes: &[u8]) -> koi_common::sealed::Sealed {
        static PASSTHROUGH_WARNED: std::sync::Once = std::sync::Once::new();
        PASSTHROUGH_WARNED.call_once(|| {
            tracing::warn!(
                "seal(): running in passthrough mode — messages are signed but NOT \
                 encrypted (group-key confidentiality is not yet available)"
            );
        });
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let ts = chrono::Utc::now().timestamp();
        let _transition = self.state.transition.lock().await;
        let identity = self.local_identity_under_transition();
        let self_revoked = self.is_self_revoked_under_transition();
        let signer = self.outbound_signer(&identity, self_revoked);
        sealed::seal_passthrough(signer, bytes, &nonce, ts)
    }

    /// Open a [`Sealed`](koi_common::sealed::Sealed) → [`Opened`](koi_common::sealed::Opened)
    /// (ADR-020 §4): the recovered bytes plus the trust state they arrived with.
    ///
    /// Self-contained (carry-cert), reusing [`verify`](Self::verify)'s machinery. A
    /// tampered / unknown-signer / expired / revoked message yields an `Err`, never
    /// bytes — read a trusted identity via `opened.assurance.identity()`.
    pub async fn open(
        &self,
        sealed: &koi_common::sealed::Sealed,
    ) -> Result<koi_common::sealed::Opened, CertmeshError> {
        let sealed = sealed.clone();
        self.run_blocking_transition(move |domain| {
            let anchor = domain.ca_anchor.current();
            let ca_cert_pem = anchor
                .anchor()
                .map_err(|reason| {
                    CertmeshError::Internal(format!("Certmesh CA anchor is unavailable: {reason}"))
                })?
                .map(|anchor| anchor.certificate_pem.clone());
            let revoked = revoked_fingerprints_under_transition(domain)?;
            sealed::open_sealed(
                &sealed,
                ca_cert_pem.as_deref(),
                &revoked,
                chrono::Utc::now().timestamp(),
            )
        })
        .await?
    }

    /// Run the trust-doctor (ADR-020 §13) → a structured
    /// [`koi_common::diagnosis::TrustDiagnosis`].
    ///
    /// Aggregates this node's real trust state — posture, identity + renewal health
    /// (reusing [`local_identity`](Self::local_identity)), on-disk-leaf integrity
    /// (chains to its CA), self-revocation, and the CA trust-install limitation —
    /// into distinct, named checks each carrying an exact remedy. The rollup exits
    /// non-zero only when something is RED (`TrustDiagnosis::exit_code`).
    pub async fn diagnose(&self) -> koi_common::diagnosis::TrustDiagnosis {
        self.status().diagnosis.clone()
    }

    /// The CA certificate this node trusts as its verification anchor: the
    /// authority's canonical CA artifact or a member leaf's pinned `ca.pem`.
    /// `None` means the Open role positively has no anchor; observation failures
    /// are returned rather than disguised as absence.
    pub async fn ca_certificate_pem(&self) -> Result<Option<String>, CertmeshError> {
        self.ca_anchor()
            .anchor()
            .map(|anchor| anchor.map(|anchor| anchor.certificate_pem.clone()))
            .map_err(|reason| {
                CertmeshError::Internal(format!("Certmesh CA anchor is unavailable: {reason}"))
            })
    }

    /// Sign one coherent roster generation for the public trust-bundle query.
    pub async fn signed_trust_bundle(&self) -> Result<bundle::SignedBundle, CertmeshError> {
        let _transition = self.state.transition.lock().await;
        let ca_guard = self.state.ca.lock();
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.status().role == CertmeshRole::Authority {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;
        let roster = self.state.roster.lock();
        bundle::sign(&roster, ca, chrono::Utc::now().to_rfc3339())
    }

    /// Best-effort revoked-leaf fingerprints honored by `verify`/`open` — the union of
    /// (a) the local roster's revoked members (a CA node holds the authoritative set)
    /// and (b) the cross-member set a pure member learned from the last accepted trust
    /// bundle (ADR-023 §3). The CA chain remains the hard gate; revocation is
    /// eventual-consistent, bounded by the member's pull cadence.
    ///
    /// `pub(crate)` so tests can assert the applied set; not a public API (a consumer
    /// reads membership via [`is_certmesh_member`](Self::is_certmesh_member) and its
    /// own revocation via [`is_self_revoked`](Self::is_self_revoked)).
    #[cfg(test)]
    pub(crate) async fn revoked_fingerprints(&self) -> Result<Vec<String>, CertmeshError> {
        let _transition = self.state.transition.lock().await;
        self.revoked_fingerprints_under_transition()
    }

    #[cfg(test)]
    fn revoked_fingerprints_under_transition(&self) -> Result<Vec<String>, CertmeshError> {
        revoked_fingerprints_under_transition(&self.state)
    }

    /// Gate `router`'s routes by authentication (ADR-020 §6 `require_auth`).
    ///
    /// Mode-transparent: a **no-op in Open posture** (homelab-open); in secure
    /// posture every request must carry an authenticated client CN (the mTLS
    /// `ClientCn` the listener / same-port dial injects) or it is rejected with
    /// 401. Apply once to your *write* routes — no per-handler boilerplate, and the
    /// same consumer code runs green in both postures.
    ///
    /// (P2 gates on the mTLS client identity; a signed-envelope-header path is a
    /// planned refinement. For per-CN/role authorization, see
    /// [`require_auth_with`](Self::require_auth_with).)
    pub fn require_auth(&self, router: Router) -> Router {
        router.layer(axum::middleware::from_fn_with_state(
            Arc::clone(&self.state),
            http::require_auth_mw,
        ))
    }

    /// Gate `router`'s routes by authentication **and** a caller-supplied CN/role
    /// policy (ADR-020 §6, wishlist 4.1).
    ///
    /// Like [`require_auth`](Self::require_auth) — a **no-op in Open posture** — but
    /// in secure posture, after confirming an authenticated client CN, it calls
    /// `policy(cn, &request)`: `true` allows the request, `false` rejects it with
    /// 403. This lets a consumer express "only these CNs/roles may write" (an
    /// allowlist, a roster-role check, a path-scoped rule) without re-implementing
    /// the middleware or re-deriving the mTLS identity. Keep [`require_auth`](Self::require_auth)
    /// for the zero-config "any mesh member" default.
    ///
    /// The policy receives the **authoritative** mTLS CN (derived from the client
    /// certificate, never a claimed field) and the full `axum` request, so it can
    /// branch on method/path as well as identity.
    ///
    /// ```ignore
    /// // Only `web-01` and `web-02` may reach the write routes.
    /// let allow = ["web-01", "web-02"];
    /// let router = core.require_auth_with(router, move |cn, _req| allow.contains(&cn));
    /// ```
    pub fn require_auth_with<F>(&self, router: Router, policy: F) -> Router
    where
        F: Fn(&str, &axum::extract::Request) -> bool + Send + Sync + 'static,
    {
        let state = Arc::clone(&self.state);
        let policy: http::AuthPolicy = Arc::new(policy);
        router.layer(axum::middleware::from_fn(move |req, next| {
            let state = Arc::clone(&state);
            let policy = Arc::clone(&policy);
            async move { http::require_auth_with_mw(state, policy, req, next).await }
        }))
    }
}

fn revoked_fingerprints_under_transition(
    domain: &CertmeshDomain,
) -> Result<Vec<String>, CertmeshError> {
    let mut set: Vec<String> = domain
        .roster
        .lock()
        .members
        .iter()
        .filter(|member| member.status == roster::MemberStatus::Revoked)
        .map(|member| member.cert_fingerprint.clone())
        .collect();
    if domain.status.current().role == CertmeshRole::Member {
        if let Some(member) = member::load(&domain.paths.member_state_path())? {
            set.extend(member.revoked_fingerprints);
        }
    }
    set.sort();
    set.dedup();
    Ok(set)
}

impl CertmeshDomain {
    pub(crate) fn local_identity_under_transition(&self) -> Option<Identity> {
        let status = self.status.current();
        if status.identity.condition != IdentityCondition::Healthy {
            return None;
        }
        let info = status.identity.info.as_ref()?;
        let tls = self.tls_identity.current();
        let material = tls.material.as_ref()?;
        if material.hostname != info.hostname {
            return None;
        }
        let certificate = pem::parse_many(material.certificate_chain_pem.as_ref())
            .ok()?
            .into_iter()
            .next()?;
        Some(Identity {
            hostname: info.hostname.clone(),
            cert_pem: pem::encode(&certificate),
            key_pem: material.private_key_pem.to_string(),
            ca_cert_pem: material.trust_anchor_pem.to_string(),
            ca_fingerprint: info.ca_fingerprint.clone(),
            renewal: info.renewal.clone(),
        })
    }

    pub(crate) fn is_self_revoked_under_transition(&self) -> bool {
        self.status.current().identity.condition == IdentityCondition::Revoked
    }
}
