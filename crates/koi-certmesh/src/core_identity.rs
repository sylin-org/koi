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
        // In-memory path: compute under the lock, but drop the guard before any I/O
        // (never hold the CA mutex across disk reads).
        let in_memory = {
            let ca_guard = self.state.ca.lock().await;
            ca_guard.as_ref().map(ca::ca_fingerprint)
        };
        if in_memory.is_some() {
            return in_memory;
        }
        // Locked CA: derive from the on-disk cert off the async executor.
        let paths = self.state.paths.clone();
        tokio::task::spawn_blocking(move || ca::ca_fingerprint_from_disk(&paths).ok())
            .await
            .ok()
            .flatten()
    }

    /// Get the current certmesh status.
    pub async fn certmesh_status(&self) -> protocol::CertmeshStatus {
        let ca_guard = self.state.ca.lock().await;
        let roster = self.state.roster.lock().await;
        let auth_guard = self.state.auth.lock().await;
        let auth_method = auth_guard.as_ref().map(|a| a.method_name());
        build_status(self.paths(), &ca_guard, &roster, auth_method)
    }

    /// This node's current trust posture — the mode oracle every
    /// mode-transparent primitive consults (ADR-020 §0).
    ///
    /// `signed` is true when this node holds a usable cryptographic identity: its
    /// CA-signed leaf (`cert.pem`/`key.pem`) is on disk *and* the node is anchored
    /// to a mesh (the CA is initialized here, or a `member.json` records the mesh
    /// it joined — so an orphaned leaf left after `destroy` does not read as
    /// secure). A cheap filesystem check, safe to call from any primitive.
    /// `encrypted` (the Confidential rung) stays false until the `seal`/`open`
    /// encryption rung lands (ADR-020 §4).
    ///
    /// Posture answers "do I have an identity", not "is it fresh" — identity
    /// *health* (expiry, renewal status) is reported separately by
    /// `ensure_identity` / `diagnose` (later ADR-020 phases).
    pub fn posture(&self) -> Posture {
        Posture {
            signed: self.has_local_identity(),
            encrypted: false,
        }
    }

    /// Whether this node holds a usable local identity (a CA-signed leaf on disk,
    /// anchored to a mesh). Backs [`posture`](Self::posture).
    fn has_local_identity(&self) -> bool {
        node_has_identity(self.paths())
    }

    /// Whether this node is an active member of a certificate mesh — it holds a
    /// usable CA-anchored identity (it created a CA, or joined one). A **cheap**
    /// filesystem check (no lock, no network): the same fact as
    /// [`posture`](Self::posture)`.signed`, named for the membership question
    /// consumers actually ask (ADR-023 §1).
    ///
    /// This is the supported predicate for a "membership = enforcement" consumer:
    /// gate enforcement on `is_certmesh_member()` — be permissive when `false` (an
    /// Open node), require authenticated envelopes when `true`. Koi keys its own
    /// self-management (renewal, revocation honoring, self-stand-down) on the same
    /// fact, so management is intrinsic to membership rather than a separate switch.
    pub fn is_certmesh_member(&self) -> bool {
        self.has_local_identity()
    }

    /// Load this node's live identity from disk, or `None` if it has none.
    ///
    /// Read-only: loads the on-disk leaf (cert/key) for the local hostname plus
    /// the CA anchor it chains to, derives the pinned CA fingerprint, and computes
    /// the leaf's renewal/expiry health from the CA-held policy. Returns `None`
    /// when the node is Open — consistent with [`posture`](Self::posture)`.signed`.
    /// Does not renew or enroll (that is `ensure_identity`'s job).
    pub async fn local_identity(&self) -> Option<Identity> {
        if !self.has_local_identity() {
            return None;
        }
        let hostname = Self::local_hostname()?;
        let leaf = self.paths().certs_dir().join(&hostname);
        let cert_pem = std::fs::read_to_string(leaf.join("cert.pem")).ok()?;
        let key_pem = std::fs::read_to_string(leaf.join("key.pem")).ok()?;
        // CA anchor: the leaf-local ca.pem, falling back to the CA dir (CA node).
        let ca_cert_pem = std::fs::read_to_string(leaf.join("ca.pem"))
            .ok()
            .or_else(|| std::fs::read_to_string(self.paths().ca_cert_path()).ok())?;
        let ca_fingerprint =
            koi_crypto::pinning::fingerprint_sha256(pem::parse(&ca_cert_pem).ok()?.contents());
        let policy = self.local_policy().await;
        let renewal = RenewalHealth::from_leaf(&cert_pem, &policy)?;
        Some(Identity {
            hostname,
            cert_pem,
            key_pem,
            ca_cert_pem,
            ca_fingerprint,
            renewal,
        })
    }

    /// The CA-held cert lifecycle policy this node follows: from `member.json`
    /// if it joined a mesh, else the local roster's (CA node), else the default.
    async fn local_policy(&self) -> roster::CertPolicy {
        if let Some(ms) = member::load(&self.paths().member_state_path()) {
            return ms.policy;
        }
        self.state.roster.lock().await.metadata.policy.clone()
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
        if self.paths().is_ca_initialized() {
            // CA node: self-enroll is idempotent (reuses a fresh leaf, re-issues
            // one within the renewal threshold). Requires the CA unlocked.
            let unlocked = self.state.ca.lock().await.is_some();
            if unlocked {
                if let Err(e) = self.self_enroll().await {
                    tracing::warn!(error = %e, "ensure_identity: self-enroll failed");
                }
            }
        } else if member::load(&self.paths().member_state_path()).is_some() {
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
        let identity = self.local_identity().await;
        let signer = self.outbound_signer(&identity).await;
        envelope::build_envelope(signer, bytes, &nonce, ts)
    }

    /// The signing material for an outbound primitive, applying the ADR-023 §5
    /// **self-gate**: returns the carried `(key_pem, cert_pem)` only when this node
    /// holds a usable identity that has **not** been revoked. A self-revoked node
    /// degrades to the Open/unsigned passthrough (a loud, one-time warning) so it can
    /// no longer assert an authenticated identity — even to peers that have not yet
    /// pulled the revocation. Bounded: it stops *claiming* an identity; it does not
    /// delete the on-disk leaf or exit (the operator owns those).
    async fn outbound_signer<'a>(
        &self,
        identity: &'a Option<Identity>,
    ) -> Option<(&'a str, &'a str)> {
        let id = identity.as_ref()?;
        if self.is_self_revoked().await {
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
        // Member node: the bundle-derived flag (hostname-keyed by the CA).
        if let Some(ms) = member::load(&self.paths().member_state_path()) {
            if ms.self_revoked {
                return true;
            }
        }
        // CA node (or a self-enrolled host that keeps a roster): authoritative for its
        // own hostname.
        if let Some(hostname) = Self::local_hostname() {
            let roster = self.state.roster.lock().await;
            if roster.is_revoked(&hostname) {
                return true;
            }
        }
        false
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
        let ca_cert_pem = self.local_ca_cert_pem().await;
        let revoked = self.revoked_fingerprints().await;
        let now = chrono::Utc::now().timestamp();
        envelope::verify_envelope(env, ca_cert_pem.as_deref(), &revoked, now)
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
        let identity = self.local_identity().await;
        let signer = self.outbound_signer(&identity).await;
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
        let ca_cert_pem = self.local_ca_cert_pem().await;
        let revoked = self.revoked_fingerprints().await;
        let now = chrono::Utc::now().timestamp();
        sealed::open_sealed(sealed, ca_cert_pem.as_deref(), &revoked, now)
    }

    /// Run the trust-doctor (ADR-020 §13) → a structured [`TrustDiagnosis`].
    ///
    /// Aggregates this node's real trust state — posture, identity + renewal health
    /// (reusing [`local_identity`](Self::local_identity)), on-disk-leaf integrity
    /// (chains to its CA), self-revocation, and the CA trust-install limitation —
    /// into distinct, named checks each carrying an exact remedy. The rollup exits
    /// non-zero only when something is RED (`TrustDiagnosis::exit_code`).
    pub async fn diagnose(&self) -> koi_common::diagnosis::TrustDiagnosis {
        let posture = self.posture();
        let identity = self.local_identity().await;
        let now = chrono::Utc::now();
        let (integrity_ok, self_revoked) = match &identity {
            Some(id) => {
                let integrity = diagnosis::leaf_chains_to_ca(&id.cert_pem, &id.ca_cert_pem);
                // Has this node's own identity been revoked mesh-wide? Hostname-keyed,
                // the same authoritative signal the outbound self-gate uses.
                let self_revoked = self.is_self_revoked().await;
                (Some(integrity), self_revoked)
            }
            None => (None, false),
        };
        diagnosis::build_diagnosis(posture, identity.as_ref(), integrity_ok, self_revoked, now)
    }

    /// The CA certificate this node trusts as its verification anchor: the leaf's
    /// `ca.pem` (member or CA node), falling back to the CA cert on disk. `None`
    /// on an Open node with no anchor.
    async fn local_ca_cert_pem(&self) -> Option<String> {
        if let Some(hostname) = Self::local_hostname() {
            let leaf_ca = self.paths().certs_dir().join(&hostname).join("ca.pem");
            if let Ok(pem) = std::fs::read_to_string(&leaf_ca) {
                return Some(pem);
            }
        }
        std::fs::read_to_string(self.paths().ca_cert_path()).ok()
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
    pub(crate) async fn revoked_fingerprints(&self) -> Vec<String> {
        // (a) CA-node path: the roster holds the authoritative revoked members. The
        // guard drops at the end of this block — never held across the file read below.
        let mut set: Vec<String> = {
            let roster = self.state.roster.lock().await;
            roster
                .members
                .iter()
                .filter(|m| m.status == roster::MemberStatus::Revoked)
                .map(|m| m.cert_fingerprint.clone())
                .collect()
        };
        // (b) Member-node path: the cross-member revoked set from the last accepted
        // trust bundle (a pure member keeps no roster). A cheap local file read.
        if let Some(ms) = member::load(&self.paths().member_state_path()) {
            set.extend(ms.revoked_fingerprints);
        }
        set.sort();
        set.dedup();
        set
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
