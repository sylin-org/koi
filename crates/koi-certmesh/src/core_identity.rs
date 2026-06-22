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
        let signer = identity
            .as_ref()
            .map(|id| (id.key_pem.as_str(), id.cert_pem.as_str()));
        envelope::build_envelope(signer, bytes, &nonce, ts)
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
        let signer = identity
            .as_ref()
            .map(|id| (id.key_pem.as_str(), id.cert_pem.as_str()));
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
                // Is this node's own leaf in the (best-effort) revoked set?
                let self_fp = pem::parse(&id.cert_pem)
                    .ok()
                    .map(|p| koi_crypto::pinning::fingerprint_sha256(p.contents()));
                let revoked = self.revoked_fingerprints().await;
                let self_revoked = self_fp
                    .as_ref()
                    .map(|fp| {
                        revoked
                            .iter()
                            .any(|r| koi_crypto::pinning::fingerprints_match(r, fp))
                    })
                    .unwrap_or(false);
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

    /// Best-effort revoked-leaf fingerprints from the local roster. A CA node holds
    /// the full roster; a pure member's roster is empty, so revocation there is
    /// eventual-consistent — the CA chain remains the hard gate (ADR-020 §3).
    async fn revoked_fingerprints(&self) -> Vec<String> {
        let roster = self.state.roster.lock().await;
        roster
            .members
            .iter()
            .filter(|m| m.status == roster::MemberStatus::Revoked)
            .map(|m| m.cert_fingerprint.clone())
            .collect()
    }

    /// Gate `router`'s routes by authentication (ADR-020 §6 `require_auth`).
    ///
    /// Mode-transparent: a **no-op in Open posture** (homelab-open); in secure
    /// posture every request must carry an authenticated client CN (the mTLS
    /// `ClientCn` the listener / same-port dial injects) or it is rejected with
    /// 401. Apply once to your *write* routes — no per-handler boilerplate, and the
    /// same consumer code runs green in both postures.
    ///
    /// (P2 gates on the mTLS client identity; an optional CN/role policy hook and a
    /// signed-envelope-header path are planned refinements.)
    pub fn require_auth(&self, router: Router) -> Router {
        router.layer(axum::middleware::from_fn_with_state(
            Arc::clone(&self.state),
            http::require_auth_mw,
        ))
    }
}
