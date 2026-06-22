//! Enrollment window and member CSR/cert custody.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    // ── Enrollment toggle ───────────────────────────────────────────

    /// Open the enrollment window. Stays open until explicitly closed.
    pub async fn open_enrollment(&self) -> Result<(), CertmeshError> {
        // Posture change → single-writer commit so a concurrent enroll can't
        // overwrite it with a stale snapshot (F8). Not bundle content → no bump.
        self.state
            .touch_roster(|roster| {
                roster.open_enrollment();
                Ok(())
            })
            .await?;

        tracing::info!("Enrollment window opened");
        let _ =
            audit::append_entry_to(&self.state.paths.audit_log_path(), "enrollment_opened", &[]);
        Ok(())
    }

    /// Close the enrollment window.
    pub async fn close_enrollment(&self) -> Result<(), CertmeshError> {
        self.state
            .touch_roster(|roster| {
                roster.close_enrollment();
                Ok(())
            })
            .await?;

        tracing::info!("Enrollment window closed");
        let _ =
            audit::append_entry_to(&self.state.paths.audit_log_path(), "enrollment_closed", &[]);
        Ok(())
    }

    /// Mint a single-use, hostname-bound enrollment invite (ADR-015 F2).
    ///
    /// Returns the one-time plaintext token plus its absolute expiry. The CA
    /// stores only a hash; the joining host presents the token once via
    /// `POST /join` (`invite_token`). The mesh must be initialized — the invite
    /// is an authorization to enroll into an existing CA. Posture booleans are
    /// unchanged: the token replaces the credential, not the `enrollment_open` /
    /// `requires_approval` gates.
    pub async fn mint_invite(
        &self,
        hostname: &str,
        ttl_mins: i64,
    ) -> Result<protocol::InviteResponse, CertmeshError> {
        if !self.state.paths.is_ca_initialized() {
            return Err(CertmeshError::CaNotInitialized);
        }
        // Validate the hostname the same way enrollment will (it becomes the
        // single host this token authorizes — and a certificate SAN at join, F15).
        validate_hostname(hostname)?;

        // The CA fingerprint the joiner will pin (ADR-017 F3). `is_ca_initialized`
        // was checked above, so `ca_fingerprint()` (in-memory or on-disk, never
        // holding a lock across I/O) yields the public CA fingerprint here.
        let ca_fingerprint = self
            .ca_fingerprint()
            .await
            .ok_or(CertmeshError::CaNotInitialized)?;

        let minted = invite::mint(&self.state.paths.invites_path(), hostname, ttl_mins)?;
        let expires_at = minted.expires_at.to_rfc3339();
        // The operator-facing code carries the pinned CA fingerprint (F3) so the
        // joiner can preflight + pin before sending its CSR.
        let code = invite::encode_code(&minted.token, &ca_fingerprint);

        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "invite_minted",
            &[("hostname", hostname), ("expires_at", &expires_at)],
        );
        tracing::info!(hostname, "Enrollment invite minted");

        Ok(protocol::InviteResponse {
            token: code,
            hostname: hostname.to_string(),
            expires_at,
            ca_fingerprint,
        })
    }

    // ── Member-side key custody (ADR-015 F1) ────────────────────────

    /// Generate this member's keypair + CSR and persist the **private key** locally.
    ///
    /// The daemon generates the keypair, writes the private key to
    /// `certs/<hostname>/key.pem` (0600 on Unix), and returns only the CSR. The
    /// key never leaves the daemon; the CLI carries only the public CSR to the
    /// remote CA. Paired with [`Self::install_member_cert`].
    pub async fn prepare_member_csr(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<String, CertmeshError> {
        validate_hostname(hostname)?;
        let (key_pem, csr_pem) = csr::generate_keypair_and_csr(hostname, sans)?;

        let cert_dir = self.state.paths.certs_dir().join(hostname);
        let key_path = cert_dir.join("key.pem");
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&cert_dir)?;
            std::fs::write(&key_path, key_pem.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write member key task: {e}")))??;

        tracing::info!(
            hostname,
            "Member keypair generated; CSR prepared (key kept local)"
        );
        Ok(csr_pem)
    }

    /// Install a CA-signed leaf next to the member key from [`Self::prepare_member_csr`].
    ///
    /// Writes `cert.pem`, `ca.pem`, and `fullchain.pem` into `certs/<hostname>/`
    /// (the key is already there) and installs the CA root in the OS trust store
    /// (best-effort). Returns the cert directory path.
    ///
    /// When `ca_endpoint` + `ca_fingerprint` are supplied (the normal join flow),
    /// it also writes the **member renewal state** (`certmesh/member.json`) so the
    /// background loop can later pull a rotate-key renewal from the CA over mTLS
    /// (ADR-017 F6). The pinned `ca_fingerprint` is verified against the supplied
    /// `ca_pem` before arming, so a mismatched pair never arms renewal.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_member_cert(
        &self,
        hostname: &str,
        cert_pem: &str,
        ca_pem: &str,
        ca_endpoint: Option<&str>,
        ca_fingerprint: Option<&str>,
        sans: &[String],
        policy: Option<roster::CertPolicy>,
    ) -> Result<String, CertmeshError> {
        validate_hostname(hostname)?;

        // Enforce the pin BEFORE writing anything (ADR-017 F3). When the caller
        // supplied a pinned fingerprint (the out-of-band-trusted one from the
        // invite), the CA cert we are about to install + trust MUST match it, or we
        // refuse — a MITM that intercepted the plain-HTTP join and substituted its
        // own CA is rejected here, before any file is written or any root is
        // trusted. Without a pin (TOTP join), this is a documented TOFU install.
        if let Some(expected_fp) = ca_fingerprint {
            let der = pem::parse(ca_pem).map_err(|e| {
                CertmeshError::InvalidPayload(format!("CA cert is not valid PEM: {e}"))
            })?;
            let actual_fp = koi_crypto::pinning::fingerprint_sha256(der.contents());
            if !koi_crypto::pinning::fingerprints_match(&actual_fp, expected_fp) {
                return Err(CertmeshError::InvalidPayload(format!(
                    "installed CA cert fingerprint {actual_fp} does not match the pinned \
                     fingerprint {expected_fp} (possible MITM) — refusing to install"
                )));
            }
        }

        let cert_dir = self.state.paths.certs_dir().join(hostname);
        let cert_owned = cert_pem.to_string();
        let ca_owned = ca_pem.to_string();
        let fullchain = format!("{cert_owned}{ca_owned}");
        let dir = cert_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&dir)?;
            write_file_atomic(&dir.join("cert.pem"), cert_owned.as_bytes(), false)?;
            write_file_atomic(&dir.join("ca.pem"), ca_owned.as_bytes(), false)?;
            write_file_atomic(&dir.join("fullchain.pem"), fullchain.as_bytes(), false)?;
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write member cert task: {e}")))??;

        // Trust the CA root so this node can verify the mesh (best-effort).
        if let Err(e) = os_truststore::Cert::from_pem(ca_pem)
            .and_then(|cert| os_truststore::install(&cert).map(drop))
        {
            tracing::warn!(error = %e, "Could not install CA cert in trust store");
        }

        // Arm member-pull renewal when the join supplied the CA coordinates. The
        // pinned fingerprint was already verified against `ca_pem` above, so the
        // MemberState records a fingerprint we have confirmed matches the installed
        // CA root.
        if let (Some(endpoint), Some(fingerprint)) = (ca_endpoint, ca_fingerprint) {
            let state = member::MemberState {
                hostname: hostname.to_string(),
                ca_host: member::host_from_endpoint(endpoint),
                ca_mtls_port: member::DEFAULT_CA_MTLS_PORT,
                ca_http_port: member::port_from_endpoint(endpoint),
                ca_fingerprint: fingerprint.to_string(),
                sans: sans.to_vec(),
                policy: policy.unwrap_or_default(),
                last_bundle_seq: 0,
                reload_hook: None,
            };
            if let Err(e) = member::save(&self.state.paths.member_state_path(), &state) {
                tracing::warn!(error = %e, "Could not persist member renewal state");
            } else {
                tracing::info!(hostname, ca_host = %state.ca_host, "Member renewal state armed");
            }
        }

        tracing::info!(hostname, "Member certificate installed locally");

        // Leaf (and possibly member.json) now on disk → Open→Authenticated.
        self.state.republish_posture();

        Ok(cert_dir.display().to_string())
    }
}
