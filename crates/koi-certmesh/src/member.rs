//! Member-side renewal state (ADR-017 F6).
//!
//! A node that *joined* a mesh (it did not create the CA) keeps no CA, no roster,
//! and no in-memory mesh state — only its cert files on disk. To drive
//! **member-initiated, rotate-key renewal**, it must remember *where* its CA is
//! and *which* CA it pinned. That is this module: a small JSON record persisted at
//! `certmesh/member.json` (0600) when the member installs its first CA-signed
//! cert, and read by the background renewal loop.
//!
//! It is deliberately separate from `roster.json` (which is the CA's private
//! superset): a pure member never owns a roster. Phase 2's signed trust bundle
//! will refresh the `policy` and `ca_fingerprint` fields from the CA.

use serde::{Deserialize, Serialize};

use crate::error::CertmeshError;
use crate::roster::CertPolicy;

/// Default mTLS port for inter-node certmesh traffic (matches the binary's
/// `adapters::mtls::DEFAULT_MTLS_PORT`). The member dials the CA here for
/// renewal; persisted per-member so a non-default CA port can be recorded.
pub const DEFAULT_CA_MTLS_PORT: u16 = 5642;

/// Default plain-HTTP port (matches the binary's `DEFAULT_HTTP_PORT`). The member
/// pulls the self-verifying trust bundle from here (a DAT-exempt GET).
pub const DEFAULT_CA_HTTP_PORT: u16 = 5641;

/// Persisted coordinates a joined member needs to pull-renew from its CA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberState {
    /// This member's hostname (its certificate CN / cert directory name).
    pub hostname: String,
    /// Host to dial for the CA's mTLS listener (derived from the join endpoint).
    pub ca_host: String,
    /// Port of the CA's mTLS listener.
    #[serde(default = "default_mtls_port")]
    pub ca_mtls_port: u16,
    /// Port of the CA's plain-HTTP listener (where the trust bundle is served).
    #[serde(default = "default_http_port")]
    pub ca_http_port: u16,
    /// The pinned CA fingerprint (sha256 of the CA cert DER). Renewal responses
    /// must match this, or the member refuses to install (anti-CA-swap).
    pub ca_fingerprint: String,
    /// SANs to request in each renewal CSR (kept stable across rotations).
    #[serde(default)]
    pub sans: Vec<String>,
    /// CA-held lifecycle policy that drives the renew schedule + grace window.
    /// Refreshed from each accepted trust bundle (ADR-017 F4).
    #[serde(default)]
    pub policy: CertPolicy,
    /// Highest trust-bundle `seq` this member has accepted. Anti-rollback floor:
    /// a pulled bundle with a strictly lower `seq` is rejected.
    #[serde(default)]
    pub last_bundle_seq: u64,
    /// Digest of the last accepted bundle's semantic contents (the signed
    /// payload excluding its informational `issued_at`). This makes an equal
    /// sequence a provable idempotent replay rather than an opportunity to
    /// equivocate about policy, membership, or revocation without advancing
    /// the authoritative sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_bundle_digest: Option<String>,
    /// Cross-member revoked leaf fingerprints learned from the last accepted trust
    /// bundle — the **full authoritative set** (full-replace each accepted bundle, so
    /// an un-revoked entry also clears). Unioned into
    /// [`revoked_fingerprints`](crate::CertmeshCore) so a pure member's `verify`/`open`
    /// rejects *other* revoked members, not only itself (ADR-023 §3). Persisted here
    /// alongside `last_bundle_seq` so the monotonic floor can never advance without the
    /// data. Empty until the first bundle carrying revocations is applied.
    #[serde(default)]
    pub revoked_fingerprints: Vec<String>,
    /// Whether **this** node's own hostname was listed revoked in the last accepted
    /// trust bundle (hostname-keyed, authoritative — independent of leaf fingerprint
    /// tracking across renewals). Drives the ADR-023 §5 outbound self-gate and
    /// [`is_self_revoked`](crate::CertmeshCore::is_self_revoked); full-replace each
    /// accepted bundle, so an un-revocation also clears it.
    #[serde(default)]
    pub self_revoked: bool,
    /// Optional local reload hook to run after a successful renewal install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_hook: Option<String>,
}

fn default_mtls_port() -> u16 {
    DEFAULT_CA_MTLS_PORT
}

fn default_http_port() -> u16 {
    DEFAULT_CA_HTTP_PORT
}

impl MemberState {
    /// The CA's mTLS authority (`host:port`) used for renewal requests.
    pub fn ca_mtls_authority(&self) -> (String, u16) {
        (self.ca_host.clone(), self.ca_mtls_port)
    }
}

/// Extract the host component from a join endpoint like `http://ca-host:5641`.
///
/// Strips an optional `scheme://`, then a trailing `:port` and any path. Returns
/// the input unchanged when it is already a bare host. IPv6 literals in brackets
/// (`[::1]:5641`) are unwrapped to `::1`.
pub fn host_from_endpoint(endpoint: &str) -> String {
    let after_scheme = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    // Drop any path/query after the authority.
    let authority = after_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(after_scheme);
    // Bracketed IPv6 literal: take what's inside the brackets.
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((inside, _)) = rest.split_once(']') {
            return inside.to_string();
        }
    }
    // Strip a trailing :port (only when the remainder is all digits, so we don't
    // truncate an unbracketed IPv6 — those should arrive bracketed anyway).
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => authority.to_string(),
    }
}

/// Extract the port from a join endpoint, defaulting to [`DEFAULT_CA_HTTP_PORT`]
/// when none is present. This is the CA's plain-HTTP port (where it serves the
/// trust bundle).
pub fn port_from_endpoint(endpoint: &str) -> u16 {
    let after_scheme = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let authority = after_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(after_scheme);
    // `[::1]:5641` → after the closing bracket; otherwise the last `:` segment.
    let port_str = authority
        .rsplit_once(']')
        .map(|(_, rest)| rest.trim_start_matches(':'))
        .or_else(|| authority.rsplit_once(':').map(|(_, p)| p))
        .unwrap_or("");
    port_str.parse().unwrap_or(DEFAULT_CA_HTTP_PORT)
}

/// Load the member renewal state.
///
/// Only a missing file is absence. Durable corruption and filesystem failures
/// are domain errors so commands cannot reinterpret a damaged member as Open.
pub fn load(path: &std::path::Path) -> Result<Option<MemberState>, CertmeshError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CertmeshError::Io(error)),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        CertmeshError::Internal(format!(
            "persisted member state at '{}' is invalid: {error}",
            path.display()
        ))
    })
}

/// Persist the member renewal state durably and atomically, 0600 on Unix.
#[cfg(test)]
pub(crate) fn save(path: &std::path::Path, state: &MemberState) -> Result<(), CertmeshError> {
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| CertmeshError::Internal(format!("serialize member state: {e}")))?;
    save_bytes_with(path, &json, |path, bytes| {
        koi_common::persist::write_bytes_atomic_with_options(
            path,
            bytes,
            koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o600),
        )
    })
}

#[cfg(test)]
fn save_bytes_with(
    path: &std::path::Path,
    bytes: &[u8],
    write: impl FnOnce(&std::path::Path, &[u8]) -> std::io::Result<koi_common::persist::AtomicCommit>,
) -> Result<(), CertmeshError> {
    match write(path, bytes)? {
        koi_common::persist::AtomicCommit::Durable => {}
        koi_common::persist::AtomicCommit::DurabilityUncertain(error) => {
            // The replacement is already visible. Reporting rejection would leave
            // the caller's model behind the state read from this path immediately
            // (and potentially after restart), so accept it and make the lost
            // crash-durability guarantee loud.
            tracing::error!(
                path = %path.display(),
                %error,
                "Member state is visible, but its crash durability could not be confirmed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_path(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "koi-memberstate-{name}-{}",
            koi_common::id::generate_short_id()
        ));
        let path = dir.join("member.json");
        (dir, path)
    }

    fn sample() -> MemberState {
        MemberState {
            hostname: "web-01".to_string(),
            ca_host: "ca-host".to_string(),
            ca_mtls_port: 5642,
            ca_http_port: 5641,
            ca_fingerprint: "deadbeef".to_string(),
            sans: vec!["web-01".to_string(), "web-01.local".to_string()],
            policy: CertPolicy::default(),
            last_bundle_seq: 0,
            last_bundle_digest: None,
            revoked_fingerprints: Vec::new(),
            self_revoked: false,
            reload_hook: None,
        }
    }

    #[test]
    fn port_from_endpoint_parses_or_defaults() {
        assert_eq!(port_from_endpoint("http://ca-host:5641"), 5641);
        assert_eq!(port_from_endpoint("http://ca-host:9000/v1"), 9000);
        assert_eq!(port_from_endpoint("http://ca-host"), DEFAULT_CA_HTTP_PORT);
        assert_eq!(port_from_endpoint("192.168.1.55:5641"), 5641);
        assert_eq!(port_from_endpoint("[::1]:5641"), 5641);
    }

    #[test]
    fn host_from_endpoint_strips_scheme_and_port() {
        assert_eq!(host_from_endpoint("http://ca-host:5641"), "ca-host");
        assert_eq!(host_from_endpoint("https://ca-host:5641/v1"), "ca-host");
        assert_eq!(host_from_endpoint("192.168.1.55:5641"), "192.168.1.55");
        assert_eq!(host_from_endpoint("ca-host"), "ca-host");
        assert_eq!(host_from_endpoint("http://ca-host"), "ca-host");
        assert_eq!(host_from_endpoint("[::1]:5641"), "::1");
    }

    #[test]
    fn save_then_load_round_trips() {
        let (dir, path) = state_path("roundtrip");
        let state = sample();
        save(&path, &state).unwrap();
        let loaded = load(&path)
            .expect("member-state read succeeds")
            .expect("state loads back");
        assert_eq!(loaded, state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_replace_failure_preserves_the_previous_member_state() {
        let (dir, path) = state_path("pre-replace-failure");
        let old = sample();
        save(&path, &old).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut replacement = old.clone();
        replacement.ca_host = "new-ca".to_string();
        let bytes = serde_json::to_vec_pretty(&replacement).unwrap();

        let result = save_bytes_with(&path, &bytes, |_, _| {
            Err(std::io::Error::other("injected pre-replace failure"))
        });

        assert!(
            matches!(result, Err(CertmeshError::Io(ref error)) if error.to_string().contains("injected"))
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(load(&path).unwrap(), Some(old));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn visible_uncertain_save_is_accepted_and_reload_observes_the_new_state() {
        let (dir, path) = state_path("visible-uncertain");
        let old = sample();
        save(&path, &old).unwrap();
        let mut replacement = old;
        replacement.ca_host = "new-ca".to_string();
        replacement.last_bundle_seq = 42;
        let bytes = serde_json::to_vec_pretty(&replacement).unwrap();

        save_bytes_with(&path, &bytes, |target, bytes| {
            let outcome = koi_common::persist::write_bytes_atomic_with_options(
                target,
                bytes,
                koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o600),
            )?;
            Ok(match outcome {
                koi_common::persist::AtomicCommit::Durable => {
                    koi_common::persist::AtomicCommit::DurabilityUncertain(std::io::Error::other(
                        "injected post-replace sync failure",
                    ))
                }
                uncertain @ koi_common::persist::AtomicCommit::DurabilityUncertain(_) => uncertain,
            })
        })
        .expect("a visible member-state replacement is an accepted commit");

        assert_eq!(load(&path).unwrap(), Some(replacement));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_absent_is_none() {
        let (dir, path) = state_path("absent");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&path).unwrap().is_none());
    }

    #[test]
    fn load_rejects_corrupt_state_instead_of_manufacturing_absence() {
        let (dir, path) = state_path("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ definitely not member json").unwrap();

        let error = load(&path).unwrap_err();
        assert!(
            matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted member state")),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_propagates_non_not_found_filesystem_failures() {
        let (dir, path) = state_path("read-error");
        std::fs::create_dir_all(&path).unwrap();

        assert!(matches!(load(&path), Err(CertmeshError::Io(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_mtls_port_defaults_when_absent_in_json() {
        let json = r#"{"hostname":"a","ca_host":"h","ca_fingerprint":"fp"}"#;
        let parsed: MemberState = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.ca_mtls_port, DEFAULT_CA_MTLS_PORT);
        assert!(parsed.sans.is_empty());
    }
}
