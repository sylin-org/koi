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

/// Load the member renewal state, or `None` if it is absent/unreadable.
pub fn load(path: &std::path::Path) -> Option<MemberState> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Persist the member renewal state atomically (temp file → rename), 0600 on Unix.
pub fn save(path: &std::path::Path, state: &MemberState) -> Result<(), CertmeshError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| CertmeshError::Internal(format!("serialize member state: {e}")))?;

    // PID-qualified temp so concurrent processes sharing the data dir don't clobber
    // each other's temp file before the rename.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let dir = std::env::temp_dir().join(format!("koi-memberstate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("member.json");
        let state = sample();
        save(&path, &state).unwrap();
        let loaded = load(&path).expect("state loads back");
        assert_eq!(loaded, state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_absent_is_none() {
        let path = std::path::Path::new("/nonexistent/koi/member.json");
        assert!(load(path).is_none());
    }

    #[test]
    fn ca_mtls_port_defaults_when_absent_in_json() {
        let json = r#"{"hostname":"a","ca_host":"h","ca_fingerprint":"fp"}"#;
        let parsed: MemberState = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.ca_mtls_port, DEFAULT_CA_MTLS_PORT);
        assert!(parsed.sans.is_empty());
    }
}
