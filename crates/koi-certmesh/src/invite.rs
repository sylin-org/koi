//! Per-host, single-use, time-bounded enrollment invite tokens.
//!
//! The *automatable* enrollment credential (ADR-015 F2). An operator mints a
//! copy-pasteable token bound to exactly one hostname; the joiner presents it
//! once. The CA stores only a SHA-256 hash of each token (never the token
//! itself), burns it on first successful enrollment, and rejects expired, used,
//! or wrong-host tokens. This replaces the QR-only mesh-wide TOTP, which could
//! not be scripted.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CertmeshError;

/// Invite lifetime used when the caller passes a non-positive TTL.
pub const DEFAULT_TTL_MINS: i64 = 60;

/// Random entropy per token (hex-encoded → 48 chars).
const TOKEN_BYTES: usize = 24;

#[derive(Debug, Default, Serialize, Deserialize)]
struct InviteStore {
    #[serde(default)]
    invites: Vec<Invite>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Invite {
    hostname: String,
    /// SHA-256 hex of the plaintext token (the token itself is never stored).
    token_hash: String,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    used: bool,
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    koi_common::encoding::hex_encode(&hasher.finalize()[..])
}

fn load(path: &Path) -> InviteStore {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(path: &Path, store: &InviteStore) -> Result<(), CertmeshError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| CertmeshError::Internal(format!("serialize invites: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// A freshly minted invite: the one-time plaintext token plus its absolute expiry.
///
/// The plaintext `token` is the only time it ever exists in cleartext — the store
/// keeps only its hash. The caller surfaces it to the operator and forgets it.
#[derive(Debug, Clone)]
pub struct MintedInvite {
    /// Plaintext token — return to the operator once; never persisted.
    pub token: String,
    /// Absolute expiry instant.
    pub expires_at: DateTime<Utc>,
}

/// Mint a fresh single-use invite for `hostname`, returning the plaintext token
/// and its expiry.
///
/// The plaintext is returned exactly once (for the operator to copy); only its
/// hash is persisted. Expired/used entries are pruned opportunistically.
pub fn mint(path: &Path, hostname: &str, ttl_mins: i64) -> Result<MintedInvite, CertmeshError> {
    let mut buf = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut buf);
    let token = koi_common::encoding::hex_encode(&buf);

    let ttl = if ttl_mins <= 0 {
        DEFAULT_TTL_MINS
    } else {
        ttl_mins
    };
    let now = Utc::now();
    let expires_at = now + Duration::minutes(ttl);

    let mut store = load(path);
    store.invites.retain(|i| !i.used && i.expires_at > now);
    store.invites.push(Invite {
        hostname: hostname.to_string(),
        token_hash: token_hash(&token),
        expires_at,
        used: false,
    });
    save(path, &store)?;
    Ok(MintedInvite { token, expires_at })
}

/// Verify `token` for `hostname` and burn it. Returns `true` iff a matching,
/// unexpired, unused invite existed and was just consumed. Fail-closed: any
/// I/O or parse error yields `false`.
pub fn verify_and_consume(path: &Path, token: &str, hostname: &str) -> bool {
    let mut store = load(path);
    let h = token_hash(token);
    let now = Utc::now();
    let pos = store.invites.iter().position(|i| {
        !i.used
            && i.expires_at > now
            && i.hostname == hostname
            && koi_crypto::pinning::fingerprints_match(&i.token_hash, &h)
    });
    match pos {
        Some(idx) => {
            store.invites[idx].used = true;
            save(path, &store).is_ok()
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_path(name: &str) -> std::path::PathBuf {
        let dir = koi_common::test::ensure_data_dir("koi-certmesh-invite-tests");
        let p = dir.join(format!("{name}.json"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn mint_then_verify_consumes_once() {
        let p = store_path("roundtrip");
        let token = mint(&p, "host-a", 60).unwrap().token;
        assert!(verify_and_consume(&p, &token, "host-a"), "first use ok");
        assert!(
            !verify_and_consume(&p, &token, "host-a"),
            "single-use: second use rejected"
        );
    }

    #[test]
    fn verify_rejects_wrong_host() {
        let p = store_path("wronghost");
        let token = mint(&p, "host-a", 60).unwrap().token;
        assert!(!verify_and_consume(&p, &token, "host-b"));
        // still valid for the right host
        assert!(verify_and_consume(&p, &token, "host-a"));
    }

    #[test]
    fn verify_rejects_unknown_token() {
        let p = store_path("unknown");
        let _ = mint(&p, "host-a", 60).unwrap();
        assert!(!verify_and_consume(&p, "deadbeefdeadbeef", "host-a"));
    }

    #[test]
    fn verify_rejects_expired() {
        let p = store_path("expired");
        let token = mint(&p, "host-a", 60).unwrap().token;
        // Force the entry's expiry into the past.
        let mut store = load(&p);
        store.invites[0].expires_at = Utc::now() - Duration::minutes(5);
        save(&p, &store).unwrap();
        assert!(!verify_and_consume(&p, &token, "host-a"));
    }
}
