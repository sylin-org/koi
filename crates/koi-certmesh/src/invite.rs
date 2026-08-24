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

/// Separator between the secret and the CA fingerprint in an invite **code**
/// (ADR-017 F3). Both halves are lowercase hex, so neither ever contains this
/// character — the split is unambiguous.
const CODE_SEP: char = '.';

/// Assemble the operator-facing invite **code** from the secret token and the CA
/// fingerprint to pin (ADR-017 F3).
///
/// The code is the one string the operator copies and the joiner pastes; the
/// embedded fingerprint lets the joiner **pin and preflight** the CA *before*
/// sending its CSR, closing the plain-HTTP-join MITM gap. Because the invite is
/// delivered out of band (the irreducible trusted bit), the embedded fingerprint
/// is exactly as trusted as the invite itself.
///
/// Crate-private: the only external entry point is the minted `InviteResponse.token`
/// produced by `CertmeshCore::mint_invite`. Callers that consume a code use
/// [`decode_code`].
pub(crate) fn encode_code(secret: &str, ca_fingerprint: &str) -> String {
    format!("{secret}{CODE_SEP}{ca_fingerprint}")
}

/// Split an invite **code** into its `(secret, ca_fingerprint)` parts.
///
/// The CA fingerprint is `Some` only when the code carries one (the F3 form
/// `<secret>.<fp>`); a bare secret (no separator) yields `None` so callers
/// degrade to an unpinned join. The **secret** is always the part the CA hashes
/// and consumes — [`verify_and_consume`] applies this same split, so a caller may
/// present either the full code or just the secret and the CA behaves identically.
pub fn decode_code(code: &str) -> (&str, Option<&str>) {
    match code.split_once(CODE_SEP) {
        Some((secret, fp)) if !fp.is_empty() => (secret, Some(fp)),
        // Trailing separator with an empty fingerprint → secret only (drop the sep).
        Some((secret, _)) => (secret, None),
        None => (code, None),
    }
}

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
    /// Membership kind this invite may enroll as (ADR-026 §4): `"member"` or
    /// `"client"`. `None` = unbound (any host role). Older stores without the
    /// field deserialize as unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
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
    mint_with_role(path, hostname, ttl_mins, None)
}

/// Mint a role-bound invite (ADR-026 §4): `Some("member"|"client")` restricts
/// what the token may enroll as; `None` leaves it unbound (any host role).
///
/// An unknown role is rejected loudly at mint time — never persisted to be
/// silently treated as unbound later.
pub fn mint_with_role(
    path: &Path,
    hostname: &str,
    ttl_mins: i64,
    role: Option<&str>,
) -> Result<MintedInvite, CertmeshError> {
    let bound_role = role.map(|r| r.to_ascii_lowercase());
    match bound_role.as_deref() {
        None | Some("member") | Some("client") => {}
        Some(other) => {
            return Err(CertmeshError::InvalidPayload(format!(
                "unknown invite role {other:?}; expected \"member\" or \"client\""
            )))
        }
    }

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
        role: bound_role,
    });
    save(path, &store)?;
    Ok(MintedInvite { token, expires_at })
}

/// Verify `token` for `hostname` and burn it. Returns the consumed invite's
/// bound role on success (`None` inside = unbound — any host role), or `None`
/// overall when no matching, unexpired, unused invite existed. Fail-closed: any
/// I/O or parse error yields `None`.
pub fn verify_and_consume_details(
    path: &Path,
    token: &str,
    hostname: &str,
) -> Option<Option<String>> {
    // Accept either the bare secret or the full F3 code (`<secret>.<fp>`): the CA
    // only ever hashes + consumes the secret half; the fingerprint is a
    // client-side pinning hint the CA does not need.
    let (secret, _fp) = decode_code(token);
    let mut store = load(path);
    let h = token_hash(secret);
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
            match save(path, &store) {
                Ok(()) => Some(store.invites[idx].role.clone()),
                Err(_) => None,
            }
        }
        None => None,
    }
}

/// Verify `token` for `hostname` and burn it. Returns `true` iff a matching,
/// unexpired, unused invite existed and was just consumed. Fail-closed: any
/// I/O or parse error yields `false`.
pub fn verify_and_consume(path: &Path, token: &str, hostname: &str) -> bool {
    verify_and_consume_details(path, token, hostname).is_some()
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

    // ── F3 invite-code encode/decode ─────────────────────────────────

    #[test]
    fn encode_then_decode_round_trips() {
        let code = encode_code("deadbeef", "cafing3rprint");
        assert_eq!(code, "deadbeef.cafing3rprint");
        assert_eq!(decode_code(&code), ("deadbeef", Some("cafing3rprint")));
    }

    #[test]
    fn decode_bare_secret_has_no_fingerprint() {
        // A code with no separator is a bare secret → no pin (unpinned join).
        assert_eq!(decode_code("deadbeef"), ("deadbeef", None));
        // A trailing separator with an empty fp also degrades to no pin.
        assert_eq!(decode_code("deadbeef."), ("deadbeef", None));
    }

    #[test]
    fn decode_splits_on_first_separator_only() {
        // A malformed multi-dot code splits on the FIRST separator: the secret is
        // the head, everything after is the (here over-long, so never-matching)
        // fingerprint. Fails closed downstream — the secret is unambiguous and the
        // bogus fingerprint simply won't match any real CA. Real codes are
        // hex.hex, so this only arises from tampered/garbage input.
        assert_eq!(
            decode_code("deadbeef.fp1.fp2"),
            ("deadbeef", Some("fp1.fp2"))
        );
    }

    #[test]
    fn verify_consumes_when_presented_as_full_code() {
        // The CA hashes only the secret half, so presenting the full F3 code
        // (secret.fp) verifies and burns exactly as the bare secret would.
        let p = store_path("fullcode");
        let secret = mint(&p, "host-a", 60).unwrap().token;
        let code = encode_code(&secret, "anyfingerprint");
        assert!(
            verify_and_consume(&p, &code, "host-a"),
            "full code consumes"
        );
        assert!(
            !verify_and_consume(&p, &secret, "host-a"),
            "single-use: the underlying secret is already burned"
        );
    }

    // ── Role-bound invites (ADR-026 §4) ──────────────────────────────

    #[test]
    fn role_bound_invite_survives_the_store_roundtrip() {
        let p = store_path("role-bound");
        let token = mint_with_role(&p, "agent-1", 60, Some("client"))
            .unwrap()
            .token;
        assert_eq!(
            verify_and_consume_details(&p, &token, "agent-1"),
            Some(Some("client".to_string())),
            "the consumed invite reports its client binding"
        );
    }

    #[test]
    fn unbound_invite_reports_no_binding() {
        // Legacy mints (no role argument) and explicit None behave identically:
        // the token may enroll any host role.
        let p = store_path("unbound-legacy");
        let legacy = mint(&p, "host-a", 60).unwrap().token;
        assert_eq!(
            verify_and_consume_details(&p, &legacy, "host-a"),
            Some(None)
        );

        let p2 = store_path("unbound-explicit");
        let explicit = mint_with_role(&p2, "host-b", 60, None).unwrap().token;
        assert_eq!(
            verify_and_consume_details(&p2, &explicit, "host-b"),
            Some(None)
        );
    }

    #[test]
    fn mint_rejects_unknown_roles_loudly() {
        let p = store_path("bad-role");
        let err = mint_with_role(&p, "host-a", 60, Some("admin")).unwrap_err();
        assert!(
            err.to_string().contains("\"member\" or \"client\""),
            "unknown roles fail at mint time with named expectations: {err}"
        );
        // Nothing was persisted — a failed mint cannot leave an invite behind.
        assert!(load(&p).invites.is_empty());
    }

    #[test]
    fn mint_normalizes_role_case() {
        // A hand-written JSON body might not use lowercase for the role.
        let p = store_path("role-case");
        let token = mint_with_role(&p, "agent-9", 60, Some("CLIENT"))
            .unwrap()
            .token;
        assert_eq!(
            verify_and_consume_details(&p, &token, "agent-9"),
            Some(Some("client".to_string()))
        );
    }
}
