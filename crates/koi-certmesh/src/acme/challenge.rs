//! dns-01 challenge computation, validation, and zone enforcement (RFC 8555 §8.4).
//!
//! The dns-01 flow Koi serves is **self-served in-process** — there is no real
//! DNS propagation wait. The server:
//! 1. computes the expected TXT value for the challenge,
//! 2. writes it to `_acme-challenge.<name>` via the [`AcmeDnsSolver`] bridge,
//! 3. immediately reads it back through the same bridge and compares,
//! 4. clears the TXT record.
//!
//! Because steps 2–4 hit the same in-process DNS core, validation is instant and
//! deterministic — exactly the "offline issuance, no propagation wait" property
//! the design promises.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Compute the dns-01 key authorization: `token + "." + thumbprint`
/// (RFC 8555 §8.1). The `thumbprint` is the RFC 7638 JWK thumbprint of the
/// account key (see [`crate::acme::jws::jwk_thumbprint`]).
pub fn key_authorization(token: &str, thumbprint: &str) -> String {
    format!("{token}.{thumbprint}")
}

/// Compute the dns-01 TXT record value:
/// `base64url(SHA256(keyAuthorization))` (RFC 8555 §8.4).
///
/// This MUST match what a conformant client (instant-acme's
/// `KeyAuthorization::dns_value`, Caddy, lego) writes for the same key auth.
pub fn dns_txt_value(key_authorization: &str) -> String {
    let digest = Sha256::digest(key_authorization.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// The DNS name a dns-01 challenge TXT lives at: `_acme-challenge.<name>`.
pub fn challenge_dns_name(identifier: &str) -> String {
    format!("_acme-challenge.{identifier}")
}

/// Normalize a DNS name for zone comparison: lowercase, strip a trailing dot.
fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// Whether `identifier` is inside `zone` and therefore issuable.
///
/// The zone is the Koi DNS zone (e.g. `lan`). An identifier is in-zone when it
/// is the zone itself, a subdomain of the zone, or the wildcard `*.<zone>` (or a
/// wildcard of any in-zone subdomain). This is the critical issuance boundary:
/// the CA NEVER issues for names outside its own zone (out-of-zone →
/// `rejectedIdentifier`).
pub fn is_in_zone(identifier: &str, zone: &str) -> bool {
    let zone = normalize(zone);
    if zone.is_empty() {
        return false;
    }
    // Strip a leading wildcard label; `*.foo.lan` is in-zone iff `foo.lan` is.
    let ident = normalize(identifier);
    let base = ident.strip_prefix("*.").unwrap_or(&ident);
    if base.is_empty() {
        return false;
    }
    // Reject any embedded wildcard beyond the single leading label.
    if base.contains('*') {
        return false;
    }
    base == zone || base.ends_with(&format!(".{zone}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_authorization_is_token_dot_thumbprint() {
        assert_eq!(key_authorization("tok", "thumb"), "tok.thumb");
    }

    #[test]
    fn dns_txt_value_is_b64url_sha256() {
        // Deterministic + 43-char (32-byte digest, no padding).
        let v = dns_txt_value("tok.thumb");
        assert_eq!(v.len(), 43);
        assert_eq!(dns_txt_value("tok.thumb"), v);
        assert_ne!(dns_txt_value("other"), v);
    }

    #[test]
    fn challenge_name_is_prefixed() {
        assert_eq!(
            challenge_dns_name("grafana.lan"),
            "_acme-challenge.grafana.lan"
        );
    }

    #[test]
    fn in_zone_accepts_subdomains_and_zone_itself() {
        assert!(is_in_zone("grafana.lan", "lan"));
        assert!(is_in_zone("a.b.lan", "lan"));
        assert!(is_in_zone("lan", "lan"));
    }

    #[test]
    fn in_zone_accepts_wildcard_in_zone() {
        assert!(is_in_zone("*.lan", "lan"));
        assert!(is_in_zone("*.team.lan", "lan"));
    }

    #[test]
    fn out_of_zone_is_rejected() {
        assert!(!is_in_zone("evil.com", "lan"));
        assert!(!is_in_zone("grafana.example.org", "lan"));
        // a zone-suffixed lookalike that isn't actually under the zone label
        assert!(!is_in_zone("notlan", "lan"));
        assert!(!is_in_zone("lan.evil.com", "lan"));
    }

    #[test]
    fn embedded_wildcard_is_rejected() {
        assert!(!is_in_zone("a.*.lan", "lan"));
    }

    #[test]
    fn case_and_trailing_dot_insensitive() {
        assert!(is_in_zone("Grafana.LAN.", "lan"));
        assert!(is_in_zone("grafana.lan", "LAN"));
    }
}
