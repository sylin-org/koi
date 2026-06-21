//! Typed peer view of a discovered service — the fleet-legibility primitive
//! (ADR-020 §8).
//!
//! `discover` yields [`Peer`]s instead of raw [`ServiceRecord`]s so a consumer
//! reads a peer's advertised trust posture, mesh anchor (`fp=`), and identity
//! expiry directly, without re-parsing TXT keys at every call site. This is what
//! turns the posture oracle into a network-wide trust map (ADR-020 §13:
//! "fleet-wide trust legibility — Tailscale's biggest gap").
//!
//! **These are untrusted hints.** A peer's advertised posture is advisory only
//! (ADR-016 §2: "ask Koi, don't trust the wire") — authority comes from
//! `verify`/mTLS against the pinned CA, never from a TXT record. The hints make
//! the LAN's trust state *visible*; they never *grant* trust.
//!
//! Neutral vocabulary only (STACK-0001 K2): the keys and posture levels are
//! standard security terms, never a consumer codename.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::posture::{Posture, PostureLevel};
use crate::types::ServiceRecord;

/// mDNS TXT key: the CA fingerprint (SHA-256 hex) the node anchors to. Already
/// advertised on the CA's `_certmesh._tcp` record (ADR-017 F12); a node stamps it
/// so peers can confirm "same mesh" before dialing mTLS.
pub const TXT_FP: &str = "fp";

/// mDNS TXT key: the node's advertised [`PostureLevel`] as its wire string
/// (`open` / `authenticated` / `confidential`).
pub const TXT_POSTURE: &str = "posture";

/// mDNS TXT key: when the node's identity expires, as an **absolute** RFC 3339
/// timestamp. Absolute (not "days left") so a cached mDNS record never reports a
/// stale countdown — readers compute the remaining time themselves.
pub const TXT_EXPIRES: &str = "expires";

/// mDNS TXT key: the node's identity Common Name. Optional/reserved — not stamped
/// by default; the **authoritative** CN comes from `verify`/mTLS, never the wire.
/// Parsed when present so a node that chooses to advertise it is surfaced.
pub const TXT_CN: &str = "cn";

/// A discovered peer enriched with its advertised trust state (ADR-020 §8).
///
/// Built from a [`ServiceRecord`] via [`Peer::from_record`]; the trust fields are
/// parsed from the record's TXT map. All trust fields are *hints* — see the module
/// docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Peer {
    /// The underlying mDNS service record (name, type, host/ip, port, full TXT).
    pub record: ServiceRecord,
    /// The peer's advertised posture (a hint; `verify` adjudicates).
    pub posture: Posture,
    /// The CA fingerprint the peer anchors to (`fp=`), if advertised.
    pub fp: Option<String>,
    /// The peer's identity CN (`cn=`), if it chose to advertise one. The trusted
    /// CN comes from `verify`/mTLS, not this field.
    pub cn: Option<String>,
    /// When the peer's identity expires (`expires=`, absolute), if advertised.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Peer {
    /// Build a typed peer from a discovered [`ServiceRecord`], parsing the trust
    /// hints from its TXT map.
    ///
    /// Posture resolution: an explicit `posture=` wins; otherwise a record that
    /// carries a CA fingerprint (`fp=`) is treated as `authenticated` (a node only
    /// advertises an anchor it holds an identity for); otherwise `open`.
    pub fn from_record(record: ServiceRecord) -> Self {
        let fp = non_empty(record.txt.get(TXT_FP));
        let cn = non_empty(record.txt.get(TXT_CN));
        let expires_at = record
            .txt
            .get(TXT_EXPIRES)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        let posture = parse_posture(&record.txt, fp.is_some());
        Self {
            record,
            posture,
            fp,
            cn,
            expires_at,
        }
    }

    /// The peer's named posture level (`Open` / `Authenticated` / `Confidential`).
    pub fn level(&self) -> PostureLevel {
        self.posture.level()
    }

    /// Whether the peer advertises a usable cryptographic identity (`signed`).
    pub fn is_secure(&self) -> bool {
        self.posture.is_secure()
    }

    /// The peer's dialable `(host, port)`: its IP if known, else its hostname,
    /// paired with its advertised port. `None` if either is missing.
    pub fn addr(&self) -> Option<(String, u16)> {
        let host = self
            .record
            .ip
            .clone()
            .or_else(|| self.record.host.clone())?;
        let port = self.record.port?;
        Some((host, port))
    }

    /// Time remaining until the peer's identity expires, computed against `now`.
    /// Negative once expired. `None` if the peer advertised no expiry.
    ///
    /// Takes `now` explicitly so callers control the clock (and tests stay
    /// deterministic); for the wall clock pass `chrono::Utc::now()`.
    pub fn expires_in(&self, now: chrono::DateTime<chrono::Utc>) -> Option<chrono::Duration> {
        self.expires_at.map(|exp| exp - now)
    }
}

/// Stamp a node's own trust state into an mDNS TXT map (ADR-020 §8).
///
/// Idempotent — overwrites the trust keys. Always writes `posture=`; writes `fp=`
/// only when a non-empty fingerprint is supplied and `expires=` only when an
/// expiry is supplied (`expires` is written as an absolute RFC 3339 timestamp so
/// the hint never goes stale). Shared by every announce site so the wire contract
/// stays one vocabulary.
pub fn stamp(
    txt: &mut HashMap<String, String>,
    posture: Posture,
    ca_fp: Option<&str>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) {
    txt.insert(
        TXT_POSTURE.to_string(),
        posture.level().as_wire().to_string(),
    );
    if let Some(fp) = ca_fp.filter(|f| !f.is_empty()) {
        txt.insert(TXT_FP.to_string(), fp.to_string());
    }
    if let Some(exp) = expires_at {
        txt.insert(TXT_EXPIRES.to_string(), exp.to_rfc3339());
    }
}

/// `Some(non-empty owned)` for a present, non-blank TXT value, else `None`.
fn non_empty(v: Option<&String>) -> Option<String> {
    v.filter(|s| !s.is_empty()).cloned()
}

/// Resolve a posture from a TXT map: explicit `posture=` first, else infer
/// `authenticated` from the presence of a CA fingerprint, else `open`.
fn parse_posture(txt: &HashMap<String, String>, has_fp: bool) -> Posture {
    if let Some(level) = txt
        .get(TXT_POSTURE)
        .and_then(|s| PostureLevel::from_wire(s))
    {
        return level.to_posture();
    }
    if has_fp {
        Posture::new(true, false)
    } else {
        Posture::OPEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(txt: &[(&str, &str)]) -> ServiceRecord {
        ServiceRecord {
            name: "peer-01".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("peer-01.local".to_string()),
            ip: Some("192.168.1.10".to_string()),
            port: Some(8443),
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn open_when_no_trust_hints() {
        let p = Peer::from_record(record_with(&[]));
        assert_eq!(p.posture, Posture::OPEN);
        assert_eq!(p.level(), PostureLevel::Open);
        assert!(!p.is_secure());
        assert!(p.fp.is_none());
        assert!(p.expires_at.is_none());
    }

    #[test]
    fn fp_without_posture_infers_authenticated() {
        let p = Peer::from_record(record_with(&[("fp", "ABC123")]));
        assert_eq!(p.level(), PostureLevel::Authenticated);
        assert!(p.is_secure());
        assert_eq!(p.fp.as_deref(), Some("ABC123"));
    }

    #[test]
    fn explicit_posture_wins_over_fp_inference() {
        // posture=open with an fp present → respect the explicit declaration.
        let p = Peer::from_record(record_with(&[("fp", "ABC123"), ("posture", "open")]));
        assert_eq!(p.level(), PostureLevel::Open);
        // The fp is still surfaced even though posture is open.
        assert_eq!(p.fp.as_deref(), Some("ABC123"));
    }

    #[test]
    fn confidential_posture_parsed() {
        let p = Peer::from_record(record_with(&[("posture", "confidential")]));
        assert_eq!(p.level(), PostureLevel::Confidential);
        assert_eq!(p.posture, Posture::new(true, true));
    }

    #[test]
    fn unknown_posture_token_falls_back_to_inference() {
        // A garbage token is ignored; with no fp it resolves Open.
        let p = Peer::from_record(record_with(&[("posture", "supersecure")]));
        assert_eq!(p.level(), PostureLevel::Open);
    }

    #[test]
    fn blank_fp_is_treated_as_absent() {
        let p = Peer::from_record(record_with(&[("fp", "")]));
        assert!(p.fp.is_none());
        assert_eq!(p.level(), PostureLevel::Open);
    }

    #[test]
    fn expires_parsed_and_remaining_computed() {
        let exp = "2030-01-01T00:00:00Z";
        let p = Peer::from_record(record_with(&[
            ("posture", "authenticated"),
            ("expires", exp),
        ]));
        assert!(p.expires_at.is_some());
        let now = chrono::DateTime::parse_from_rfc3339("2029-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let remaining = p.expires_in(now).unwrap();
        assert!(remaining.num_days() >= 364 && remaining.num_days() <= 366);
    }

    #[test]
    fn expired_identity_reports_negative_remaining() {
        let p = Peer::from_record(record_with(&[("expires", "2020-01-01T00:00:00Z")]));
        let now = chrono::DateTime::parse_from_rfc3339("2021-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(p.expires_in(now).unwrap() < chrono::Duration::zero());
    }

    #[test]
    fn malformed_expires_is_ignored() {
        let p = Peer::from_record(record_with(&[("expires", "not-a-timestamp")]));
        assert!(p.expires_at.is_none());
    }

    #[test]
    fn cn_parsed_when_present() {
        let p = Peer::from_record(record_with(&[("cn", "peer-01")]));
        assert_eq!(p.cn.as_deref(), Some("peer-01"));
    }

    #[test]
    fn addr_prefers_ip_then_falls_back_to_host() {
        let p = Peer::from_record(record_with(&[]));
        assert_eq!(p.addr(), Some(("192.168.1.10".to_string(), 8443)));

        let mut rec = record_with(&[]);
        rec.ip = None;
        let p = Peer::from_record(rec);
        assert_eq!(p.addr(), Some(("peer-01.local".to_string(), 8443)));
    }

    #[test]
    fn addr_none_without_port() {
        let mut rec = record_with(&[]);
        rec.port = None;
        let p = Peer::from_record(rec);
        assert_eq!(p.addr(), None);
    }

    #[test]
    fn stamp_then_parse_round_trips() {
        let mut txt = HashMap::new();
        let exp = chrono::DateTime::parse_from_rfc3339("2031-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        stamp(
            &mut txt,
            Posture::new(true, false),
            Some("FP-XYZ"),
            Some(exp),
        );

        let rec = ServiceRecord {
            name: "n".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: Some("10.0.0.1".into()),
            port: Some(443),
            txt,
        };
        let p = Peer::from_record(rec);
        assert_eq!(p.level(), PostureLevel::Authenticated);
        assert_eq!(p.fp.as_deref(), Some("FP-XYZ"));
        assert_eq!(p.expires_at, Some(exp));
    }

    #[test]
    fn stamp_open_writes_posture_only() {
        let mut txt = HashMap::new();
        stamp(&mut txt, Posture::OPEN, None, None);
        assert_eq!(txt.get(TXT_POSTURE).map(String::as_str), Some("open"));
        assert!(!txt.contains_key(TXT_FP));
        assert!(!txt.contains_key(TXT_EXPIRES));
    }

    #[test]
    fn stamp_skips_empty_fp() {
        let mut txt = HashMap::new();
        stamp(&mut txt, Posture::new(true, false), Some(""), None);
        assert!(!txt.contains_key(TXT_FP));
    }

    #[test]
    fn peer_serde_round_trips() {
        let p = Peer::from_record(record_with(&[("fp", "ABC"), ("posture", "authenticated")]));
        let json = serde_json::to_string(&p).unwrap();
        let back: Peer = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
