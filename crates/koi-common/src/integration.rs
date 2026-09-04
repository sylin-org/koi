//! Integration traits for cross-crate abstractions.
//!
//! These traits define contracts that domain crates implement
//! and the binary crate wires together, without domain crates
//! importing each other.
//!
//! Domain crates depend only on `koi-common`, never on each other.
//! The binary crate (or `koi-embedded`) provides bridge implementations
//! that wrap concrete domain cores and implement these traits.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::types::ServiceRecord;

// ── Summary types ──────────────────────────────────────────────────

/// Summary of a certmesh member, projected through the trait boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSummary {
    pub hostname: String,
    pub sans: Vec<String>,
    pub cert_expires: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub status: String,
    pub proxy_entries: Vec<ProxyConfigSummary>,
}

/// Proxy configuration entry projected through the trait boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfigSummary {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
}

/// Lightweight proxy entry used by health checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntrySummary {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
}

/// Immutable latest-value projection of Proxy's effective desired entries.
///
/// This merges durable operator configuration with transient, explicitly scoped
/// cross-domain desire. Proxy owns the merge, precedence, and revision;
/// integration consumers retain the surrounding [`Arc`] or subscribe to the
/// coalescing watch feed rather than rebuilding desire from listener status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntriesSnapshot {
    /// Process-local monotonic revision assigned by the Proxy domain.
    pub revision: u64,
    /// Desired entries sorted by name for stable semantic equality.
    pub entries: Vec<ProxyEntrySummary>,
}

/// Sensitive local TLS identity supplied by its owning Certmesh domain.
/// `koi-trust` separately owns installation of operating-system trust anchors;
/// it is not the authority for this node's certificate or private key.
///
/// This type deliberately implements neither serialization nor an exposing
/// `Debug`: private key material may cross an in-process composition port, but
/// must never become general status or wire data.
#[derive(Clone, PartialEq, Eq)]
pub struct TlsIdentityMaterial {
    pub hostname: String,
    pub certificate_chain_pem: Arc<str>,
    pub private_key_pem: Arc<str>,
    /// Trust anchor used to authenticate peers of this identity.
    pub trust_anchor_pem: Arc<str>,
}

impl std::fmt::Debug for TlsIdentityMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsIdentityMaterial")
            .field("hostname", &self.hostname)
            .field("certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("trust_anchor_pem", &"<redacted>")
            .finish()
    }
}

/// Latest-value view of usable local TLS material.
///
/// `material` becomes `None` when identity is absent, invalid, expired, or
/// revoked. The revision advances only when the material itself changes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TlsIdentitySnapshot {
    pub revision: u64,
    pub material: Option<TlsIdentityMaterial>,
}

/// Immutable, latest-value projection of active Certmesh members.
///
/// Certmesh owns both this projection and its revision. Consumers keep the
/// surrounding [`Arc`] or subscribe to the coalescing watch feed; they never
/// reconstruct roster state from one-shot events or private persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertmeshRosterSnapshot {
    /// Process-local monotonic revision assigned by the Certmesh domain.
    pub revision: u64,
    /// Active members, sorted by hostname for stable semantic equality.
    pub active_members: Vec<MemberSummary>,
}

impl std::fmt::Debug for TlsIdentitySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsIdentitySnapshot")
            .field("revision", &self.revision)
            .field(
                "hostname",
                &self.material.as_ref().map(|material| &material.hostname),
            )
            .field("available", &self.material.is_some())
            .finish()
    }
}

/// Immutable, latest-value projection of mDNS discovery state.
///
/// The mDNS domain owns this snapshot and its revision. Integration consumers
/// retain the surrounding [`Arc`] or subscribe to the coalescing watch feed;
/// they never reconstruct a second cache from best-effort browse events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MdnsDiscoverySnapshot {
    /// Process-local monotonic revision assigned by the mDNS domain.
    pub revision: u64,
    /// Canonical service types currently visible, sorted for stable equality.
    pub service_types: Vec<String>,
    /// Resolved service records currently visible, sorted by the mDNS domain.
    pub records: Vec<ServiceRecord>,
}

impl MdnsDiscoverySnapshot {
    /// Project the resolved records into the hostname map used by DNS and
    /// machine-health integrations.
    pub fn host_ips(&self) -> HashMap<String, IpAddr> {
        let mut hosts = HashMap::new();
        for record in &self.records {
            let Some(host) = record.host.as_deref() else {
                continue;
            };
            let Some(ip) = record.ip.as_deref().and_then(|value| value.parse().ok()) else {
                continue;
            };
            let hostname = host.trim_end_matches('.').trim_end_matches(".local");
            if !hostname.is_empty() {
                hosts.insert(hostname.to_string(), ip);
            }
        }
        hosts
    }
}

// ── Cross-domain traits ────────────────────────────────────────────

/// Read-only snapshot of the certmesh roster.
pub trait CertmeshSnapshot: Send + Sync {
    /// Return Certmesh's current immutable roster projection.
    fn snapshot(&self) -> Arc<CertmeshRosterSnapshot>;

    /// Subscribe to the current projection and future coalesced changes.
    fn watch_snapshot(&self) -> watch::Receiver<Arc<CertmeshRosterSnapshot>>;
}

/// Sensitive, in-process TLS identity port owned by the Certmesh domain.
pub trait TlsIdentitySource: Send + Sync {
    /// Return the current immutable material snapshot in constant time.
    fn tls_identity(&self) -> Arc<TlsIdentitySnapshot>;

    /// Observe rotations, revocation, expiry, destruction, and recovery.
    fn watch_tls_identity(&self) -> watch::Receiver<Arc<TlsIdentitySnapshot>>;
}

/// Read-only snapshot of mDNS network state.
pub trait MdnsSnapshot: Send + Sync {
    /// Return the mDNS domain's current immutable discovery projection.
    fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot>;

    /// Subscribe to the current projection and future coalesced changes.
    fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>>;
}

/// Resolve a local DNS name without importing the DNS crate.
pub trait DnsProbe: Send + Sync {
    /// Resolve a local name to IP addresses (A or AAAA).
    fn resolve_local(&self, name: &str) -> Option<Vec<IpAddr>>;
}

/// Read-only latest-value projection of Proxy's effective desired entries.
pub trait ProxySnapshot: Send + Sync {
    /// Return Proxy's current immutable entries projection.
    fn snapshot(&self) -> Arc<ProxyEntriesSnapshot>;

    /// Subscribe to the current projection and future coalesced changes.
    fn watch_snapshot(&self) -> watch::Receiver<Arc<ProxyEntriesSnapshot>>;
}

/// Write-back channel for DNS alias feedback to certmesh.
///
/// When the DNS resolver discovers mDNS aliases, it can push them
/// to certmesh so that certificates include the correct SANs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AliasFeedbackError(pub String);

#[async_trait::async_trait]
pub trait AliasFeedback: Send + Sync {
    /// Durably record that `hostname` should have `alias` as a SAN.
    /// Returning success is the command acknowledgement boundary; callers can
    /// retain and retry failed desired state without spawning orphan work.
    async fn record_alias(&self, hostname: &str, alias: &str) -> Result<(), AliasFeedbackError>;
}

/// Read ephemeral DNS TXT records while validating ACME `dns-01` challenges.
///
/// The ACME client owns publication and cleanup through the DNS capability's
/// authenticated API. certmesh only reads through this composition boundary,
/// so it never imports `koi-dns` or mutates another domain's state.
pub trait AcmeDnsResolver: Send + Sync {
    /// Return the currently published TXT values for `name` (empty if none).
    fn get_txt(&self, name: &str) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_entries_snapshot_round_trips_with_its_revision() {
        let snapshot = ProxyEntriesSnapshot {
            revision: 7,
            entries: vec![ProxyEntrySummary {
                name: "api".to_string(),
                listen_port: 9443,
                backend: "127.0.0.1:8080".to_string(),
            }],
        };
        let encoded = serde_json::to_vec(&snapshot).expect("serialize Proxy entries");
        let decoded =
            serde_json::from_slice::<ProxyEntriesSnapshot>(&encoded).expect("decode Proxy entries");
        assert_eq!(decoded, snapshot);
    }
}
