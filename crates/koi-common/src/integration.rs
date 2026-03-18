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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::ServiceRecord;

// ── Status reporter ────────────────────────────────────────────────

/// Trait for types that can report a capability status summary.
///
/// Each domain core implements this so the binary crate can
/// build a unified status view without coupling domains.
pub trait StatusReporter: Send + Sync {
    /// Machine-readable capability name (e.g. "mdns", "dns", "health").
    fn capability_name(&self) -> &'static str;

    /// Whether the capability is currently operational.
    fn is_running(&self) -> bool;

    /// Optional human-readable status detail.
    fn status_detail(&self) -> Option<String> {
        None
    }
}

// ── Summary types ──────────────────────────────────────────────────

/// Summary of a certmesh member, projected through the trait boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberSummary {
    pub hostname: String,
    pub sans: Vec<String>,
    pub cert_expires: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub status: String,
    pub proxy_entries: Vec<ProxyConfigSummary>,
}

/// Proxy configuration entry projected through the trait boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfigSummary {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
}

/// Lightweight proxy entry used by health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntrySummary {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
}

// ── Cross-domain traits ────────────────────────────────────────────

/// Read-only snapshot of the certmesh roster.
pub trait CertmeshSnapshot: Send + Sync {
    /// Return summaries of all active members.
    fn active_members(&self) -> Vec<MemberSummary>;
}

/// Read-only snapshot of mDNS network state.
pub trait MdnsSnapshot: Send + Sync {
    /// Map of hostname → IP derived from mDNS service records.
    fn host_ips(&self) -> HashMap<String, IpAddr>;

    /// All cached mDNS service records (for DNS alias building).
    fn cached_records(&self) -> Vec<ServiceRecord>;
}

/// Resolve a local DNS name without importing the DNS crate.
pub trait DnsProbe: Send + Sync {
    /// Resolve a local name to IP addresses (A or AAAA).
    fn resolve_local(&self, name: &str) -> Option<Vec<IpAddr>>;
}

/// Read-only snapshot of proxy entries.
pub trait ProxySnapshot: Send + Sync {
    /// Return all configured proxy entries.
    fn entries(&self) -> Vec<ProxyEntrySummary>;
}

/// Write-back channel for DNS alias feedback to certmesh.
///
/// When the DNS resolver discovers mDNS aliases, it can push them
/// to certmesh so that certificates include the correct SANs.
pub trait AliasFeedback: Send + Sync {
    /// Record that `hostname` should have `alias` as a SAN.
    fn record_alias(&self, hostname: &str, alias: &str);
}
