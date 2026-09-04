//! Koi DNS - lightweight local DNS resolver (Phase 6).

mod aliases;
pub mod http;
mod listener;
mod records;
mod resolver;
mod runtime;
mod safety;
mod state;
mod zone;

use koi_common::firewall::{FirewallPort, FirewallProtocol};

pub use resolver::{
    DnsCatalogSnapshot, DnsConfig, DnsCore, DnsEntryScope, DnsError, DnsEvent, DnsLookupResult,
};
pub use runtime::{DnsRecordSummary, DnsRuntime, DnsRuntimeState, DnsRuntimeStatus, DnsTxtLease};
pub use state::DnsEntry;
pub use zone::DnsZone;

/// Product-wide default for Koi's authoritative local DNS zone.
pub const DEFAULT_ZONE: &str = "internal";

/// Firewall ports required by the DNS capability.
pub fn firewall_ports(config: &DnsConfig) -> Vec<FirewallPort> {
    vec![
        FirewallPort::new("DNS", FirewallProtocol::Udp, config.port),
        FirewallPort::new("DNS", FirewallProtocol::Tcp, config.port),
    ]
}
