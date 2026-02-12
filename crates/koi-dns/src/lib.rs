//! Koi DNS — lightweight local DNS resolver (Phase 6).

mod aliases;
pub mod http;
mod records;
mod resolver;
mod runtime;
mod safety;
mod zone;

use koi_common::firewall::{FirewallPort, FirewallProtocol};

pub use resolver::{DnsConfig, DnsCore, DnsError, DnsLookupResult};
pub use runtime::{DnsRuntime, DnsRuntimeStatus};
pub use zone::DnsZone;

/// Firewall ports required by the DNS capability.
pub fn firewall_ports(config: &DnsConfig) -> Vec<FirewallPort> {
    vec![
        FirewallPort::new("DNS", FirewallProtocol::Udp, config.port),
        FirewallPort::new("DNS", FirewallProtocol::Tcp, config.port),
    ]
}
