use std::collections::HashMap;
use std::net::IpAddr;

use crate::state::DnsState;
use koi_common::integration::{CertmeshRosterSnapshot, MdnsDiscoverySnapshot};

use crate::aliases::{build_aliases, AliasFeedback};
use crate::safety::is_private_ip;
use crate::zone::DnsZone;

/// Aggregated local record sources used by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordsSnapshot {
    pub static_entries: HashMap<String, Vec<IpAddr>>,
    pub certmesh_entries: HashMap<String, Vec<IpAddr>>,
    pub mdns_entries: HashMap<String, Vec<IpAddr>>,
    pub alias_feedback: Vec<AliasFeedback>,
}

pub fn build_snapshot(
    zone: &DnsZone,
    state: &DnsState,
    certmesh: Option<&CertmeshRosterSnapshot>,
    mdns: Option<&MdnsDiscoverySnapshot>,
) -> RecordsSnapshot {
    let static_entries = static_entries(zone, state);
    let mdns_records = mdns
        .map(|snapshot| snapshot.records.clone())
        .unwrap_or_default();
    let host_ips = mdns.map(|snapshot| snapshot.host_ips()).unwrap_or_default();
    let certmesh_entries = certmesh
        .map(|snapshot| certmesh_entries(zone, &snapshot.active_members, &host_ips))
        .unwrap_or_default();
    let aliases = build_aliases(zone, &mdns_records);

    RecordsSnapshot {
        static_entries,
        certmesh_entries,
        mdns_entries: aliases.aliases,
        alias_feedback: aliases.feedback,
    }
}

fn static_entries(zone: &DnsZone, state: &DnsState) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in &state.entries {
        let Some(name) = zone.normalize_name(&entry.name) else {
            continue;
        };
        let Ok(ip) = entry.ip.parse() else {
            continue;
        };
        if !is_private_ip(&ip) {
            tracing::warn!(name, ip = %entry.ip, "Static entry resolves to non-local IP");
            continue;
        }
        map.entry(name).or_default().push(ip);
    }
    map
}

fn certmesh_entries(
    zone: &DnsZone,
    members: &[koi_common::integration::MemberSummary],
    host_ips: &HashMap<String, IpAddr>,
) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for member in members {
        if member.status != "active" {
            continue;
        }
        let ip = match host_ips.get(&member.hostname) {
            Some(ip) => *ip,
            None => continue,
        };
        if !is_private_ip(&ip) {
            continue;
        }
        for san in &member.sans {
            let Some(name) = zone.normalize_name(san) else {
                continue;
            };
            map.entry(name).or_default().push(ip);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_entries_ignore_outside_zone() {
        let zone = DnsZone::new("lan").unwrap();
        let state = DnsState {
            entries: vec![crate::DnsEntry {
                name: "example.com".to_string(),
                ip: "10.0.0.1".to_string(),
                ttl: None,
            }],
        };
        let map = static_entries(&zone, &state);
        assert!(map.is_empty());
    }
}
