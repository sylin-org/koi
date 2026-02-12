use std::collections::HashMap;
use std::net::IpAddr;

use koi_certmesh::roster::{MemberStatus, Roster};
use koi_common::types::ServiceRecord;
use koi_config::state::DnsState;

use crate::aliases::{build_aliases, AliasFeedback};
use crate::safety::is_private_ip;
use crate::zone::DnsZone;

/// Aggregated local record sources used by the resolver.
pub struct RecordsSnapshot {
    pub static_entries: HashMap<String, Vec<IpAddr>>,
    pub certmesh_entries: HashMap<String, Vec<IpAddr>>,
    pub mdns_entries: HashMap<String, Vec<IpAddr>>,
    pub alias_feedback: Vec<AliasFeedback>,
}

pub fn build_snapshot(
    zone: &DnsZone,
    state: &DnsState,
    roster: Option<&Roster>,
    mdns_records: &[ServiceRecord],
) -> RecordsSnapshot {
    let static_entries = static_entries(zone, state);
    let host_ips = mdns_host_ips(mdns_records);
    let certmesh_entries = roster
        .map(|r| certmesh_entries(zone, r, &host_ips))
        .unwrap_or_default();
    let aliases = build_aliases(zone, mdns_records);

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
    roster: &Roster,
    host_ips: &HashMap<String, IpAddr>,
) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for member in &roster.members {
        if member.status != MemberStatus::Active {
            continue;
        }
        let ip = match host_ips.get(&member.hostname) {
            Some(ip) => *ip,
            None => continue,
        };
        if !is_private_ip(&ip) {
            continue;
        }
        for san in &member.cert_sans {
            let Some(name) = zone.normalize_name(san) else {
                continue;
            };
            map.entry(name).or_default().push(ip);
        }
    }
    map
}

fn mdns_host_ips(records: &[ServiceRecord]) -> HashMap<String, IpAddr> {
    let mut map = HashMap::new();
    for record in records {
        let Some(host) = record.host.as_deref() else {
            continue;
        };
        let Some(ip) = record.ip.as_deref().and_then(|ip| ip.parse().ok()) else {
            continue;
        };
        let hostname = host.trim_end_matches('.').trim_end_matches(".local");
        if !hostname.is_empty() {
            map.insert(hostname.to_string(), ip);
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
            entries: vec![koi_config::state::DnsEntry {
                name: "example.com".to_string(),
                ip: "10.0.0.1".to_string(),
                ttl: None,
            }],
        };
        let map = static_entries(&zone, &state);
        assert!(map.is_empty());
    }
}
