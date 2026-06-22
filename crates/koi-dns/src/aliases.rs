use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use koi_common::types::ServiceRecord;

use crate::safety::is_private_ip;
use crate::zone::DnsZone;

/// Alias records and feedback hints derived from mDNS service records.
pub struct AliasResult {
    pub aliases: HashMap<String, Vec<IpAddr>>,
    pub feedback: Vec<AliasFeedback>,
}

/// Alias feedback to notify certmesh about.
pub struct AliasFeedback {
    pub hostname: String,
    pub alias: String,
}

pub fn build_aliases(zone: &DnsZone, records: &[ServiceRecord]) -> AliasResult {
    let mut by_type: HashMap<String, Vec<&ServiceRecord>> = HashMap::new();
    for record in records {
        if record.service_type.is_empty() {
            continue;
        }
        by_type
            .entry(record.service_type.clone())
            .or_default()
            .push(record);
    }

    let mut aliases: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut feedback = Vec::new();

    for (service_type, recs) in by_type {
        let service_name = service_type
            .trim_start_matches('_')
            .split('.')
            .next()
            .unwrap_or("");
        if service_name.is_empty() {
            continue;
        }

        let base = format!("{service_name}.{}", zone.zone());
        let base = match zone.normalize_name(&base) {
            Some(name) => name,
            None => continue,
        };

        let mut base_ips = Vec::new();
        let mut seen_ips = HashSet::new();

        for record in recs {
            let ip = match record.ip.as_deref().and_then(parse_ip) {
                Some(ip) => ip,
                None => continue,
            };
            // Locality guard (mirrors the static + certmesh record sources):
            // mDNS announcements are unauthenticated LAN input, so refuse to alias
            // a non-private / non-link-local IP into the authoritative zone —
            // otherwise any LAN host could point an in-zone name at an external IP.
            if !is_private_ip(&ip) {
                tracing::warn!(%ip, name = %record.name, "skipping mDNS alias with non-private IP");
                continue;
            }
            if seen_ips.insert(ip) {
                base_ips.push(ip);
            }

            let instance = sanitize_label(&record.name);
            if !instance.is_empty() {
                let alias = format!("{instance}.{}", zone.zone());
                if let Some(alias) = zone.normalize_name(&alias) {
                    aliases.entry(alias).or_default().push(ip);
                }
            }

            // Also generate an alias from the mDNS hostname (e.g.
            // "node-azure-pool.local." → "node-azure-pool.internal.").
            // The hostname is stable — unlike the instance name it never
            // gets an mDNS conflict suffix like "(2)".
            if let Some(host) = record.host.as_deref() {
                let hostname = host.trim_end_matches('.').trim_end_matches(".local");
                if !hostname.is_empty() {
                    let host_alias = format!("{hostname}.{}", zone.zone());
                    if let Some(host_alias) = zone.normalize_name(&host_alias) {
                        aliases.entry(host_alias).or_default().push(ip);
                    }
                    feedback.push(AliasFeedback {
                        hostname: hostname.to_string(),
                        alias: base.clone(),
                    });
                }
            }
        }

        if !base_ips.is_empty() {
            aliases.insert(base, base_ips);
        }
    }

    AliasResult { aliases, feedback }
}

fn parse_ip(ip: &str) -> Option<IpAddr> {
    ip.parse().ok()
}

fn sanitize_label(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in input.chars() {
        let ch = ch.to_ascii_lowercase();
        let allowed = ch.is_ascii_alphanumeric();
        if allowed {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_label_basic() {
        assert_eq!(sanitize_label("My Server"), "my-server");
        assert_eq!(sanitize_label("_Grafana_01"), "grafana-01");
    }

    #[test]
    fn build_aliases_rejects_non_private_ip() {
        // mDNS is unauthenticated LAN input: a record advertising a public IP must
        // never become an authoritative .internal alias (zone-poisoning guard).
        let zone = DnsZone::new("internal").unwrap();
        let rec = |name: &str, ip: &str| ServiceRecord {
            name: name.to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some(format!("{name}.local")),
            ip: Some(ip.to_string()),
            port: Some(80),
            txt: HashMap::new(),
        };
        let recs = vec![rec("evil", "8.8.8.8"), rec("good", "10.0.0.5")];
        let result = build_aliases(&zone, &recs);
        let all_ips: Vec<String> = result
            .aliases
            .values()
            .flatten()
            .map(|ip| ip.to_string())
            .collect();
        assert!(
            !all_ips.iter().any(|ip| ip == "8.8.8.8"),
            "a non-private mDNS-advertised IP must never become an alias: {all_ips:?}"
        );
        assert!(
            all_ips.iter().any(|ip| ip == "10.0.0.5"),
            "a private mDNS IP should still be aliased: {all_ips:?}"
        );
    }
}
