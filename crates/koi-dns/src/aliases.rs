use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use koi_common::types::ServiceRecord;

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
            if seen_ips.insert(ip) {
                base_ips.push(ip);
            }

            let instance = sanitize_label(&record.name);
            if !instance.is_empty() {
                let alias = format!("{service_name}-{instance}.{}", zone.zone());
                if let Some(alias) = zone.normalize_name(&alias) {
                    aliases.entry(alias).or_default().push(ip);
                }
            }

            if let Some(host) = record.host.as_deref() {
                let hostname = host.trim_end_matches('.').trim_end_matches(".local");
                if !hostname.is_empty() {
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
}
