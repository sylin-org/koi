use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use koi_common::integration::{CertmeshRosterSnapshot, DnsProbe};

use crate::service::ServiceStatus;

const CERT_EXPIRY_WARN_DAYS: i64 = 7;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct MachineHealth {
    pub hostname: String,
    pub status: ServiceStatus,
    pub last_seen_secs: Option<u64>,
    pub sources: Vec<String>,
    pub cert_expires: Option<DateTime<Utc>>,
    pub dns_resolves: Option<bool>,
    pub warnings: Vec<String>,
}

pub fn collect_machine_health(
    mdns_snapshot: &HashMap<String, Instant>,
    dns: Option<&Arc<dyn DnsProbe>>,
    certmesh: Option<&CertmeshRosterSnapshot>,
    threshold: Duration,
    observed_at: Instant,
    observed_utc: DateTime<Utc>,
) -> Vec<MachineHealth> {
    let roster_members = certmesh
        .map(|snapshot| snapshot.active_members.as_slice())
        .unwrap_or_default();

    let mut hostnames: HashSet<String> =
        roster_members.iter().map(|m| m.hostname.clone()).collect();
    hostnames.extend(mdns_snapshot.keys().cloned());

    let mut machines = Vec::new();
    for hostname in hostnames {
        let member = roster_members.iter().find(|m| m.hostname == hostname);
        let cert_last_seen = member.and_then(|m| m.last_seen);
        let cert_expires = member.and_then(|m| m.cert_expires);

        let mut sources = Vec::new();
        let mdns_age = mdns_snapshot.get(&hostname).map(|seen| {
            sources.push("mdns".to_string());
            observed_at.saturating_duration_since(*seen).as_secs()
        });

        let cert_age = cert_last_seen.map(|seen| {
            sources.push("certmesh".to_string());
            let age = observed_utc.signed_duration_since(seen);
            age.num_seconds().max(0) as u64
        });

        let best_age = match (mdns_age, cert_age) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let mut warnings = Vec::new();
        if let Some(exp) = cert_expires {
            if exp <= observed_utc {
                warnings.push("cert_expired".to_string());
            } else if exp <= observed_utc + chrono::Duration::days(CERT_EXPIRY_WARN_DAYS) {
                warnings.push("cert_expiring".to_string());
            }
        }

        let status = match best_age {
            Some(age) if age <= threshold.as_secs() => ServiceStatus::Up,
            Some(_) => ServiceStatus::Down,
            None => ServiceStatus::Unknown,
        };

        let dns_resolves = dns.map(|probe| probe.resolve_local(&hostname).is_some());

        machines.push(MachineHealth {
            hostname,
            status,
            last_seen_secs: best_age,
            sources,
            cert_expires,
            dns_resolves,
            warnings,
        });
    }

    machines.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    machines
}
