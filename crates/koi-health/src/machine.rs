use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;

use koi_common::integration::{CertmeshSnapshot, DnsProbe, MdnsSnapshot};

use crate::service::ServiceStatus;

const CERT_EXPIRY_WARN_DAYS: i64 = 7;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct MachineHealth {
    pub hostname: String,
    pub status: ServiceStatus,
    pub last_seen_secs: Option<u64>,
    pub sources: Vec<String>,
    pub cert_expires: Option<DateTime<Utc>>,
    pub dns_resolves: Option<bool>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct MdnsHostState {
    last_seen: Instant,
}

pub struct MdnsTracker {
    hosts: Arc<tokio::sync::RwLock<HashMap<String, MdnsHostState>>>,
    cancel: CancellationToken,
}

impl MdnsTracker {
    pub async fn spawn(mdns: Arc<dyn MdnsSnapshot>) -> Self {
        let hosts = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let tracker_hosts = Arc::clone(&hosts);
        let tracker_cancel = cancel.clone();
        tokio::spawn(async move {
            run_mdns_poll(mdns, tracker_hosts, tracker_cancel).await;
        });

        Self { hosts, cancel }
    }

    pub fn snapshot(&self) -> HashMap<String, Instant> {
        match self.hosts.try_read() {
            Ok(guard) => guard
                .iter()
                .map(|(host, state)| (host.clone(), state.last_seen))
                .collect(),
            Err(_) => HashMap::new(),
        }
    }
}

impl Drop for MdnsTracker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub fn collect_machine_health(
    mdns_snapshot: &HashMap<String, Instant>,
    dns: Option<&Arc<dyn DnsProbe>>,
    certmesh: Option<&Arc<dyn CertmeshSnapshot>>,
    threshold: Duration,
) -> Vec<MachineHealth> {
    let roster_members = certmesh
        .map(|cm| cm.active_members())
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
            seen.elapsed().as_secs()
        });

        let cert_age = cert_last_seen.map(|seen| {
            sources.push("certmesh".to_string());
            let age = Utc::now().signed_duration_since(seen);
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
            if exp <= Utc::now() {
                warnings.push("cert_expired".to_string());
            } else if exp <= Utc::now() + chrono::Duration::days(CERT_EXPIRY_WARN_DAYS) {
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

/// Periodically poll the MdnsSnapshot for host IPs and update the tracker.
///
/// This replaces the previous direct browse-handle approach. The MdnsSnapshot
/// trait provides a polled view of the mDNS cache, which is sufficient for
/// health monitoring (we don't need real-time events, just periodic snapshots).
async fn run_mdns_poll(
    mdns: Arc<dyn MdnsSnapshot>,
    hosts: Arc<tokio::sync::RwLock<HashMap<String, MdnsHostState>>>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                let host_ips = mdns.host_ips();
                let now = Instant::now();
                let mut guard = hosts.write().await;
                guard.retain(|h, _| host_ips.contains_key(h));
                for hostname in host_ips.keys() {
                    guard.entry(hostname.clone()).or_insert(MdnsHostState { last_seen: now });
                }
            }
        }
    }
}

