use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hickory_proto::rr::RecordType;
use tokio_util::sync::CancellationToken;

use koi_certmesh::roster::{MemberStatus, RosterMember};
use koi_common::types::META_QUERY;

use crate::service::ServiceStatus;

const CERT_EXPIRY_WARN_DAYS: i64 = 7;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub async fn spawn(core: Arc<koi_mdns::MdnsCore>) -> Self {
        let hosts = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let meta_core = Arc::clone(&core);
        let meta_hosts = Arc::clone(&hosts);
        let meta_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Ok(handle) = meta_core.browse(META_QUERY).await {
                run_meta_browse(meta_core, handle, meta_hosts, meta_cancel).await;
            }
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
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    threshold: Duration,
) -> Vec<MachineHealth> {
    let roster_members = load_active_members();

    let mut hostnames: HashSet<String> = roster_members
        .iter()
        .map(|m| m.hostname.clone())
        .collect();
    hostnames.extend(mdns_snapshot.keys().cloned());

    let mut machines = Vec::new();
    for hostname in hostnames {
        let member = roster_members.iter().find(|m| m.hostname == hostname);
        let cert_last_seen = member.and_then(|m| m.last_seen);
        let cert_expires = member.map(|m| m.cert_expires);

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

        let dns_resolves = dns
            .as_ref()
            .map(|runtime| runtime.core())
            .map(|core| {
                core.resolve_local(&hostname, RecordType::A)
                    .or_else(|| core.resolve_local(&hostname, RecordType::AAAA))
                    .is_some()
            });

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

fn load_active_members() -> Vec<RosterMember> {
    let path = koi_certmesh::ca::roster_path();
    let Ok(roster) = koi_certmesh::roster::load_roster(&path) else {
        return Vec::new();
    };
    roster
        .members
        .into_iter()
        .filter(|m| m.status == MemberStatus::Active)
        .collect()
}

async fn run_meta_browse(
    core: Arc<koi_mdns::MdnsCore>,
    handle: koi_mdns::BrowseHandle,
    hosts: Arc<tokio::sync::RwLock<HashMap<String, MdnsHostState>>>,
    cancel: CancellationToken,
) {
    let active = Arc::new(tokio::sync::Mutex::new(HashSet::<String>::new()));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                if let koi_mdns::events::MdnsEvent::Found(record) = event {
                    let service_type = record.name;
                    let mut guard = active.lock().await;
                    if guard.insert(service_type.clone()) {
                        let c = Arc::clone(&core);
                        let h = Arc::clone(&hosts);
                        let t = service_type.clone();
                        let cancel_child = cancel.clone();
                        tokio::spawn(async move {
                            if let Ok(handle) = c.browse(&t).await {
                                run_type_browse(handle, h, cancel_child).await;
                            }
                        });
                    }
                }
            }
        }
    }
}

async fn run_type_browse(
    handle: koi_mdns::BrowseHandle,
    hosts: Arc<tokio::sync::RwLock<HashMap<String, MdnsHostState>>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                if let koi_mdns::events::MdnsEvent::Resolved(record) = event {
                    if let Some(host) = record.host.as_deref() {
                        let host = normalize_host(host);
                        if host.is_empty() {
                            continue;
                        }
                        let mut guard = hosts.write().await;
                        guard.insert(
                            host,
                            MdnsHostState {
                                last_seen: Instant::now(),
                            },
                        );
                    }
                }
            }
        }
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}
