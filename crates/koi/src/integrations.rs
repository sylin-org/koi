//! Bridge implementations that wrap domain cores and implement cross-domain
//! integration traits from `koi_common::integration`.
//!
//! These bridges are the only place where domain crates "see" each other,
//! through the binary crate's wiring.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use tokio_util::sync::CancellationToken;

use koi_common::integration;
use koi_common::types::{ServiceRecord, META_QUERY};

// ── CertmeshBridge ─────────────────────────────────────────────────

pub struct CertmeshBridge {
    _core: Arc<koi_certmesh::CertmeshCore>,
}

impl CertmeshBridge {
    pub fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self { _core: core })
    }
}

impl integration::CertmeshSnapshot for CertmeshBridge {
    fn active_members(&self) -> Vec<integration::MemberSummary> {
        let roster_path = koi_certmesh::CertmeshPaths::default().roster_path();
        let Ok(roster) = koi_certmesh::roster::load_roster(&roster_path) else {
            return Vec::new();
        };
        roster
            .members
            .into_iter()
            .filter(|m| m.status == koi_certmesh::roster::MemberStatus::Active)
            .map(|m| integration::MemberSummary {
                hostname: m.hostname,
                sans: m.cert_sans,
                cert_expires: Some(m.cert_expires),
                last_seen: m.last_seen,
                status: "active".to_string(),
                proxy_entries: m
                    .proxy_entries
                    .into_iter()
                    .map(|p| integration::ProxyConfigSummary {
                        name: p.name,
                        listen_port: p.listen_port,
                        backend: p.backend,
                        allow_remote: p.allow_remote,
                    })
                    .collect(),
            })
            .collect()
    }
}

// ── MdnsBridge ─────────────────────────────────────────────────────

/// Maintains a polled cache of mDNS service records and exposes them
/// through the `MdnsSnapshot` trait.
pub struct MdnsBridge {
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
    cancel: CancellationToken,
}

impl MdnsBridge {
    /// Spawn a background browse task that keeps the cache warm.
    pub async fn spawn(core: Arc<koi_mdns::MdnsCore>) -> Arc<Self> {
        let records = Arc::new(RwLock::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let meta_core = Arc::clone(&core);
        let meta_records = Arc::clone(&records);
        let meta_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Ok(handle) = meta_core.browse(META_QUERY).await {
                run_meta_browse(meta_core, handle, meta_records, meta_cancel).await;
            }
        });

        Arc::new(Self { records, cancel })
    }

    fn snapshot_records(&self) -> Vec<ServiceRecord> {
        let guard = self.records.read().unwrap_or_else(|e| e.into_inner());
        guard
            .values()
            .flat_map(|map| map.values().cloned())
            .collect()
    }
}

impl Drop for MdnsBridge {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl integration::MdnsSnapshot for MdnsBridge {
    fn host_ips(&self) -> HashMap<String, IpAddr> {
        let records = self.snapshot_records();
        let mut map = HashMap::new();
        for record in &records {
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

    fn cached_records(&self) -> Vec<ServiceRecord> {
        self.snapshot_records()
    }
}

// ── DnsBridge ──────────────────────────────────────────────────────

pub struct DnsBridge {
    runtime: Arc<koi_dns::DnsRuntime>,
}

impl DnsBridge {
    pub fn new(runtime: Arc<koi_dns::DnsRuntime>) -> Arc<Self> {
        Arc::new(Self { runtime })
    }
}

impl integration::DnsProbe for DnsBridge {
    fn resolve_local(&self, name: &str) -> Option<Vec<IpAddr>> {
        use hickory_proto::rr::RecordType;
        let core = self.runtime.core();
        let result = core
            .resolve_local(name, RecordType::A)
            .or_else(|| core.resolve_local(name, RecordType::AAAA));
        result.map(|r| r.ips)
    }
}

// ── ProxyBridge ────────────────────────────────────────────────────

pub struct ProxyBridge {
    _core: Arc<koi_proxy::ProxyCore>,
}

impl ProxyBridge {
    pub fn new(core: Arc<koi_proxy::ProxyCore>) -> Arc<Self> {
        Arc::new(Self { _core: core })
    }
}

impl integration::ProxySnapshot for ProxyBridge {
    fn entries(&self) -> Vec<integration::ProxyEntrySummary> {
        // Use the config module to load entries (sync operation is fine here).
        let Ok(entries) = koi_proxy::config::load_entries() else {
            return Vec::new();
        };
        entries
            .into_iter()
            .map(|e| integration::ProxyEntrySummary {
                name: e.name,
                listen_port: e.listen_port,
                backend: e.backend,
            })
            .collect()
    }
}

// ── AliasFeedbackBridge ────────────────────────────────────────────

pub struct AliasFeedbackBridge {
    core: Arc<koi_certmesh::CertmeshCore>,
}

impl AliasFeedbackBridge {
    pub fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self { core })
    }
}

impl integration::AliasFeedback for AliasFeedbackBridge {
    fn record_alias(&self, hostname: &str, alias: &str) {
        let core = Arc::clone(&self.core);
        let hostname = hostname.to_string();
        let alias = alias.to_string();
        // Fire and forget — alias feedback is best-effort.
        tokio::spawn(async move {
            let _ = core.add_alias_sans(&hostname, &[alias]).await;
        });
    }
}

// ── mDNS browse helpers (ported from koi-dns resolver.rs) ──────────

async fn run_meta_browse(
    core: Arc<koi_mdns::MdnsCore>,
    handle: koi_mdns::BrowseHandle,
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
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
                        let r = Arc::clone(&records);
                        let t = service_type.clone();
                        let cancel_child = cancel.clone();
                        tokio::spawn(async move {
                            if let Ok(handle) = c.browse(&t).await {
                                run_type_browse(handle, r, cancel_child).await;
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
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                match event {
                    koi_mdns::events::MdnsEvent::Resolved(record) => {
                        let mut guard = records.write().unwrap_or_else(|e| e.into_inner());
                        let entry = guard.entry(record.service_type.clone()).or_default();
                        entry.insert(record.name.clone(), record);
                    }
                    koi_mdns::events::MdnsEvent::Removed { name, service_type } => {
                        let mut guard = records.write().unwrap_or_else(|e| e.into_inner());
                        let service_type = if service_type.is_empty() {
                            extract_service_type(&name)
                        } else {
                            Some(service_type)
                        };
                        if let Some(st) = service_type {
                            if let Some(map) = guard.get_mut(&st) {
                                let instance = extract_instance_name(&name);
                                if let Some(instance) = instance {
                                    map.remove(&instance);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn extract_service_type(fullname: &str) -> Option<String> {
    let idx = fullname.find("._")?;
    let rest = &fullname[idx + 1..];
    let trimmed = rest.trim_end_matches('.').trim_end_matches(".local");
    Some(trimmed.to_string())
}

fn extract_instance_name(fullname: &str) -> Option<String> {
    let idx = fullname.find("._")?;
    Some(fullname[..idx].to_string())
}
