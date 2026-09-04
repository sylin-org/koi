//! Bridge implementations that wrap domain cores and implement the cross-domain
//! integration traits from `koi_common::integration`.
//!
//! These bridges are the only place where domains "see" each other — through the
//! composition layer's wiring, never a direct domain→domain dependency. Moved here from
//! the binary's `integrations.rs` (P07) so the daemon, the Windows service, and
//! koi-embedded share one copy instead of three.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_common::integration;
use koi_common::types::META_QUERY;

// ── CertmeshBridge ─────────────────────────────────────────────────

pub struct CertmeshBridge {
    core: Arc<koi_certmesh::CertmeshCore>,
}

impl CertmeshBridge {
    pub fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self { core })
    }
}

impl integration::CertmeshSnapshot for CertmeshBridge {
    fn snapshot(&self) -> Arc<integration::CertmeshRosterSnapshot> {
        self.core.roster_snapshot()
    }

    fn watch_snapshot(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<integration::CertmeshRosterSnapshot>> {
        self.core.watch_roster_snapshot()
    }
}

/// Sensitive local TLS-material port. Keeping this separate from
/// `CertmeshSnapshot` prevents a roster/status consumer from gaining private-key
/// access merely because it needs public membership facts.
pub struct CertmeshTlsIdentityBridge {
    core: Arc<koi_certmesh::CertmeshCore>,
}

impl CertmeshTlsIdentityBridge {
    pub fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self { core })
    }
}

impl integration::TlsIdentitySource for CertmeshTlsIdentityBridge {
    fn tls_identity(&self) -> Arc<integration::TlsIdentitySnapshot> {
        self.core.tls_identity()
    }

    fn watch_tls_identity(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<integration::TlsIdentitySnapshot>> {
        self.core.watch_tls_identity()
    }
}

// ── MdnsBridge ─────────────────────────────────────────────────────

/// Keeps the domain-owned meta/type browses warm and projects the mDNS
/// discovery status through the narrow integration port. It owns no cache.
pub struct MdnsBridge {
    core: Arc<koi_mdns::MdnsCore>,
    cancel: CancellationToken,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl MdnsBridge {
    /// Spawn a background browse task that keeps the cache warm.
    pub async fn spawn(core: Arc<koi_mdns::MdnsCore>) -> Arc<Self> {
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(keep_discovery_warm(Arc::clone(&core), cancel.clone()));
        Arc::new(Self {
            core,
            cancel,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Stop and reap the composition-owned warm-cache projection.
    ///
    /// This is intentionally crate-private: the retained composition release
    /// transaction is the lifecycle boundary that guarantees this waiter is
    /// driven through completion.
    pub(crate) async fn shutdown(&self) {
        self.cancel.cancel();
        // Borrow in place so cancelling this shutdown does not detach the task.
        let mut worker = self.worker.lock().await;
        if let Some(task) = worker.as_mut() {
            let _ = task.await;
        }
        worker.take();
    }
}

impl Drop for MdnsBridge {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut worker) = self.worker.try_lock() {
            if let Some(task) = worker.take() {
                task.abort();
            }
        }
    }
}

impl integration::MdnsSnapshot for MdnsBridge {
    fn snapshot(&self) -> Arc<integration::MdnsDiscoverySnapshot> {
        self.core.discovery_snapshot()
    }

    fn watch_snapshot(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<integration::MdnsDiscoverySnapshot>> {
        self.core.watch_discovery()
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
        let result = self
            .runtime
            .resolve_local(name, RecordType::A)
            .or_else(|| self.runtime.resolve_local(name, RecordType::AAAA));
        result.map(|r| r.ips)
    }
}

// ── AcmeDnsBridge ──────────────────────────────────────────────────

/// Bridges certmesh's ACME `dns-01` validation to the DNS core's ephemeral TXT
/// store. certmesh holds an `Arc<dyn AcmeDnsResolver>` and never imports koi-dns;
/// the binary wires this bridge (same pattern as `DnsBridge`).
pub struct AcmeDnsBridge {
    runtime: Arc<koi_dns::DnsRuntime>,
}

impl AcmeDnsBridge {
    pub fn new(runtime: Arc<koi_dns::DnsRuntime>) -> Arc<Self> {
        Arc::new(Self { runtime })
    }
}

impl integration::AcmeDnsResolver for AcmeDnsBridge {
    fn get_txt(&self, name: &str) -> Vec<String> {
        self.runtime.get_txt(name)
    }
}

// ── ProxyBridge ────────────────────────────────────────────────────

pub struct ProxyBridge {
    runtime: Arc<koi_proxy::ProxyRuntime>,
}

impl ProxyBridge {
    pub fn new(runtime: Arc<koi_proxy::ProxyRuntime>) -> Arc<Self> {
        Arc::new(Self { runtime })
    }
}

impl integration::ProxySnapshot for ProxyBridge {
    fn snapshot(&self) -> Arc<integration::ProxyEntriesSnapshot> {
        self.runtime.entries_snapshot()
    }

    fn watch_snapshot(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<integration::ProxyEntriesSnapshot>> {
        self.runtime.watch_entries()
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

#[async_trait::async_trait]
impl integration::AliasFeedback for AliasFeedbackBridge {
    async fn record_alias(
        &self,
        hostname: &str,
        alias: &str,
    ) -> Result<(), integration::AliasFeedbackError> {
        match self
            .core
            .add_alias_sans(hostname, &[alias.to_string()])
            .await
        {
            Ok(_) | Err(koi_certmesh::CertmeshError::NotFound(_)) => Ok(()),
            Err(error) => Err(integration::AliasFeedbackError(error.to_string())),
        }
    }
}

// ── mDNS browse warmth ─────────────────────────────────────────────

async fn keep_discovery_warm(core: Arc<koi_mdns::MdnsCore>, cancel: CancellationToken) {
    let meta = match core.subscribe_type(META_QUERY).await {
        Ok(meta) => meta,
        Err(error) => {
            tracing::warn!(%error, "could not arm the mDNS meta-browse");
            return;
        }
    };
    let mut status = core.watch_discovery();
    let mut type_browses = HashMap::<String, koi_mdns::BrowseSubscription>::new();
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
    retry.tick().await;

    loop {
        let desired = status
            .borrow_and_update()
            .service_types
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        type_browses.retain(|service_type, _| desired.contains(service_type));
        for service_type in desired {
            if type_browses.contains_key(&service_type) {
                continue;
            }
            match core.subscribe_type(&service_type).await {
                Ok(handle) => {
                    type_browses.insert(service_type, handle);
                }
                Err(error) => {
                    tracing::debug!(%service_type, %error, "mDNS type browse will retry");
                }
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = status.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = retry.tick() => {}
        }
    }

    drop(type_browses);
    drop(meta);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn alias_feedback_acknowledges_hosts_outside_the_certmesh_roster() {
        let paths = koi_certmesh::CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-compose-alias-feedback-tests").join(format!(
                "unknown-host-{}",
                koi_common::id::generate_short_id()
            )),
        );
        let bridge = AliasFeedbackBridge::new(Arc::new(
            koi_certmesh::CertmeshCore::uninitialized_with_paths(paths),
        ));

        integration::AliasFeedback::record_alias(
            bridge.as_ref(),
            "discovered-lan-host",
            "http.internal",
        )
        .await
        .expect("an unknown LAN host is not retryable certmesh work");
    }
}
