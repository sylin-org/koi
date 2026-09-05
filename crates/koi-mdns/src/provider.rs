//! Native-provider session ports for the mDNS bounded context.
//!
//! These contracts model owned, acknowledged resources. The application control
//! plane uses them; domain registration and discovery state never live here.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use koi_common::mdns_protocol::{MdnsCapabilities, ProviderSessionState};
use koi_common::types::{ServiceType, META_QUERY};

use crate::adapter::ProviderDescriptor;
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::Result;

/// Provider-neutral announcement desired by one registry registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub id: String,
    pub name: String,
    pub service_type: String,
    pub port: u16,
    pub address: Option<IpAddr>,
    pub txt: HashMap<String, String>,
}

/// One address observed for a resolved service, including interface identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAddress {
    pub address: IpAddr,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
}

/// Lossless provider-neutral resolved service data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderService {
    pub name: String,
    pub service_type: String,
    pub host: Option<String>,
    pub addresses: Vec<ProviderAddress>,
    pub port: Option<u16>,
    pub txt: HashMap<String, String>,
}

/// Normalized observations emitted by every provider session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderEvent {
    Found(ProviderService),
    Resolved(ProviderService),
    Removed { name: String, service_type: String },
}

/// DNS-SD meaning of one PTR whose owner matches an active browse query.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum DnsSdPtr {
    ServiceType {
        service_type: String,
    },
    Instance {
        full_name: String,
        name: String,
        service_type: String,
    },
}

/// Admit one DNS-SD PTR at an adapter boundary.
///
/// A multicast callback can include records additional to the requested answer.
/// The record owner, not the callback batch, determines whether the PTR belongs
/// to this browse. The target then determines the service type: subtype queries
/// still point at the base service instance namespace.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn classify_dnssd_ptr(
    requested_query: &str,
    record_owner: &str,
    target: &str,
) -> Option<DnsSdPtr> {
    if !dns_name_eq(requested_query, record_owner) {
        return None;
    }
    if dns_name_eq(requested_query, META_QUERY) {
        return ServiceType::parse(target)
            .ok()
            .map(|service_type| DnsSdPtr::ServiceType {
                service_type: service_type.as_str().to_string(),
            });
    }
    ServiceType::parse_browse(requested_query).ok()?;
    let (name, service_type) = parse_service_instance_name(target)?;
    Some(DnsSdPtr::Instance {
        full_name: target.to_string(),
        name,
        service_type,
    })
}

pub(crate) fn dns_name_eq(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

/// Parse the presentation form of `<Instance>.<Service>.<Domain>` while
/// preserving escaped dots as part of the single instance label.
pub(crate) fn parse_service_instance_name(value: &str) -> Option<(String, String)> {
    let labels = split_presentation_labels(value.trim_end_matches('.'))?;
    if labels.len() != 4 || !labels[3].eq_ignore_ascii_case("local") {
        return None;
    }
    let service_name = format!("{}.{}.local.", labels[1], labels[2]);
    let service_type = ServiceType::parse(&service_name).ok()?.as_str().to_string();
    let name = unescape_dns_label(labels[0])?;
    (!name.is_empty()).then_some((name, service_type))
}

fn split_presentation_labels(value: &str) -> Option<Vec<&str>> {
    if value.is_empty() {
        return None;
    }
    let bytes = value.as_bytes();
    let mut labels = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                cursor += 1;
                if cursor >= bytes.len() {
                    return None;
                }
                cursor += 1;
            }
            b'.' => {
                if cursor == start {
                    return None;
                }
                labels.push(&value[start..cursor]);
                cursor += 1;
                start = cursor;
            }
            _ => cursor += 1,
        }
    }
    if start == bytes.len() {
        return None;
    }
    labels.push(&value[start..]);
    Some(labels)
}

fn unescape_dns_label(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'\\' {
            decoded.push(bytes[cursor]);
            cursor += 1;
            continue;
        }
        cursor += 1;
        if cursor >= bytes.len() {
            return None;
        }
        if cursor + 2 < bytes.len() && bytes[cursor..cursor + 3].iter().all(u8::is_ascii_digit) {
            let value = std::str::from_utf8(&bytes[cursor..cursor + 3])
                .ok()?
                .parse::<u16>()
                .ok()?;
            if value > u8::MAX.into() {
                return None;
            }
            decoded.push(value as u8);
            cursor += 3;
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// Ownership token for one established native publication.
#[async_trait::async_trait]
pub trait PublicationLease: Send {
    fn announcement_id(&self) -> &str;
    fn provider_name(&self) -> &'static str;
    async fn withdraw(&mut self) -> Result<()>;
}

/// Ownership token for one native browse resource.
#[async_trait::async_trait]
pub trait BrowseLease: Send {
    fn provider_name(&self) -> &'static str;
    async fn close(&mut self) -> Result<()>;
}

/// Event receiver paired with the native resource that produces it.
pub struct ProviderBrowse {
    events: mpsc::Receiver<ProviderEvent>,
    lease: Option<Box<dyn BrowseLease>>,
    source: ProviderBrowseSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderBrowseSource {
    pub provider: String,
    pub generation: u64,
}

/// Exclusive owner for one asynchronous provider worker.
///
/// Joining borrows the handle in place. If the caller's shutdown future is
/// cancelled, the handle therefore remains owned and a later shutdown can
/// finish the same barrier. A timed-out task is asked to abort but also stays
/// owned: this matters for `spawn_blocking` workers, where abort is only a
/// request and the native cancellation signal must be allowed to finish.
pub(crate) struct ProviderTask {
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl ProviderTask {
    pub(crate) fn new(task: JoinHandle<()>) -> Self {
        Self {
            task: tokio::sync::Mutex::new(Some(task)),
        }
    }

    pub(crate) async fn join(&self, wait: Duration) -> std::result::Result<(), String> {
        let mut slot = self.task.lock().await;
        let Some(task) = slot.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(wait, &mut *task).await {
            Ok(Ok(())) => {
                slot.take();
                Ok(())
            }
            Ok(Err(error)) if error.is_cancelled() => {
                slot.take();
                Ok(())
            }
            Ok(Err(error)) => {
                slot.take();
                Err(format!("worker failed: {error}"))
            }
            Err(_) => {
                // Normal async workers stop promptly. A blocking worker cannot
                // be force-stopped after it starts, so retain its handle for a
                // later acknowledgement instead of silently detaching it.
                task.abort();
                Err(format!("worker completion exceeded {wait:?}"))
            }
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) async fn is_reaped(&self) -> bool {
        self.task.lock().await.is_none()
    }

    pub(crate) fn abort(&self) {
        if let Ok(slot) = self.task.try_lock() {
            if let Some(task) = slot.as_ref() {
                task.abort();
            }
        }
    }
}

impl Drop for ProviderTask {
    fn drop(&mut self) {
        if let Ok(slot) = self.task.try_lock() {
            if let Some(task) = slot.as_ref() {
                task.abort();
            }
        }
    }
}

impl ProviderBrowse {
    pub fn new(events: mpsc::Receiver<ProviderEvent>, lease: Box<dyn BrowseLease>) -> Self {
        let provider = lease.provider_name().to_string();
        Self {
            events,
            lease: Some(lease),
            source: ProviderBrowseSource {
                provider,
                generation: 0,
            },
        }
    }

    pub(crate) fn with_source(mut self, provider: impl Into<String>, generation: u64) -> Self {
        self.source = ProviderBrowseSource {
            provider: provider.into(),
            generation,
        };
        self
    }

    pub(crate) fn source(&self) -> &ProviderBrowseSource {
        &self.source
    }

    pub async fn recv(&mut self) -> Option<ProviderEvent> {
        self.events.recv().await
    }

    pub async fn close(mut self) -> Result<()> {
        match self.lease.take() {
            Some(mut lease) => lease.close().await,
            None => Ok(()),
        }
    }
}

/// One opened provider epoch. It owns native resources and their recovery.
#[async_trait::async_trait]
pub trait ProviderSession: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    fn capabilities(&self) -> MdnsCapabilities;
    fn state(&self) -> watch::Receiver<ProviderSessionState>;

    /// Return only after a real native publication exists.
    async fn publish(&self, announcement: &Announcement) -> Result<Box<dyn PublicationLease>>;

    /// Return only after a real native browser exists.
    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse>;

    async fn resolve(&self, _name: &str, _service_type: &str) -> Result<ProviderService> {
        let descriptor = self.descriptor();
        Err(provider_error(
            descriptor.name,
            ProviderOperation::Resolve,
            ProviderFailure::Unavailable,
            "provider session does not advertise direct resolution",
        ))
    }

    /// Return only after every native resource is released or, following
    /// confirmed provider death, its owner and callback context are safely
    /// quarantined from the next provider generation.
    async fn shutdown(&self) -> Result<()>;
}

pub(crate) fn provider_error(
    provider: impl Into<String>,
    operation: ProviderOperation,
    failure: ProviderFailure,
    detail: impl Into<String>,
) -> MdnsError {
    MdnsError::Provider {
        provider: provider.into(),
        operation,
        failure,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use koi_common::types::META_QUERY;
    use tokio::sync::Notify;

    use super::{classify_dnssd_ptr, dns_name_eq, DnsSdPtr, ProviderTask};

    #[derive(Clone, Copy)]
    enum FixtureRecord<'a> {
        Ptr { owner: &'a str, target: &'a str },
        Srv,
        Txt,
        A,
        Aaaa,
    }

    fn ptrs_for_query(query: &str, records: &[FixtureRecord<'_>]) -> Vec<DnsSdPtr> {
        records
            .iter()
            .filter_map(|record| match record {
                FixtureRecord::Ptr { owner, target } => classify_dnssd_ptr(query, owner, target),
                FixtureRecord::Srv
                | FixtureRecord::Txt
                | FixtureRecord::A
                | FixtureRecord::Aaaa => None,
            })
            .collect()
    }

    #[test]
    fn mixed_meta_response_admits_only_service_enumeration_ptrs() {
        let records = [
            FixtureRecord::Ptr {
                owner: "_SERVICES._DNS-SD._UDP.LOCAL",
                target: "_UnKnOwN._TcP.LoCaL.",
            },
            FixtureRecord::Ptr {
                owner: "_unknown._tcp.local.",
                target: r"Living\032Room\.Display._unknown._tcp.local.",
            },
            FixtureRecord::Ptr {
                owner: "speaker.local.",
                target: "elsewhere.local.",
            },
            FixtureRecord::Srv,
            FixtureRecord::Txt,
            FixtureRecord::A,
            FixtureRecord::Aaaa,
        ];

        assert_eq!(
            ptrs_for_query(META_QUERY, &records),
            vec![DnsSdPtr::ServiceType {
                service_type: "_unknown._tcp.local.".to_string(),
            }]
        );
    }

    #[test]
    fn ordinary_and_subtype_browses_use_owner_and_target_semantics() {
        let unrelated = classify_dnssd_ptr(
            "_http._tcp.local.",
            "_ipp._tcp.local.",
            "Printer._ipp._tcp.local.",
        );
        assert!(unrelated.is_none());

        assert_eq!(
            classify_dnssd_ptr(
                "_Printer._SUB._HTTP._TCP.LOCAL",
                "_printer._sub._http._tcp.local.",
                r"A\. printer\\desk._HTTP._TCP.local.",
            ),
            Some(DnsSdPtr::Instance {
                full_name: r"A\. printer\\desk._HTTP._TCP.local.".to_string(),
                name: "A. printer\\desk".to_string(),
                service_type: "_http._tcp.local.".to_string(),
            })
        );
    }

    #[test]
    fn dns_name_comparison_is_ascii_case_and_trailing_dot_insensitive() {
        assert!(dns_name_eq("_HTTP._TCP.LOCAL", "_http._tcp.local."));
        assert!(!dns_name_eq("_http._tcp.local.", "host.local."));
    }

    #[tokio::test]
    async fn provider_task_join_is_cancellation_safe() {
        let release = Arc::new(Notify::new());
        let task_release = Arc::clone(&release);
        let owner = Arc::new(ProviderTask::new(tokio::spawn(async move {
            task_release.notified().await;
        })));

        let joining = {
            let owner = Arc::clone(&owner);
            tokio::spawn(async move { owner.join(Duration::from_secs(5)).await })
        };
        tokio::task::yield_now().await;
        joining.abort();
        joining.await.expect_err("cancel the first shutdown waiter");

        release.notify_one();
        owner
            .join(Duration::from_secs(1))
            .await
            .expect("the retained worker is still joinable");
    }

    #[tokio::test]
    async fn dropping_provider_task_aborts_async_worker() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let owner = ProviderTask::new(tokio::spawn(async move {
            let _guard = Dropped(task_dropped);
            std::future::pending::<()>().await;
        }));
        tokio::task::yield_now().await;
        drop(owner);
        for _ in 0..16 {
            if dropped.load(Ordering::Acquire) {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(dropped.load(Ordering::Acquire), "worker was not aborted");
    }

    #[tokio::test]
    async fn timed_out_worker_remains_owned_until_abort_is_reaped() {
        let owner = ProviderTask::new(tokio::spawn(std::future::pending::<()>()));

        assert!(owner.join(Duration::from_millis(1)).await.is_err());
        owner
            .join(Duration::from_secs(1))
            .await
            .expect("the timeout-requested abort is explicitly reaped");
        assert!(owner.is_reaped().await);
    }
}
