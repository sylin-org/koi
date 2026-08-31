//! Provider port for the mDNS bounded context.
//!
//! `MdnsCore` and the shared browse hub depend on this contract. Concrete
//! platform engines translate their native APIs into these value objects before
//! anything reaches domain state or a public transport.

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::mpsc;

use crate::adapter::{AdapterApi, MdnsCapabilities};
use crate::error::MdnsError;
use crate::Result;

/// One address observed for a resolved service, including the interface that
/// supplied it when the provider exposes that information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAddress {
    pub address: IpAddr,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
}

/// Provider-neutral resolved service data.
///
/// This deliberately retains every address and its interface identity. The
/// existing public `ServiceRecord::ip` remains a compatibility projection made
/// by the browse hub, not a limitation imposed on platform adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderService {
    pub name: String,
    pub service_type: String,
    pub host: Option<String>,
    pub addresses: Vec<ProviderAddress>,
    pub port: Option<u16>,
    pub txt: HashMap<String, String>,
}

/// Normalized observations emitted by every mDNS provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderEvent {
    Found(ProviderService),
    Resolved(ProviderService),
    Removed { name: String, service_type: String },
}

/// One provider-owned browse stream.
pub type ProviderBrowse = mpsc::Receiver<ProviderEvent>;

/// Operational state of the armed provider or capability-aware provider plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    pub name: String,
    pub healthy: bool,
    pub detail: String,
}

/// Outbound port used by Koi's mDNS domain.
///
/// Implementations own their socket/API handles and concurrency model. Method
/// success means the provider accepted the operation; domain leases, caches,
/// fan-out, and transport contracts remain the responsibility of `MdnsCore`
/// and its shared browse hub.
#[async_trait::async_trait]
pub trait MdnsProvider: Send + Sync {
    /// Stable provider name for diagnostics.
    fn name(&self) -> &'static str;

    /// Operations this armed provider actually implements.
    ///
    /// This is deliberately mandatory: an incomplete provider must never
    /// inherit a fictional full-capability declaration.
    fn capabilities(&self) -> MdnsCapabilities;

    /// Native API surface used by this provider.
    fn api(&self) -> AdapterApi;

    /// Current adapter health for the public capability status surface.
    /// Providers must supply real evidence rather than inherit optimistic state.
    fn status(&self) -> ProviderStatus;

    /// Publish a service through this provider.
    fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()>;

    /// Withdraw a previously published service.
    fn unregister(&self, name: &str, service_type: &str) -> Result<()>;

    /// Start a provider browse for one canonical service type.
    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse>;

    /// Resolve one service without opening a continuous browse. Providers that
    /// do not declare `direct_resolve` are never called through this operation.
    async fn resolve(&self, _name: &str, _service_type: &str) -> Result<ProviderService> {
        Err(MdnsError::Daemon(format!(
            "provider {} has no direct resolve operation",
            self.name()
        )))
    }

    /// Stop the provider browse for one canonical service type.
    fn stop_browse(&self, service_type: &str) -> Result<()>;

    /// Shut down this provider and release its resources.
    async fn shutdown(&self) -> Result<()>;
}
