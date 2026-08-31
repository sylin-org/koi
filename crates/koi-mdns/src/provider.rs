//! Provider port for the mDNS bounded context.
//!
//! `MdnsCore` and the shared browse hub depend on this contract. Concrete
//! platform engines translate their native APIs into these value objects before
//! anything reaches domain state or a public transport.

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::mpsc;

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

/// Operational state of the one provider armed for this core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    pub name: &'static str,
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

    /// Current adapter health for the public capability status surface.
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            name: self.name(),
            healthy: true,
            detail: "ready".to_string(),
        }
    }

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

    /// Stop the provider browse for one canonical service type.
    fn stop_browse(&self, service_type: &str) -> Result<()>;

    /// Shut down this provider and release its resources.
    async fn shutdown(&self) -> Result<()>;
}
