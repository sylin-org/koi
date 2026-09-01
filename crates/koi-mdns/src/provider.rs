//! Native-provider session ports for the mDNS bounded context.
//!
//! These contracts model owned, acknowledged resources. The application control
//! plane uses them; domain registration and discovery state never live here.

use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::{mpsc, watch};

use koi_common::mdns_protocol::{MdnsCapabilities, ProviderSessionState};

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
}

impl ProviderBrowse {
    pub fn new(events: mpsc::Receiver<ProviderEvent>, lease: Box<dyn BrowseLease>) -> Self {
        Self {
            events,
            lease: Some(lease),
        }
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
            "direct resolution is not implemented by this session",
        ))
    }

    /// Return only after every native resource has been released.
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
