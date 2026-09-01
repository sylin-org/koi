//! Adapter discovery boundary for the mDNS bounded context.
//!
//! An adapter answers every platform-specific availability question and opens
//! one native provider session. The control plane consumes evidence and never
//! reaches around this boundary to inspect processes, sockets, D-Bus, or APIs.

use std::sync::Arc;

pub use koi_common::mdns_protocol::{
    MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi, ProviderAvailability,
    ProviderSessionState,
};

use crate::provider::ProviderSession;
use crate::Result;

/// Static identity and maximum capability shape of one provider adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDescriptor {
    pub name: &'static str,
    pub priority: u16,
    pub api: ProviderApi,
    pub capabilities: MdnsCapabilities,
}

impl ProviderDescriptor {
    pub const fn new(
        name: &'static str,
        priority: u16,
        api: ProviderApi,
        capabilities: MdnsCapabilities,
    ) -> Self {
        Self {
            name,
            priority,
            api,
            capabilities,
        }
    }
}

/// Platform adapter consumed by Koi's internal mDNS control plane.
///
/// `assess` is read-only and must not activate or reconfigure an external
/// service. `open` returns only a real provider session backed by the described
/// native facility.
#[async_trait::async_trait]
pub trait MdnsAdapter: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    async fn assess(&self) -> MdnsProviderReport;
    async fn open(&self) -> Result<Arc<dyn ProviderSession>>;
}

pub(crate) fn failed_assessment(
    descriptor: ProviderDescriptor,
    availability: ProviderAvailability,
    detail: impl Into<String>,
) -> MdnsProviderReport {
    MdnsProviderReport {
        name: descriptor.name.to_string(),
        priority: descriptor.priority,
        api: descriptor.api,
        availability,
        installed: ProbeFact::Unknown,
        configured: ProbeFact::Unknown,
        running: ProbeFact::Unknown,
        capabilities: MdnsCapabilities::default(),
        session: None,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_flags_are_composable() {
        let publication = MdnsCapabilities {
            publish: true,
            withdraw: true,
            ..MdnsCapabilities::default()
        };
        let browse = MdnsCapabilities {
            continuous_browse: true,
            browse_resolves: true,
            ..MdnsCapabilities::default()
        };
        let combined = publication.union(browse);
        assert!(combined.supports(publication));
        assert!(combined.supports(browse));
        assert!(!combined.supports(MdnsCapabilities {
            explicit_address: true,
            ..MdnsCapabilities::default()
        }));
    }

    #[test]
    fn descriptor_is_the_single_static_identity() {
        let descriptor = ProviderDescriptor::new(
            "avahi",
            300,
            ProviderApi::SystemDbus,
            MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
        );
        assert_eq!(descriptor.name, "avahi");
        assert!(descriptor.capabilities.satisfies_provider_contract());
    }
}
