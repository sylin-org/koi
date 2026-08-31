//! Platform mDNS composition.
//!
//! This root names the adapters compiled for the target and hands them to the
//! bounded context. Detection, capability evidence, selection, hysteresis,
//! transition ordering, and fallback all remain inside `koi-mdns`.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use koi_mdns::adapter::MdnsAdapter;
use koi_mdns::supervisor::MdnsSupervisor;
use koi_mdns::{MdnsCore, Result};

/// Build the stable mDNS control plane around the live provider catalog.
pub async fn build_core(cancel: CancellationToken) -> Result<MdnsCore> {
    let supervisor = Arc::new(MdnsSupervisor::start(platform_adapters()).await?);
    let selected = koi_mdns::provider::MdnsProvider::status(supervisor.as_ref());
    tracing::info!(
        providers = %selected.name,
        detail = %selected.detail,
        "mDNS provider plan armed"
    );
    MdnsCore::with_provider(supervisor, cancel)
}

fn platform_adapters() -> Vec<Arc<dyn MdnsAdapter>> {
    #[allow(unused_mut)]
    let mut adapters: Vec<Arc<dyn MdnsAdapter>> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        adapters.push(Arc::new(koi_mdns::avahi::AvahiAdapter));
        adapters.push(Arc::new(koi_mdns::systemd_resolved::SystemdResolvedAdapter));
    }

    // The supervisor appends Koi's native provider at the lowest priority on
    // every platform. Windows system DNS-SD and Bonjour adapters join this
    // catalog in their target-specific modules; they do not replace the seam.
    adapters
}
