//! Platform mDNS composition.
//!
//! This root names the adapters compiled for the target and hands them to the
//! bounded context. Detection, capability evidence, selection, hysteresis,
//! transition ordering, and fallback all remain inside `koi-mdns`.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use koi_mdns::adapter::MdnsAdapter;
use koi_mdns::{MdnsCore, Result};

/// Build the stable mDNS control plane around the live provider catalog.
pub async fn build_core(cancel: CancellationToken) -> Result<MdnsCore> {
    let core = MdnsCore::with_adapters(platform_adapters(), cancel).await?;
    let selected = core.control_plane_status();
    tracing::info!(
        publish = ?selected.routes.publish,
        browse = ?selected.routes.browse,
        resolve = ?selected.routes.resolve,
        "mDNS control-plane routes armed"
    );
    Ok(core)
}

fn platform_adapters() -> Vec<Arc<dyn MdnsAdapter>> {
    #[allow(unused_mut)]
    let mut adapters: Vec<Arc<dyn MdnsAdapter>> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        adapters.push(Arc::new(koi_mdns::avahi::AvahiAdapter));
        adapters.push(Arc::new(koi_mdns::systemd_resolved::SystemdResolvedAdapter));
    }

    // The control plane appends Koi's native provider at the lowest priority on
    // every platform. The Windows adapters join this catalog ahead of it; each
    // one's assessment decides what it actually contributes.
    #[cfg(target_os = "windows")]
    {
        adapters.push(Arc::new(koi_mdns::windows_dnsapi::WindowsDnsSdAdapter));
        adapters.push(Arc::new(koi_mdns::windows_bonjour::WindowsBonjourAdapter));
    }

    adapters
}
