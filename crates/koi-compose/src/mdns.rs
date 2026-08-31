//! Platform mDNS bootstrap policy.
//!
//! The composition root probes once and injects exactly one provider into the
//! domain core. A selected provider owns its own recovery; Koi never switches
//! engines mid-process or arms native mDNS beside a present-but-broken Avahi.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use koi_mdns::native::NativeMdnsProvider;
use koi_mdns::provider::MdnsProvider;
use koi_mdns::{MdnsCore, Result};
#[cfg(target_os = "linux")]
use koi_mdns::{MdnsError, MDNS_PORT};

/// Build an mDNS core with the one provider appropriate for this boot.
pub async fn build_core(cancel: CancellationToken) -> Result<MdnsCore> {
    let provider = select_provider().await?;
    let selected = provider.status();
    tracing::info!(
        provider = selected.name,
        detail = %selected.detail,
        "mDNS provider armed"
    );
    MdnsCore::with_provider(provider, cancel)
}

async fn select_provider() -> Result<Arc<dyn MdnsProvider>> {
    #[cfg(target_os = "linux")]
    {
        use koi_mdns::avahi::{AvahiMdnsProvider, AvahiProbe};

        match AvahiMdnsProvider::probe().await {
            AvahiProbe::Ready(provider) => return Ok(Arc::new(provider)),
            AvahiProbe::Unavailable(reason) => {
                return Err(MdnsError::Daemon(format!(
                    "Avahi is present but unavailable; refusing to arm a second mDNS responder: {reason}"
                )));
            }
            AvahiProbe::Absent(reason) => {
                if !koi_mdns::udp_port_exclusively_free(MDNS_PORT) {
                    return Err(MdnsError::Daemon(format!(
                        "{reason}, but UDP {MDNS_PORT} is already held; refusing ambiguous native mDNS startup"
                    )));
                }
                tracing::info!(%reason, "Avahi absent; selecting Koi native mDNS");
            }
        }
    }

    Ok(Arc::new(NativeMdnsProvider::new()?))
}
