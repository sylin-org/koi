use std::sync::Arc;

use koi_common::runtime_state::DomainRuntime;

use crate::resolver::{DnsCore, DnsError};

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DnsRuntimeStatus {
    pub running: bool,
}

/// Runtime controller for starting/stopping the DNS server task.
///
/// A thin wrapper over the shared [`DomainRuntime`] start/stop machine; the only
/// DNS-specific piece is the spawned loop (`core.serve(token)`).
#[derive(Clone)]
pub struct DnsRuntime {
    inner: DomainRuntime<DnsCore>,
}

impl DnsRuntime {
    pub fn new(core: DnsCore) -> Self {
        Self {
            inner: DomainRuntime::new(Arc::new(core)),
        }
    }

    pub fn core(&self) -> Arc<DnsCore> {
        self.inner.core()
    }

    pub async fn start(&self) -> Result<bool, DnsError> {
        let core = self.inner.core();
        // DomainRuntime::start signals already-running via Ok(false) and never yields
        // AlreadyRunning for this launcher; map that to a started=false no-op. The
        // Result<_, DnsError> shape is preserved (this start path cannot fail).
        let started = self
            .inner
            .start(move |token| {
                tokio::spawn(async move {
                    if let Err(e) = core.serve(token).await {
                        tracing::error!(error = %e, "DNS server stopped with error");
                    }
                })
            })
            .await
            .unwrap_or(false);
        Ok(started)
    }

    pub async fn stop(&self) -> bool {
        self.inner.stop().await
    }

    pub async fn status(&self) -> DnsRuntimeStatus {
        DnsRuntimeStatus {
            running: self.inner.status().await.running,
        }
    }
}
