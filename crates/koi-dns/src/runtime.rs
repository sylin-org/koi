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
/// DNS-specific piece is binding the server before spawning its loop.
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
        self.inner
            .start(move |token| async move {
                // Bind both sockets before the caller receives success. A port conflict is
                // therefore an explicit, retryable start error rather than a background log
                // followed by a briefly dishonest `running=true` status.
                let server = core.bind_server().await?;
                Ok::<_, DnsError>(tokio::spawn(async move {
                    if let Err(e) = server.serve(token).await {
                        tracing::error!(error = %e, "DNS server stopped with error");
                    }
                }))
            })
            .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn bind_failure_is_reported_stopped_and_can_be_retried() {
        let blocker = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = blocker.local_addr().unwrap().port();
        let core = DnsCore::new(
            crate::DnsConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                state_path: Some(std::env::temp_dir().join(format!(
                    "koi-dns-runtime-{}-{port}.json",
                    std::process::id()
                ))),
                ..Default::default()
            },
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let runtime = DnsRuntime::new(core);

        assert!(matches!(runtime.start().await, Err(DnsError::Bind(_))));
        assert!(!runtime.status().await.running);

        drop(blocker);
        assert!(runtime.start().await.unwrap());
        assert!(runtime.status().await.running);
        assert!(runtime.stop().await);
    }
}
