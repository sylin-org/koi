use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::resolver::{DnsCore, DnsError};

const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const INTERFACE_PROBE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsRuntimeState {
    Stopped,
    Reconciling,
    Running,
    Waiting,
}

/// Rich desired-state projection for operators and adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct DnsRuntimeStatus {
    /// Backward-compatible convenience field.
    pub running: bool,
    pub desired: bool,
    pub state: DnsRuntimeState,
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl DnsRuntimeStatus {
    fn stopped() -> Self {
        Self {
            running: false,
            desired: false,
            state: DnsRuntimeState::Stopped,
            endpoints: Vec::new(),
            reason: None,
        }
    }
}

struct RunHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

/// Desired-state DNS listener controller.
///
/// A requested listener remains armed through address contention and interface
/// changes. Manual stop is the only operation that clears desire and retry.
#[derive(Clone)]
pub struct DnsRuntime {
    core: Arc<DnsCore>,
    status: Arc<RwLock<DnsRuntimeStatus>>,
    control: Arc<Mutex<Option<RunHandle>>>,
}

impl DnsRuntime {
    pub fn new(core: DnsCore) -> Self {
        Self {
            core: Arc::new(core),
            status: Arc::new(RwLock::new(DnsRuntimeStatus::stopped())),
            control: Arc::new(Mutex::new(None)),
        }
    }

    pub fn core(&self) -> Arc<DnsCore> {
        Arc::clone(&self.core)
    }

    /// Arm DNS serving. Success means the desired-state reconciler is live;
    /// inspect [`Self::status`] to distinguish running from waiting.
    pub async fn start(&self) -> Result<bool, DnsError> {
        let mut control = self.control.lock().await;
        if control.is_some() {
            return Ok(false);
        }

        set_status(
            &self.status,
            DnsRuntimeStatus {
                running: false,
                desired: true,
                state: DnsRuntimeState::Reconciling,
                endpoints: Vec::new(),
                reason: None,
            },
        )
        .await;

        let cancel = CancellationToken::new();
        let (initial_tx, initial_rx) = oneshot::channel();
        let task = tokio::spawn(reconcile(
            Arc::clone(&self.core),
            Arc::clone(&self.status),
            cancel.clone(),
            initial_tx,
        ));
        *control = Some(RunHandle { cancel, task });
        drop(control);

        initial_rx
            .await
            .map_err(|_| DnsError::Bind("DNS reconciler stopped during startup".to_string()))?;
        Ok(true)
    }

    pub async fn stop(&self) -> bool {
        let handle = self.control.lock().await.take();
        let Some(handle) = handle else {
            return false;
        };
        handle.cancel.cancel();
        let _ = handle.task.await;
        set_status(&self.status, DnsRuntimeStatus::stopped()).await;
        true
    }

    pub async fn status(&self) -> DnsRuntimeStatus {
        self.status.read().await.clone()
    }
}

async fn reconcile(
    core: Arc<DnsCore>,
    status: Arc<RwLock<DnsRuntimeStatus>>,
    cancel: CancellationToken,
    initial_tx: oneshot::Sender<()>,
) {
    let mut initial_tx = Some(initial_tx);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        set_status(
            &status,
            DnsRuntimeStatus {
                running: false,
                desired: true,
                state: DnsRuntimeState::Reconciling,
                endpoints: Vec::new(),
                reason: None,
            },
        )
        .await;

        match core.bind_server().await {
            Ok(server) => {
                let endpoints = server
                    .endpoints
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let reason = server.reason.clone();
                let observation = server.observation.clone();
                set_status(
                    &status,
                    DnsRuntimeStatus {
                        running: true,
                        desired: true,
                        state: DnsRuntimeState::Running,
                        endpoints,
                        reason,
                    },
                )
                .await;
                signal_initial(&mut initial_tx);

                let server_cancel = CancellationToken::new();
                let mut server_task = tokio::spawn(server.serve(server_cancel.clone()));
                let mut probe = tokio::time::interval(INTERFACE_PROBE_INTERVAL);
                let retry_reason = loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            server_cancel.cancel();
                            let _ = server_task.await;
                            return;
                        }
                        result = &mut server_task => {
                            break match result {
                                Ok(Ok(())) => "DNS listener ended unexpectedly".to_string(),
                                Ok(Err(error)) => error.to_string(),
                                Err(error) => format!("DNS listener task failed: {error}"),
                            };
                        }
                        _ = probe.tick() => {
                            if observation.changed().await {
                                server_cancel.cancel();
                                let _ = server_task.await;
                                break "network interfaces changed; rebuilding DNS listeners".to_string();
                            }
                        }
                    }
                };
                set_waiting(&status, retry_reason).await;
            }
            Err(error) => {
                set_waiting(&status, error.to_string()).await;
                signal_initial(&mut initial_tx);
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

async fn set_waiting(status: &RwLock<DnsRuntimeStatus>, reason: String) {
    set_status(
        status,
        DnsRuntimeStatus {
            running: false,
            desired: true,
            state: DnsRuntimeState::Waiting,
            endpoints: Vec::new(),
            reason: Some(reason),
        },
    )
    .await;
}

async fn set_status(status: &RwLock<DnsRuntimeStatus>, value: DnsRuntimeStatus) {
    *status.write().await = value;
}

fn signal_initial(sender: &mut Option<oneshot::Sender<()>>) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    async fn runtime_on(port: u16) -> DnsRuntime {
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
        DnsRuntime::new(core)
    }

    #[tokio::test]
    async fn contention_is_waiting_and_recovers_without_another_start() {
        let blocker = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = blocker.local_addr().unwrap().port();
        let runtime = runtime_on(port).await;

        assert!(runtime.start().await.unwrap());
        let waiting = runtime.status().await;
        assert_eq!(waiting.state, DnsRuntimeState::Waiting);
        assert!(waiting.desired);
        assert!(!waiting.running);

        drop(blocker);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if runtime.status().await.running {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("runtime should recover after the incumbent leaves");
        assert!(runtime.stop().await);
        assert_eq!(runtime.status().await.state, DnsRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn port_zero_reports_the_real_endpoint() {
        let runtime = runtime_on(0).await;
        assert!(runtime.start().await.unwrap());
        let status = runtime.status().await;
        assert_eq!(status.state, DnsRuntimeState::Running);
        assert_eq!(status.endpoints.len(), 1);
        assert!(!status.endpoints[0].ends_with(":0"));
        assert!(runtime.stop().await);
    }
}
