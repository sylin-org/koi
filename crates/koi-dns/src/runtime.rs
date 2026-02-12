use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::resolver::{DnsCore, DnsError};

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DnsRuntimeStatus {
    pub running: bool,
}

struct RuntimeState {
    running: bool,
    cancel: Option<CancellationToken>,
}

/// Runtime controller for starting/stopping the DNS server task.
pub struct DnsRuntime {
    core: Arc<DnsCore>,
    state: Arc<tokio::sync::Mutex<RuntimeState>>,
}

impl DnsRuntime {
    pub fn new(core: DnsCore) -> Self {
        Self {
            core: Arc::new(core),
            state: Arc::new(tokio::sync::Mutex::new(RuntimeState {
                running: false,
                cancel: None,
            })),
        }
    }

    pub fn core(&self) -> Arc<DnsCore> {
        Arc::clone(&self.core)
    }

    pub async fn start(&self) -> Result<bool, DnsError> {
        let mut state = self.state.lock().await;
        if state.running {
            return Ok(false);
        }

        let token = CancellationToken::new();
        state.cancel = Some(token.clone());
        state.running = true;
        drop(state);

        let core = Arc::clone(&self.core);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            if let Err(e) = core.serve(token).await {
                tracing::error!(error = %e, "DNS server stopped with error");
            }
            let mut guard = state.lock().await;
            guard.running = false;
            guard.cancel = None;
        });

        Ok(true)
    }

    pub async fn stop(&self) -> bool {
        let mut state = self.state.lock().await;
        if let Some(token) = state.cancel.take() {
            token.cancel();
            state.running = false;
            true
        } else {
            false
        }
    }

    pub async fn status(&self) -> DnsRuntimeStatus {
        let state = self.state.lock().await;
        DnsRuntimeStatus {
            running: state.running,
        }
    }
}

impl Clone for DnsRuntime {
    fn clone(&self) -> Self {
        Self {
            core: Arc::clone(&self.core),
            state: Arc::clone(&self.state),
        }
    }
}
