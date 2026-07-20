//! Shared start/stop runtime state machine for domain background loops.
//!
//! Several domains (DNS, health) wrap a core in a controller that can start a single
//! background loop, stop it via a [`CancellationToken`], and report whether it is running.
//! That ~80-line `Mutex<RuntimeState{running, cancel}>` machine was duplicated verbatim;
//! [`DomainRuntime`] is the one copy.
//!
//! Lifecycles that are *not* a single start/stop loop (proxy's per-entry listeners, udp's
//! reaper-on-construction, the runtime adapter's external-token watcher) are deliberately
//! left bespoke — forcing them onto this would distort their semantics.
//!
//! ## `running` flag semantics (matches the hand-written DNS/health machines exactly)
//!
//! - [`start`](DomainRuntime::start) awaits the domain's fallible launcher, then sets
//!   `running = true` and stores the cancel token only after startup succeeds.
//! - When the spawned loop finishes on its own, a watcher flips `running = false` and clears
//!   the token. A generation guard prevents an older loop's completion from clobbering a
//!   replacement started after stop/restart.
//! - [`stop`](DomainRuntime::stop) cancels the token and sets `running = false` immediately
//!   (it does not wait for the loop to wind down), again matching the old behaviour.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Snapshot of a [`DomainRuntime`]'s state.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RuntimeStatus {
    pub running: bool,
}

struct State {
    running: bool,
    cancel: Option<CancellationToken>,
    generation: u64,
}

/// A start/stop controller around a shared core `C`.
///
/// `C` is the domain core the loop operates on; it is held as an `Arc<C>` so the controller
/// can hand it to the spawned loop and to [`core`](Self::core) callers.
pub struct DomainRuntime<C> {
    core: Arc<C>,
    state: Arc<Mutex<State>>,
}

impl<C> Clone for DomainRuntime<C> {
    fn clone(&self) -> Self {
        Self {
            core: Arc::clone(&self.core),
            state: Arc::clone(&self.state),
        }
    }
}

impl<C> DomainRuntime<C> {
    /// Wrap a core. The controller starts in the stopped state.
    pub fn new(core: Arc<C>) -> Self {
        Self {
            core,
            state: Arc::new(Mutex::new(State {
                running: false,
                cancel: None,
                generation: 0,
            })),
        }
    }

    /// The shared core.
    pub fn core(&self) -> Arc<C> {
        Arc::clone(&self.core)
    }

    /// Start the background loop.
    ///
    /// `mk` is called with a fresh [`CancellationToken`] and must prepare and spawn the
    /// domain loop. The launcher is asynchronous so a domain can acquire resources (for
    /// example, bind sockets) before reporting success. A launcher error leaves the runtime
    /// stopped and retryable. On success a watcher flips `running` back to `false` when the
    /// loop finishes. Returns `Ok(false)` (a no-op) if already running.
    pub async fn start<F, Fut, E>(&self, mk: F) -> Result<bool, E>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: std::future::Future<Output = Result<JoinHandle<()>, E>>,
    {
        let mut state = self.state.lock().await;
        if state.running {
            return Ok(false);
        }

        let token = CancellationToken::new();
        let handle = mk(token.clone()).await?;
        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        state.cancel = Some(token);
        state.running = true;
        drop(state);

        // Watcher: when the loop's handle finishes (cancelled or done), clear running/cancel
        // exactly as the old hand-written machines did at the tail of their spawned task.
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let _ = handle.await;
            let mut guard = state.lock().await;
            if guard.generation == generation {
                guard.running = false;
                guard.cancel = None;
            }
        });

        Ok(true)
    }

    /// Stop the background loop by cancelling its token.
    ///
    /// Returns `true` if a token was present (i.e. the loop was running), `false` otherwise.
    /// Marks `running = false` immediately without waiting for the loop to wind down.
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

    /// Current running state.
    pub async fn status(&self) -> RuntimeStatus {
        let state = self.state.lock().await;
        RuntimeStatus {
            running: state.running,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    struct Core;

    async fn never_ending(token: CancellationToken) -> Result<JoinHandle<()>, &'static str> {
        Ok(tokio::spawn(async move {
            token.cancelled().await;
        }))
    }

    #[tokio::test]
    async fn start_then_status_running() {
        let rt = DomainRuntime::new(Arc::new(Core));
        assert!(!rt.status().await.running);

        let started = rt.start(never_ending).await.unwrap();
        assert!(started);
        assert!(rt.status().await.running);
    }

    #[tokio::test]
    async fn double_start_is_noop() {
        let rt = DomainRuntime::new(Arc::new(Core));
        assert!(rt.start(never_ending).await.unwrap());
        // Second start while running returns Ok(false) and does not spawn another loop.
        assert!(!rt.start(never_ending).await.unwrap());
        assert!(rt.status().await.running);
    }

    #[tokio::test]
    async fn stop_clears_running() {
        let rt = DomainRuntime::new(Arc::new(Core));
        rt.start(never_ending).await.unwrap();
        assert!(rt.stop().await);
        assert!(!rt.status().await.running);
        // Stopping again with no live loop returns false.
        assert!(!rt.stop().await);
    }

    #[tokio::test]
    async fn watcher_flips_running_when_loop_finishes() {
        let rt = DomainRuntime::new(Arc::new(Core));
        // A loop that returns immediately; the watcher should flip running=false.
        rt.start(|_token| async { Ok::<_, &'static str>(tokio::spawn(async {})) })
            .await
            .unwrap();
        // Give the watcher a chance to observe completion.
        for _ in 0..50 {
            if !rt.status().await.running {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!rt.status().await.running);
    }

    #[tokio::test]
    async fn failed_launcher_leaves_runtime_stopped_and_retryable() {
        let rt = DomainRuntime::new(Arc::new(Core));
        let failed = rt
            .start(|_token| async { Err::<JoinHandle<()>, _>("bind failed") })
            .await;
        assert_eq!(failed, Err("bind failed"));
        assert!(!rt.status().await.running);
        assert!(rt.start(never_ending).await.unwrap());
        assert!(rt.status().await.running);
    }

    #[tokio::test]
    async fn stale_loop_completion_cannot_stop_its_replacement() {
        let rt = DomainRuntime::new(Arc::new(Core));
        let (release_tx, release_rx) = oneshot::channel();
        rt.start(|token| async move {
            Ok::<_, &'static str>(tokio::spawn(async move {
                token.cancelled().await;
                let _ = release_rx.await;
            }))
        })
        .await
        .unwrap();
        assert!(rt.stop().await);
        assert!(rt.start(never_ending).await.unwrap());
        release_tx.send(()).unwrap();
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(rt.status().await.running);
    }
}
