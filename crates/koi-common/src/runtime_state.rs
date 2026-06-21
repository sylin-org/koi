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
//! - [`start`](DomainRuntime::start) sets `running = true` *synchronously* (before returning)
//!   and stores the cancel token.
//! - When the spawned loop finishes on its own, a watcher flips `running = false` and clears
//!   the token — identical to the old machines, which appended that cleanup after the loop.
//! - [`stop`](DomainRuntime::stop) cancels the token and sets `running = false` immediately
//!   (it does not wait for the loop to wind down), again matching the old behaviour.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Returned by [`DomainRuntime::start`] when the loop is already running.
///
/// `start` returns `Ok(false)` for the already-running case rather than this error, so the
/// type exists mainly to give callers a typed, infallible-to-construct marker; the generic
/// `start` never actually yields it today but keeps the door open for fallible launchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyRunning;

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("runtime is already running")
    }
}

impl std::error::Error for AlreadyRunning {}

/// Snapshot of a [`DomainRuntime`]'s state.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RuntimeStatus {
    pub running: bool,
}

struct State {
    running: bool,
    cancel: Option<CancellationToken>,
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
            })),
        }
    }

    /// The shared core.
    pub fn core(&self) -> Arc<C> {
        Arc::clone(&self.core)
    }

    /// Start the background loop.
    ///
    /// `mk` is called with a fresh [`CancellationToken`] and must spawn the domain loop,
    /// returning its [`JoinHandle`]. On success the controller marks itself running and
    /// stores the token; a watcher task flips `running` back to `false` when the loop's
    /// handle completes. Returns `Ok(false)` (a no-op) if already running.
    pub async fn start<F>(&self, mk: F) -> Result<bool, AlreadyRunning>
    where
        F: FnOnce(CancellationToken) -> JoinHandle<()>,
    {
        let mut state = self.state.lock().await;
        if state.running {
            return Ok(false);
        }

        let token = CancellationToken::new();
        let handle = mk(token.clone());
        state.cancel = Some(token);
        state.running = true;
        drop(state);

        // Watcher: when the loop's handle finishes (cancelled or done), clear running/cancel
        // exactly as the old hand-written machines did at the tail of their spawned task.
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let _ = handle.await;
            let mut guard = state.lock().await;
            guard.running = false;
            guard.cancel = None;
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

    struct Core;

    fn never_ending(token: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            token.cancelled().await;
        })
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
        rt.start(|_token| tokio::spawn(async {})).await.unwrap();
        // Give the watcher a chance to observe completion.
        for _ in 0..50 {
            if !rt.status().await.running {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!rt.status().await.running);
    }

    #[test]
    fn already_running_display() {
        assert_eq!(AlreadyRunning.to_string(), "runtime is already running");
    }
}
