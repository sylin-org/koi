//! Lease auto-heartbeat registry.
//!
//! `lan_announce` registers a service with a heartbeat lease. To keep that lease
//! alive while the MCP session runs, we spawn a background task per registration
//! that calls `heartbeat(id)` at roughly one third of the lease interval. The task
//! handle is tracked in [`Registry`] keyed by registration id so:
//!
//! - `lan_unregister` can cancel the heartbeat task before unregistering, and
//! - server shutdown can cancel every task and unregister every tracked id.
//!
//! If the agent (and therefore this process) crashes, the heartbeat tasks die with
//! it and the daemon drains the registration when the lease expires — leases over
//! liveness guesses (charter principle 7).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::source::KoiSource;

/// Lower bound on the heartbeat interval, so a tiny lease cannot create a
/// busy-loop of renewals.
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// Tracks the live heartbeat task for each announced registration id.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    tasks: HashMap<String, JoinHandle<()>>,
    /// Registrations whose heartbeat has stopped but whose best-effort explicit
    /// withdrawal has not yet returned. Retaining the id makes shutdown
    /// retryable when its own waiter is cancelled during the network call.
    pending_unregister: HashSet<String>,
}

impl RegistryInner {
    async fn stop_tasks(&self) {
        let mut state = self.state.lock().await;
        let ids = state.tasks.keys().cloned().collect::<Vec<_>>();
        state.pending_unregister.extend(ids);
        for task in state.tasks.values() {
            task.abort();
        }
        while let Some(id) = state.tasks.keys().next().cloned() {
            let task = state
                .tasks
                .get_mut(&id)
                .expect("selected heartbeat remains owned");
            let _ = (&mut *task).await;
            state.tasks.remove(&id);
        }
    }

    async fn pending_unregister(&self) -> Vec<String> {
        self.state
            .lock()
            .await
            .pending_unregister
            .iter()
            .cloned()
            .collect()
    }

    async fn settle_unregister(&self, id: &str) {
        self.state.lock().await.pending_unregister.remove(id);
    }
}

impl Drop for RegistryInner {
    fn drop(&mut self) {
        // HTTP sessions may disappear without an async shutdown callback. Stop
        // renewing immediately; the daemon-owned lease then expires even when
        // graceful unregister could not run.
        for task in self.state.get_mut().tasks.values() {
            task.abort();
        }
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a heartbeat task for `id` that renews the lease at ~1/3 of
    /// `lease_secs`, and record its handle. Replaces (and aborts) any prior task
    /// for the same id. Renewal goes through the [`KoiSource`] so it works for
    /// both the stdio client and the in-process cores.
    pub async fn track<S: KoiSource>(&self, source: &Arc<S>, id: String, lease_secs: u64) {
        let interval = heartbeat_interval(lease_secs);
        let task = spawn_heartbeat(Arc::clone(source), id.clone(), interval);
        let previous = {
            let mut state = self.inner.state.lock().await;
            state.pending_unregister.remove(&id);
            state.tasks.insert(id, task)
        };
        if let Some(previous) = previous {
            abort_and_reap(previous).await;
        }
    }

    /// Stop tracking `id`, aborting its heartbeat task. Returns `true` if a task
    /// was being tracked.
    pub async fn untrack(&self, id: &str) -> bool {
        let task = {
            let mut state = self.inner.state.lock().await;
            state.pending_unregister.remove(id);
            state.tasks.remove(id)
        };
        match task {
            Some(task) => {
                abort_and_reap(task).await;
                true
            }
            None => false,
        }
    }

    /// Cancel every heartbeat task and best-effort unregister every tracked id.
    /// Called on server shutdown so no announced service is left to go stale.
    pub async fn shutdown<S: KoiSource>(&self, source: &Arc<S>) {
        // Abort every renewal before the first await, then retain each handle in
        // the registry until its abort is reaped. If this shutdown waiter is
        // cancelled, a later waiter (or RegistryInner::drop) still owns all
        // unfinished tasks; no detached heartbeat can renew a dead session.
        self.inner.stop_tasks().await;
        for id in self.inner.pending_unregister().await {
            if let Err(e) = source.unregister(id.clone()).await {
                tracing::warn!(id = %id, error = %e, "failed to unregister on shutdown");
            } else {
                tracing::debug!(id = %id, "unregistered on shutdown");
            }
            // Success and an explicit failure are both settled best-effort
            // outcomes. Cancellation occurs at the await above and leaves the
            // id pending for a later shutdown waiter.
            self.inner.settle_unregister(&id).await;
        }
    }
}

struct AbortOnDrop(Option<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(task) = self.0.as_ref() {
            task.abort();
        }
    }
}

async fn abort_and_reap(task: JoinHandle<()>) {
    let mut task = AbortOnDrop(Some(task));
    let handle = task.0.as_mut().expect("owned heartbeat task");
    handle.abort();
    let _ = handle.await;
    task.0.take();
}

/// Heartbeat cadence: one third of the lease, floored at [`MIN_HEARTBEAT_INTERVAL`].
fn heartbeat_interval(lease_secs: u64) -> Duration {
    let third = lease_secs / 3;
    if third < MIN_HEARTBEAT_INTERVAL.as_secs() {
        MIN_HEARTBEAT_INTERVAL
    } else {
        Duration::from_secs(third)
    }
}

/// Spawn the renewal loop for one registration. Stops itself if the source
/// reports the id is gone (renewal error), letting the lease drain naturally.
fn spawn_heartbeat<S: KoiSource>(source: Arc<S>, id: String, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match source.heartbeat(id.clone()).await {
                Ok(_) => tracing::trace!(id = %id, "heartbeat renewed"),
                Err(e) => {
                    tracing::debug!(id = %id, error = %e, "heartbeat failed; stopping renewal");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_registry_shutdown_retains_the_heartbeat_owner() {
        let registry = Registry::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx.await.expect("blocking heartbeat started");
        registry
            .inner
            .state
            .lock()
            .await
            .tasks
            .insert("service".to_string(), task);

        let stopping = tokio::spawn({
            let inner = Arc::clone(&registry.inner);
            async move { inner.stop_tasks().await }
        });
        for _ in 0..32 {
            if registry.inner.state.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(registry.inner.state.try_lock().is_err());
        stopping.abort();
        assert!(stopping.await.unwrap_err().is_cancelled());
        assert!(
            registry
                .inner
                .state
                .lock()
                .await
                .tasks
                .contains_key("service"),
            "cancelled waiter detached the heartbeat"
        );

        release_tx.send(()).expect("release blocking heartbeat");
        registry.inner.stop_tasks().await;
        registry.inner.stop_tasks().await;
        let state = registry.inner.state.lock().await;
        assert!(state.tasks.is_empty());
        assert_eq!(
            state.pending_unregister,
            HashSet::from(["service".to_string()])
        );
        drop(state);
        registry.inner.settle_unregister("service").await;
        registry.inner.settle_unregister("service").await;
        assert!(registry
            .inner
            .state
            .lock()
            .await
            .pending_unregister
            .is_empty());
    }

    #[test]
    fn heartbeat_interval_is_one_third() {
        assert_eq!(heartbeat_interval(90), Duration::from_secs(30));
        assert_eq!(heartbeat_interval(30), Duration::from_secs(10));
    }

    #[test]
    fn heartbeat_interval_floors_at_minimum() {
        assert_eq!(heartbeat_interval(0), MIN_HEARTBEAT_INTERVAL);
        assert_eq!(heartbeat_interval(2), MIN_HEARTBEAT_INTERVAL);
    }

    #[tokio::test]
    async fn untrack_unknown_id_is_false() {
        let registry = Registry::new();
        assert!(!registry.untrack("nope").await);
    }
}
