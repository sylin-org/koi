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

use std::collections::HashMap;
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
    inner: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
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
        let mut map = self.inner.lock().await;
        if let Some(previous) = map.insert(id, task) {
            previous.abort();
        }
    }

    /// Stop tracking `id`, aborting its heartbeat task. Returns `true` if a task
    /// was being tracked.
    pub async fn untrack(&self, id: &str) -> bool {
        let mut map = self.inner.lock().await;
        match map.remove(id) {
            Some(task) => {
                task.abort();
                true
            }
            None => false,
        }
    }

    /// Cancel every heartbeat task and best-effort unregister every tracked id.
    /// Called on server shutdown so no announced service is left to go stale.
    pub async fn shutdown<S: KoiSource>(&self, source: &Arc<S>) {
        let drained: Vec<(String, JoinHandle<()>)> = {
            let mut map = self.inner.lock().await;
            map.drain().collect()
        };
        for (id, task) in drained {
            task.abort();
            if let Err(e) = source.unregister(id.clone()).await {
                tracing::warn!(id = %id, error = %e, "failed to unregister on shutdown");
            } else {
                tracing::debug!(id = %id, "unregistered on shutdown");
            }
        }
    }
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
