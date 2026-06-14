//! Lazy LAN-wide meta-browse controller.
//!
//! The mDNS browser cache is populated by [`crate::browser::worker`], which runs a
//! meta-browse over every service type on the LAN — chatty multicast. Rather than run
//! it from daemon start (whether or not anyone opens the browser), [`LazyMetaBrowse`]
//! starts the worker on the first browser request and stops it after a period of
//! inactivity. `koi status` reports whether it is currently active.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::browse_source::BrowseSource;
use crate::browser::{worker, BrowserCache};

/// Stop the meta-browse after this long with no browser request.
pub const META_BROWSE_IDLE: Duration = Duration::from_secs(300);

/// How often the idle supervisor checks for inactivity.
const SUPERVISOR_TICK: Duration = Duration::from_secs(30);

/// Lazy controller for the browser cache's meta-browse worker.
pub struct LazyMetaBrowse {
    source: Arc<dyn BrowseSource>,
    cache: BrowserCache,
    parent_cancel: CancellationToken,
    idle: Duration,
    tick: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Cancellation token for the running worker, or `None` when idle.
    worker_cancel: Option<CancellationToken>,
    /// Last browser request (tokio clock so idle is testable under `time::pause`).
    last_active: Instant,
    /// Whether the idle supervisor task is running.
    supervisor_started: bool,
}

impl LazyMetaBrowse {
    /// Construct a controller with the default idle timeout. The worker is **not**
    /// started — the first [`touch`](Self::touch) starts it.
    pub fn new(
        source: Arc<dyn BrowseSource>,
        cache: BrowserCache,
        parent_cancel: CancellationToken,
    ) -> Arc<Self> {
        Self::with_intervals(
            source,
            cache,
            parent_cancel,
            META_BROWSE_IDLE,
            SUPERVISOR_TICK,
        )
    }

    fn with_intervals(
        source: Arc<dyn BrowseSource>,
        cache: BrowserCache,
        parent_cancel: CancellationToken,
        idle: Duration,
        tick: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            source,
            cache,
            parent_cancel,
            idle,
            tick,
            inner: Mutex::new(Inner {
                worker_cancel: None,
                last_active: Instant::now(),
                supervisor_started: false,
            }),
        })
    }

    fn locked(&self) -> MutexGuard<'_, Inner> {
        // Recover from a poisoned lock rather than panicking — the guarded state is
        // simple bookkeeping and never left inconsistent across an await.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Mark a browser request: bump activity and start the worker (and idle supervisor)
    /// if not already running. Cheap and safe to call on every request.
    pub fn touch(self: &Arc<Self>) {
        let mut inner = self.locked();
        inner.last_active = Instant::now();

        if inner.worker_cancel.is_none() {
            let child = self.parent_cancel.child_token();
            inner.worker_cancel = Some(child.clone());
            tokio::spawn(worker(self.source.clone(), self.cache.clone(), child));
            tracing::debug!("mDNS meta-browse started (lazy, on first request)");
        }

        if !inner.supervisor_started {
            inner.supervisor_started = true;
            let this = Arc::clone(self);
            tokio::spawn(this.supervise());
        }
    }

    /// Whether the meta-browse worker is currently running.
    pub fn is_active(&self) -> bool {
        self.locked().worker_cancel.is_some()
    }

    /// Idle supervisor: stop the worker once it has been inactive for `idle`. Lives for
    /// the controller's lifetime so a later `touch` can restart it.
    async fn supervise(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.tick);
        tick.tick().await; // consume the immediate tick

        loop {
            tokio::select! {
                _ = self.parent_cancel.cancelled() => break,
                _ = tick.tick() => {
                    let mut inner = self.locked();
                    if inner.worker_cancel.is_some() && inner.last_active.elapsed() >= self.idle {
                        if let Some(cancel) = inner.worker_cancel.take() {
                            cancel.cancel();
                        }
                        tracing::debug!("mDNS meta-browse idle-stopped");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browse_source::{BrowseError, BrowseHandle, BrowserEvent};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::{broadcast, mpsc};

    /// A `BrowseSource` that never emits events but counts `browse()` calls and keeps
    /// each handle's sender alive so the worker parks instead of seeing EOF.
    struct StubSource {
        browses: AtomicUsize,
        keepalive: Mutex<Vec<mpsc::Sender<BrowserEvent>>>,
        tx: broadcast::Sender<BrowserEvent>,
    }

    impl StubSource {
        fn new() -> Arc<Self> {
            let (tx, _) = broadcast::channel(16);
            Arc::new(Self {
                browses: AtomicUsize::new(0),
                keepalive: Mutex::new(Vec::new()),
                tx,
            })
        }
        fn browse_count(&self) -> usize {
            self.browses.load(Ordering::SeqCst)
        }
    }

    impl BrowseSource for StubSource {
        fn browse(
            &self,
            _service_type: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
        > {
            self.browses.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = mpsc::channel(8);
            self.keepalive
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(tx);
            Box::pin(async move { Ok(BrowseHandle::new(rx)) })
        }

        fn subscribe(&self) -> broadcast::Receiver<BrowserEvent> {
            self.tx.subscribe()
        }
    }

    fn controller(idle: Duration, tick: Duration) -> (Arc<LazyMetaBrowse>, Arc<StubSource>) {
        let source = StubSource::new();
        let cache = BrowserCache::new();
        let dyn_source = source.clone() as Arc<dyn BrowseSource>;
        let lazy =
            LazyMetaBrowse::with_intervals(dyn_source, cache, CancellationToken::new(), idle, tick);
        (lazy, source)
    }

    #[tokio::test]
    async fn no_browse_before_touch() {
        let (lazy, source) = controller(Duration::from_secs(60), Duration::from_secs(30));
        assert!(!lazy.is_active());
        assert_eq!(source.browse_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn touch_starts_one_meta_browse() {
        let (lazy, source) = controller(Duration::from_secs(60), Duration::from_secs(10));
        lazy.touch();
        // Let the spawned worker run far enough to issue its meta-browse.
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(lazy.is_active());
        assert_eq!(source.browse_count(), 1, "exactly one meta-browse started");

        // A second touch must not start a second worker.
        lazy.touch();
        tokio::task::yield_now().await;
        assert_eq!(source.browse_count(), 1);
        assert!(lazy.is_active());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_stops_then_touch_restarts() {
        let (lazy, source) = controller(Duration::from_millis(50), Duration::from_millis(10));
        lazy.touch();
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(lazy.is_active());

        // Advance past idle; the supervisor must stop the worker.
        tokio::time::advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;
        assert!(!lazy.is_active(), "worker idle-stopped");

        // A later request restarts it (new browse).
        lazy.touch();
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(lazy.is_active());
        assert_eq!(
            source.browse_count(),
            2,
            "restart issues a fresh meta-browse"
        );
    }
}
