//! Lazy LAN-wide meta-browse controller.
//!
//! The mDNS browser cache projects the domain-owned discovery snapshot. The
//! [`crate::browser::worker`] owns only the query demand that feeds that domain snapshot:
//! a meta-browse over every service type on the LAN — chatty multicast. Rather than run it
//! from daemon start (whether or not anyone opens the browser), [`LazyMetaBrowse`] starts
//! the worker on the first browser request and stops it after a period of inactivity.
//! `koi status` reports whether it is currently active.

use std::sync::{Arc, Mutex, MutexGuard, Weak};
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
    cancel: CancellationToken,
    idle: Duration,
    tick: Duration,
    restart_gate: tokio::sync::Mutex<()>,
    inner: Mutex<Inner>,
}

struct Inner {
    /// The owned running worker, or `None` when idle.
    worker: Option<WorkerTask>,
    /// Last browser request (tokio clock so idle is testable under `time::pause`).
    last_active: Instant,
    /// Prevent a synchronous touch from racing an explicit asynchronous restart.
    restarting: bool,
    /// Weakly supervised idle controller. It never retains `LazyMetaBrowse`.
    supervisor: Option<tokio::task::JoinHandle<()>>,
}

struct WorkerTask {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl WorkerTask {
    async fn shutdown(mut self) {
        self.cancel.cancel();
        let Some(task) = self.task.as_mut() else {
            return;
        };
        if tokio::time::timeout(Duration::from_secs(2), &mut *task)
            .await
            .is_err()
        {
            task.abort();
            let _ = (&mut *task).await;
        }
        self.task.take();
    }
}

impl Drop for WorkerTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
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

    pub(crate) fn with_intervals(
        source: Arc<dyn BrowseSource>,
        cache: BrowserCache,
        parent_cancel: CancellationToken,
        idle: Duration,
        tick: Duration,
    ) -> Arc<Self> {
        let cancel = parent_cancel.child_token();
        Arc::new(Self {
            source,
            cache,
            cancel,
            idle,
            tick,
            restart_gate: tokio::sync::Mutex::new(()),
            inner: Mutex::new(Inner {
                worker: None,
                last_active: Instant::now(),
                restarting: false,
                supervisor: None,
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
        if inner
            .worker
            .as_ref()
            .and_then(|worker| worker.task.as_ref())
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            inner.worker.take();
        }

        if inner.worker.is_none() && !inner.restarting && !self.cancel.is_cancelled() {
            inner.worker = Some(self.spawn_worker());
            tracing::debug!("mDNS meta-browse started (lazy, on first request)");
        }

        if inner
            .supervisor
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
            && !self.cancel.is_cancelled()
        {
            inner.supervisor.take();
            inner.supervisor = Some(tokio::spawn(Self::supervise(
                Arc::downgrade(self),
                self.cancel.clone(),
                self.idle,
                self.tick,
            )));
        }
    }

    fn spawn_worker(&self) -> WorkerTask {
        let cancel = self.cancel.child_token();
        let task = tokio::spawn(worker(
            self.source.clone(),
            self.cache.clone(),
            cancel.clone(),
        ));
        WorkerTask {
            cancel,
            task: Some(task),
        }
    }

    /// Whether the meta-browse worker is currently running.
    pub fn is_active(&self) -> bool {
        let mut inner = self.locked();
        if inner
            .worker
            .as_ref()
            .and_then(|worker| worker.task.as_ref())
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            inner.worker.take();
        }
        inner.worker.is_some()
    }

    /// Force a fresh query burst: cancel the current worker and start a new one.
    /// The new worker re-queries `_services._dns-sd._udp` (the mDNS "what types
    /// exist?" question every client answers) and then re-queries each known
    /// type, so every mDNS host on the LAN speaks up immediately instead of
    /// waiting for its own announcement timer. Idempotent: repeated calls just
    /// restart the burst. Returns the number of types the cache already knows —
    /// the burst re-discovers them within moments.
    pub async fn requery(self: &Arc<Self>) -> usize {
        let _restart = self.restart_gate.lock().await;
        let retiring = {
            let mut inner = self.locked();
            inner.last_active = Instant::now();
            inner.restarting = true;
            inner.worker.take()
        };
        if let Some(worker) = retiring {
            worker.shutdown().await;
        }

        let known = self.cache.known_type_count().await;
        let mut inner = self.locked();
        if !self.cancel.is_cancelled() {
            inner.worker = Some(self.spawn_worker());
        }
        inner.restarting = false;
        known
    }

    /// Idle supervisor: stop the worker once it has been inactive for `idle`. Lives for
    /// the controller's lifetime so a later `touch` can restart it.
    async fn supervise(
        controller: Weak<Self>,
        cancel: CancellationToken,
        idle: Duration,
        interval: Duration,
    ) {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await; // consume the immediate tick

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    if let Some(controller) = controller.upgrade() {
                        let worker = controller.locked().worker.take();
                        if let Some(worker) = worker {
                            worker.shutdown().await;
                        }
                    }
                    break;
                },
                _ = tick.tick() => {
                    let Some(controller) = controller.upgrade() else {
                        break;
                    };
                    let worker = {
                        let mut inner = controller.locked();
                        (inner.worker.is_some()
                            && !inner.restarting
                            && inner.last_active.elapsed() >= idle)
                            .then(|| inner.worker.take())
                            .flatten()
                    };
                    drop(controller);
                    if let Some(worker) = worker {
                        worker.shutdown().await;
                        tracing::debug!("mDNS meta-browse idle-stopped");
                    }
                }
            }
        }
    }
}

impl Drop for LazyMetaBrowse {
    fn drop(&mut self) {
        self.cancel.cancel();
        let inner = self
            .inner
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.worker.take();
        if let Some(task) = inner.supervisor.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::browse_source::{BrowseError, BrowseHandle, BrowserEvent};
    use koi_common::integration::MdnsDiscoverySnapshot;
    use koi_common::status::StatusFeed;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::{broadcast, mpsc, watch};

    /// A `BrowseSource` that never emits events but counts `browse()` calls and keeps
    /// each handle's sender alive so the worker parks instead of seeing EOF.
    pub(crate) struct StubSource {
        pub(crate) browses: AtomicUsize,
        keepalive: Mutex<Vec<mpsc::Sender<BrowserEvent>>>,
        tx: broadcast::Sender<BrowserEvent>,
        snapshots: StatusFeed<MdnsDiscoverySnapshot>,
    }

    impl StubSource {
        pub(crate) fn new() -> Arc<Self> {
            let (tx, _) = broadcast::channel(16);
            Arc::new(Self {
                browses: AtomicUsize::new(0),
                keepalive: Mutex::new(Vec::new()),
                tx,
                snapshots: StatusFeed::default(),
            })
        }
        pub(crate) fn browse_count(&self) -> usize {
            self.browses.load(Ordering::SeqCst)
        }

        pub(crate) fn publish_snapshot(&self, snapshot: MdnsDiscoverySnapshot) {
            self.snapshots.publish(snapshot);
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

        fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
            self.snapshots.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
            self.snapshots.subscribe()
        }
    }

    pub(crate) fn controller(
        idle: Duration,
        tick: Duration,
    ) -> (Arc<LazyMetaBrowse>, Arc<StubSource>) {
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

    #[tokio::test]
    async fn supervisor_does_not_retain_its_controller() {
        let (lazy, _) = controller(Duration::from_secs(60), Duration::from_secs(30));
        lazy.touch();
        let weak = Arc::downgrade(&lazy);

        drop(lazy);
        tokio::task::yield_now().await;

        assert!(
            weak.upgrade().is_none(),
            "the owned supervisor must not create an Arc self-cycle"
        );
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
    async fn requery_forces_a_fresh_query_burst() {
        let (lazy, source) = controller(Duration::from_secs(60), Duration::from_secs(10));
        lazy.touch();
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.browse_count(), 1);

        // requery restarts the burst: a new meta-browse is issued even though
        // the worker is already running, and the call stays idempotent-safe.
        let known = lazy.requery().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(lazy.is_active(), "a worker is running again after requery");
        assert_eq!(
            source.browse_count(),
            2,
            "requery cancels the old worker and starts a fresh meta-browse"
        );
        assert_eq!(known, 0, "the empty cache knows no types yet");

        // Repeated requeries keep working (idempotent restarts, no panic).
        lazy.requery().await;
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.browse_count(), 3);
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
