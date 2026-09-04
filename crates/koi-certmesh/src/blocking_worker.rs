//! Bounded owner for Certmesh's blocking preparation and platform effects.
//!
//! A command accepted by this worker is independent from the request future
//! that submitted it. Pure preparation may therefore finish and be discarded
//! after cancellation, while a job carrying an owned aggregate transition
//! guard keeps that fence until its complete effect has settled. Rare local
//! unlock/backup commands deliberately retain the aggregate gate during their
//! bounded KDF: status remains lock-free, and this avoids a second artifact
//! version/revalidation protocol. Network and other unbounded waits must never
//! enter this worker. The worker is lazy so read-only/status-only Certmesh
//! facades do not allocate a thread.

use std::sync::{Mutex as StdMutex, PoisonError};
use std::thread::JoinHandle;

use tokio::sync::{mpsc, oneshot};

use crate::{CertmeshCore, CertmeshDomain, CertmeshError, CertmeshState};

pub(crate) const CERTMESH_BLOCKING_CAPACITY: usize = 16;

type BlockingWork = Box<dyn FnOnce() + Send + 'static>;

pub(crate) struct CertmeshBlockingPermit(mpsc::OwnedPermit<BlockingWork>);

struct WorkerOwner {
    started: bool,
    sender: Option<mpsc::Sender<BlockingWork>>,
    thread: Option<JoinHandle<()>>,
    start_error: Option<String>,
}

/// One lazy blocking worker owned and joined by a Certmesh aggregate.
pub(crate) struct CertmeshBlockingWorker {
    owner: StdMutex<WorkerOwner>,
    #[cfg(test)]
    probe: std::sync::Arc<WorkerProbe>,
}

impl CertmeshBlockingWorker {
    pub(crate) fn new() -> Self {
        Self {
            owner: StdMutex::new(WorkerOwner {
                started: false,
                sender: None,
                thread: None,
                start_error: None,
            }),
            #[cfg(test)]
            probe: std::sync::Arc::new(WorkerProbe::default()),
        }
    }

    /// Admit one bounded blocking operation and await its acknowledgement.
    ///
    /// Cancellation while the bounded send is waiting admits nothing. Once the
    /// send succeeds, the worker owns the closure and runs it even if the caller
    /// drops `reply_rx`.
    pub(crate) async fn run<R>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, CertmeshError>
    where
        R: Send + 'static,
    {
        let permit = self.reserve().await?;
        self.run_with_permit(permit, work).await
    }

    /// Reserve bounded admission before a command crosses its durable point.
    /// Dropping an unused permit admits nothing.
    pub(crate) async fn reserve(&self) -> Result<CertmeshBlockingPermit, CertmeshError> {
        self.sender()?
            .reserve_owned()
            .await
            .map(CertmeshBlockingPermit)
            .map_err(|_| {
                CertmeshError::Internal("Certmesh blocking worker stopped before admission".into())
            })
    }

    /// Synchronously consume reserved admission, then await worker settlement.
    pub(crate) async fn run_with_permit<R>(
        &self,
        permit: CertmeshBlockingPermit,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, CertmeshError>
    where
        R: Send + 'static,
    {
        self.dispatch_with_permit(permit, work).await.map_err(|_| {
            CertmeshError::Internal("Certmesh blocking worker ended before acknowledgement".into())
        })
    }

    /// Transfer an already-reserved job to the worker without awaiting it.
    ///
    /// Domain-specific owners use this only after atomically recording a
    /// durable intent. Dropping the returned receiver does not cancel the job.
    pub(crate) fn dispatch_with_permit<R>(
        &self,
        permit: CertmeshBlockingPermit,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> oneshot::Receiver<R>
    where
        R: Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        #[cfg(test)]
        let probe = std::sync::Arc::clone(&self.probe);
        let work = Box::new(move || {
            let result = work();
            #[cfg(test)]
            probe.after_work_before_ack();
            let _ = reply_tx.send(result);
        });
        permit.0.send(work);
        reply_rx
    }

    /// Admit startup reconciliation synchronously. The worker is new and its
    /// queue is empty; a full queue is still reported instead of becoming an
    /// unbounded fallback.
    pub(crate) fn try_run<R>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<oneshot::Receiver<R>, CertmeshError>
    where
        R: Send + 'static,
    {
        let permit = self
            .sender()?
            .try_reserve_owned()
            .map(CertmeshBlockingPermit)
            .map_err(|_| {
                CertmeshError::Internal(
                    "Certmesh blocking worker has no capacity for startup reconciliation".into(),
                )
            })?;
        Ok(self.dispatch_with_permit(permit, work))
    }

    fn sender(&self) -> Result<mpsc::Sender<BlockingWork>, CertmeshError> {
        let mut owner = self.owner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sender) = owner.sender.as_ref() {
            return Ok(sender.clone());
        }
        if owner.started {
            return Err(CertmeshError::Internal(
                owner
                    .start_error
                    .clone()
                    .unwrap_or_else(|| "Certmesh blocking worker is unavailable".into()),
            ));
        }

        owner.started = true;
        let (sender, mut receiver) = mpsc::channel::<BlockingWork>(CERTMESH_BLOCKING_CAPACITY);
        #[cfg(test)]
        let probe = std::sync::Arc::clone(&self.probe);
        match std::thread::Builder::new()
            .name("koi-certmesh-blocking".into())
            .spawn(move || {
                while let Some(work) = receiver.blocking_recv() {
                    #[cfg(test)]
                    probe.before_work();
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).is_err() {
                        tracing::error!("Certmesh blocking operation panicked; worker retained");
                    }
                    #[cfg(test)]
                    probe
                        .completed
                        .fetch_add(1, std::sync::atomic::Ordering::Release);
                }
            }) {
            Ok(thread) => {
                owner.sender = Some(sender.clone());
                owner.thread = Some(thread);
                Ok(sender)
            }
            Err(error) => {
                let message = format!("could not start Certmesh blocking worker: {error}");
                owner.start_error = Some(message.clone());
                Err(CertmeshError::Internal(message))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_next_work(&self) {
        self.probe
            .release
            .store(false, std::sync::atomic::Ordering::Release);
        self.probe
            .pause_next
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn is_work_paused(&self) -> bool {
        self.probe.paused.load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn release_work(&self) {
        self.probe
            .release
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn pause_after_next_work(&self) {
        self.probe
            .release_after
            .store(false, std::sync::atomic::Ordering::Release);
        self.probe
            .pause_after_next
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn is_work_paused_after_effect(&self) -> bool {
        self.probe
            .paused_after
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn release_after_work(&self) {
        self.probe
            .release_after
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn completed_work(&self) -> usize {
        self.probe
            .completed
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn remaining_capacity(&self) -> Result<usize, CertmeshError> {
        self.sender().map(|sender| sender.capacity())
    }
}

impl CertmeshState {
    /// Run one complete aggregate transition on Certmesh's retained worker.
    ///
    /// This state-level owner is also used by in-domain adapters such as ACME;
    /// they do not construct a parallel executor or reach around the aggregate
    /// transaction boundary.
    pub(crate) async fn run_blocking_transition<R>(
        &self,
        transition: impl FnOnce(&CertmeshDomain) -> R + Send + 'static,
    ) -> Result<R, CertmeshError>
    where
        R: Send + 'static,
    {
        let permit = self.blocking.reserve().await?;
        let guard = std::sync::Arc::clone(&self.transition).lock_owned().await;
        let domain = std::sync::Arc::clone(&self.domain);
        self.blocking
            .run_with_permit(permit, move || {
                let _guard = guard;
                transition(&domain)
            })
            .await
    }
}

impl CertmeshCore {
    /// Run one complete aggregate transition on Certmesh's retained worker.
    ///
    /// Capacity is reserved before the aggregate gate. Once the owned guard and
    /// closure are sent, caller cancellation cannot split persistence from the
    /// model, projections, or semantic event tail. The closure must contain no
    /// network or otherwise unbounded wait.
    pub(crate) async fn run_blocking_transition<R>(
        &self,
        transition: impl FnOnce(&CertmeshDomain) -> R + Send + 'static,
    ) -> Result<R, CertmeshError>
    where
        R: Send + 'static,
    {
        self.state.run_blocking_transition(transition).await
    }
}

impl Drop for CertmeshBlockingWorker {
    fn drop(&mut self) {
        let owner = self.owner.get_mut().unwrap_or_else(PoisonError::into_inner);
        // Closing the sole retained sender makes the receiver drain every job
        // accepted before aggregate release and then exit.
        drop(owner.sender.take());
        if let Some(thread) = owner.thread.take() {
            if thread.join().is_err() {
                tracing::error!("Certmesh blocking worker panicked while shutting down");
            }
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct WorkerProbe {
    pause_next: std::sync::atomic::AtomicBool,
    paused: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
    pause_after_next: std::sync::atomic::AtomicBool,
    paused_after: std::sync::atomic::AtomicBool,
    release_after: std::sync::atomic::AtomicBool,
    completed: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl WorkerProbe {
    fn before_work(&self) {
        use std::sync::atomic::Ordering;

        if !self.pause_next.swap(false, Ordering::AcqRel) {
            return;
        }
        self.paused.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.paused.store(false, Ordering::Release);
    }

    fn after_work_before_ack(&self) {
        use std::sync::atomic::Ordering;

        if !self.pause_after_next.swap(false, Ordering::AcqRel) {
            return;
        }
        self.paused_after.store(true, Ordering::Release);
        while !self.release_after.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.paused_after.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_before_bounded_admission_executes_no_work() {
        let worker = Arc::new(CertmeshBlockingWorker::new());
        worker.pause_next_work();
        let first = tokio::spawn({
            let worker = Arc::clone(&worker);
            async move { worker.run(|| ()).await }
        });
        while !worker.is_work_paused() {
            tokio::task::yield_now().await;
        }

        let mut admitted = Vec::new();
        for _ in 0..CERTMESH_BLOCKING_CAPACITY {
            admitted.push(tokio::spawn({
                let worker = Arc::clone(&worker);
                async move { worker.run(|| ()).await }
            }));
        }
        while worker.remaining_capacity().unwrap() != 0 {
            tokio::task::yield_now().await;
        }

        let overflow_ran = Arc::new(AtomicBool::new(false));
        let overflow = tokio::spawn({
            let worker = Arc::clone(&worker);
            let overflow_ran = Arc::clone(&overflow_ran);
            async move {
                worker
                    .run(move || overflow_ran.store(true, Ordering::Release))
                    .await
            }
        });
        tokio::task::yield_now().await;
        overflow.abort();
        let _ = overflow.await;

        worker.release_work();
        first.await.unwrap().unwrap();
        for task in admitted {
            task.await.unwrap().unwrap();
        }
        assert!(!overflow_ran.load(Ordering::Acquire));
        assert_eq!(worker.completed_work(), CERTMESH_BLOCKING_CAPACITY + 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn last_owner_drop_drains_an_admitted_job_after_caller_cancellation() {
        let worker = Arc::new(CertmeshBlockingWorker::new());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let worker = Arc::clone(&worker);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let completed = Arc::clone(&completed);
            async move {
                worker
                    .run(move || {
                        entered.store(true, Ordering::Release);
                        while !release.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                        completed.store(true, Ordering::Release);
                    })
                    .await
            }
        });
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;

        let releaser = {
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                release.store(true, Ordering::Release);
            })
        };
        drop(worker);
        releaser.join().unwrap();
        assert!(completed.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_effect_before_ack_keeps_the_effect() {
        let worker = Arc::new(CertmeshBlockingWorker::new());
        let effect = Arc::new(AtomicBool::new(false));
        worker.pause_after_next_work();
        let task = tokio::spawn({
            let worker = Arc::clone(&worker);
            let effect = Arc::clone(&effect);
            async move {
                worker
                    .run(move || effect.store(true, Ordering::Release))
                    .await
            }
        });
        while !worker.is_work_paused_after_effect() {
            tokio::task::yield_now().await;
        }
        assert!(effect.load(Ordering::Acquire));
        task.abort();
        let _ = task.await;
        worker.release_after_work();
        while worker.completed_work() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(effect.load(Ordering::Acquire));
    }
}
