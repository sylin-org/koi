//! Cancellation-safe asynchronous ownership for Certmesh bootstrap.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread::JoinHandle;

use tokio::sync::oneshot;

use crate::{CertmeshCore, CertmeshError, CertmeshPaths};

/// One joinable bootstrap transaction running outside async executors.
///
/// `load_with_paths` can recover repository state, retire durable cleanup
/// outboxes, consult platform identity/vaults, and perform a legacy migration.
/// Those effects must finish if an async startup requester is cancelled.
pub(crate) struct CertmeshBootstrapJob {
    result: oneshot::Receiver<Result<CertmeshCore, CertmeshError>>,
    worker: Option<JoinHandle<()>>,
}

impl CertmeshBootstrapJob {
    pub(crate) fn start(
        paths: CertmeshPaths,
        dns_zone: String,
        local_hostname: String,
    ) -> Result<Self, CertmeshError> {
        Self::start_with_hook(paths, dns_zone, local_hostname, None, None)
    }

    fn start_with_hook(
        paths: CertmeshPaths,
        dns_zone: String,
        local_hostname: String,
        before: Option<Box<dyn FnOnce() + Send>>,
        #[cfg_attr(not(test), allow(unused_variables))] finished: Option<
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        >,
    ) -> Result<Self, CertmeshError> {
        let (result_tx, result) = oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("koi-certmesh-bootstrap".into())
            .spawn(move || {
                if let Some(before) = before {
                    before();
                }
                let loaded = CertmeshCore::load_with_paths(paths, &dns_zone, &local_hostname);
                #[cfg(test)]
                if let Some(finished) = finished {
                    finished.store(true, std::sync::atomic::Ordering::Release);
                }
                let _ = result_tx.send(loaded);
            })
            .map_err(|error| {
                CertmeshError::Internal(format!("could not start Certmesh bootstrap: {error}"))
            })?;
        Ok(Self {
            result,
            worker: Some(worker),
        })
    }

    fn join_worker(&mut self) -> Result<(), CertmeshError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| CertmeshError::Internal("Certmesh bootstrap worker panicked".to_string()))
    }
}

impl Future for CertmeshBootstrapJob {
    type Output = Result<CertmeshCore, CertmeshError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.result).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                let join = self.join_worker();
                Poll::Ready(match result {
                    Ok(result) => {
                        join?;
                        result
                    }
                    Err(_) => {
                        join?;
                        Err(CertmeshError::Internal(
                            "Certmesh bootstrap ended without a result".into(),
                        ))
                    }
                })
            }
        }
    }
}

impl Drop for CertmeshBootstrapJob {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };

        // Never make a current-thread runtime wait for cancelled bootstrap I/O
        // or KDF work. The tiny reaper owns and joins the already-running worker.
        // If thread creation itself is unavailable, joining here is the only
        // safe fallback: detaching an effectful bootstrap is not permitted.
        let (reap_tx, reap_rx) = std::sync::mpsc::sync_channel::<std::thread::JoinHandle<()>>(1);
        match std::thread::Builder::new()
            .name("koi-certmesh-bootstrap-reaper".into())
            .spawn(move || {
                if let Ok(worker) = reap_rx.recv() {
                    if worker.join().is_err() {
                        tracing::error!("Cancelled Certmesh bootstrap worker panicked");
                    }
                }
            }) {
            Ok(reaper) => {
                if let Err(error) = reap_tx.send(worker) {
                    if error.0.join().is_err() {
                        tracing::error!("Cancelled Certmesh bootstrap worker panicked");
                    }
                }
                drop(reaper);
            }
            Err(error) => {
                tracing::warn!(%error, "Could not start Certmesh bootstrap reaper; joining inline");
                if worker.join().is_err() {
                    tracing::error!("Cancelled Certmesh bootstrap worker panicked");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn paths(tag: &str) -> CertmeshPaths {
        CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-bootstrap-tests").join(tag),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_keeps_current_thread_responsive() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let job = CertmeshBootstrapJob::start_with_hook(
            paths("responsive"),
            "internal".into(),
            "certmesh-test-host".into(),
            Some(Box::new({
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                move || {
                    entered.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                }
            })),
            None,
        )
        .unwrap();
        let task = tokio::spawn(job);
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .expect("bootstrap must not block the current-thread timer");
        release.store(true, Ordering::Release);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_bootstrap_is_reaped_and_finishes_owned_work() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let job = CertmeshBootstrapJob::start_with_hook(
            paths("cancelled"),
            "internal".into(),
            "certmesh-test-host".into(),
            Some(Box::new({
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                move || {
                    entered.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                }
            })),
            Some(Arc::clone(&finished)),
        )
        .unwrap();
        let task = tokio::spawn(job);
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .expect("cancellation reaping must not block the current-thread timer");
        release.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !finished.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled bootstrap must finish under its reaper");
    }
}
