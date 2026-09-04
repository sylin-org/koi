//! Cancellation-safe boundary for short, blocking domain invariants.
//!
//! Tokio's `spawn_blocking` detaches when the awaiting future is dropped. That
//! is useful for pure work whose result may be abandoned, but unsafe for a
//! durable transition: cancellation could let disk or a platform store change
//! after the domain released its model gate and before status/events caught up.
//!
//! [`run_to_completion`] keeps the complete synchronous invariant in the
//! calling task's current poll. A multithread Tokio runtime compensates for the
//! blocked worker through `block_in_place`; current-thread and non-Tokio callers
//! execute directly. Callers must keep the closure bounded and include every
//! synchronous model/status/event effect that makes the transition coherent.

/// Run one bounded blocking invariant without introducing an async
/// cancellation point.
pub fn run_to_completion<F, R>(work: F) -> R
where
    F: FnOnce() -> R,
{
    let mut work = Some(work);
    if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    }) {
        return tokio::task::block_in_place(work.take().expect("blocking work called once"));
    }
    work.take().expect("blocking work called once")()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;

    #[test]
    fn works_without_a_runtime() {
        assert_eq!(run_to_completion(|| 42), 42);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn works_on_a_current_thread_runtime() {
        assert_eq!(run_to_completion(|| "done"), "done");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_cannot_interrupt_the_synchronous_invariant() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let task = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let completed = Arc::clone(&completed);
            tokio::spawn(async move {
                run_to_completion(|| {
                    entered.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    completed.store(true, Ordering::Release);
                });
            })
        };

        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        task.abort();
        release.store(true, Ordering::Release);
        let _ = task.await;
        assert!(completed.load(Ordering::Acquire));
    }
}
