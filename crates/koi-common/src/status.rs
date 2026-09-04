//! Cheap, observable domain-status storage.
//!
//! A domain owns its mutable model and publishes an immutable projection only after a
//! successful transition. Consumers can either clone the current [`Arc`] in constant time or
//! subscribe to the latest value through Tokio's coalescing [`watch`] channel. The feed is a
//! delivery primitive, not another source of truth: status construction and revision semantics
//! remain with the domain that owns them.

use std::sync::Arc;

use tokio::sync::watch;

/// The current immutable status of a domain plus a coalescing change subscription.
///
/// Keep the feed itself private inside a domain facade. Expose only
/// `status() -> Arc<S>` and `watch_status() -> watch::Receiver<Arc<S>>`; mutation remains a
/// domain responsibility.
#[derive(Debug, Clone)]
pub struct StatusFeed<S> {
    tx: watch::Sender<Arc<S>>,
}

impl<S> StatusFeed<S> {
    /// Seed a feed before exposing the domain facade.
    pub fn new(initial: S) -> Self {
        Self {
            tx: watch::channel(Arc::new(initial)).0,
        }
    }

    /// Clone the current immutable status in constant time.
    pub fn current(&self) -> Arc<S> {
        self.tx.borrow().clone()
    }

    /// Subscribe to the current status and all later semantic changes.
    ///
    /// A new receiver immediately contains the value returned by [`Self::current`]. Multiple
    /// updates may coalesce; a consumer that needs history uses the domain's semantic event or
    /// audit surface instead.
    pub fn subscribe(&self) -> watch::Receiver<Arc<S>> {
        self.tx.subscribe()
    }

    /// Publish a new status unconditionally.
    ///
    /// Domains normally prefer [`Self::publish_if_changed`], reserving this method for a status
    /// whose equality deliberately cannot represent its transition semantics.
    pub fn publish(&self, next: S) -> Arc<S> {
        let next = Arc::new(next);
        self.tx.send_replace(Arc::clone(&next));
        next
    }

    /// Atomically derive an optional replacement from the current status.
    ///
    /// The closure runs while the watch value is exclusively borrowed. This is useful for
    /// domain-owned monotonic revisions: compare a freshly assembled projection with `current`,
    /// assign `current.revision + 1` only for a real change, and return `None` for a no-op.
    pub fn update(&self, update: impl FnOnce(&S) -> Option<S>) -> Arc<S> {
        let mut update = Some(update);
        self.tx.send_if_modified(|current| {
            let Some(next) = update.take().expect("status update called once")(current.as_ref())
            else {
                return false;
            };
            *current = Arc::new(next);
            true
        });
        self.current()
    }
}

impl<S: PartialEq> StatusFeed<S> {
    /// Publish only when the semantic status changed.
    ///
    /// The returned value is the authoritative current allocation: the existing [`Arc`] for a
    /// no-op, or the newly published allocation for a transition.
    pub fn publish_if_changed(&self, next: S) -> Arc<S> {
        let next = Arc::new(next);
        let changed = self.tx.send_if_modified(|current| {
            if current.as_ref() == next.as_ref() {
                false
            } else {
                *current = Arc::clone(&next);
                true
            }
        });
        if changed {
            next
        } else {
            self.current()
        }
    }
}

impl<S: Default> Default for StatusFeed<S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_is_a_cheap_arc_clone() {
        let feed = StatusFeed::new(String::from("ready"));
        let first = feed.current();
        let second = feed.current();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn subscriber_starts_with_current_and_observes_change() {
        let feed = StatusFeed::new(1_u64);
        let mut rx = feed.subscribe();
        assert_eq!(**rx.borrow(), 1);

        feed.publish(2);
        rx.changed().await.unwrap();
        assert_eq!(**rx.borrow_and_update(), 2);
    }

    #[tokio::test]
    async fn equal_status_does_not_wake_subscribers() {
        let feed = StatusFeed::new(String::from("ready"));
        let mut rx = feed.subscribe();
        let before = feed.current();

        let after = feed.publish_if_changed(String::from("ready"));
        assert!(Arc::ptr_eq(&before, &after));
        assert!(rx.has_changed().is_ok_and(|changed| !changed));

        feed.publish_if_changed(String::from("degraded"));
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().as_str(), "degraded");
    }

    #[tokio::test]
    async fn status_changes_coalesce_to_latest_value() {
        let feed = StatusFeed::new(0_u64);
        let mut rx = feed.subscribe();
        feed.publish(1);
        feed.publish(2);
        feed.publish(3);

        rx.changed().await.unwrap();
        assert_eq!(**rx.borrow_and_update(), 3);
    }

    #[tokio::test]
    async fn atomic_update_can_assign_a_revision_and_suppress_a_noop() {
        #[derive(Debug, PartialEq, Eq)]
        struct Status {
            revision: u64,
            value: &'static str,
        }

        let feed = StatusFeed::new(Status {
            revision: 7,
            value: "ready",
        });
        let mut rx = feed.subscribe();
        feed.update(|current| {
            (current.value != "ready").then_some(Status {
                revision: current.revision.saturating_add(1),
                value: "ready",
            })
        });
        assert!(rx.has_changed().is_ok_and(|changed| !changed));

        let changed = feed.update(|current| {
            Some(Status {
                revision: current.revision.saturating_add(1),
                value: "degraded",
            })
        });
        rx.changed().await.unwrap();
        assert_eq!(changed.revision, 8);
        assert_eq!(rx.borrow_and_update().revision, 8);
    }
}
