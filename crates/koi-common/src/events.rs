//! Shared event-channel primitive.
//!
//! Every domain core publishes lifecycle events over a `tokio::sync::broadcast`
//! channel sized identically (the per-crate `const BROADCAST_CHANNEL_CAPACITY: usize = 256;`
//! was copied six times before this). [`BROADCAST_CHANNEL_CAPACITY`] is now the one source;
//! [`event_channel`] is a thin constructor for the common case.

use tokio::sync::broadcast;

/// Capacity for a domain's event broadcast channel.
///
/// Sized so a moderately busy subscriber can fall behind by up to this many events before
/// it starts seeing `RecvError::Lagged`. All domains share this so back-pressure behaviour
/// is uniform.
pub const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// Create a broadcast channel sized at [`BROADCAST_CHANNEL_CAPACITY`].
///
/// Returns the `(Sender, Receiver)` pair. Most cores keep only the sender (subscribers call
/// `sender.subscribe()` later) and drop the initial receiver.
pub fn event_channel<E: Clone>() -> (broadcast::Sender<E>, broadcast::Receiver<E>) {
    broadcast::channel(BROADCAST_CHANNEL_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_256() {
        assert_eq!(BROADCAST_CHANNEL_CAPACITY, 256);
    }

    #[tokio::test]
    async fn event_channel_delivers_to_subscriber() {
        let (tx, mut rx) = event_channel::<u32>();
        let mut rx2 = tx.subscribe();
        let _ = tx.send(7);
        assert_eq!(rx.recv().await.unwrap(), 7);
        assert_eq!(rx2.recv().await.unwrap(), 7);
    }
}
