//! Replay-nonce store (RFC 8555 §6.5).
//!
//! Every ACME POST carries a `nonce` in its protected header that the server
//! must have issued and not yet seen. The server hands out a fresh
//! `Replay-Nonce` header on **every** response (success or error) so the client
//! always has an unused one for its next request.
//!
//! This store is a concurrency-safe set of outstanding nonces:
//! - `issue()` mints a random URL-safe token and records it as valid.
//! - `redeem()` removes a nonce, returning whether it was present. A second
//!   `redeem()` of the same value returns `false` → the handler emits `badNonce`.
//!
//! Nonces are short-lived and in-memory only; they are deliberately NOT
//! persisted (a daemon restart invalidates outstanding nonces, which is fine —
//! the client just retries with a fresh `new-nonce`).

use std::collections::HashSet;
use std::sync::Mutex;

use base64::Engine;
use rand::RngCore;

/// Number of random bytes per nonce before base64url encoding.
const NONCE_BYTES: usize = 24;

/// Soft cap on outstanding nonces. A misbehaving or hostile client could
/// otherwise force unbounded growth by fetching new-nonce in a loop. When the
/// set exceeds this, the oldest-insertion-order entries are dropped (a redeem of
/// a dropped nonce just yields `badNonce`, which is a legal, recoverable error).
const MAX_OUTSTANDING: usize = 4096;

/// A concurrency-safe replay-nonce store.
pub struct NonceStore {
    /// Outstanding (issued, unredeemed) nonces.
    issued: Mutex<HashSet<String>>,
}

impl NonceStore {
    /// Create an empty nonce store.
    pub fn new() -> Self {
        Self {
            issued: Mutex::new(HashSet::new()),
        }
    }

    /// Mint a fresh nonce, record it as valid, and return it.
    pub fn issue(&self) -> String {
        let mut bytes = [0u8; NONCE_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        let mut set = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        if set.len() >= MAX_OUTSTANDING {
            // Bounded eviction: clear the set rather than tracking insertion order.
            // Outstanding clients retry transparently via badNonce + a fresh nonce.
            set.clear();
        }
        set.insert(nonce.clone());
        nonce
    }

    /// Redeem a nonce. Returns `true` if it was outstanding (and removes it);
    /// `false` if it was unknown or already used.
    pub fn redeem(&self, nonce: &str) -> bool {
        let mut set = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(nonce)
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_nonce_redeems_once() {
        let store = NonceStore::new();
        let n = store.issue();
        assert!(store.redeem(&n), "freshly issued nonce must redeem");
        assert!(
            !store.redeem(&n),
            "a redeemed nonce must NOT redeem again (replay)"
        );
    }

    #[test]
    fn unknown_nonce_does_not_redeem() {
        let store = NonceStore::new();
        assert!(!store.redeem("never-issued"));
    }

    #[test]
    fn nonces_are_unique() {
        let store = NonceStore::new();
        let a = store.issue();
        let b = store.issue();
        assert_ne!(a, b, "each issued nonce must be distinct");
    }

    #[test]
    fn concurrent_issue_redeem_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(NonceStore::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let n = s.issue();
                    assert!(s.redeem(&n));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
