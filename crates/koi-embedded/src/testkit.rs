//! Spin a real embedded Koi in a known posture for tests — **no Docker** (ADR-020 §13).
//!
//! Shipped as a normal module (not a `cfg(feature)` — the additive-feature trap):
//! a consumer's integration tests get real-daemon fidelity by depending only on
//! `koi-embedded`. [`open`] yields an Open node (no identity); [`secured`] yields
//! an Authenticated node (a CA is created so it holds a real leaf).
//!
//! ## The "same code, both postures" acceptance gate (ADR-020 §2)
//!
//! The mode-transparency contract is: *one* consumer code path must work whether or
//! not the node has an identity. The gate is simply to run that path against both:
//!
//! ```no_run
//! # async fn gate() {
//! use koi_embedded::testkit;
//! for node in [testkit::open().await, testkit::secured().await] {
//!     let cm = node.certmesh().unwrap();
//!     let env = cm.sign(b"hello").await.unwrap();          // identical in both
//!     assert!(!cm.verify(&env).await.unwrap().is_rejected());
//!     node.shutdown().await;
//! }
//! # }
//! ```
//!
//! If the body ever needs `if secure { … } else { … }`, a primitive is missing or
//! wrong — that is exactly what this gate catches.
//!
//! Note: testkit nodes run with mDNS off (no multicast in CI); they exercise the
//! trust primitives (sign/verify, seal/open, posture, diagnose), not LAN discovery.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Builder, KoiHandle, ServiceMode};

/// A running embedded Koi node for a test, with its data dir cleaned up on
/// [`shutdown`](TestNode::shutdown). Derefs to [`KoiHandle`], so call any handle
/// method (`certmesh()`, `mdns()`, …) directly on it.
pub struct TestNode {
    handle: KoiHandle,
    data_dir: PathBuf,
}

impl std::ops::Deref for TestNode {
    type Target = KoiHandle;
    fn deref(&self) -> &KoiHandle {
        &self.handle
    }
}

impl TestNode {
    /// Shut the node down and remove its (isolated) data dir.
    pub async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// A fresh, isolated, wiped data dir (unique per process + call).
fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("koi-testkit-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Build a lean embedded node (certmesh on, everything else off) in its own dir.
async fn build(tag: &str) -> TestNode {
    let data_dir = unique_dir(tag);
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(true)
        .proxy(false)
        .build()
        .expect("testkit: build embedded");
    let handle = koi.start().await.expect("testkit: start embedded");
    TestNode { handle, data_dir }
}

/// An **Open** node — certmesh enabled but no CA, so it holds no identity. `sign`
/// produces a freshness-stamped passthrough; `posture()` is `Open`.
pub async fn open() -> TestNode {
    build("open").await
}

/// A **secured (Authenticated)** node — a CA is created so the node self-enrolls a
/// real leaf. `sign` produces an ES256-signed envelope; `posture()` is
/// `Authenticated`. The CA is created with `auto_unlock: false` (no vault write).
pub async fn secured() -> TestNode {
    // testkit is a test harness; keep CA creation off the OS keyring deterministically.
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let node = build("secured").await;
    let core = node
        .certmesh()
        .expect("testkit: certmesh enabled")
        .core()
        .expect("testkit: embedded certmesh core");
    core.create(koi_certmesh::protocol::CreateCaRequest {
        passphrase: "testkit-passphrase".to_string(),
        entropy_hex: "2a".repeat(32), // 32 bytes
        operator: None,
        enrollment_open: false,
        requires_approval: false,
        auto_unlock: false,
        totp_secret_hex: None,
    })
    .await
    .expect("testkit: create CA");
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_node_is_open_and_secured_node_is_authenticated() {
        let open = open().await;
        assert!(
            !open.certmesh().unwrap().posture().unwrap().signed,
            "open() must yield an Open node"
        );
        open.shutdown().await;

        let secured = secured().await;
        assert!(
            secured.certmesh().unwrap().posture().unwrap().signed,
            "secured() must yield an Authenticated node"
        );
        secured.shutdown().await;
    }
}
