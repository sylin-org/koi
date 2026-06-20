//! ADR-020 §2 acceptance gate — the **same consumer code path runs green in both
//! postures**. This is the structural guard against re-introducing a posture leak:
//! if any primitive forced an `if secure { … } else { … }`, the identical body
//! below could not pass against both an Open and a Secured node.
//!
//! Runs in CI via `cargo test` (no Docker — `koi_embedded::testkit` spins real
//! embedded daemons).

use koi_embedded::testkit;

#[tokio::test]
async fn same_consumer_code_runs_in_both_postures() {
    for node in [testkit::open().await, testkit::secured().await] {
        let cm = node.certmesh().expect("certmesh handle");

        // ── sign → verify (ADR-020 §3) — ONE code path ──
        // Open: a freshness-stamped passthrough → Anonymous. Authenticated: ES256
        // signed → Authenticated. Both are "not rejected"; the consumer keys off the
        // assurance, never on a posture branch.
        let env = cm.sign(b"hello, mesh").await.expect("sign");
        let assurance = cm.verify(&env).await.expect("verify");
        assert!(
            !assurance.is_rejected(),
            "verify must accept our own envelope in any posture (got {assurance:?})"
        );

        // ── seal → open (ADR-020 §4) — ONE code path ──
        let sealed = cm.seal(b"a secret").await.expect("seal");
        let opened = cm.open(&sealed).await.expect("open");
        assert_eq!(
            opened.payload, b"a secret",
            "seal/open must round-trip in any posture"
        );

        // ── diagnose (ADR-020 §13) — never errors, never RED for a fresh node ──
        let diagnosis = cm.diagnose().await.expect("diagnose");
        assert!(
            !diagnosis.is_red(),
            "a freshly-built node must not diagnose RED (got {diagnosis:?})"
        );

        node.shutdown().await;
    }
}
