//! Embedded HTTP ephemeral-port binding (`Builder::http_port(0)`).
//!
//! The root fix for the ephemeral-port test races: passing port 0 binds an
//! OS-assigned free port and `KoiHandle::bound_http_port()` reports it. There is
//! no probe → drop → re-bind TOCTOU, so parallel instances need no shared guard
//! (contrast the `PORT_GUARD` workaround in `udp.rs`).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use koi_embedded::{Builder, ServiceMode};

fn temp_data_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("koi-http-eph-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

async fn start_ephemeral(tag: &str) -> (koi_embedded::KoiHandle, PathBuf) {
    let dir = temp_data_dir(tag);
    let koi = Builder::new()
        .data_dir(&dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .http(true)
        .http_port(0)
        .build()
        .expect("build");
    let handle = koi.start().await.expect("start");
    (handle, dir)
}

#[tokio::test]
async fn http_port_zero_binds_ephemeral_and_reports_it() {
    let (handle, _dir) = start_ephemeral("single").await;

    let port = handle
        .bound_http_port()
        .expect("an ephemeral port must be reported after start");
    assert_ne!(
        port, 0,
        "the reported port must be the OS-assigned one, not 0"
    );
    assert_eq!(handle.http_addr().map(|a| a.port()), Some(port));

    // `bound_http_port()` is only `Some` once the listener reported its address,
    // so the server is bound when `start()` returns — no readiness sleep / probe.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .expect("healthz request");
    assert_eq!(resp.status(), 200);

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn two_ephemeral_instances_get_distinct_ports_without_a_guard() {
    // The whole point of the root fix: no PORT_GUARD, no probe-and-drop race —
    // each instance binds its own OS-assigned port concurrently.
    let (a, _da) = start_ephemeral("a").await;
    let (b, _db) = start_ephemeral("b").await;

    let pa = a.bound_http_port().expect("a bound");
    let pb = b.bound_http_port().expect("b bound");
    assert_ne!(pa, 0);
    assert_ne!(pb, 0);
    assert_ne!(pa, pb, "two ephemeral instances must bind different ports");

    a.shutdown().await.expect("shutdown a");
    b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn announce_http_without_token_fails_closed() {
    // Secure-by-default: exposing the HTTP adapter on 0.0.0.0 (announce_http) with
    // no token must error at start() — before any socket is bound — rather than
    // silently serving unauthenticated mutations to the LAN. (No bind happens, so
    // this never opens a non-loopback port.)
    let dir = temp_data_dir("insecure-expose");
    let result = Builder::new()
        .data_dir(&dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .http(true)
        .announce_http(true)
        .build()
        .expect("build")
        .start()
        .await;
    assert!(
        matches!(result, Err(koi_embedded::KoiError::InsecureConfig(_))),
        "exposed-without-token must fail closed"
    );
}

#[tokio::test]
async fn http_disabled_reports_no_bound_port() {
    let dir = temp_data_dir("disabled");
    let koi = Builder::new()
        .data_dir(&dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .http(false)
        .build()
        .expect("build");
    let handle = koi.start().await.expect("start");
    assert_eq!(handle.bound_http_port(), None);
    assert_eq!(handle.http_addr(), None);
    handle.shutdown().await.expect("shutdown");
}
