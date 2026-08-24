//! Integration: embedded-instance webhook parity (ADR-028 D1 follow-up).
//!
//! Proves that a programmatically configured sink on a [`koi_embedded::Builder`]
//! receives the same signed deliveries as the daemon path — real TCP delivery of
//! a domain event emitted through the handle's DNS API, HMAC verified at
//! receive, envelope shape pinned, and `/v1/status` reporting parity.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koi_compose::webhook::{signature_header, WebhookSink};
use koi_config::state::DnsEntry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn temp_data_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "koi-webhook-embedded-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// One accepted request: (method, headers-lowercase, body-bytes).
struct CapturedRequest {
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn header<'a>(req: &'a CapturedRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

async fn serve_one_request(listener: &TcpListener) -> CapturedRequest {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).await.unwrap();
        assert!(n > 0, "peer closed before sending a full request");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap().to_string();
    let method = request_line.split_whitespace().next().unwrap().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).await.unwrap();
        assert!(n > 0, "peer closed mid-body");
        body.extend_from_slice(&chunk[..n]);
    }

    sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    CapturedRequest {
        method,
        headers,
        body,
    }
}

#[tokio::test]
async fn configured_sink_delivers_signed_domain_event_and_reports_in_status() {
    let secret = "embedded-parity-secret";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = listener.local_addr().unwrap();

    // mDNS off (no multicast), DNS enabled but never started (add_entry drives the
    // core directly, no port bind), HTTP on an ephemeral loopback port.
    let handle = koi_embedded::Builder::new()
        .data_dir(temp_data_dir())
        .service_mode(koi_embedded::ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(true)
        .health(false)
        .proxy(false)
        .udp(false)
        .certmesh(false)
        .http(true)
        .http_port(0)
        .dashboard(true)
        .webhooks(vec![WebhookSink {
            url: format!("http://{sink_addr}/hook"),
            secret: secret.to_string(),
            enabled: true,
        }])
        .build()
        .expect("build")
        .start()
        .await
        .expect("start");

    // Emit one domain event through the public handle API.
    handle
        .dns()
        .expect("dns handle")
        .add_entry(DnsEntry {
            name: "parity.internal".to_string(),
            ip: "10.0.0.7".to_string(),
            ttl: None,
        })
        .expect("add entry");

    // The fan-out must POST it to our sink with the exact wire contract.
    let req = tokio::time::timeout(Duration::from_secs(30), serve_one_request(&listener))
        .await
        .expect("delivery within timeout");

    assert_eq!(req.method, "POST");
    assert!(
        header(&req, "x-koi-event-id").is_some(),
        "every delivery carries its ADR-006 event id"
    );
    assert_eq!(
        header(&req, "x-koi-signature"),
        Some(signature_header(secret, &req.body).as_str()),
        "HMAC-SHA256 signature must verify against the shared sink secret"
    );
    assert_eq!(
        header(&req, "content-type"),
        Some("application/json"),
        "one wire contract: JSON body"
    );

    let envelope: serde_json::Value = serde_json::from_slice(&req.body).expect("envelope json");
    assert_eq!(envelope["v"], 1, "envelope version is pinned at 1");
    assert_eq!(envelope["event"]["type"], "dns.updated");
    assert_eq!(envelope["event"]["data"]["name"], "parity.internal");
    assert_eq!(
        envelope["provenance"]["zone"], "internal",
        "provenance zone is the instance's configured DNS zone"
    );
    assert!(
        envelope["provenance"]["node"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "provenance node is the hostname"
    );

    // /v1/status reports the outbound surface (transport-not-domain precedent).
    let port = handle.bound_http_port().expect("bound http port");
    let status: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/v1/status"))
        .await
        .expect("status get")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["webhooks"]["enabled"], true);
    assert_eq!(status["webhooks"]["sinks"], 1);

    handle.shutdown().await.expect("shutdown");
}
