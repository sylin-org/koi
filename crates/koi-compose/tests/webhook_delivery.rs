//! Integration: the webhook fan-out delivers over a real TCP socket with exact
//! headers, envelope shape, and bounded retry on server failure (ADR-028).
//!
//! The sink is a hand-rolled HTTP/1.1 listener on loopback — no web framework,
//! just enough server to capture one request's head + body per connection.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use koi_compose::webhook::{
    signature_header, spawn_webhook_fanout, WebhookProvenance, WebhookSink,
};
use koi_dashboard::dashboard::DashboardSseEvent;
use tokio_util::sync::CancellationToken;

fn sse(id: &str, event_type: &str, data: serde_json::Value) -> DashboardSseEvent {
    DashboardSseEvent {
        event_type: event_type.to_string(),
        id: id.to_string(),
        data,
    }
}

fn provenance() -> WebhookProvenance {
    WebhookProvenance {
        node: "test-node".to_string(),
        zone: "internal".to_string(),
    }
}

/// One accepted request: (method, path, headers-lowercase, body-bytes).
struct CapturedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn header<'a>(req: &'a CapturedRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

async fn serve_one_request(listener: &TcpListener, status_line: &str) -> CapturedRequest {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    // Read until end of head, then honor Content-Length.
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
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().to_string();
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

    sock.write_all(
        format!("{status_line}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    sock.flush().await.unwrap();

    CapturedRequest {
        method,
        path,
        headers,
        body,
    }
}

#[tokio::test]
async fn delivers_signed_event_with_exact_headers_and_envelope() {
    let secret = "integration-sink-secret";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, _keep_alive) = broadcast::channel::<DashboardSseEvent>(16);
    let cancel = CancellationToken::new();
    let handles = spawn_webhook_fanout(
        &tx,
        vec![WebhookSink {
            url: format!("http://{addr}/hook"),
            secret: secret.to_string(),
            enabled: true,
        }],
        provenance(),
        None,
        cancel.clone(),
    );
    assert_eq!(handles.len(), 1, "one enabled sink spawns one worker");

    let ev = sse(
        "018f-test-0001",
        "health.changed",
        serde_json::json!({ "name": "grafana", "status": "down" }),
    );
    tx.send(ev.clone()).unwrap();

    let req = tokio::time::timeout(
        Duration::from_secs(10),
        serve_one_request(&listener, "HTTP/1.1 200 OK"),
    )
    .await
    .expect("delivery within timeout");

    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/hook");
    assert_eq!(header(&req, "x-koi-event-id"), Some(ev.id.as_str()));
    assert_eq!(
        header(&req, "x-koi-signature"),
        Some(signature_header(secret, &req.body).as_str()),
        "signature must verify against the delivered body"
    );
    assert_eq!(header(&req, "content-type"), Some("application/json"));

    let parsed: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(parsed["v"], 1);
    assert_eq!(parsed["event"]["id"], ev.id);
    assert_eq!(parsed["event"]["type"], "health.changed");
    assert_eq!(parsed["event"]["data"]["name"], "grafana");
    assert_eq!(parsed["provenance"]["node"], "test-node");
    assert_eq!(parsed["provenance"]["zone"], "internal");
    // Signature must NOT verify under a different secret (negative control).
    assert_ne!(
        header(&req, "x-koi-signature"),
        Some(signature_header("wrong-secret", &req.body).as_str())
    );

    cancel.cancel();
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn retries_after_server_failure_and_succeeds() {
    let secret = "retry-secret";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, _keep_alive) = broadcast::channel::<DashboardSseEvent>(16);
    let cancel = CancellationToken::new();
    let handles = spawn_webhook_fanout(
        &tx,
        vec![WebhookSink {
            url: format!("http://{addr}/hook"),
            secret: secret.to_string(),
            enabled: true,
        }],
        provenance(),
        None,
        cancel.clone(),
    );

    tx.send(sse(
        "018f-test-0002",
        "mdns.found",
        serde_json::json!({ "name": "svc" }),
    ))
    .unwrap();

    // First attempt fails server-side...
    let failed = tokio::time::timeout(
        Duration::from_secs(10),
        serve_one_request(&listener, "HTTP/1.1 500 No"),
    )
    .await
    .expect("first attempt within timeout");
    // ...second attempt (after bounded backoff) succeeds.
    let retried = tokio::time::timeout(
        Duration::from_secs(15),
        serve_one_request(&listener, "HTTP/1.1 200 OK"),
    )
    .await
    .expect("retried attempt within timeout");

    assert_eq!(
        failed.headers.iter().find(|(k, _)| k == "x-koi-event-id"),
        retried.headers.iter().find(|(k, _)| k == "x-koi-event-id"),
        "retry must carry the same event id"
    );
    assert_eq!(failed.body, retried.body, "retry must carry the same body");

    cancel.cancel();
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn disabled_sink_spawns_nothing_and_events_are_not_delivered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, _keep_alive) = broadcast::channel::<DashboardSseEvent>(16);
    let cancel = CancellationToken::new();
    let handles = spawn_webhook_fanout(
        &tx,
        vec![
            WebhookSink {
                url: format!("http://{addr}/off"),
                secret: "s".into(),
                enabled: false,
            },
            WebhookSink {
                url: "http://192.0.2.1/impossible".into(),
                secret: "s".into(),
                enabled: false,
            },
        ],
        provenance(),
        None,
        cancel.clone(),
    );
    assert!(handles.is_empty(), "no enabled sinks → no workers");

    tx.send(sse("018f-test-0003", "dns.updated", serde_json::json!({})))
        .unwrap();

    // Nothing should connect: a short accept attempt must time out.
    let result = tokio::time::timeout(Duration::from_millis(700), listener.accept()).await;
    assert!(result.is_err(), "disabled sink must not be contacted");

    cancel.cancel();
}
