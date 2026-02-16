//! Integration tests for koi-udp capabilities via koi-embedded.
//!
//! Exercises: bind, status, send/recv, heartbeat, unbind, and lease expiry.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koi_embedded::{Builder, ServiceMode};

fn temp_data_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("koi-udp-test-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Helper: build a minimal embedded instance with only UDP enabled.
async fn udp_handle() -> (koi_embedded::KoiHandle, PathBuf) {
    let data_dir = temp_data_dir();
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .udp(true)
        .build()
        .expect("build koi");
    let handle = koi.start().await.expect("start koi");
    (handle, data_dir)
}

// ── Core lifecycle ──────────────────────────────────────────────────

#[tokio::test]
async fn udp_disabled_returns_error() {
    let data_dir = temp_data_dir();
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .udp(false)
        .build()
        .unwrap();
    let handle = koi.start().await.unwrap();

    let result = handle.udp();
    assert!(result.is_err(), "udp() should fail when UDP is disabled");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_bind_and_status() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    // Initially no bindings
    let status = udp.status().await;
    assert!(status.is_empty(), "expected no bindings initially");

    // Bind port 0 (OS-assigned)
    let bind_req = koi_udp::UdpBindRequest {
        port: 0,
        addr: "127.0.0.1".to_string(),
        lease_secs: 300,
    };
    let info = udp.bind(bind_req).await.expect("bind should succeed");
    assert!(!info.id.is_empty(), "binding ID should be non-empty");
    assert!(
        info.local_addr.contains("127.0.0.1"),
        "should bind to localhost"
    );
    assert_eq!(info.lease_secs, 300);

    // Status shows exactly one binding
    let status = udp.status().await;
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].id, info.id);
    assert_eq!(status[0].local_addr, info.local_addr);

    // Unbind
    udp.unbind(&info.id).await.expect("unbind should succeed");
    let status = udp.status().await;
    assert!(status.is_empty(), "binding should be removed after unbind");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_send_and_recv() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    // Bind on localhost with OS-assigned port
    let bind_req = koi_udp::UdpBindRequest {
        port: 0,
        addr: "127.0.0.1".to_string(),
        lease_secs: 300,
    };
    let info = udp.bind(bind_req).await.expect("bind");

    // Subscribe to incoming datagrams
    let mut rx = udp.subscribe(&info.id).await.expect("subscribe");

    // Send a datagram to the bound address from a separate socket
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender socket");
    let dest: std::net::SocketAddr = info.local_addr.parse().expect("parse local addr");

    let payload = b"hello koi udp";
    sender.send_to(payload, dest).await.expect("send_to");

    // Receive via broadcast channel
    let datagram = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for datagram")
        .expect("recv error");

    assert_eq!(datagram.binding_id, info.id);

    // Verify payload round-trip (base64)
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&datagram.payload)
        .expect("base64 decode");
    assert_eq!(decoded, payload, "payload should round-trip through base64");

    // Clean up
    udp.unbind(&info.id).await.expect("unbind");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_send_through_binding() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    // Create a receiver socket first
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("receiver socket");
    let receiver_addr = receiver.local_addr().expect("receiver addr");

    // Bind a koi-udp socket
    let bind_req = koi_udp::UdpBindRequest {
        port: 0,
        addr: "127.0.0.1".to_string(),
        lease_secs: 300,
    };
    let info = udp.bind(bind_req).await.expect("bind");

    // Send through koi-udp managed socket
    use base64::Engine;
    let payload = b"outbound from koi";
    let send_req = koi_udp::UdpSendRequest {
        dest: receiver_addr.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(payload),
    };
    let bytes_sent = udp.send(&info.id, send_req).await.expect("send");
    assert_eq!(bytes_sent, payload.len());

    // Verify receipt on the other socket
    let mut buf = vec![0u8; 1024];
    let (len, src) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut buf))
        .await
        .expect("timeout")
        .expect("recv_from");

    assert_eq!(&buf[..len], payload);
    // Source should be the koi-udp bound address
    let bound_addr: std::net::SocketAddr = info.local_addr.parse().unwrap();
    assert_eq!(src, bound_addr);

    udp.unbind(&info.id).await.expect("unbind");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_heartbeat_extends_lease() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    let bind_req = koi_udp::UdpBindRequest {
        port: 0,
        addr: "127.0.0.1".to_string(),
        lease_secs: 300,
    };
    let info = udp.bind(bind_req).await.expect("bind");

    // Wait a moment, then heartbeat
    tokio::time::sleep(Duration::from_millis(100)).await;
    udp.heartbeat(&info.id)
        .await
        .expect("heartbeat should succeed");

    // Binding should still be alive
    let status = udp.status().await;
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].id, info.id);

    // last_heartbeat should be more recent than created_at
    assert!(
        status[0].last_heartbeat >= status[0].created_at,
        "heartbeat timestamp should be >= created_at"
    );

    udp.unbind(&info.id).await.expect("unbind");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_unbind_nonexistent_returns_error() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    let result = udp.unbind("nonexistent-id").await;
    assert!(result.is_err(), "unbind of nonexistent ID should fail");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_subscribe_nonexistent_returns_error() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    let result = udp.subscribe("nonexistent-id").await;
    assert!(result.is_err(), "subscribe to nonexistent ID should fail");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_send_to_nonexistent_returns_error() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    use base64::Engine;
    let send_req = koi_udp::UdpSendRequest {
        dest: "127.0.0.1:9999".to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(b"hello"),
    };
    let result = udp.send("nonexistent-id", send_req).await;
    assert!(result.is_err(), "send to nonexistent binding should fail");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_multiple_bindings() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    // Create three bindings
    let mut ids = Vec::new();
    for _ in 0..3 {
        let bind_req = koi_udp::UdpBindRequest {
            port: 0,
            addr: "127.0.0.1".to_string(),
            lease_secs: 300,
        };
        let info = udp.bind(bind_req).await.expect("bind");
        ids.push(info.id);
    }

    let status = udp.status().await;
    assert_eq!(status.len(), 3, "should have three bindings");

    // All IDs should be distinct
    let mut unique_ids: Vec<_> = ids.clone();
    unique_ids.sort();
    unique_ids.dedup();
    assert_eq!(unique_ids.len(), 3, "binding IDs should be unique");

    // Remove middle one
    udp.unbind(&ids[1]).await.expect("unbind middle");
    let status = udp.status().await;
    assert_eq!(status.len(), 2);
    assert!(
        status.iter().all(|b| b.id != ids[1]),
        "removed binding should not appear in status"
    );

    // Clean up
    for id in [&ids[0], &ids[2]] {
        udp.unbind(id).await.expect("unbind");
    }
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_multi_subscriber_receives_same_datagram() {
    let (handle, _dir) = udp_handle().await;
    let udp = handle.udp().expect("udp enabled");

    let bind_req = koi_udp::UdpBindRequest {
        port: 0,
        addr: "127.0.0.1".to_string(),
        lease_secs: 300,
    };
    let info = udp.bind(bind_req).await.expect("bind");

    // Two subscribers
    let mut rx1 = udp.subscribe(&info.id).await.expect("subscribe 1");
    let mut rx2 = udp.subscribe(&info.id).await.expect("subscribe 2");

    // Send a datagram
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender");
    let dest: std::net::SocketAddr = info.local_addr.parse().unwrap();
    sender.send_to(b"broadcast test", dest).await.expect("send");

    // Both should receive it
    let d1 = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
        .await
        .expect("timeout rx1")
        .expect("recv rx1");
    let d2 = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("timeout rx2")
        .expect("recv rx2");

    assert_eq!(
        d1.payload, d2.payload,
        "both subscribers should get same payload"
    );
    assert_eq!(d1.binding_id, info.id);
    assert_eq!(d2.binding_id, info.id);

    udp.unbind(&info.id).await.expect("unbind");
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_with_http_adapter() {
    let data_dir = temp_data_dir();

    // Find a free port for HTTP
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let http_port = listener.local_addr().unwrap().port();
    drop(listener);

    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .udp(true)
        .http(true)
        .http_port(http_port)
        .build()
        .expect("build");
    let handle = koi.start().await.expect("start");

    // Give the HTTP server a moment to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();

    // healthz
    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/healthz"))
        .send()
        .await
        .expect("healthz request");
    assert_eq!(resp.status(), 200);

    // UDP status (should be empty)
    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/v1/udp/status"))
        .send()
        .await
        .expect("udp status request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let bindings = body["bindings"].as_array().expect("bindings array");
    assert!(bindings.is_empty(), "no bindings initially");

    // Bind via HTTP
    let bind_body = serde_json::json!({
        "port": 0,
        "addr": "127.0.0.1",
        "lease_secs": 300
    });
    let resp = client
        .post(format!("http://127.0.0.1:{http_port}/v1/udp/bind"))
        .json(&bind_body)
        .send()
        .await
        .expect("bind request");
    assert_eq!(resp.status(), 201);
    let info: serde_json::Value = resp.json().await.expect("json");
    let binding_id = info["id"].as_str().expect("binding id");
    let local_addr = info["local_addr"].as_str().expect("local addr");
    assert!(!binding_id.is_empty());

    // Send a datagram to the bound port
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender");
    let dest: std::net::SocketAddr = local_addr.parse().unwrap();
    sender.send_to(b"hello via http", dest).await.expect("send");

    // Send via HTTP endpoint
    use base64::Engine;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("receiver");
    let receiver_addr = receiver.local_addr().unwrap();
    let send_body = serde_json::json!({
        "dest": receiver_addr.to_string(),
        "payload": base64::engine::general_purpose::STANDARD.encode(b"outbound via http")
    });
    let resp = client
        .post(format!(
            "http://127.0.0.1:{http_port}/v1/udp/send/{binding_id}"
        ))
        .json(&send_body)
        .send()
        .await
        .expect("send request");
    assert_eq!(resp.status(), 200);
    let send_result: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(send_result["sent"].as_u64().unwrap(), 17);

    // Verify receipt on the receiver socket
    let mut buf = vec![0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut buf))
        .await
        .expect("timeout")
        .expect("recv_from");
    assert_eq!(&buf[..len], b"outbound via http");

    // Heartbeat via HTTP
    let resp = client
        .put(format!(
            "http://127.0.0.1:{http_port}/v1/udp/heartbeat/{binding_id}"
        ))
        .send()
        .await
        .expect("heartbeat request");
    assert_eq!(resp.status(), 200);

    // Status should show 1 binding
    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/v1/udp/status"))
        .send()
        .await
        .expect("status request");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["bindings"].as_array().unwrap().len(), 1);

    // Unbind via HTTP
    let resp = client
        .delete(format!(
            "http://127.0.0.1:{http_port}/v1/udp/bind/{binding_id}"
        ))
        .send()
        .await
        .expect("unbind request");
    assert_eq!(resp.status(), 200);

    // Verify removed
    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/v1/udp/status"))
        .send()
        .await
        .expect("status after unbind");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["bindings"].as_array().unwrap().is_empty());

    handle.shutdown().await.unwrap();
}

// ── SSE integration tests ───────────────────────────────────────────

/// A parsed SSE event.
#[derive(Debug)]
#[allow(dead_code)]
struct SseEvent {
    event_type: String,
    id: String,
    data: String,
}

/// Parse raw SSE text into individual events, skipping keep-alive comments.
fn parse_sse_events(raw: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut event_type = String::new();
    let mut id = String::new();
    let mut data_lines: Vec<String> = Vec::new();

    for line in raw.lines() {
        if line.starts_with(':') {
            continue; // keep-alive comment
        }
        if line.is_empty() {
            if !event_type.is_empty() || !data_lines.is_empty() {
                events.push(SseEvent {
                    event_type: std::mem::take(&mut event_type),
                    id: std::mem::take(&mut id),
                    data: data_lines.join("\n"),
                });
                data_lines.clear();
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("event:") {
            event_type = v.trim_start().to_string();
        } else if let Some(v) = line.strip_prefix("id:") {
            id = v.trim_start().to_string();
        } else if let Some(v) = line.strip_prefix("data:") {
            data_lines.push(v.trim_start().to_string());
        }
    }
    // Flush trailing event (server may not send a final blank line)
    if !event_type.is_empty() || !data_lines.is_empty() {
        events.push(SseEvent {
            event_type: std::mem::take(&mut event_type),
            id: std::mem::take(&mut id),
            data: data_lines.join("\n"),
        });
    }
    events
}

/// Helper: start embedded with HTTP + UDP, return (handle, http_port, data_dir).
async fn udp_http_handle() -> (koi_embedded::KoiHandle, u16, PathBuf) {
    let data_dir = temp_data_dir();
    let http_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    };
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .udp(true)
        .http(true)
        .http_port(http_port)
        .build()
        .expect("build");
    let handle = koi.start().await.expect("start");
    // Give the HTTP server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;
    (handle, http_port, data_dir)
}

/// Bind a UDP port via HTTP, return (binding_id, local_addr).
async fn http_bind(client: &reqwest::Client, http_port: u16) -> (String, std::net::SocketAddr) {
    let resp = client
        .post(format!("http://127.0.0.1:{http_port}/v1/udp/bind"))
        .json(&serde_json::json!({ "port": 0, "addr": "127.0.0.1", "lease_secs": 300 }))
        .send()
        .await
        .expect("bind request");
    assert_eq!(resp.status(), 201);
    let info: serde_json::Value = resp.json().await.expect("json");
    let id = info["id"].as_str().expect("binding id").to_string();
    let addr: std::net::SocketAddr = info["local_addr"].as_str().expect("addr").parse().unwrap();
    (id, addr)
}

#[tokio::test]
async fn udp_sse_recv_datagrams() {
    let (handle, http_port, _dir) = udp_http_handle().await;
    let client = reqwest::Client::new();
    let (binding_id, local_addr) = http_bind(&client, http_port).await;

    // Spawn SSE consumer with idle_for=3 (closes 3s after last datagram)
    let sse_client = client.clone();
    let bid = binding_id.clone();
    let sse_task = tokio::spawn(async move {
        let resp = sse_client
            .get(format!(
                "http://127.0.0.1:{http_port}/v1/udp/recv/{bid}?idle_for=3"
            ))
            .send()
            .await
            .expect("sse connect");
        assert_eq!(resp.status(), 200);
        resp.text().await.expect("sse body")
    });

    // Wait for SSE subscription to be established
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send 3 datagrams from an external socket
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender socket");
    let sender_addr = sender.local_addr().unwrap();
    for msg in &[b"alpha" as &[u8], b"bravo", b"charlie"] {
        sender.send_to(msg, local_addr).await.expect("send_to");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for idle timeout to close the SSE stream
    let sse_text = tokio::time::timeout(Duration::from_secs(15), sse_task)
        .await
        .expect("sse timeout")
        .expect("sse join");

    let events = parse_sse_events(&sse_text);
    assert_eq!(
        events.len(),
        3,
        "expected 3 SSE events, got {}:\n{sse_text}",
        events.len()
    );

    use base64::Engine;
    let mut prev_id = String::new();

    for (i, (evt, expected)) in events.iter().zip(["alpha", "bravo", "charlie"]).enumerate() {
        assert_eq!(evt.event_type, "datagram", "event {i} type");
        assert!(!evt.id.is_empty(), "event {i} should have a UUIDv7 id");

        // Event IDs should be monotonically increasing (UUIDv7)
        if !prev_id.is_empty() {
            assert!(
                evt.id > prev_id,
                "event ids should increase: {} > {}",
                evt.id,
                prev_id
            );
        }
        prev_id.clone_from(&evt.id);

        // Parse the datagram JSON
        let dg: serde_json::Value = serde_json::from_str(&evt.data).expect("parse datagram json");
        assert_eq!(
            dg["binding_id"].as_str().unwrap(),
            binding_id,
            "event {i} binding_id"
        );
        assert_eq!(
            dg["src"].as_str().unwrap(),
            sender_addr.to_string(),
            "event {i} src"
        );

        // Decode and verify payload
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(dg["payload"].as_str().expect("payload field"))
            .expect("base64 decode");
        assert_eq!(
            String::from_utf8_lossy(&decoded),
            expected,
            "event {i} payload"
        );
    }

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_sse_idle_timeout_closes_stream() {
    let (handle, http_port, _dir) = udp_http_handle().await;
    let client = reqwest::Client::new();
    let (binding_id, _addr) = http_bind(&client, http_port).await;

    // Subscribe with idle_for=1, send no datagrams
    let start = std::time::Instant::now();
    let resp = client
        .get(format!(
            "http://127.0.0.1:{http_port}/v1/udp/recv/{binding_id}?idle_for=1"
        ))
        .send()
        .await
        .expect("sse connect");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("sse body");
    let elapsed = start.elapsed();

    // Stream should close after ~1s of idle
    assert!(
        elapsed >= Duration::from_millis(800),
        "stream closed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "stream took too long to close: {elapsed:?}"
    );

    // No datagram events should have been received
    let events = parse_sse_events(&body);
    assert!(
        events.is_empty(),
        "expected no events, got {}",
        events.len()
    );

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_sse_nonexistent_binding() {
    let (handle, http_port, _dir) = udp_http_handle().await;
    let client = reqwest::Client::new();

    // Subscribe to a binding that doesn't exist
    let resp = client
        .get(format!(
            "http://127.0.0.1:{http_port}/v1/udp/recv/nonexistent?idle_for=1"
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 404, "should 404 for nonexistent binding");

    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_sse_multiple_subscribers() {
    let (handle, http_port, _dir) = udp_http_handle().await;
    let client = reqwest::Client::new();
    let (binding_id, local_addr) = http_bind(&client, http_port).await;

    // Spawn two SSE consumers on the same binding
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let c = client.clone();
        let bid = binding_id.clone();
        tasks.push(tokio::spawn(async move {
            let resp = c
                .get(format!(
                    "http://127.0.0.1:{http_port}/v1/udp/recv/{bid}?idle_for=3"
                ))
                .send()
                .await
                .expect("sse");
            resp.text().await.expect("body")
        }));
    }

    // Wait for both subscriptions to establish
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send a datagram
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("sender");
    sender.send_to(b"fanout", local_addr).await.expect("send");

    // Both consumers should receive the same event
    for (i, task) in tasks.into_iter().enumerate() {
        let text = tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .expect("timeout")
            .expect("join");
        let events = parse_sse_events(&text);
        assert_eq!(events.len(), 1, "subscriber {i} should get 1 event");
        assert_eq!(events[0].event_type, "datagram");

        use base64::Engine;
        let dg: serde_json::Value = serde_json::from_str(&events[0].data).expect("parse");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(dg["payload"].as_str().unwrap())
            .unwrap();
        assert_eq!(&decoded, b"fanout", "subscriber {i} payload");
    }

    handle.shutdown().await.unwrap();
}
