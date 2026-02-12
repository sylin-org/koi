use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use koi_config::state::DnsEntry;
use koi_embedded::{Builder, KoiEvent, ServiceMode};
use koi_health::{HealthCheck, ServiceCheckKind, ServiceStatus};
use koi_mdns::protocol::{RegisterPayload, Request as MdnsRequest};
use koi_proxy::ProxyEntry;

struct Harness {
    passed: usize,
    failed: usize,
    skipped: usize,
    verbose: bool,
}

impl Harness {
    fn new(verbose: bool) -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            verbose,
        }
    }

    fn log(&self, msg: impl AsRef<str>) {
        if self.verbose {
            println!("  {}", msg.as_ref());
        }
    }

    fn pass(&mut self, name: &str) {
        self.passed += 1;
        println!("[PASS] {name}");
    }

    fn fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        println!("[FAIL] {name} - {reason}");
    }

    #[allow(dead_code)]
    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        println!("[SKIP] {name} - {reason}");
    }

    fn summary(&self) {
        println!(
            "\nSummary: {} passed, {} failed, {} skipped",
            self.passed, self.failed, self.skipped
        );
    }
}

#[cfg(windows)]
async fn open_pipe(
    pipe_name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, Box<dyn std::error::Error>> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut last_err = None;
    for _ in 0..20 {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(Box::new(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "pipe not available")
    })))
}

#[cfg(windows)]
async fn ipc_send<R, W>(
    reader: &mut tokio::io::Lines<tokio::io::BufReader<R>>,
    writer: &mut W,
    value: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    writer
        .write_all(serde_json::to_string(&value)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    let line = reader.next_line().await?.ok_or("empty response")?;
    let value: serde_json::Value = serde_json::from_str(&line)?;
    Ok(value)
}

fn temp_data_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("koi-embedded-integration-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn read_arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

async fn wait_for_event<F>(
    rx: &mut tokio::sync::broadcast::Receiver<KoiEvent>,
    timeout: Duration,
    predicate: F,
) -> Option<KoiEvent>
where
    F: Fn(&KoiEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => {
                if predicate(&event) {
                    return Some(event);
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return None,
            Err(_) => return None,
        }
    }
}

async fn start_http_server(
    mdns: std::sync::Arc<koi_mdns::MdnsCore>,
    dns: std::sync::Arc<koi_dns::DnsRuntime>,
    health: std::sync::Arc<koi_health::HealthCore>,
    certmesh: std::sync::Arc<koi_certmesh::CertmeshCore>,
    proxy: std::sync::Arc<koi_proxy::ProxyRuntime>,
) -> Result<(SocketAddr, CancellationToken), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        )
        .nest("/v1/mdns", koi_mdns::http::routes(mdns))
        .nest("/v1/dns", koi_dns::http::routes(dns))
        .nest("/v1/health", koi_health::http::routes(health))
        .nest("/v1/certmesh", certmesh.http_routes())
        .nest("/v1/proxy", koi_proxy::http::routes(proxy));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(token.cancelled_owned())
            .await;
    });

    Ok((addr, cancel))
}

async fn read_sse_body(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(url).send().await?;
    let body = tokio::time::timeout(timeout, response.text()).await??;
    Ok(body)
}

async fn run_http_tests(
    base_url: &str,
    client: &reqwest::Client,
    harness: &mut Harness,
) -> Result<(), Box<dyn std::error::Error>> {
    let health: serde_json::Value = client
        .get(format!("{base_url}/healthz"))
        .send()
        .await?
        .json()
        .await?;
    if health.get("ok") == Some(&serde_json::Value::Bool(true)) {
        harness.pass("http: healthz ok");
    } else {
        harness.fail("http: healthz ok", "unexpected response");
    }

    let mdns_payload = serde_json::json!({
        "name": "koi-http-test",
        "type": "_koi._tcp",
        "port": 51516,
        "ip": "127.0.0.1",
        "lease_secs": 30,
        "txt": {"source": "http"}
    });
    let register_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/mdns/services"))
        .json(&mdns_payload)
        .send()
        .await?
        .json()
        .await?;
    let mdns_id = register_resp
        .get("registered")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if mdns_id.is_some() {
        harness.pass("http: mdns register");
    } else {
        harness.fail("http: mdns register", "missing registered id");
    }

    let resolve_resp: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/mdns/resolve?name=koi-http-test._koi._tcp.local."
        ))
        .send()
        .await?
        .json()
        .await?;
    if resolve_resp.get("resolved").is_some() {
        harness.pass("http: mdns resolve");
    } else {
        harness.fail("http: mdns resolve", "missing resolved response");
    }

    let events_url = format!("{base_url}/v1/mdns/events?type=_koi._tcp&idle_for=1");
    let sse_payload = serde_json::json!({
        "name": "koi-http-sse",
        "type": "_koi._tcp",
        "port": 51518,
        "ip": "127.0.0.1",
        "lease_secs": 30,
        "txt": {"source": "http-sse"}
    });
    let sse_future = read_sse_body(client, &events_url, Duration::from_secs(3));
    let register_future = client
        .post(format!("{base_url}/v1/mdns/services"))
        .json(&sse_payload)
        .send();
    let (events_body, register_result) = tokio::join!(sse_future, register_future);
    let _ = register_result?;
    let events_body = events_body?;
    if events_body.contains("data:") {
        harness.pass("http: mdns events sse");
    } else {
        harness.fail("http: mdns events sse", "no sse data received");
    }

    if let Some(id) = mdns_id {
        let unregister_resp: serde_json::Value = client
            .delete(format!("{base_url}/v1/mdns/services/{id}"))
            .send()
            .await?
            .json()
            .await?;
        if unregister_resp.get("unregistered").is_some() {
            harness.pass("http: mdns unregister");
        } else {
            harness.fail("http: mdns unregister", "missing unregistered response");
        }
    }

    let dns_entry = serde_json::json!({
        "name": "http-test",
        "ip": "127.0.0.1",
        "ttl": null
    });
    let add_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/dns/entries"))
        .json(&dns_entry)
        .send()
        .await?
        .json()
        .await?;
    if add_resp.get("entries").is_some() {
        harness.pass("http: dns add entry");
    } else {
        harness.fail("http: dns add entry", "missing entries response");
    }

    let lookup_resp: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/dns/lookup?name=http-test.lan&type=A"
        ))
        .send()
        .await?
        .json()
        .await?;
    if lookup_resp.get("ips").is_some() {
        harness.pass("http: dns lookup");
    } else {
        harness.fail("http: dns lookup", "missing lookup response");
    }

    let list_resp: serde_json::Value = client
        .get(format!("{base_url}/v1/dns/list"))
        .send()
        .await?
        .json()
        .await?;
    if list_resp
        .get("names")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|name| name == "http-test.lan."))
        .unwrap_or(false)
    {
        harness.pass("http: dns list names");
    } else {
        harness.fail("http: dns list names", "name missing from list");
    }

    let start_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/dns/admin/start"))
        .send()
        .await?
        .json()
        .await?;
    if start_resp.get("started").is_some() {
        harness.pass("http: dns start");
    } else {
        harness.fail("http: dns start", "missing started response");
    }

    let stop_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/dns/admin/stop"))
        .send()
        .await?
        .json()
        .await?;
    if stop_resp.get("stopped").is_some() {
        harness.pass("http: dns stop");
    } else {
        harness.fail("http: dns stop", "missing stopped response");
    }

    let remove_resp: serde_json::Value = client
        .delete(format!("{base_url}/v1/dns/entries/http-test"))
        .send()
        .await?
        .json()
        .await?;
    if remove_resp.get("entries").is_some() {
        harness.pass("http: dns remove entry");
    } else {
        harness.fail("http: dns remove entry", "missing entries response");
    }

    let health_add = serde_json::json!({
        "name": "http-tcp",
        "kind": "tcp",
        "target": "127.0.0.1:9",
        "interval_secs": 1,
        "timeout_secs": 1
    });
    let health_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/health/checks"))
        .json(&health_add)
        .send()
        .await?
        .json()
        .await?;
    if health_resp.get("status") == Some(&serde_json::Value::String("ok".to_string())) {
        harness.pass("http: health add check");
    } else {
        harness.fail("http: health add check", "unexpected response");
    }

    let checks_resp: serde_json::Value = client
        .get(format!("{base_url}/v1/health/checks"))
        .send()
        .await?
        .json()
        .await?;
    if checks_resp.get("checks").is_some() {
        harness.pass("http: health list checks");
    } else {
        harness.fail("http: health list checks", "missing checks response");
    }

    let remove_health: serde_json::Value = client
        .delete(format!("{base_url}/v1/health/checks/http-tcp"))
        .send()
        .await?
        .json()
        .await?;
    if remove_health.get("status") == Some(&serde_json::Value::String("ok".to_string())) {
        harness.pass("http: health remove check");
    } else {
        harness.fail("http: health remove check", "unexpected response");
    }

    let proxy_payload = serde_json::json!({
        "name": "http-proxy",
        "listen_port": 18090,
        "backend": "http://127.0.0.1:18091",
        "allow_remote": false
    });
    let proxy_resp: serde_json::Value = client
        .post(format!("{base_url}/v1/proxy/entries"))
        .json(&proxy_payload)
        .send()
        .await?
        .json()
        .await?;
    if proxy_resp.get("status") == Some(&serde_json::Value::String("ok".to_string())) {
        harness.pass("http: proxy add entry");
    } else {
        harness.fail("http: proxy add entry", "unexpected response");
    }

    let proxy_entries: serde_json::Value = client
        .get(format!("{base_url}/v1/proxy/entries"))
        .send()
        .await?
        .json()
        .await?;
    if proxy_entries.get("entries").is_some() {
        harness.pass("http: proxy list entries");
    } else {
        harness.fail("http: proxy list entries", "missing entries response");
    }

    let proxy_remove: serde_json::Value = client
        .delete(format!("{base_url}/v1/proxy/entries/http-proxy"))
        .send()
        .await?
        .json()
        .await?;
    if proxy_remove.get("status") == Some(&serde_json::Value::String("ok".to_string())) {
        harness.pass("http: proxy remove entry");
    } else {
        harness.fail("http: proxy remove entry", "unexpected response");
    }

    let entropy_hex = koi_common::encoding::hex_encode(&[42u8; 32]);
    let certmesh_payload = serde_json::json!({
        "passphrase": "http-test-pass",
        "entropy_hex": entropy_hex,
        "profile": "just_me"
    });
    let certmesh_create: serde_json::Value = client
        .post(format!("{base_url}/v1/certmesh/create"))
        .json(&certmesh_payload)
        .send()
        .await?
        .json()
        .await?;
    if certmesh_create.get("totp_uri").is_some() {
        harness.pass("http: certmesh create");
    } else {
        harness.fail("http: certmesh create", "missing totp_uri");
    }

    let status: serde_json::Value = client
        .get(format!("{base_url}/v1/certmesh/status"))
        .send()
        .await?
        .json()
        .await?;
    if status.get("ca_initialized") == Some(&serde_json::Value::Bool(true)) {
        harness.pass("http: certmesh status");
    } else {
        harness.fail("http: certmesh status", "unexpected status");
    }

    let _ = client
        .post(format!("{base_url}/v1/certmesh/enrollment/open"))
        .json(&serde_json::json!({"deadline": null}))
        .send()
        .await?;
    let _ = client
        .post(format!("{base_url}/v1/certmesh/enrollment/close"))
        .send()
        .await?;
    harness.pass("http: certmesh enrollment open/close");

    let _ = client
        .put(format!("{base_url}/v1/certmesh/policy"))
        .json(&serde_json::json!({"allowed_domain": "example.com", "allowed_subnet": null}))
        .send()
        .await?;
    harness.pass("http: certmesh set policy");

    let rotate: serde_json::Value = client
        .post(format!("{base_url}/v1/certmesh/rotate-totp"))
        .json(&serde_json::json!({"passphrase": "http-test-pass"}))
        .send()
        .await?
        .json()
        .await?;
    if rotate.get("totp_uri").is_some() {
        harness.pass("http: certmesh rotate totp");
    } else {
        harness.fail("http: certmesh rotate totp", "missing totp_uri");
    }

    let destroy: serde_json::Value = client
        .post(format!("{base_url}/v1/certmesh/destroy"))
        .send()
        .await?
        .json()
        .await?;
    if destroy.get("destroyed") == Some(&serde_json::Value::Bool(true)) {
        harness.pass("http: certmesh destroy");
    } else {
        harness.fail("http: certmesh destroy", "unexpected response");
    }

    Ok(())
}

#[cfg(windows)]
async fn run_ipc_tests(
    mdns: std::sync::Arc<koi_mdns::MdnsCore>,
    harness: &mut Harness,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = format!(
        "\\\\.\\pipe\\koi-embedded-ipc-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let cancel = CancellationToken::new();
    let server_core = mdns.clone();
    let server_cancel = cancel.clone();
    let pipe_name_clone = pipe_name.clone();

    let server = tokio::spawn(async move {
        loop {
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(pipe_name_clone.as_str());
            let server = match server {
                Ok(server) => server,
                Err(_) => break,
            };

            tokio::select! {
                result = server.connect() => {
                    if result.is_err() {
                        continue;
                    }
                    let core = server_core.clone();
                    tokio::spawn(async move {
                        let (reader, mut writer) = tokio::io::split(server);
                        let reader = BufReader::new(reader);
                        let mut lines = reader.lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            let request: serde_json::Result<MdnsRequest> = serde_json::from_str(line);
                            let response = match request {
                                Ok(MdnsRequest::Register(payload)) => {
                                    let policy = koi_mdns::LeasePolicy::Session {
                                        grace: Duration::from_secs(30),
                                    };
                                    match core.register_with_policy(payload, policy, None) {
                                        Ok(result) => koi_mdns::protocol::MdnsPipelineResponse::clean(
                                            koi_mdns::protocol::Response::Registered(result),
                                        ),
                                        Err(err) => koi_mdns::protocol::error_to_pipeline(&err),
                                    }
                                }
                                Ok(MdnsRequest::Resolve(name)) => match core.resolve(&name).await {
                                    Ok(record) => koi_mdns::protocol::MdnsPipelineResponse::clean(
                                        koi_mdns::protocol::Response::Resolved(record),
                                    ),
                                    Err(err) => koi_mdns::protocol::error_to_pipeline(&err),
                                },
                                Ok(MdnsRequest::Heartbeat(id)) => match core.heartbeat(&id) {
                                    Ok(lease_secs) => koi_mdns::protocol::MdnsPipelineResponse::clean(
                                        koi_mdns::protocol::Response::Renewed(
                                            koi_mdns::protocol::RenewalResult { id, lease_secs },
                                        ),
                                    ),
                                    Err(err) => koi_mdns::protocol::error_to_pipeline(&err),
                                },
                                Ok(MdnsRequest::Unregister(id)) => match core.unregister(&id) {
                                    Ok(()) => koi_mdns::protocol::MdnsPipelineResponse::clean(
                                        koi_mdns::protocol::Response::Unregistered(id),
                                    ),
                                    Err(err) => koi_mdns::protocol::error_to_pipeline(&err),
                                },
                                Ok(MdnsRequest::Browse(service_type)) => {
                                    let handle = match core.browse(&service_type).await {
                                        Ok(handle) => handle,
                                        Err(err) => {
                                            let resp = koi_mdns::protocol::error_to_pipeline(&err);
                                            let _ = writer
                                                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                                                .await;
                                            let _ = writer.write_all(b"\n").await;
                                            continue;
                                        }
                                    };
                                    let handle = handle;
                                    while let Some(event) = handle.recv().await {
                                        let resp = koi_mdns::protocol::browse_event_to_pipeline(event);
                                        let _ = writer
                                            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                                            .await;
                                        let _ = writer.write_all(b"\n").await;
                                    }
                                    continue;
                                }
                                Ok(MdnsRequest::Subscribe(service_type)) => {
                                    let handle = match core.browse(&service_type).await {
                                        Ok(handle) => handle,
                                        Err(err) => {
                                            let resp = koi_mdns::protocol::error_to_pipeline(&err);
                                            let _ = writer
                                                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                                                .await;
                                            let _ = writer.write_all(b"\n").await;
                                            continue;
                                        }
                                    };
                                    let handle = handle;
                                    while let Some(event) = handle.recv().await {
                                        let resp = koi_mdns::protocol::subscribe_event_to_pipeline(event);
                                        let _ = writer
                                            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                                            .await;
                                        let _ = writer.write_all(b"\n").await;
                                    }
                                    continue;
                                }
                                Err(_) => koi_mdns::protocol::MdnsPipelineResponse::clean(
                                    koi_mdns::protocol::Response::Error(koi_common::api::error_body(
                                        koi_common::error::ErrorCode::ParseError,
                                        "invalid_json",
                                    )),
                                ),
                            };

                            let _ = writer
                                .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                                .await;
                            let _ = writer.write_all(b"\n").await;
                        }
                    });
                }
                _ = server_cancel.cancelled() => break,
            }
        }
    });

    let client = open_pipe(&pipe_name).await?;
    let (reader, mut writer) = tokio::io::split(client);
    let mut reader = BufReader::new(reader).lines();

    let register_value = serde_json::json!({
        "register": {
            "name": "koi-ipc-test",
            "type": "_koi._tcp",
            "port": 51517,
            "ip": "127.0.0.1",
            "lease_secs": 30,
            "txt": {"source": "ipc"}
        }
    });
    let register_resp = ipc_send(&mut reader, &mut writer, register_value).await?;
    let id = register_resp
        .get("registered")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if id.is_some() {
        harness.pass("ipc: mdns register");
    } else {
        harness.fail("ipc: mdns register", "missing registered id");
    }

    let resolve_resp = ipc_send(
        &mut reader,
        &mut writer,
        serde_json::json!({
            "resolve": "koi-ipc-test._koi._tcp.local."
        }),
    )
    .await?;
    if resolve_resp.get("resolved").is_some() {
        harness.pass("ipc: mdns resolve");
    } else {
        harness.fail("ipc: mdns resolve", "missing resolved response");
    }

    if let Some(id) = id.clone() {
        let heartbeat_resp = ipc_send(
            &mut reader,
            &mut writer,
            serde_json::json!({
                "heartbeat": id
            }),
        )
        .await?;
        if heartbeat_resp.get("renewed").is_some() {
            harness.pass("ipc: mdns heartbeat");
        } else {
            harness.fail("ipc: mdns heartbeat", "missing renewed response");
        }
    }

    if let Some(id) = id {
        let unregister_resp = ipc_send(
            &mut reader,
            &mut writer,
            serde_json::json!({
                "unregister": id
            }),
        )
        .await?;
        if unregister_resp.get("unregistered").is_some() {
            harness.pass("ipc: mdns unregister");
        } else {
            harness.fail("ipc: mdns unregister", "missing unregistered response");
        }
    }

    cancel.cancel();
    let _ = server.await;
    Ok(())
}

#[cfg(not(windows))]
async fn run_ipc_tests(
    _mdns: std::sync::Arc<koi_mdns::MdnsCore>,
    harness: &mut Harness,
) -> Result<(), Box<dyn std::error::Error>> {
    harness.skip("ipc: mdns", "named pipes unsupported on this platform");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if has_flag(&args, "--help") {
        println!(
            "Usage: cargo run -p koi-embedded --example embedded-integration -- [options]\n\nOptions:\n  --timeout N   Overall timeout in seconds (default: 30)\n  --verbose     Verbose logging"
        );
        return Ok(());
    }

    let verbose = has_flag(&args, "--verbose");
    let with_certmesh = true;
    let skip_mdns = false;
    let timeout_secs = read_arg_value(&args, "--timeout")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    let total_deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let data_dir = temp_data_dir();
    let mut harness = Harness::new(verbose);

    harness.log(format!("data dir: {}", data_dir.display()));
    harness.log(format!("mdns: {}", !skip_mdns));
    harness.log(format!("certmesh: {}", with_certmesh));

    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(!skip_mdns)
        .dns_enabled(true)
        .dns(|cfg| cfg.port(15353))
        .health(true)
        .certmesh(with_certmesh)
        .proxy(true)
        .event_poll_interval_secs(1)
        .build()?;
    let handle = koi.start().await?;

    let mdns = match handle.mdns() {
        Ok(mdns) => mdns,
        Err(err) => {
            harness.fail("mdns: setup", &format!("{err}"));
            handle.shutdown().await?;
            harness.summary();
            std::process::exit(1);
        }
    };
    let dns = match handle.dns() {
        Ok(dns) => dns,
        Err(err) => {
            harness.fail("dns: setup", &format!("{err}"));
            handle.shutdown().await?;
            harness.summary();
            std::process::exit(1);
        }
    };
    let health = match handle.health() {
        Ok(health) => health,
        Err(err) => {
            harness.fail("health: setup", &format!("{err}"));
            handle.shutdown().await?;
            harness.summary();
            std::process::exit(1);
        }
    };
    let proxy = match handle.proxy() {
        Ok(proxy) => proxy,
        Err(err) => {
            harness.fail("proxy: setup", &format!("{err}"));
            handle.shutdown().await?;
            harness.summary();
            std::process::exit(1);
        }
    };
    let certmesh = match handle.certmesh() {
        Ok(certmesh) => certmesh,
        Err(err) => {
            harness.fail("certmesh: setup", &format!("{err}"));
            handle.shutdown().await?;
            harness.summary();
            std::process::exit(1);
        }
    };

    let (http_addr, http_cancel) = start_http_server(
        mdns.core()?,
        dns.runtime()?,
        health.core()?,
        certmesh.core()?,
        proxy.runtime()?,
    )
    .await?;
    let http_base = format!("http://{}", http_addr);
    harness.log(format!("http base: {http_base}"));

    // DNS: add entry, lookup, and event.
    let mut rx = handle.subscribe();
    let entry = DnsEntry {
        name: "embedded-test.lan".to_string(),
        ip: "127.0.0.1".to_string(),
        ttl: None,
    };
    let _ = dns.add_entry(entry)?;
    let event = wait_for_event(
        &mut rx,
        Duration::from_secs(2),
        |event| matches!(event, KoiEvent::DnsUpdated { name, .. } if name == "embedded-test.lan"),
    )
    .await;
    if event.is_some() {
        harness.pass("dns: event emitted");
    } else {
        harness.fail("dns: event emitted", "no DnsUpdated event received");
    }

    let result = dns
        .lookup("embedded-test.lan", hickory_proto::rr::RecordType::A)
        .await;
    match result {
        Some(result) => {
            if result.ips.contains(&IpAddr::from([127, 0, 0, 1])) && result.source == "static" {
                harness.pass("dns: lookup static entry");
            } else {
                harness.fail("dns: lookup static entry", "unexpected lookup result");
            }
        }
        None => harness.fail("dns: lookup static entry", "lookup returned none"),
    }

    let names = dns.list_names();
    if names.iter().any(|name| name == "embedded-test.lan.") {
        harness.pass("dns: list names includes entry");
    } else {
        harness.fail("dns: list names includes entry", "name missing from list");
    }

    let _ = dns.remove_entry("embedded-test.lan");
    let removed_event = wait_for_event(&mut rx, Duration::from_secs(2), |event| {
        matches!(event, KoiEvent::DnsUpdated { name, ips, .. } if name == "embedded-test.lan" && ips.is_empty())
    })
    .await;
    if removed_event.is_some() {
        harness.pass("dns: remove emits empty update");
    } else {
        harness.fail(
            "dns: remove emits empty update",
            "no removal update received",
        );
    }

    // Health: run a TCP check against a local listener.
    let mut rx = handle.subscribe();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let check = HealthCheck {
        name: "tcp-local".to_string(),
        kind: ServiceCheckKind::Tcp,
        target: format!("127.0.0.1:{}", addr.port()),
        interval_secs: 1,
        timeout_secs: 1,
    };
    health.add_check(check).await?;
    health.core()?.run_checks_once().await;
    let snapshot = health.status().await;
    let status = snapshot
        .services
        .iter()
        .find(|svc| svc.name == "tcp-local")
        .map(|svc| svc.status);
    match status {
        Some(ServiceStatus::Up) => harness.pass("health: tcp check up"),
        Some(other) => harness.fail(
            "health: tcp check up",
            &format!("unexpected status: {other:?}"),
        ),
        None => harness.fail("health: tcp check up", "service missing"),
    }

    let event = wait_for_event(
        &mut rx,
        Duration::from_secs(3),
        |event| matches!(event, KoiEvent::HealthChanged { name, .. } if name == "tcp-local"),
    )
    .await;
    if event.is_some() {
        harness.pass("health: event emitted");
    } else {
        harness.fail("health: event emitted", "no HealthChanged event received");
    }

    let _ = health.remove_check("tcp-local").await;
    let snapshot = health.status().await;
    if snapshot.services.iter().any(|svc| svc.name == "tcp-local") {
        harness.fail("health: remove check", "check still present after removal");
    } else {
        harness.pass("health: remove check");
    }

    // mDNS: register + browse.
    let browse = mdns.browse("_koi._tcp").await;
    if let Ok(browse) = browse {
        let mut txt = HashMap::new();
        txt.insert("source".to_string(), "embedded".to_string());
        let payload = RegisterPayload {
            name: "koi-embedded-test".to_string(),
            service_type: "_koi._tcp".to_string(),
            port: 51515,
            ip: Some("127.0.0.1".to_string()),
            lease_secs: Some(30),
            txt,
        };
        let reg = mdns.register(payload);
        if let Ok(reg) = reg {
            let found = tokio::time::timeout(Duration::from_secs(5), browse.recv()).await;
            match found {
                Ok(Some(_event)) => harness.pass("mdns: register + browse"),
                Ok(None) => harness.fail("mdns: register + browse", "browse stream ended"),
                Err(_) => harness.fail("mdns: register + browse", "no events within timeout"),
            }

            match mdns.resolve("koi-embedded-test._koi._tcp.local.").await {
                Ok(record) if record.port == Some(51515) => {
                    harness.pass("mdns: resolve registered service");
                }
                Ok(_) => harness.fail("mdns: resolve registered service", "unexpected record"),
                Err(err) => harness.fail("mdns: resolve registered service", &format!("{err}")),
            }

            match mdns.unregister(&reg.id) {
                Ok(()) => harness.pass("mdns: unregister"),
                Err(err) => harness.fail("mdns: unregister", &format!("{err}")),
            }
        } else {
            harness.fail("mdns: register + browse", "register failed");
        }
    } else {
        harness.fail("mdns: register + browse", "browse failed");
    }

    // Proxy: upsert and read entries.
    let mut rx = handle.subscribe();
    let entry = ProxyEntry {
        name: "embedded-proxy".to_string(),
        listen_port: 18080,
        backend: "http://127.0.0.1:18081".to_string(),
        allow_remote: false,
    };
    let result = proxy.upsert(entry.clone()).await;
    if result.is_ok() {
        let entries = proxy.entries().await;
        if entries.iter().any(|item| item.name == entry.name) {
            harness.pass("proxy: upsert entry");
        } else {
            harness.fail("proxy: upsert entry", "entry missing after upsert");
        }
        let event = wait_for_event(&mut rx, Duration::from_secs(3), |event| {
            matches!(event, KoiEvent::ProxyUpdated { entry } if entry.name == "embedded-proxy")
        })
        .await;
        if event.is_some() {
            harness.pass("proxy: event emitted");
        } else {
            harness.fail("proxy: event emitted", "no ProxyUpdated event received");
        }
        let _ = proxy.remove("embedded-proxy").await;
        let entries = proxy.entries().await;
        if entries.iter().any(|item| item.name == "embedded-proxy") {
            harness.fail("proxy: remove entry", "entry still present after removal");
        } else {
            harness.pass("proxy: remove entry");
        }
    } else {
        harness.fail("proxy: upsert entry", "upsert failed");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    if let Err(err) = run_http_tests(&http_base, &client, &mut harness).await {
        harness.fail("http: suite", &format!("{err}"));
    }

    if let Err(err) = run_ipc_tests(mdns.core()?, &mut harness).await {
        harness.fail("ipc: suite", &format!("{err}"));
    }

    http_cancel.cancel();
    handle.shutdown().await?;
    if tokio::time::Instant::now() > total_deadline {
        harness.fail("runtime", "overall timeout exceeded");
    }
    harness.summary();
    if harness.failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
