//! Outbound event fan-out: HMAC-signed delivery of the merged event stream to
//! operator-declared webhook sinks (ADR-028).
//!
//! This is a **composition-layer adapter**, not a domain: like the dashboard
//! forwarder it owns no state machine and emits no domain events of its own. It
//! consumes only the published integration envelope
//! ([`koi_dashboard::dashboard::DashboardSseEvent`] — the
//! same shape the SSE feed carries, ADR-006 identity included) so a domain-event
//! shape change lands once. Sinks are outbound-only; nothing about them is ever
//! advertised.
//!
//! Engine shape: one worker per enabled sink, each holding its **own receiver** on
//! the shared broadcast channel. Broadcast `Lagged` semantics *are* drop-oldest —
//! a slow or dead sink simply falls behind and skips, and can never back-pressure
//! the bus or the other sinks (ADR-028 deviation ledger: the drafted per-sink mpsc
//! queue was replaced by this shared-buffer design — fewer moving parts, same
//! guarantees). Overflow/lag surfaces as a `webhook.*` diagnostic event once per
//! episode, never generated *for* `webhook.*` events (no recursion).
//!
//! Delivery semantics: best-effort with bounded retry (3 attempts per event,
//! exponential backoff with id-derived jitter). Each sink owns one joinable
//! blocking actor, so synchronous `ureq` calls never occupy an async executor
//! worker and admitted calls are reaped before the sink task can finish. There
//! is no durable queue.

use std::time::Duration;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use koi_dashboard::dashboard::DashboardSseEvent;

/// Delivery attempts per event per sink (1 initial + 2 retries).
const MAX_ATTEMPTS: usize = 3;
/// Base backoff between attempts (doubled per attempt, plus id-derived jitter).
const BASE_BACKOFF_MS: u64 = 1_000;
/// Per-request overall timeout for a sink POST.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

// ── Configuration types ─────────────────────────────────────────────

/// One declared sink. `secret` keys the HMAC-SHA256 body signature; it is never
/// logged, echoed by status, or included in any payload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebhookSink {
    pub url: String,
    pub secret: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Static provenance stamped into every delivery (`node` = hostname, `zone` =
/// configured DNS zone). Built once at spawn so deliveries cannot drift.
#[derive(Clone, Debug)]
pub struct WebhookProvenance {
    pub node: String,
    pub zone: String,
}

impl WebhookProvenance {
    /// Build provenance from the composition's already accepted host identity.
    pub fn from_host(host: &crate::host::HostIdentity, zone: String) -> Self {
        Self {
            node: host.hostname().to_string(),
            zone,
        }
    }
}

/// Parse the sink manifest (JSON array of [`WebhookSink`]) from `path`.
///
/// The manifest is read once at daemon start; there is no runtime reload in 1.0.
pub fn parse_sinks_file(path: &std::path::Path) -> Result<Vec<WebhookSink>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read webhooks manifest {}: {e}", path.display()))?;
    parse_sinks_str(&raw)
}

/// Parse a sink manifest from an in-memory string (shared by file loading + tests).
pub fn parse_sinks_str(raw: &str) -> Result<Vec<WebhookSink>, String> {
    let sinks: Vec<WebhookSink> =
        serde_json::from_str(raw).map_err(|e| format!("invalid webhooks manifest: {e}"))?;
    for sink in &sinks {
        if sink.url.is_empty() {
            return Err("webhooks manifest contains a sink with an empty url".to_string());
        }
        if sink.secret.is_empty() {
            return Err(format!(
                "webhook sink {} has an empty secret (unsigned deliveries are not supported)",
                mask_url(&sink.url)
            ));
        }
    }
    Ok(sinks)
}

/// Mask scheme+host for diagnostics so manifest errors never leak paths/tokens.
fn mask_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.split('/').next().unwrap_or("")),
        None => String::new(),
    }
}

// ── Wire contract (pure, unit-tested) ───────────────────────────────

/// Serialize the delivery body: `{v:1, event:{id,type,data}, provenance:{node,zone,seen_at}}`.
/// The inner `event` object is the SSE event verbatim (one wire contract, two transports).
pub fn envelope_bytes(
    ev: &DashboardSseEvent,
    provenance: &WebhookProvenance,
) -> serde_json::Result<Vec<u8>> {
    let body = serde_json::json!({
        "v": 1,
        "event": {
            "id": ev.id,
            "type": ev.event_type,
            "data": ev.data,
        },
        "provenance": {
            "node": provenance.node,
            "zone": provenance.zone,
            "seen_at": chrono::Utc::now().to_rfc3339(),
        },
    });
    serde_json::to_vec(&body)
}

/// The `x-koi-signature` header value: `sha256=<hex HMAC-SHA256(body, secret)>`.
pub fn signature_header(secret: &str, body: &[u8]) -> String {
    let digest = koi_crypto::hmac::hmac_sha256(secret.as_bytes(), body);
    format!("sha256={}", koi_crypto::hmac::hex_32(&digest))
}

/// Backoff before retry `attempt` (1-based): base doubled per attempt plus 0–249 ms
/// of jitter derived deterministically from the event id (no rand dependency; the
/// jitter exists only to de-synchronize colliding retries).
fn backoff_delay(attempt: usize, event_id: &str) -> Duration {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in event_id.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let jitter_ms = hash % 250;
    let base_ms = BASE_BACKOFF_MS * (1 << (attempt - 1).min(4));
    Duration::from_millis(base_ms + jitter_ms)
}

fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(DELIVERY_TIMEOUT).build()
}

#[derive(Debug)]
enum DeliveryOutcome {
    Delivered,
    Failed(String),
    Panicked,
}

struct DeliveryJob {
    event_id: String,
    signature: String,
    body: Vec<u8>,
    reply: tokio::sync::oneshot::Sender<DeliveryOutcome>,
}

/// One joinable blocking owner per sink.
///
/// The capacity-one queue bounds accepted work to the request currently in the
/// platform client plus one sender waiting for admission. Dropping the async
/// sink worker closes the queue and joins this thread, so an admitted HTTP call
/// can never continue after its lifecycle owner has reported completion.
struct DeliveryActor {
    sender: Option<tokio::sync::mpsc::Sender<DeliveryJob>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DeliveryActor {
    fn start(url: String) -> std::io::Result<Self> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<DeliveryJob>(1);
        let thread = std::thread::Builder::new()
            .name("koi-webhook-delivery".to_string())
            .spawn(move || {
                let agent = build_agent();
                while let Some(job) = receiver.blocking_recv() {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        agent
                            .post(&url)
                            .set("content-type", "application/json")
                            .set("x-koi-event-id", &job.event_id)
                            .set("x-koi-signature", &job.signature)
                            .send_bytes(&job.body)
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    }));
                    let outcome = match result {
                        Ok(Ok(())) => DeliveryOutcome::Delivered,
                        Ok(Err(error)) => DeliveryOutcome::Failed(error),
                        Err(_) => DeliveryOutcome::Panicked,
                    };
                    let _ = job.reply.send(outcome);
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    async fn deliver(&self, pending: &PendingDelivery) -> DeliveryOutcome {
        let (reply, response) = tokio::sync::oneshot::channel();
        let job = DeliveryJob {
            event_id: pending.event_id.clone(),
            signature: pending.signature.clone(),
            body: pending.body.clone(),
            reply,
        };
        let Some(sender) = self.sender.as_ref() else {
            return DeliveryOutcome::Failed("delivery actor has shut down".to_string());
        };
        if sender.send(job).await.is_err() {
            return DeliveryOutcome::Failed("delivery actor stopped before admission".to_string());
        }
        response.await.unwrap_or_else(|_| {
            DeliveryOutcome::Failed("delivery actor stopped before acknowledgement".to_string())
        })
    }
}

impl Drop for DeliveryActor {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::warn!("webhook delivery actor panicked during shutdown");
            }
        }
    }
}

// ── Fan-out engine ──────────────────────────────────────────────────

struct SinkWorker {
    sink: WebhookSink,
    rx: broadcast::Receiver<DashboardSseEvent>,
    provenance: WebhookProvenance,
    diagnostics_tx: Option<broadcast::Sender<DashboardSseEvent>>,
    cancel: CancellationToken,
}

/// Spawn one worker per enabled sink plus nothing else; returns every handle so the
/// caller can push them into its ordered-shutdown task set. Disabled sinks spawn
/// nothing. Each worker holds its own receiver on `event_tx`, so fan-out is N cheap
/// subscriptions on one buffer rather than a router fanning copies out.
pub fn spawn_webhook_fanout(
    event_tx: &broadcast::Sender<DashboardSseEvent>,
    sinks: Vec<WebhookSink>,
    provenance: WebhookProvenance,
    diagnostics_tx: Option<broadcast::Sender<DashboardSseEvent>>,
    cancel: CancellationToken,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for sink in sinks.into_iter().filter(|s| s.enabled) {
        tracing::info!(url = %mask_url(&sink.url), "Webhook sink enabled");
        handles.push(tokio::spawn(sink_worker(SinkWorker {
            sink,
            rx: event_tx.subscribe(),
            provenance: provenance.clone(),
            diagnostics_tx: diagnostics_tx.clone(),
            cancel: cancel.clone(),
        })));
    }
    if handles.is_empty() {
        tracing::debug!("Webhook fan-out disabled (no enabled sinks)");
    }
    handles
}

async fn sink_worker(mut worker: SinkWorker) {
    let actor = match DeliveryActor::start(worker.sink.url.clone()) {
        Ok(actor) => actor,
        Err(error) => {
            tracing::warn!(%error, url = %mask_url(&worker.sink.url), "could not start webhook delivery actor");
            return;
        }
    };
    // An overflow episode opens on Lagged and closes on the next successful
    // delivery, so sustained saturation warns once instead of spamming.
    let mut episode_open = false;

    loop {
        let ev = tokio::select! {
            _ = worker.cancel.cancelled() => break,
            recv = worker.rx.recv() => match recv {
                Ok(ev) => ev,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    if !episode_open {
                        emit_diagnostic(
                            worker.diagnostics_tx.as_ref(),
                            &worker.provenance,
                            "webhook.stream_lagged",
                            serde_json::json!({ "skipped": n, "sink": mask_url(&worker.sink.url) }),
                        );
                        episode_open = true;
                    }
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };

        if worker.cancel.is_cancelled() {
            break;
        }

        // Recursion guard: diagnostics are never generated *for* webhook.* events.
        if ev.event_type.starts_with("webhook.") {
            continue;
        }

        let body = match envelope_bytes(&ev, &worker.provenance) {
            Ok(body) => body,
            Err(error) => {
                emit_diagnostic(
                    worker.diagnostics_tx.as_ref(),
                    &worker.provenance,
                    "webhook.serialization_failed",
                    serde_json::json!({ "error": error.to_string() }),
                );
                continue;
            }
        };
        let pending = PendingDelivery {
            event_id: ev.id.clone(),
            signature: signature_header(&worker.sink.secret, &body),
            body,
        };

        if deliver_with_retries(&actor, &worker.sink, &pending, &worker.cancel).await {
            episode_open = false;
        }
    }
}

struct PendingDelivery {
    event_id: String,
    signature: String,
    body: Vec<u8>,
}

async fn deliver_with_retries(
    actor: &DeliveryActor,
    sink: &WebhookSink,
    p: &PendingDelivery,
    cancel: &CancellationToken,
) -> bool {
    for attempt in 1..=MAX_ATTEMPTS {
        if cancel.is_cancelled() {
            return false;
        }
        match actor.deliver(p).await {
            DeliveryOutcome::Delivered => return true,
            DeliveryOutcome::Failed(error) => {
                tracing::debug!(attempt, %error, url = %mask_url(&sink.url), "webhook delivery failed");
            }
            DeliveryOutcome::Panicked => {
                tracing::warn!("webhook delivery panicked");
                return false;
            }
        }

        if cancel.is_cancelled() {
            return false;
        }

        if attempt < MAX_ATTEMPTS {
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = tokio::time::sleep(backoff_delay(attempt, &p.event_id)) => {}
            }
        }
    }
    false
}

fn emit_diagnostic(
    tx: Option<&broadcast::Sender<DashboardSseEvent>>,
    provenance: &WebhookProvenance,
    event_type: &str,
    detail: serde_json::Value,
) {
    tracing::warn!(event_type, ?detail, "webhook fan-out diagnostic");
    if let Some(tx) = tx {
        let _ = tx.send(DashboardSseEvent {
            event_type: event_type.to_string(),
            id: uuid::Uuid::now_v7().to_string(),
            data: serde_json::json!({
                "detail": detail,
                "node": provenance.node,
            }),
        });
    }
}

// ── Tests (pure contract + redaction guard) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn provenance() -> WebhookProvenance {
        WebhookProvenance {
            node: "brook".to_string(),
            zone: "internal".to_string(),
        }
    }

    fn sse(event_type: &str, data: serde_json::Value) -> DashboardSseEvent {
        DashboardSseEvent {
            event_type: event_type.to_string(),
            id: "018f6d2a-0000-7000-8000-000000000000".to_string(),
            data,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_a_sink_worker_joins_its_admitted_http_call() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("test HTTP listener");
        let address = listener.local_addr().expect("test HTTP address");
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let completed = Arc::clone(&completed);
            move || {
                let (mut stream, _) = listener.accept().expect("accept webhook request");
                entered.store(true, Ordering::Release);
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .expect("complete webhook response");
                completed.store(true, Ordering::Release);
            }
        });
        let pending = PendingDelivery {
            event_id: "owned-request".to_string(),
            signature: "sha256=test".to_string(),
            body: b"{}".to_vec(),
        };
        let mut task = tokio::spawn(async move {
            let actor =
                DeliveryActor::start(format!("http://{address}/hook")).expect("delivery actor");
            actor.deliver(&pending).await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking actor admitted the real HTTP request");

        task.abort();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut task)
                .await
                .is_err(),
            "task cancellation must wait for the actor's admitted call"
        );
        release.store(true, Ordering::Release);
        let result = tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .expect("sink owner joined after the HTTP call completed");
        assert!(result.expect_err("task was aborted").is_cancelled());
        server.join().expect("test HTTP server");
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn envelope_carries_event_verbatim_plus_provenance() {
        let ev = sse(
            "health.changed",
            json!({ "name": "grafana", "status": "down" }),
        );
        let body = envelope_bytes(&ev, &provenance()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["v"], 1);
        assert_eq!(parsed["event"]["id"], ev.id);
        assert_eq!(parsed["event"]["type"], "health.changed");
        assert_eq!(parsed["event"]["data"]["name"], "grafana");
        assert_eq!(parsed["provenance"]["node"], "brook");
        assert_eq!(parsed["provenance"]["zone"], "internal");
        // seen_at parses as RFC3339
        chrono::DateTime::parse_from_rfc3339(parsed["provenance"]["seen_at"].as_str().unwrap())
            .unwrap();
    }

    #[test]
    fn signature_matches_independent_hmac_computation() {
        let body = b"{\"v\":1}";
        let header = signature_header("sink-secret", body);
        assert!(header.starts_with("sha256="));
        let expected =
            koi_crypto::hmac::hex_32(&koi_crypto::hmac::hmac_sha256(b"sink-secret", body));
        assert_eq!(header, format!("sha256={expected}"));
    }

    #[test]
    fn backoff_is_deterministic_and_bounded() {
        let a = backoff_delay(1, "id-a");
        let b = backoff_delay(2, "id-a");
        assert_eq!(backoff_delay(1, "id-a"), a, "same input, same delay");
        assert!(b.as_millis() >= 2000, "attempt 2 at least doubles base");
        for attempt in 1..=MAX_ATTEMPTS {
            let d = backoff_delay(attempt, "id-a").as_millis();
            assert!(
                d < u128::from(BASE_BACKOFF_MS * (1 << ((attempt - 1).min(4))) + 250),
                "jitter bounded under 250ms"
            );
        }
    }

    #[test]
    fn parse_rejects_empty_url_and_empty_secret() {
        let err = parse_sinks_str(r#"[{"url":"","secret":"s"}]"#).unwrap_err();
        assert!(err.contains("empty url"));
        let err = parse_sinks_str(r#"[{"url":"https://host/hook","secret":""}]"#).unwrap_err();
        assert!(err.contains("empty secret"), "{err}");
    }

    #[test]
    fn parse_defaults_enabled_and_accepts_valid_manifest() {
        let sinks =
            parse_sinks_str(r#"[{"url":"https://notify.internal/koi","secret":"abc"}]"#).unwrap();
        assert_eq!(sinks.len(), 1);
        assert!(sinks[0].enabled);
    }

    /// Redaction guard (ADR-028 §5): the envelope is built only from the SSE
    /// event's three public fields plus static provenance — this test proves no
    /// credential-bearing key name can appear in an envelope's keys.
    #[test]
    fn envelope_keys_are_closed_set() {
        let ev = sse(
            "certmesh.enrolled",
            json!({ "hostname": "granite", "fingerprint": "deadbeef" }),
        );
        let body = envelope_bytes(&ev, &provenance()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        fn collect_keys(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, inner) in map {
                        out.push(k.clone());
                        collect_keys(inner, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        collect_keys(item, out);
                    }
                }
                _ => {}
            }
        }
        let mut keys = Vec::new();
        collect_keys(&parsed, &mut keys);
        // ("needle", is_exact): "dat" must be exact or it matches the legitimate
        // envelope key "data"; the rest are substring checks by design.
        let forbidden: [(&str, bool); 5] = [
            ("token", false),
            ("secret", false),
            ("passphrase", false),
            ("key_pem", false),
            ("dat", true),
        ];
        for (needle, is_exact) in forbidden {
            assert!(
                !keys.iter().any(|k| if is_exact {
                    k == needle
                } else {
                    k.to_lowercase().contains(needle)
                }),
                "forbidden key material '{needle}' in envelope keys: {keys:?}"
            );
        }
    }

    #[test]
    fn mask_url_never_leaks_paths() {
        assert_eq!(
            mask_url("https://notify.internal/koi/abc?x=1"),
            "https://notify.internal"
        );
        assert_eq!(mask_url("not-a-url"), "");
    }
}
