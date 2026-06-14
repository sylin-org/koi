//! Security regression tests for the mDNS browser's XSS class (assessment claim 9).
//!
//! These are JS-free: one is a **structural guard** over the rendered asset (no dynamic
//! value is string-concatenated into an HTML attribute, and a scheme allowlist exists);
//! the other serves the snapshot endpoint with LAN-attacker-controlled hostile service
//! names and asserts the response is inert JSON (never HTML).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for `oneshot`

use koi_dashboard::browse_source::{
    BrowseError, BrowseHandle, BrowseSource, BrowserEvent, ResolvedService,
};
use koi_dashboard::browser::{self, BrowserCache, BrowserState};
use koi_dashboard::meta_browse::LazyMetaBrowse;

const BROWSER_HTML: &str = include_str!("../assets/mdns-browser.html");

// ── Structural guard (genuinely fail-first against the pre-rewrite asset) ──

#[test]
fn asset_never_concatenates_dynamic_values_into_attributes() {
    // The pre-rewrite render concatenated escaped values straight into double-quoted
    // attributes; `esc()` does not escape quotes, so a hostile name broke out. The
    // structural DOM rewrite must eliminate every one of these patterns.
    let forbidden = [
        r#"href="' +"#,
        r#"data-key="' +"#,
        r#"data-type="' +"#,
        r#"data-detail="' +"#,
        r#"title="Open ' +"#,
    ];
    for pat in forbidden {
        assert!(
            !BROWSER_HTML.contains(pat),
            "mdns-browser.html still concatenates a dynamic value into an attribute: {pat}"
        );
    }
}

#[test]
fn asset_has_an_http_scheme_allowlist_for_launch_links() {
    // Launch links must pass through an explicit http/https allowlist so `javascript:`
    // and `data:` TXT urls are dropped.
    assert!(
        BROWSER_HTML.contains("safeLaunchUrl"),
        "mdns-browser.html must define a scheme-allowlisted safeLaunchUrl() helper"
    );
    assert!(
        BROWSER_HTML.contains("https:") && BROWSER_HTML.contains("http:"),
        "scheme allowlist must enumerate http:/https:"
    );
}

// ── Hostile-snapshot serve (server emits inert JSON, never HTML) ──

/// Minimal `BrowseSource` for serving `/snapshot` (which never calls `browse`/`subscribe`
/// in anger; the worker that `touch()` spawns just parks).
struct StubSource {
    tx: tokio::sync::broadcast::Sender<BrowserEvent>,
}

impl BrowseSource for StubSource {
    fn browse(
        &self,
        _service_type: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
    > {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Box::pin(async move { Ok(BrowseHandle::new(rx)) })
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<BrowserEvent> {
        self.tx.subscribe()
    }
}

fn resolved(name: &str, txt: HashMap<String, String>) -> ResolvedService {
    ResolvedService {
        name: name.to_string(),
        service_type: "_http._tcp".to_string(),
        host: "evil.local".to_string(),
        ip: "10.0.0.66".to_string(),
        port: 8080,
        txt,
    }
}

#[tokio::test]
async fn snapshot_serves_hostile_names_as_inert_json() {
    let (tx, _) = tokio::sync::broadcast::channel(16);
    let source: Arc<dyn BrowseSource> = Arc::new(StubSource { tx });
    let cache = BrowserCache::new();

    // Seed the cache with LAN-attacker-controlled hostile data.
    let img = r#""><img src=x onerror=alert(1)>"#;
    let handler = r#"" onmouseover="alert(1)"#;
    let mut js_txt = HashMap::new();
    js_txt.insert("url".to_string(), "javascript:alert(1)".to_string());

    cache
        .ingest(&BrowserEvent::Resolved(resolved(img, HashMap::new())))
        .await;
    cache
        .ingest(&BrowserEvent::Resolved(resolved(handler, js_txt)))
        .await;

    let meta = LazyMetaBrowse::new(
        source.clone(),
        cache.clone(),
        tokio_util::sync::CancellationToken::new(),
    );
    let state = BrowserState {
        source,
        cache,
        meta,
    };

    let app = browser::routes(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/snapshot")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/json"),
        "snapshot must be JSON (a browser never renders it as HTML), got {ct}"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("snapshot is valid JSON");

    // The hostile names round-trip as JSON string values — serde escapes them as JSON,
    // never as live HTML. (The client-side render is hardened structurally; the asset
    // guards above lock that in.)
    let blob = json.to_string();
    assert!(
        blob.contains("onerror=alert(1)"),
        "hostile name present as data"
    );
    assert!(blob.contains("onmouseover"), "hostile name present as data");
    // The javascript: url is carried as inert TXT data; the client drops it at render.
    assert!(blob.contains("javascript:alert(1)"));
}

// ── Dashboard page: defense-in-depth ──

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");

#[test]
fn dashboard_activity_log_uses_dom_construction_and_quote_safe_esc() {
    // The activity log receives LAN-attacker mDNS names; it must not flow through
    // innerHTML, and the shared esc() must escape quotes (the defense line for the
    // remaining operator-data panels).
    assert!(
        !DASHBOARD_HTML.contains("log.innerHTML"),
        "dashboard activity log must not use innerHTML for attacker-controlled names"
    );
    assert!(
        DASHBOARD_HTML.contains("&quot;") && DASHBOARD_HTML.contains("&#39;"),
        "dashboard esc() must escape double and single quotes"
    );
}

#[tokio::test]
async fn served_pages_set_a_content_security_policy() {
    use axum::routing::get;

    // Dashboard page.
    let app = axum::Router::new().route("/", get(koi_dashboard::dashboard::get_dashboard));
    assert_csp(app, "/").await;

    // mDNS browser page.
    let app = axum::Router::new().route("/mdns-browser", get(browser::get_page));
    assert_csp(app, "/mdns-browser").await;
}

async fn assert_csp(app: axum::Router, uri: &str) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp
        .headers()
        .get(axum::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        csp.contains("default-src 'self'"),
        "{uri} must send a Content-Security-Policy (got {csp:?})"
    );
}
