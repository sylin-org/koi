//! Operator-armed, read-only LAN presentation adapter (ADR-042).
//!
//! Pond is not another daemon or a second domain model. It is one desired-state
//! listener inside the serving monolith. The full operator API stays on its configured
//! bind; this adapter mounts only the assets and read models the browser UI consumes.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::Extension;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, put};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use utoipa::{OpenApi, ToSchema};

use koi_dashboard::browser::BrowserState;

/// The standard Pond listener follows the daemon's standard three-port run.
pub const DEFAULT_POND_PORT: u16 = 5644;

const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const OBSERVE_INTERVAL: Duration = Duration::from_secs(5);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const UI_FILES: [&str; 5] = [
    "index.html",
    "app.js",
    "styles.css",
    "sentences.js",
    "koi.png",
];
const POND_HTML_CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
    object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Derive the fourth port in a Koi install's contiguous port run.
pub fn port_for_http(http_port: u16) -> Option<u16> {
    http_port.checked_add(3)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PondState {
    Disabled,
    Reconciling,
    Running,
    Waiting,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PondFirewallState {
    /// A known active firewall confirmed the port is admitted.
    Open,
    /// No active supported host firewall was found.
    Inactive,
    /// A known active firewall rejects the port.
    Blocked,
    /// The host policy could not be assessed without guessing.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondFirewallStatus {
    pub state: PondFirewallState,
    pub detail: String,
}

/// Exact desired and observed state returned by the authenticated operator API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondStatus {
    pub desired: bool,
    pub running: bool,
    pub state: PondState,
    pub port: u16,
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub firewall: PondFirewallStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PondStatus {
    fn disabled(port: u16) -> Self {
        Self {
            desired: false,
            running: false,
            state: PondState::Disabled,
            port,
            urls: Vec::new(),
            url: None,
            firewall: PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: "not assessed while Pond is disabled".to_string(),
            },
            reason: None,
        }
    }
}

#[derive(Clone)]
pub struct PondConfig {
    pub port: u16,
    pub ui_dir: PathBuf,
    pub intent_path: PathBuf,
    pub started_at: Instant,
    pub browser: Option<BrowserState>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub parent_cancel: CancellationToken,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PondIntent {
    desired: bool,
}

struct RunHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct Inner {
    config: PondConfig,
    status: watch::Sender<PondStatus>,
    control: Mutex<Option<RunHandle>>,
    publish: Mutex<()>,
    reconcile_now: Notify,
}

/// One in-process desired-state controller for the read-only listener.
#[derive(Clone)]
pub struct PondRuntime {
    inner: Arc<Inner>,
}

impl PondRuntime {
    pub fn new(config: PondConfig) -> Self {
        let (status, _) = watch::channel(PondStatus::disabled(config.port));
        let runtime = Self {
            inner: Arc::new(Inner {
                config,
                status,
                control: Mutex::new(None),
                publish: Mutex::new(()),
                reconcile_now: Notify::new(),
            }),
        };
        runtime.publish_capability(&runtime.status());
        runtime
    }

    pub fn status(&self) -> PondStatus {
        self.inner.status.borrow().clone()
    }

    /// Restore persisted desire, then own shutdown of the listener task.
    pub async fn supervise(&self) {
        match koi_common::persist::read_json_if_exists::<PondIntent>(&self.inner.config.intent_path)
        {
            Ok(Some(intent)) if intent.desired => {
                self.arm().await;
            }
            Ok(_) => {}
            Err(error) => self.set_status(PondStatus {
                desired: false,
                running: false,
                state: PondState::Error,
                port: self.inner.config.port,
                urls: Vec::new(),
                url: None,
                firewall: unknown_firewall(),
                reason: Some(format!("could not read Pond intent: {error}")),
            }),
        }

        self.inner.config.parent_cancel.cancelled().await;
        self.stop_listener().await;
    }

    /// Persist desire and settle the first real bind/assessment attempt.
    pub async fn enable(&self) -> Result<PondStatus, std::io::Error> {
        koi_common::persist::write_json_pretty(
            &self.inner.config.intent_path,
            &PondIntent { desired: true },
        )?;
        self.arm().await;
        self.inner.reconcile_now.notify_waiters();
        Ok(self.wait_until_settled().await)
    }

    /// Persist the stop before tearing down the socket, so restart cannot re-arm it.
    pub async fn disable(&self) -> Result<PondStatus, std::io::Error> {
        koi_common::persist::write_json_pretty(
            &self.inner.config.intent_path,
            &PondIntent { desired: false },
        )?;
        self.stop_listener().await;
        self.set_status(PondStatus::disabled(self.inner.config.port));
        Ok(self.status())
    }

    async fn arm(&self) {
        let mut control = self.inner.control.lock().await;
        if control
            .as_ref()
            .is_some_and(|handle| !handle.task.is_finished())
        {
            return;
        }
        if let Some(finished) = control.take() {
            let _ = finished.task.await;
        }

        self.set_status(PondStatus {
            desired: true,
            running: false,
            state: PondState::Reconciling,
            port: self.inner.config.port,
            urls: Vec::new(),
            url: None,
            firewall: unknown_firewall(),
            reason: None,
        });

        let cancel = CancellationToken::new();
        let (initial_tx, initial_rx) = oneshot::channel();
        let runtime = self.clone();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            runtime.reconcile(task_cancel, initial_tx).await;
        });
        *control = Some(RunHandle { cancel, task });
        drop(control);

        let _ = tokio::time::timeout(SETTLE_TIMEOUT, initial_rx).await;
    }

    async fn stop_listener(&self) {
        let handle = self.inner.control.lock().await.take();
        if let Some(handle) = handle {
            handle.cancel.cancel();
            let _ = handle.task.await;
        }
    }

    async fn wait_until_settled(&self) -> PondStatus {
        let mut receiver = self.inner.status.subscribe();
        let _ = tokio::time::timeout(SETTLE_TIMEOUT, async {
            loop {
                let status = receiver.borrow().clone();
                if status.running
                    || matches!(status.state, PondState::Error)
                    || (status.state == PondState::Waiting
                        && !status
                            .reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("UI is incomplete")))
                {
                    break;
                }
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        self.status()
    }

    async fn reconcile(&self, cancel: CancellationToken, initial: oneshot::Sender<()>) {
        let mut initial = Some(initial);
        loop {
            if cancel.is_cancelled() {
                return;
            }
            self.set_reconciling();

            if !ui_is_complete(&self.inner.config.ui_dir) {
                self.set_waiting(
                    self.inner.config.port,
                    "published UI is incomplete; open Koi Desktop and choose Phone".to_string(),
                    unknown_firewall(),
                );
                signal_initial(&mut initial);
                if self.wait_retry(&cancel).await {
                    return;
                }
                continue;
            }

            let listener = match tokio::net::TcpListener::bind((
                Ipv4Addr::UNSPECIFIED,
                self.inner.config.port,
            ))
            .await
            {
                Ok(listener) => listener,
                Err(error) => {
                    self.set_waiting(
                        self.inner.config.port,
                        format!("Pond listener bind failed: {error}"),
                        unknown_firewall(),
                    );
                    signal_initial(&mut initial);
                    if self.wait_retry(&cancel).await {
                        return;
                    }
                    continue;
                }
            };

            let bound_port = match listener.local_addr() {
                Ok(address) => address.port(),
                Err(error) => {
                    self.set_waiting(
                        self.inner.config.port,
                        format!("could not inspect Pond listener: {error}"),
                        unknown_firewall(),
                    );
                    signal_initial(&mut initial);
                    if self.wait_retry(&cancel).await {
                        return;
                    }
                    continue;
                }
            };
            self.refresh_observation(bound_port).await;
            signal_initial(&mut initial);

            let server_cancel = CancellationToken::new();
            let router = public_routes(self.clone());
            let graceful = server_cancel.clone();
            let mut server = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move { graceful.cancelled().await })
                    .await
            });
            let mut observe = tokio::time::interval(OBSERVE_INTERVAL);
            observe.tick().await;

            let ended_reason = loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        server_cancel.cancel();
                        let _ = server.await;
                        return;
                    }
                    result = &mut server => {
                        break match result {
                            Ok(Ok(())) => "Pond listener ended unexpectedly".to_string(),
                            Ok(Err(error)) => format!("Pond listener failed: {error}"),
                            Err(error) => format!("Pond listener task failed: {error}"),
                        };
                    }
                    _ = observe.tick() => self.refresh_observation(bound_port).await,
                    _ = self.inner.reconcile_now.notified() => {
                        self.refresh_observation(bound_port).await;
                    }
                }
            };
            self.set_waiting(bound_port, ended_reason, unknown_firewall());
            if self.wait_retry(&cancel).await {
                return;
            }
        }
    }

    fn set_reconciling(&self) {
        self.set_status(PondStatus {
            desired: true,
            running: false,
            state: PondState::Reconciling,
            port: self.inner.config.port,
            urls: Vec::new(),
            url: None,
            firewall: unknown_firewall(),
            reason: None,
        });
    }

    fn set_waiting(&self, port: u16, reason: String, firewall: PondFirewallStatus) {
        self.set_status(PondStatus {
            desired: true,
            running: false,
            state: PondState::Waiting,
            port,
            urls: Vec::new(),
            url: None,
            firewall,
            reason: Some(reason),
        });
    }

    async fn refresh_observation(&self, port: u16) {
        if !ui_is_complete(&self.inner.config.ui_dir) {
            self.set_waiting(
                port,
                "published UI is incomplete; open Koi Desktop and choose Phone".to_string(),
                unknown_firewall(),
            );
            return;
        }
        let interfaces = crate::network::lan_ipv4_interfaces();
        if interfaces.is_empty() {
            self.set_waiting(
                port,
                "no LAN-routable IPv4 interface is available".to_string(),
                PondFirewallStatus {
                    state: PondFirewallState::Unknown,
                    detail: "waiting for a LAN interface".to_string(),
                },
            );
            return;
        }
        let firewall = assess_firewall(port, &interfaces[0].name).await;
        if firewall.state == PondFirewallState::Blocked {
            self.set_waiting(port, firewall.detail.clone(), firewall);
            return;
        }

        let urls = interfaces
            .into_iter()
            .map(|interface| format!("http://{}:{port}/", interface.address))
            .collect::<Vec<_>>();
        self.set_status(PondStatus {
            desired: true,
            running: true,
            state: PondState::Running,
            port,
            url: urls.first().cloned(),
            urls,
            firewall,
            reason: None,
        });
    }

    async fn wait_retry(&self, cancel: &CancellationToken) -> bool {
        tokio::select! {
            _ = cancel.cancelled() => true,
            _ = tokio::time::sleep(RETRY_INTERVAL) => false,
            _ = self.inner.reconcile_now.notified() => false,
        }
    }

    fn set_status(&self, status: PondStatus) {
        self.publish_capability(&status);
        self.inner.status.send_replace(status);
    }

    fn publish_capability(&self, status: &PondStatus) {
        let reason = match status.state {
            PondState::Running => status
                .url
                .as_deref()
                .map(|url| format!("read-only listener at {url}"))
                .unwrap_or_else(|| "read-only listener running".to_string()),
            PondState::Disabled => "operator-controlled read-only listener".to_string(),
            _ => status
                .reason
                .clone()
                .unwrap_or_else(|| format!("{:?}", status.state).to_lowercase()),
        };
        koi_common::capability::set_note(koi_common::capability::CapabilityNote {
            capability: "pond".to_string(),
            state: match status.state {
                PondState::Disabled => "disabled",
                PondState::Reconciling => "reconciling",
                PondState::Running => "running",
                PondState::Waiting => "waiting",
                PondState::Error => "error",
            }
            .to_string(),
            reason,
            depends_on: vec!["http".to_string()],
        });
    }
}

fn signal_initial(sender: &mut Option<oneshot::Sender<()>>) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(());
    }
}

fn unknown_firewall() -> PondFirewallStatus {
    PondFirewallStatus {
        state: PondFirewallState::Unknown,
        detail: "firewall not assessed before a listener bind".to_string(),
    }
}

async fn assess_firewall(port: u16, interface: &str) -> PondFirewallStatus {
    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || assess_firewall_blocking(port, &interface))
        .await
        .unwrap_or_else(|error| PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("firewall assessment task failed: {error}"),
        })
}

#[cfg(target_os = "linux")]
fn assess_firewall_blocking(port: u16, interface: &str) -> PondFirewallStatus {
    assess_firewalld(port, interface)
        .or_else(|| assess_ufw(port))
        .unwrap_or_else(|| PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail:
                "neither firewalld nor UFW is active; other host firewall policy was not assessed"
                    .to_string(),
        })
}

#[cfg(target_os = "linux")]
fn assess_firewalld(port: u16, interface: &str) -> Option<PondFirewallStatus> {
    use std::process::Command;

    let state = Command::new("firewall-cmd").arg("--state").output();
    let Ok(state) = state else { return None };
    if !state.status.success() {
        return None;
    }

    let zone = Command::new("firewall-cmd")
        .arg(format!("--get-zone-of-interface={interface}"))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|zone| zone.trim().to_string())
        .filter(|zone| !zone.is_empty())
        .or_else(|| {
            Command::new("firewall-cmd")
                .arg("--get-default-zone")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|zone| zone.trim().to_string())
                .filter(|zone| !zone.is_empty())
        });
    let Some(zone) = zone else {
        return Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("firewalld is active but the zone for {interface} is unknown"),
        });
    };
    let query = Command::new("firewall-cmd")
        .arg(format!("--zone={zone}"))
        .arg(format!("--query-port={port}/tcp"))
        .output();
    match query {
        Ok(output) if output.status.success() => Some(PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("firewalld zone {zone} admits TCP {port}"),
        }),
        Ok(output) if output.status.code() == Some(1) => Some(PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!("firewalld zone {zone} does not admit TCP {port}"),
        }),
        Ok(output) => Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!(
                "firewalld could not assess TCP {port} in zone {zone} (exit {:?})",
                output.status.code()
            ),
        }),
        Err(error) => Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("could not query firewalld: {error}"),
        }),
    }
}

#[cfg(target_os = "linux")]
fn assess_ufw(port: u16) -> Option<PondFirewallStatus> {
    use std::process::Command;

    let output = Command::new("ufw").args(["status", "verbose"]).output();
    let Ok(output) = output else { return None };
    if !output.status.success() {
        return Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!(
                "UFW is present but could not be assessed non-interactively (exit {:?})",
                output.status.code()
            ),
        });
    }
    let body = String::from_utf8_lossy(&output.stdout);
    if body.lines().any(|line| line.trim() == "Status: inactive") {
        return None;
    }
    Some(assess_ufw_status(port, &body))
}

#[cfg(target_os = "linux")]
fn assess_ufw_status(port: u16, status: &str) -> PondFirewallStatus {
    for line in status.lines().map(str::trim) {
        let mut fields = line.split_whitespace();
        let Some(target) = fields.next() else {
            continue;
        };
        if !ufw_target_admits_tcp(target, port) {
            continue;
        }
        let action = fields.find(|field| matches!(*field, "ALLOW" | "LIMIT" | "DENY" | "REJECT"));
        match action {
            Some("ALLOW" | "LIMIT") => {
                return PondFirewallStatus {
                    state: PondFirewallState::Open,
                    detail: format!("UFW rule {target} admits TCP {port}"),
                };
            }
            Some("DENY" | "REJECT") => {
                return PondFirewallStatus {
                    state: PondFirewallState::Blocked,
                    detail: format!("UFW rule {target} rejects TCP {port}"),
                };
            }
            _ => {}
        }
    }

    if status.contains("Default: allow (incoming)") {
        PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("UFW's default incoming policy admits TCP {port}"),
        }
    } else if status.contains("Default: deny (incoming)")
        || status.contains("Default: reject (incoming)")
    {
        PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!("UFW's default incoming policy does not admit TCP {port}"),
        }
    } else {
        PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("UFW is active but its policy for TCP {port} is unclear"),
        }
    }
}

#[cfg(target_os = "linux")]
fn ufw_target_admits_tcp(target: &str, port: u16) -> bool {
    let (ports, protocol) = target.split_once('/').unwrap_or((target, "tcp"));
    if !protocol.eq_ignore_ascii_case("tcp") {
        return false;
    }
    let (start, end) = ports
        .split_once(':')
        .map_or((ports, ports), |(start, end)| (start, end));
    let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
        return false;
    };
    (start..=end).contains(&port)
}

#[cfg(windows)]
fn assess_firewall_blocking(port: u16, _interface: &str) -> PondFirewallStatus {
    let rule = format!("Koi Pond (TCP {port})");
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: format!("could not resolve the running executable: {error}"),
            };
        }
    };
    match crate::windows_firewall::assess_managed(&rule, "TCP", port, &exe) {
        Ok(crate::windows_firewall::Assessment::Open) => PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("Windows Firewall managed rule admits TCP {port}"),
        },
        Ok(crate::windows_firewall::Assessment::Inactive) => PondFirewallStatus {
            state: PondFirewallState::Inactive,
            detail: "Windows Firewall is not enabled for an active network profile".to_string(),
        },
        Ok(crate::windows_firewall::Assessment::Blocked(
            crate::windows_firewall::BlockReason::MissingOrMismatchedRule,
        )) => PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!(
                "Windows Firewall managed rule for TCP {port} is absent, disabled, or not scoped to the running executable"
            ),
        },
        Ok(crate::windows_firewall::Assessment::Blocked(
            crate::windows_firewall::BlockReason::ActiveProfileNotCovered,
        )) => PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!(
                "Windows Firewall managed rule for TCP {port} does not cover the active network profile"
            ),
        },
        Err(error) => PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("could not query Windows Firewall: {error}"),
        },
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn assess_firewall_blocking(port: u16, _interface: &str) -> PondFirewallStatus {
    PondFirewallStatus {
        state: PondFirewallState::Unknown,
        detail: format!(
            "host firewall admission for TCP {port} is provisioned by the platform installer"
        ),
    }
}

fn ui_is_complete(dir: &Path) -> bool {
    UI_FILES.iter().all(|name| dir.join(name).is_file())
}

fn public_routes(runtime: PondRuntime) -> Router {
    Router::new()
        .route("/", get(ui_index_handler))
        .route("/app.js", get(ui_asset_app))
        .route("/styles.css", get(ui_asset_styles))
        .route("/sentences.js", get(ui_asset_sentences))
        .route("/koi.png", get(ui_asset_png))
        .route("/healthz", get(pond_health_handler))
        .route("/v1/status", get(pond_status_projection_handler))
        .route(
            "/v1/mdns/browser/snapshot",
            get(pond_browser_snapshot_handler),
        )
        .route("/v1/dns/entries", get(pond_dns_entries_handler))
        .layer(Extension(runtime))
}

/// Routes mounted only on the full operator adapter. DAT middleware remains outside.
pub fn operator_routes(runtime: PondRuntime) -> Router {
    Router::new()
        .route("/v1/ui", put(ui_publish_handler))
        .route(
            "/v1/pond",
            get(pond_operator_status_handler)
                .put(pond_enable_handler)
                .delete(pond_disable_handler),
        )
        .layer(Extension(runtime))
}

fn ui_file_response(runtime: &PondRuntime, name: &str, content_type: &str) -> Response {
    match std::fs::read(runtime.inner.config.ui_dir.join(name)) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "no-cache"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "capability_disabled",
                "message": "Pond UI is not published"
            })),
        )
            .into_response(),
    }
}

async fn ui_index_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    let mut response = ui_file_response(&runtime, "index.html", "text/html; charset=utf-8");
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(POND_HTML_CSP),
    );
    response
}

async fn ui_asset_app(Extension(runtime): Extension<PondRuntime>) -> Response {
    ui_file_response(&runtime, "app.js", "text/javascript; charset=utf-8")
}

async fn ui_asset_styles(Extension(runtime): Extension<PondRuntime>) -> Response {
    ui_file_response(&runtime, "styles.css", "text/css; charset=utf-8")
}

async fn ui_asset_sentences(Extension(runtime): Extension<PondRuntime>) -> Response {
    ui_file_response(&runtime, "sentences.js", "text/javascript; charset=utf-8")
}

async fn ui_asset_png(Extension(runtime): Extension<PondRuntime>) -> Response {
    ui_file_response(&runtime, "koi.png", "image/png")
}

async fn pond_health_handler() -> &'static str {
    "OK"
}

async fn pond_status_projection_handler(
    Extension(runtime): Extension<PondRuntime>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "uptime_secs": runtime.inner.config.started_at.elapsed().as_secs(),
        "daemon": true,
        "surface": "pond",
    }))
}

async fn pond_browser_snapshot_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    let Some(browser) = &runtime.inner.config.browser else {
        return disabled_response("mdns-browser");
    };
    browser.meta.touch();
    Json(browser.cache.snapshot().await).into_response()
}

async fn pond_dns_entries_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    let Some(dns) = &runtime.inner.config.dns else {
        return disabled_response("dns");
    };
    Json(serde_json::json!({ "entries": dns.core().list_entries() })).into_response()
}

fn disabled_response(capability: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "capability_disabled",
            "message": format!("The '{capability}' capability is disabled on this daemon.")
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PondUiFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PondUiPublish {
    pub files: Vec<PondUiFile>,
}

#[utoipa::path(put, path = "/v1/ui", tag = "pond",
    summary = "Publish the fixed Pond browser bundle",
    request_body = PondUiPublish,
    responses(
        (status = 200, description = "Complete bundle published"),
        (status = 400, description = "Bundle is incomplete or contains another file"),
        (status = 401, description = "Daemon access token required")
    ))]
async fn ui_publish_handler(
    Extension(runtime): Extension<PondRuntime>,
    Json(publish): Json<PondUiPublish>,
) -> Response {
    let _publish_guard = runtime.inner.publish.lock().await;
    let names = publish
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    if names.len() != UI_FILES.len()
        || !UI_FILES.iter().all(|required| names.contains(required))
        || publish.files.len() != UI_FILES.len()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_pond_bundle",
                "message": "a Pond publish must contain each of the five fixed UI files exactly once"
            })),
        )
            .into_response();
    }
    if let Err(error) = write_ui_bundle(&runtime.inner.config.ui_dir, &publish.files) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response();
    }
    runtime.inner.reconcile_now.notify_waiters();
    Json(serde_json::json!({ "published": UI_FILES.len(), "ok": true })).into_response()
}

fn write_ui_bundle(dir: &Path, files: &[PondUiFile]) -> Result<(), String> {
    use base64::Engine as _;

    let decoded = files
        .iter()
        .map(|file| {
            let bytes = if file.path == "koi.png" {
                base64::engine::general_purpose::STANDARD
                    .decode(file.content.as_bytes())
                    .map_err(|error| format!("koi.png: {error}"))?
            } else {
                file.content.as_bytes().to_vec()
            };
            Ok((file.path.as_str(), bytes))
        })
        .collect::<Result<Vec<_>, String>>()?;

    std::fs::create_dir_all(dir)
        .map_err(|error| format!("could not create UI directory: {error}"))?;
    for (path, bytes) in &decoded {
        let temporary = dir.join(format!(".{path}.{}.tmp", std::process::id()));
        std::fs::write(&temporary, bytes).map_err(|error| format!("{path}: {error}"))?;
    }
    for (path, _) in &decoded {
        let target = dir.join(path);
        let temporary = dir.join(format!(".{path}.{}.tmp", std::process::id()));
        koi_common::persist::replace_file(&temporary, &target)
            .map_err(|error| format!("{path}: {error}"))?;
    }
    Ok(())
}

#[utoipa::path(get, path = "/v1/pond", tag = "pond",
    summary = "Read Pond desired and observed state",
    responses((status = 200, body = PondStatus),
              (status = 401, description = "Daemon access token required")))]
async fn pond_operator_status_handler(
    Extension(runtime): Extension<PondRuntime>,
) -> Json<PondStatus> {
    Json(runtime.status())
}

#[utoipa::path(put, path = "/v1/pond", tag = "pond",
    summary = "Desire and reconcile the read-only LAN listener",
    responses((status = 200, body = PondStatus),
              (status = 503, body = PondStatus, description = "Desired but not reachable yet"),
              (status = 401, description = "Daemon access token required")))]
async fn pond_enable_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    match runtime.enable().await {
        Ok(status) if status.running => Json(status).into_response(),
        Ok(status) => (StatusCode::SERVICE_UNAVAILABLE, Json(status)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_not_persisted",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/pond", tag = "pond",
    summary = "Persistently stop the read-only LAN listener",
    responses((status = 200, body = PondStatus),
              (status = 401, description = "Daemon access token required")))]
async fn pond_disable_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    match runtime.disable().await {
        Ok(status) => Json(status).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_not_persisted",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        ui_publish_handler,
        pond_operator_status_handler,
        pond_enable_handler,
        pond_disable_handler
    ),
    components(schemas(
        PondUiFile,
        PondUiPublish,
        PondStatus,
        PondState,
        PondFirewallStatus,
        PondFirewallState
    ))
)]
pub struct PondApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_runtime() -> PondRuntime {
        let root = koi_common::test::ensure_data_dir("pond-runtime-tests");
        PondRuntime::new(PondConfig {
            port: DEFAULT_POND_PORT,
            ui_dir: root.join("ui"),
            intent_path: root.join("pond.json"),
            started_at: Instant::now(),
            browser: None,
            dns: None,
            parent_cancel: CancellationToken::new(),
        })
    }

    #[test]
    fn status_wire_round_trips() {
        let status = PondStatus {
            desired: true,
            running: true,
            state: PondState::Running,
            port: DEFAULT_POND_PORT,
            urls: vec!["http://192.168.1.2:5644/".to_string()],
            url: Some("http://192.168.1.2:5644/".to_string()),
            firewall: PondFirewallStatus {
                state: PondFirewallState::Open,
                detail: "open".to_string(),
            },
            reason: None,
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<PondStatus>(&encoded).unwrap(),
            status
        );
    }

    #[test]
    fn pond_port_is_the_fourth_port_and_refuses_overflow() {
        assert_eq!(port_for_http(5641), Some(DEFAULT_POND_PORT));
        assert_eq!(port_for_http(u16::MAX), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ufw_assessment_honors_tcp_rules_ranges_and_default_policy() {
        let open = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\
             5600:5700/tcp ALLOW IN 192.168.1.0/24\n",
        );
        assert_eq!(open.state, PondFirewallState::Open);

        let udp_only = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\
             5644/udp ALLOW IN Anywhere\n",
        );
        assert_eq!(udp_only.state, PondFirewallState::Blocked);

        let default_open = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: allow (incoming), allow (outgoing)\n",
        );
        assert_eq!(default_open.state, PondFirewallState::Open);
    }

    #[test]
    fn fixed_bundle_can_be_republished_without_stale_files() {
        let root = koi_common::test::ensure_data_dir("pond-runtime-tests").join("pond-republish");
        let _ = std::fs::remove_dir_all(&root);
        let bundle = |marker: &str| {
            UI_FILES
                .iter()
                .map(|path| PondUiFile {
                    path: (*path).to_string(),
                    content: if *path == "koi.png" {
                        "aGVsbG8=".to_string()
                    } else {
                        format!("{path}-{marker}")
                    },
                })
                .collect::<Vec<_>>()
        };

        write_ui_bundle(&root, &bundle("first")).unwrap();
        write_ui_bundle(&root, &bundle("second")).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("app.js")).unwrap(),
            "app.js-second"
        );
        assert_eq!(std::fs::read(root.join("koi.png")).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn public_router_has_only_allowlisted_reads() {
        let runtime = test_runtime();
        let app = public_routes(runtime);

        let mutation = app
            .clone()
            .oneshot(Request::post("/v1/dns/add").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(mutation.status(), StatusCode::NOT_FOUND);

        let excluded = app
            .clone()
            .oneshot(
                Request::get("/v1/certmesh/log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(excluded.status(), StatusCode::NOT_FOUND);

        let dns = app
            .oneshot(Request::get("/v1/dns/entries").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(dns.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
