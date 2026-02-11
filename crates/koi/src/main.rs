mod adapters;
mod admin;
mod client;
pub(crate) mod cli;
mod commands;
mod format;
mod platform;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio_util::sync::CancellationToken;

use cli::{AdminSubcommand, CertmeshSubcommand, Cli, Command, Config, MdnsSubcommand};

/// Maximum time to wait for orderly shutdown before forcing exit.
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Brief pause after cancellation to let in-flight requests complete.
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

fn main() -> anyhow::Result<()> {
    // ── Windows Service dispatch ────────────────────────────────────
    // Must happen before anything else — the SCM expects the service
    // process to connect to the dispatcher almost immediately.
    #[cfg(windows)]
    {
        if platform::windows::try_run_as_service() {
            return Ok(());
        }
    }

    let cli = Cli::parse();
    let config = Config::from_cli(&cli);

    // Initialize logging
    let level = match cli.verbose {
        0 => cli.log_level.as_str(),
        1 => "debug",
        _ => "trace",
    };
    let env_filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Hold the non-blocking guards for the lifetime of main so logs flush on exit.
    let _log_guards = init_logging(env_filter, cli.log_file.as_deref())?;

    // ── Synchronous subcommands (no runtime needed) ──────────────────
    if let Some(command) = &cli.command {
        match command {
            Command::Install => {
                return {
                    #[cfg(windows)]
                    {
                        platform::windows::install()
                    }
                    #[cfg(target_os = "linux")]
                    {
                        platform::unix::install()
                    }
                    #[cfg(target_os = "macos")]
                    {
                        platform::macos::install()
                    }
                    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
                    {
                        anyhow::bail!("Service install is not supported on this platform.")
                    }
                };
            }
            Command::Uninstall => {
                return {
                    #[cfg(windows)]
                    {
                        platform::windows::uninstall()
                    }
                    #[cfg(target_os = "linux")]
                    {
                        platform::unix::uninstall()
                    }
                    #[cfg(target_os = "macos")]
                    {
                        platform::macos::uninstall()
                    }
                    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
                    {
                        anyhow::bail!("Service uninstall is not supported on this platform.")
                    }
                };
            }
            Command::Version => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "version": env!("CARGO_PKG_VERSION"),
                            "platform": std::env::consts::OS,
                        })
                    );
                } else {
                    println!("koi {}", env!("CARGO_PKG_VERSION"));
                }
                return Ok(());
            }
            Command::Status => {
                return dispatch_status(&cli, &config);
            }
            Command::Mdns(mdns_cmd) => {
                config.require_capability("mdns")?;
                // Admin subcommands are sync — handle before runtime
                if let MdnsSubcommand::Admin(admin_cmd) = &mdns_cmd.command {
                    let endpoint = resolve_endpoint(&cli)?;
                    return dispatch_mdns_admin(&admin_cmd.command, &endpoint, cli.json);
                }
            }
            Command::Certmesh(cm_cmd) => {
                config.require_capability("certmesh")?;
                return dispatch_certmesh_sync(&cm_cmd.command, &cli);
            }
        }
    }

    // ── Everything below needs a Tokio runtime ──────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli, config))
}

async fn async_main(cli: Cli, config: Config) -> anyhow::Result<()> {
    // ── Moniker subcommands (async) ─────────────────────────────────
    if let Some(command) = &cli.command {
        if let Command::Mdns(mdns_cmd) = command {
            // Capability check already done in main()
            return match detect_mode(&cli) {
                RunMode::Standalone => dispatch_mdns_standalone(&mdns_cmd.command, &cli).await,
                RunMode::Client { endpoint } => {
                    dispatch_mdns_client(&mdns_cmd.command, &endpoint, &cli).await
                }
            };
        }

        // Non-moniker commands already handled in main()
        return Ok(());
    }

    // ── Piped CLI mode ──────────────────────────────────────────────
    if is_piped_stdin() && !cli.daemon {
        if config.no_mdns {
            anyhow::bail!(
                "Piped mode requires the mDNS capability. \
                 Remove --no-mdns or unset KOI_NO_MDNS to enable it."
            );
        }
        let core = Arc::new(koi_mdns::MdnsCore::new()?);
        adapters::cli::start(core.clone()).await?;
        let _ = core.shutdown().await;
        return Ok(());
    }

    // ── Daemon mode ─────────────────────────────────────────────────
    koi_config::dirs::ensure_data_dir();
    startup_diagnostics(&config);

    // Write breadcrumb so clients can discover the daemon
    if !config.no_http {
        let endpoint = format!("http://localhost:{}", config.http_port);
        koi_config::breadcrumb::write_breadcrumb(&endpoint);
    }

    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    let started_at = std::time::Instant::now();

    // ── Create domain cores based on config ──
    let mdns_core = if !config.no_mdns {
        match koi_mdns::MdnsCore::with_cancel(cancel.clone()) {
            Ok(core) => Some(Arc::new(core)),
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize mDNS core");
                None
            }
        }
    } else {
        tracing::info!("mDNS capability: disabled");
        None
    };

    let certmesh_core = if !config.no_certmesh {
        init_certmesh_core()
    } else {
        tracing::info!("Certmesh capability: disabled");
        None
    };

    let cores = DaemonCores {
        mdns: mdns_core.clone(),
        certmesh: certmesh_core,
    };

    // ── HTTP adapter ──
    if !config.no_http {
        let c = cores.clone();
        let port = config.http_port;
        let token = cancel.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = start_http(c, port, token, started_at).await {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    // ── IPC adapter (only if mDNS is enabled — IPC speaks mDNS NDJSON protocol) ──
    if !config.no_ipc {
        if let Some(ref mdns) = mdns_core {
            let c = mdns.clone();
            let path = config.pipe_path.clone();
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = adapters::pipe::start(c, path, token).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        } else {
            tracing::info!("IPC adapter: skipped (mDNS disabled)");
        }
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal().await;
    tracing::info!("Shutting down...");

    // Ordered shutdown with hard timeout
    let shutdown = async {
        cancel.cancel();
        tokio::time::sleep(SHUTDOWN_DRAIN).await;
        for task in tasks {
            let _ = task.await;
        }
        if let Some(ref core) = mdns_core {
            if let Err(e) = core.shutdown().await {
                tracing::warn!(error = %e, "Error during mDNS shutdown");
            }
        }
    };
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown)
        .await
        .is_err()
    {
        tracing::warn!(
            "Shutdown timed out after {:?} — forcing exit",
            SHUTDOWN_TIMEOUT
        );
    }

    koi_config::breadcrumb::delete_breadcrumb();

    Ok(())
}

// ── Daemon cores ──────────────────────────────────────────────────────

/// Runtime state for a running daemon. Each domain core is present
/// only if its capability is enabled via Config.
#[derive(Clone)]
pub(crate) struct DaemonCores {
    pub(crate) mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub(crate) certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
}

/// Attempt to initialize the certmesh core for daemon mode.
///
/// If a CA is initialized, creates a locked core with the roster.
/// If not initialized, returns None (certmesh CLI commands still work).
pub(crate) fn init_certmesh_core() -> Option<Arc<koi_certmesh::CertmeshCore>> {
    if !koi_certmesh::ca::is_ca_initialized() {
        tracing::info!("Certmesh: CA not initialized");
        return None;
    }

    let roster_path = koi_certmesh::ca::roster_path();
    let roster = match koi_certmesh::roster::load_roster(&roster_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load certmesh roster");
            return None;
        }
    };

    let profile = roster.metadata.trust_profile.clone();
    let core = koi_certmesh::CertmeshCore::locked(roster, profile);
    tracing::info!("Certmesh: CA initialized (locked, use `koi certmesh unlock` to decrypt)");
    Some(Arc::new(core))
}

// ── HTTP server startup ─────────────────────────────────────────────

pub(crate) async fn start_http(
    cores: DaemonCores,
    port: u16,
    cancel: CancellationToken,
    started_at: std::time::Instant,
) -> anyhow::Result<()> {
    use axum::extract::State as AxumState;
    use axum::response::Json;
    use axum::routing::get;
    use axum::Router;
    use koi_common::capability::Capability;
    use tower_http::cors::CorsLayer;

    #[derive(Clone)]
    struct AppState {
        mdns: Option<Arc<koi_mdns::MdnsCore>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
        started_at: std::time::Instant,
    }

    async fn unified_status_handler(
        AxumState(state): AxumState<AppState>,
    ) -> Json<serde_json::Value> {
        use koi_common::capability::CapabilityStatus;

        let mut capabilities = Vec::new();

        if let Some(ref core) = state.mdns {
            capabilities.push(core.status());
        } else {
            capabilities.push(CapabilityStatus {
                name: "mdns".to_string(),
                summary: "disabled".to_string(),
                healthy: false,
            });
        }

        if let Some(ref core) = state.certmesh {
            capabilities.push(core.status());
        } else {
            capabilities.push(CapabilityStatus {
                name: "certmesh".to_string(),
                summary: "disabled".to_string(),
                healthy: false,
            });
        }

        let uptime_secs = state.started_at.elapsed().as_secs();
        Json(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "uptime_secs": uptime_secs,
            "daemon": true,
            "capabilities": capabilities,
        }))
    }

    let app_state = AppState {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        started_at,
    };

    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(unified_status_handler))
        .with_state(app_state);

    // ── Mount domain routes or fallback routers ──
    if let Some(ref mdns_core) = cores.mdns {
        app = app.nest("/v1/mdns", koi_mdns::http::routes(mdns_core.clone()));
    } else {
        app = app.nest("/v1/mdns", disabled_fallback_router("mdns"));
    }

    if let Some(ref certmesh_core) = cores.certmesh {
        app = app.nest("/v1/certmesh", certmesh_core.routes());
    } else {
        app = app.nest("/v1/certmesh", disabled_fallback_router("certmesh"));
    }

    app = app.layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("HTTP adapter listening on port {}", port);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
        })
        .await?;

    tracing::debug!("HTTP adapter stopped");
    Ok(())
}

async fn health() -> &'static str {
    "OK"
}

/// Returns a router that responds 503 for any request to a disabled capability.
fn disabled_fallback_router(capability_name: &'static str) -> axum::Router {
    axum::Router::new().fallback(move || async move {
        let body = serde_json::json!({
            "error": "capability_disabled",
            "message": format!(
                "The '{}' capability is disabled on this daemon.",
                capability_name
            ),
        });
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(body),
        )
    })
}

// ── Mode detection ───────────────────────────────────────────────────

enum RunMode {
    Standalone,
    Client { endpoint: String },
}

/// Determine whether to run standalone (local mDNS core) or as a client
/// talking to an already-running daemon.
fn detect_mode(cli: &Cli) -> RunMode {
    if cli.standalone {
        return RunMode::Standalone;
    }
    if let Some(endpoint) = &cli.endpoint {
        return RunMode::Client {
            endpoint: endpoint.clone(),
        };
    }
    // Check breadcrumb — if a daemon is advertising its endpoint, use client mode
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        let c = client::KoiClient::new(&endpoint);
        if c.health().is_ok() {
            return RunMode::Client { endpoint };
        }
    }
    RunMode::Standalone
}

/// Resolve an endpoint for admin commands (which always need a daemon).
fn resolve_endpoint(cli: &Cli) -> anyhow::Result<String> {
    if let Some(endpoint) = &cli.endpoint {
        return Ok(endpoint.clone());
    }
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        return Ok(endpoint);
    }
    anyhow::bail!("No daemon endpoint found. Is the daemon running? Use --endpoint to specify.")
}

// ── mDNS command dispatch ────────────────────────────────────────────

async fn dispatch_mdns_standalone(
    subcmd: &MdnsSubcommand,
    cli: &Cli,
) -> anyhow::Result<()> {
    let core = Arc::new(koi_mdns::MdnsCore::new()?);
    match subcmd {
        MdnsSubcommand::Discover { service_type } => {
            commands::standalone::browse(core, service_type.as_deref(), cli.json, cli.timeout).await
        }
        MdnsSubcommand::Announce {
            name,
            service_type,
            port,
            ip,
            txt,
        } => {
            commands::standalone::register(
                core,
                name,
                service_type,
                *port,
                ip.as_deref(),
                txt,
                cli.json,
                cli.timeout,
            )
            .await
        }
        MdnsSubcommand::Unregister { id } => {
            commands::standalone::unregister(core, id, cli.json).await
        }
        MdnsSubcommand::Resolve { instance } => {
            commands::standalone::resolve(core, instance, cli.json).await
        }
        MdnsSubcommand::Subscribe { service_type } => {
            commands::standalone::subscribe(core, service_type, cli.json, cli.timeout).await
        }
        MdnsSubcommand::Admin(_) => {
            anyhow::bail!("Admin commands are handled synchronously; this path should not be reached")
        }
    }
}

async fn dispatch_mdns_client(
    subcmd: &MdnsSubcommand,
    endpoint: &str,
    cli: &Cli,
) -> anyhow::Result<()> {
    match subcmd {
        MdnsSubcommand::Discover { service_type } => {
            commands::client::browse(endpoint, service_type.as_deref(), cli.json, cli.timeout).await
        }
        MdnsSubcommand::Announce {
            name,
            service_type,
            port,
            ip,
            txt,
        } => {
            commands::client::register(
                endpoint,
                name,
                service_type,
                *port,
                ip.as_deref(),
                txt,
                cli.json,
                cli.timeout,
            )
            .await
        }
        MdnsSubcommand::Unregister { id } => {
            commands::client::unregister(endpoint, id, cli.json)
        }
        MdnsSubcommand::Resolve { instance } => {
            commands::client::resolve(endpoint, instance, cli.json)
        }
        MdnsSubcommand::Subscribe { service_type } => {
            commands::client::subscribe(endpoint, service_type, cli.json, cli.timeout).await
        }
        MdnsSubcommand::Admin(_) => {
            anyhow::bail!("Admin commands are handled synchronously; this path should not be reached")
        }
    }
}

fn dispatch_mdns_admin(
    admin_cmd: &AdminSubcommand,
    endpoint: &str,
    json: bool,
) -> anyhow::Result<()> {
    match admin_cmd {
        AdminSubcommand::Status => admin::status(endpoint, json),
        AdminSubcommand::List => admin::list(endpoint, json),
        AdminSubcommand::Inspect { id } => admin::inspect(endpoint, id, json),
        AdminSubcommand::Unregister { id } => admin::unregister(endpoint, id, json),
        AdminSubcommand::Drain { id } => admin::drain(endpoint, id, json),
        AdminSubcommand::Revive { id } => admin::revive(endpoint, id, json),
    }
}

// ── Certmesh command dispatch ───────────────────────────────────────

fn dispatch_certmesh_sync(
    subcmd: &CertmeshSubcommand,
    cli: &Cli,
) -> anyhow::Result<()> {
    use koi_certmesh::{
        audit, ca, certfiles, entropy, profiles::TrustProfile, roster,
    };

    match subcmd {
        CertmeshSubcommand::Create {
            profile,
            operator,
            entropy: entropy_mode,
            passphrase,
        } => {
            if ca::is_ca_initialized() {
                anyhow::bail!("CA already initialized. Remove {:?} to start over.", ca::ca_dir());
            }

            let trust_profile = profile
                .as_deref()
                .and_then(TrustProfile::from_str_loose)
                .unwrap_or(TrustProfile::JustMe);

            if trust_profile.requires_operator() && operator.is_none() {
                anyhow::bail!(
                    "The '{}' profile requires --operator <name>.",
                    trust_profile
                );
            }

            // Collect entropy
            let entropy_seed = match entropy_mode.as_str() {
                "keyboard" => entropy::collect_entropy(entropy::EntropyMode::KeyboardMashing)?,
                "manual" => {
                    let phrase = passphrase
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("--passphrase required with --entropy=manual"))?;
                    entropy::collect_entropy(entropy::EntropyMode::Manual(phrase.to_string()))?
                }
                _ => entropy::collect_entropy(entropy::EntropyMode::AutoPassphrase)?,
            };

            // Prompt for CA passphrase
            let ca_passphrase = passphrase
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    eprintln!("Enter a passphrase to protect the CA key:");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).unwrap_or_default();
                    line.trim().to_string()
                });

            if ca_passphrase.is_empty() {
                anyhow::bail!("Passphrase cannot be empty.");
            }

            // Create CA
            let ca_state = ca::create_ca(&ca_passphrase, &entropy_seed)?;

            // Generate and save TOTP secret
            let totp_secret = koi_crypto::totp::generate_secret();
            let encrypted_totp = koi_crypto::totp::encrypt_secret(&totp_secret, &ca_passphrase)?;
            koi_crypto::keys::save_encrypted_key(&ca::totp_secret_path(), &encrypted_totp)?;

            // Create roster
            let mut r = roster::Roster::new(trust_profile.clone(), operator.clone());

            // Self-enroll this host as primary
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "localhost".to_string());
            let sans = vec![hostname.clone(), format!("{hostname}.local")];
            let issued = ca::issue_certificate(&ca_state, &hostname, &sans)?;
            let cert_dir = certfiles::write_cert_files(&hostname, &issued)?;

            r.members.push(roster::RosterMember {
                hostname: hostname.clone(),
                role: roster::MemberRole::Primary,
                enrolled_at: chrono::Utc::now(),
                enrolled_by: operator.clone(),
                cert_fingerprint: issued.fingerprint.clone(),
                cert_expires: issued.expires,
                cert_sans: sans,
                cert_path: cert_dir.display().to_string(),
                status: roster::MemberStatus::Active,
            });

            roster::save_roster(&r, &ca::roster_path())?;

            // Audit log
            let _ = audit::append_entry(
                "pond_initialized",
                &[
                    ("profile", &trust_profile.to_string()),
                    ("operator", operator.as_deref().unwrap_or("self")),
                    ("hostname", &hostname),
                ],
            );

            // Install root CA in trust store (best-effort)
            if let Err(e) = koi_truststore::install_ca_cert(&ca_state.cert_pem, "koi-certmesh-ca") {
                eprintln!("Warning: Could not install CA in system trust store: {e}");
                eprintln!("You may need to install it manually.");
            }

            // Display results
            format::certmesh_create_success(
                &hostname,
                &cert_dir,
                &trust_profile,
                &ca::ca_fingerprint(&ca_state),
            );

            // Show QR code for TOTP
            let qr = koi_crypto::totp::qr_code_unicode(
                &totp_secret,
                "Koi Certmesh",
                &format!("admin@{hostname}"),
            );
            println!("\nScan this QR code with your authenticator app:\n");
            println!("{qr}");

            Ok(())
        }

        CertmeshSubcommand::Status => {
            if !ca::is_ca_initialized() {
                if cli.json {
                    println!("{}", serde_json::json!({
                        "ca_initialized": false,
                    }));
                } else {
                    println!("Certificate mesh: not initialized");
                    println!("  Run `koi certmesh create` to set up a CA.");
                }
                return Ok(());
            }

            let roster_path = ca::roster_path();
            if roster_path.exists() {
                let r = roster::load_roster(&roster_path)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "ca_initialized": true,
                        "profile": r.metadata.trust_profile,
                        "enrollment_state": r.metadata.enrollment_state,
                        "member_count": r.active_count(),
                        "members": r.members.iter().map(|m| serde_json::json!({
                            "hostname": m.hostname,
                            "role": format!("{:?}", m.role).to_lowercase(),
                            "status": format!("{:?}", m.status).to_lowercase(),
                            "cert_fingerprint": m.cert_fingerprint,
                            "cert_expires": m.cert_expires.to_rfc3339(),
                        })).collect::<Vec<_>>(),
                    }))?);
                } else {
                    format::certmesh_status(&r);
                }
            } else {
                println!("CA initialized but roster not found.");
            }

            Ok(())
        }

        CertmeshSubcommand::Log => {
            let log = audit::read_log()?;
            if log.is_empty() {
                println!("No audit log entries.");
            } else {
                print!("{log}");
            }
            Ok(())
        }

        CertmeshSubcommand::Unlock => {
            if !ca::is_ca_initialized() {
                anyhow::bail!("CA not initialized. Run `koi certmesh create` first.");
            }

            eprintln!("Enter the CA passphrase:");
            let mut passphrase = String::new();
            std::io::stdin().read_line(&mut passphrase)?;
            let passphrase = passphrase.trim();

            let _ca = ca::load_ca(passphrase)?;
            println!("CA unlocked successfully.");
            Ok(())
        }

        CertmeshSubcommand::Join { endpoint } => {
            eprintln!("Enter the TOTP code from your authenticator app:");
            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let code = code.trim().to_string();

            let client = client::KoiClient::new(endpoint);
            let body = serde_json::json!({ "totp_code": code });
            let resp = client.post_json("/v1/certmesh/join", &body)?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let hostname = resp
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let cert_path = resp
                    .get("cert_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                println!("Enrolled as: {hostname}");
                println!("Certificates written to: {cert_path}");
            }
            Ok(())
        }
    }
}

// ── Status command ──────────────────────────────────────────────────

fn offline_capabilities(config: &Config) -> Vec<koi_common::capability::CapabilityStatus> {
    use koi_common::capability::CapabilityStatus;

    let mut caps = Vec::new();

    if config.no_mdns {
        caps.push(CapabilityStatus {
            name: "mdns".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        caps.push(CapabilityStatus {
            name: "mdns".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        });
    }

    if config.no_certmesh {
        caps.push(CapabilityStatus {
            name: "certmesh".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        let certmesh_summary = if koi_certmesh::ca::is_ca_initialized() {
            "CA initialized (daemon not running)".to_string()
        } else {
            "CA not initialized".to_string()
        };
        caps.push(CapabilityStatus {
            name: "certmesh".to_string(),
            summary: certmesh_summary,
            healthy: false,
        });
    }

    caps
}

fn dispatch_status(cli: &Cli, config: &Config) -> anyhow::Result<()> {
    use koi_common::capability::CapabilityStatus;
    use serde::Serialize;

    #[derive(Serialize)]
    struct UnifiedStatus {
        version: String,
        platform: String,
        daemon: bool,
        capabilities: Vec<CapabilityStatus>,
    }

    // Try to connect to daemon first
    if !cli.standalone {
        if let Some(endpoint) = cli
            .endpoint
            .clone()
            .or_else(koi_config::breadcrumb::read_breadcrumb)
        {
            let c = client::KoiClient::new(&endpoint);
            if c.health().is_ok() {
                match c.unified_status() {
                    Ok(status_json) => {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&status_json)?);
                        } else {
                            format_unified_status(&status_json);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Could not fetch unified status");
                    }
                }
            }
        }
    }

    // No daemon — report offline status
    let capabilities = offline_capabilities(config);

    let status = UnifiedStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        daemon: false,
        capabilities,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Koi v{}", status.version);
        println!("  Platform:  {}", status.platform);
        println!("  Daemon:    not running");
        for cap in &status.capabilities {
            let marker = if cap.healthy { "+" } else { "-" };
            println!("  [{}] {}:  {}", marker, cap.name, cap.summary);
        }
    }

    Ok(())
}

fn format_unified_status(json: &serde_json::Value) {
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let platform = json
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let uptime = json.get("uptime_secs").and_then(|v| v.as_u64());

    println!("Koi v{version}");
    println!("  Platform:  {platform}");
    if let Some(secs) = uptime {
        println!("  Uptime:    {secs}s");
    }
    println!("  Daemon:    running");

    if let Some(caps) = json.get("capabilities").and_then(|v| v.as_array()) {
        for cap in caps {
            let name = cap.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let summary = cap.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let healthy = cap.get("healthy").and_then(|v| v.as_bool()).unwrap_or(false);
            let marker = if healthy { "+" } else { "-" };
            println!("  [{marker}] {name}:  {summary}");
        }
    }
}

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Wait for Ctrl+C or platform-specific shutdown signal.
async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "Failed to listen for Ctrl+C");
    }
}

// ── Daemon startup diagnostics ──────────────────────────────────────

pub(crate) fn startup_diagnostics(config: &Config) {
    tracing::info!("Koi v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("Platform: {}", std::env::consts::OS);

    match hostname::get() {
        Ok(h) => tracing::info!("Hostname: {}", h.to_string_lossy()),
        Err(e) => tracing::warn!(error = %e, "Could not determine hostname"),
    }

    if config.no_mdns {
        tracing::info!("mDNS capability: disabled");
    } else {
        tracing::info!("mDNS engine: mdns-sd");
    }

    if config.no_certmesh {
        tracing::info!("Certmesh capability: disabled");
    }

    if !config.no_http {
        tracing::info!("TCP {}: listening (HTTP adapter)", config.http_port);
    } else {
        tracing::info!("HTTP adapter: disabled");
    }

    if !config.no_ipc {
        tracing::info!("IPC: {}", config.pipe_path.display());
    } else {
        tracing::info!("IPC adapter: disabled");
    }

    #[cfg(windows)]
    platform::windows::check_firewall(config.http_port);
}

// ── Logging setup ───────────────────────────────────────────────────

/// Initialize tracing with stderr + optional file output.
/// Returns guards that must be held for the lifetime of the program
/// to ensure the non-blocking writers flush on shutdown.
pub(crate) fn init_logging(
    env_filter: tracing_subscriber::EnvFilter,
    log_file: Option<&std::path::Path>,
) -> anyhow::Result<Vec<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::prelude::*;

    // Always use non-blocking stderr to avoid deadlocks when stderr is a
    // redirected pipe that nobody reads (e.g. Windows service, test harness).
    let (nb_stderr, stderr_guard) = tracing_appender::non_blocking(std::io::stderr());
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(nb_stderr);

    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let (nb_file, file_guard) = tracing_appender::non_blocking(file);
        let file_layer = tracing_subscriber::fmt::layer().with_writer(nb_file);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();

        Ok(vec![stderr_guard, file_guard])
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stderr_layer)
            .init();

        Ok(vec![stderr_guard])
    }
}
