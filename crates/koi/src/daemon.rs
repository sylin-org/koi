//! Daemon mode — constructs the daemon via koi-compose (`build_cores`), spawns the binary's
//! transport adapters, writes the breadcrumb, and runs the ordered shutdown; plus the stdin
//! enrollment-approval prompt. Moved from main.rs (P07 step 6b).

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cli::Config;
use crate::infra::{
    breadcrumb_endpoint, resolve_http_bind_ip, shutdown_signal, startup_diagnostics,
};
use crate::{adapters, platform};

// ── Daemon mode ──────────────────────────────────────────────────────

pub(crate) async fn daemon_mode(config: Config) -> anyhow::Result<()> {
    koi_config::dirs::ensure_data_dir();

    // Resolve the HTTP bind address up front so startup logs and the breadcrumb
    // agree with what the adapter actually binds. Only meaningful when HTTP is on.
    let http_bind_ip = if config.no_http {
        None
    } else {
        Some(resolve_http_bind_ip(&config.http_bind)?)
    };
    startup_diagnostics(&config, http_bind_ip);

    // Generate a Daemon Access Token (DAT) for authenticating mutation requests
    let dat_token = {
        use base64::Engine;
        use rand::RngCore;
        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    };

    // Write breadcrumb so clients can discover the daemon. Clients connect over a
    // routable address, so an unspecified bind (0.0.0.0) is advertised as loopback.
    if !config.no_http {
        let endpoint = breadcrumb_endpoint(http_bind_ip, config.http_port);
        koi_config::breadcrumb::write_breadcrumb(&endpoint, &dat_token);
    }

    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    let started_at = std::time::Instant::now();

    // ── Build all domain cores + bridges + domain background tasks ──
    // The construction graph, the orchestrator, and the certmesh role loops live in
    // koi-compose so the Windows service constructs the identical daemon (P07).
    let cores = koi_compose::cores::build_cores(
        &koi_compose::cores::CoreSpec {
            no_mdns: config.no_mdns,
            no_certmesh: config.no_certmesh,
            no_dns: config.no_dns,
            no_health: config.no_health,
            no_proxy: config.no_proxy,
            no_udp: config.no_udp,
            no_runtime: config.no_runtime,
            data_dir: config.data_dir.clone(),
            dns_config: config.dns_config(),
            runtime: config.runtime.clone(),
            http_port: config.http_port,
        },
        &cancel,
        &mut tasks,
    )
    .await;

    // ── Dashboard state ──
    let dashboard_state = adapters::dashboard::build_dashboard_state(&cores, started_at, "daemon");
    tasks.push(koi_dashboard::forward::spawn_event_forwarder(
        koi_dashboard::forward::ForwarderCores {
            mdns: cores.mdns.clone(),
            certmesh: cores.certmesh.clone(),
            dns: cores.dns.clone(),
            health: cores.health.clone(),
            proxy: cores.proxy.clone(),
            runtime: cores.runtime.clone(),
        },
        dashboard_state.event_tx.clone(),
        cancel.clone(),
    ));

    // ── mDNS browser state (conditional on mDNS being enabled) ──
    // The LAN-wide meta-browse worker is NOT started here: it starts on the first
    // browser request and idles out (koi_dashboard::meta_browse). Default daemon
    // startup performs no LAN-wide browsing.
    let browser_state = cores
        .mdns
        .as_ref()
        .map(|mdns| koi_dashboard::browser::build_state(mdns.clone(), cancel.clone()));

    // ── HTTP adapter ──
    if !config.no_http {
        let c = cores.clone();
        let port = config.http_port;
        let bind_ip = http_bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let cancel_token = cancel.clone();
        let ds = dashboard_state.clone();
        let bs = browser_state.clone();
        let dat = dat_token.clone();
        let mdns_snap = cores.mdns_snapshot.clone();
        let mcp_http = !config.no_mcp_http;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::http::start(
                c,
                bind_ip,
                port,
                cancel_token,
                started_at,
                ds,
                bs,
                dat,
                mdns_snap,
                mcp_http,
            )
            .await
            {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    // ── mTLS adapter (only if certmesh CA is initialized and unlocked) ──
    // The daemon self-enrollment also produces the server leaf the ACME listener
    // reuses, so it's done once here and shared.
    if let Some(ref certmesh) = cores.certmesh {
        match certmesh.self_enroll().await {
            Ok(enrollment) => {
                // mTLS inter-node listener.
                {
                    let cm = certmesh.clone();
                    let port = config.mtls_port;
                    let token = cancel.clone();
                    let enr = enrollment.clone();
                    tasks.push(tokio::spawn(async move {
                        if let Err(e) = adapters::mtls::start(
                            port,
                            cm,
                            &enr.cert_pem,
                            &enr.key_pem,
                            &enr.ca_cert_pem,
                            token,
                        )
                        .await
                        {
                            tracing::error!(error = %e, "mTLS adapter failed");
                        }
                    }));
                }

                // ── ACME (RFC 8555) server-auth TLS listener ──
                // Requires the DNS capability (the dns-01 solver writes TXT into
                // the DNS core) and the certmesh CA. Skipped when --no-acme,
                // --no-dns, or the CA is unavailable.
                if !config.no_acme {
                    if let Some(ref dns) = cores.dns {
                        let base_url = format!("https://{}:{}", local_fqdn(), config.acme_port);
                        let dns_solver: std::sync::Arc<dyn koi_common::integration::AcmeDnsSolver> =
                            koi_compose::bridges::AcmeDnsBridge::new(dns.clone());
                        let acme_state = certmesh.acme_state(koi_certmesh::acme::AcmeStateConfig {
                            base_url,
                            zone: config.dns_zone.clone(),
                            dns: dns_solver,
                        });
                        let port = config.acme_port;
                        let token = cancel.clone();
                        let enr = enrollment.clone();
                        tasks.push(tokio::spawn(async move {
                            if let Err(e) = adapters::acme::start(
                                port,
                                acme_state,
                                &enr.cert_pem,
                                &enr.key_pem,
                                token,
                            )
                            .await
                            {
                                tracing::error!(error = %e, "ACME adapter failed");
                            }
                        }));
                    } else {
                        tracing::info!(
                            "ACME adapter: skipped (DNS capability disabled; dns-01 needs the DNS core)"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::info!(
                    reason = %e,
                    "mTLS + ACME adapters: skipped (CA not available for self-enrollment)"
                );
            }
        }
    }

    // ── IPC adapter (only if mDNS is enabled - IPC speaks mDNS NDJSON protocol) ──
    if !config.no_ipc {
        if let Some(ref mdns) = cores.mdns {
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

    // ── HTTP mDNS announcement (opt-in) ──
    let mut http_announce_id: Option<String> = None;
    if config.announce_http && !config.no_http {
        if let Some(ref mdns) = cores.mdns {
            let hostname = hostname::get()
                .ok()
                .and_then(|os| os.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string());

            let mut txt = std::collections::HashMap::new();
            txt.insert("path".to_string(), "/".to_string());
            txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
            txt.insert("api".to_string(), "v1".to_string());
            txt.insert("dashboard".to_string(), "true".to_string());

            // Stamp this node's trust posture so peers discovering it read the
            // mesh's trust map directly (ADR-020 §8). Advisory hints; verify/mTLS
            // adjudicates actual trust.
            if let Some(ref certmesh) = cores.certmesh {
                let id = certmesh.local_identity().await;
                koi_common::peer::stamp(
                    &mut txt,
                    certmesh.posture(),
                    id.as_ref().map(|i| i.ca_fingerprint.as_str()),
                    id.as_ref().map(|i| i.renewal.expires_at),
                );
            }

            let payload = koi_mdns::protocol::RegisterPayload {
                name: format!("Koi ({hostname})"),
                service_type: "_http._tcp".to_string(),
                port: config.http_port,
                ip: None,
                lease_secs: None,
                txt,
            };
            match mdns.register(payload) {
                Ok(result) => {
                    tracing::info!(
                        id = %result.id,
                        port = config.http_port,
                        "HTTP server announced via mDNS"
                    );
                    http_announce_id = Some(result.id);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to announce HTTP server via mDNS");
                }
            }
        } else {
            tracing::debug!("--announce-http set but mDNS is disabled — skipping");
        }
    }

    // ── MCP endpoint discovery descriptors (one `_mcp._tcp` per host + in-zone TXT) ──
    // Gated on the transport being mounted; withdrawn by the mDNS goodbye on shutdown.
    let _mcp_announce_id = crate::infra::announce_mcp_endpoint(
        &cores,
        config.http_port,
        &config.dns_zone,
        !config.no_mcp_http && !config.no_http,
    );

    // ── Certmesh CA discovery descriptor (one `_certmesh._tcp` with fp= TXT) ──
    // ADR-017 F12. Gated on certmesh + a CA existing; withdrawn by the mDNS goodbye
    // on shutdown. A no-op when HTTP/mDNS is disabled (no mdns core to register on).
    let _certmesh_announce_id = if !config.no_http {
        crate::infra::announce_certmesh_endpoint(&cores, config.http_port).await
    } else {
        None
    };

    // ── Enrollment-approval pump ──
    // The certmesh role loops are spawned by build_cores (shared with the Windows service).
    // Only the approval pump is wired here, because its decider is host-specific: the
    // foreground daemon prompts on stdin; consoleless hosts use `deny_and_log_decider`.
    if let Some(ref certmesh) = cores.certmesh {
        let decider: koi_compose::certmesh::ApprovalDecider = Arc::new(prompt_enrollment_approval);
        koi_compose::certmesh::spawn_enrollment_approval(certmesh, decider, &cancel, &mut tasks)
            .await;
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal(cancel.clone()).await;
    tracing::info!("Shutting down...");

    // Ordered shutdown with hard timeout (shared with the Windows service via koi-compose).
    koi_compose::cores::ordered_shutdown(
        &cancel,
        tasks,
        &cores,
        http_announce_id,
        crate::SHUTDOWN_TIMEOUT,
        crate::SHUTDOWN_DRAIN,
    )
    .await;

    koi_config::breadcrumb::delete_breadcrumb();

    Ok(())
}

/// Best-effort local hostname for building the ACME base URL. ACME clients
/// reach the listener at this name; the daemon leaf's SAN covers
/// `<hostname>`/`<hostname>.local`/`localhost`, so any of those resolves.
fn local_fqdn() -> String {
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn prompt_enrollment_approval(
    hostname: &str,
    requires_approval: bool,
) -> koi_certmesh::ApprovalDecision {
    eprintln!("Enrollment approval requested for '{hostname}'");
    let approve = read_yes_no("Approve enrollment? [y/N]: ");
    if !approve {
        return koi_certmesh::ApprovalDecision::Denied;
    }

    // When approval is required, an accountable operator name must accompany it.
    let operator = if requires_approval {
        let operator = read_line("Operator name: ");
        if operator.is_empty() {
            return koi_certmesh::ApprovalDecision::Denied;
        }
        Some(operator)
    } else {
        None
    };

    koi_certmesh::ApprovalDecision::Approved { operator }
}

fn read_yes_no(prompt: &str) -> bool {
    let line = read_line(prompt);
    matches!(line.as_str(), "y" | "yes")
}

fn read_line(prompt: &str) -> String {
    eprintln!("{prompt}");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_ok() {
        line.trim().to_string()
    } else {
        String::new()
    }
}
