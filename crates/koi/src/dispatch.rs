//! CLI command dispatch — the async entry point. Routes each subcommand to its handler in
//! `commands::*`, then falls through to `daemon::daemon_mode`. Moved from main.rs (P07 step 6b).

use std::sync::Arc;

use crate::cli::{
    CertmeshSubcommand, Cli, Command, Config, DnsSubcommand, HealthSubcommand, McpSubcommand,
    MdnsSubcommand, ProxySubcommand, TrustSubcommand, UdpSubcommand,
};
use crate::commands::status::try_daemon_status;
use crate::daemon::daemon_mode;
use crate::infra::{is_piped_stdin, print_top_level_help};
use crate::{adapters, commands, format, help};

// ── Async entry point ────────────────────────────────────────────────

pub(crate) async fn run(cli: Cli, config: Config) -> anyhow::Result<()> {
    if let Some(command) = &cli.command {
        return match command {
            Command::Status => commands::status::status(&cli, &config),
            Command::Mdns(mdns_cmd) => {
                config.require_capability("mdns")?;
                match &mdns_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Discovery, None)?;
                        Ok(())
                    }
                    Some(MdnsSubcommand::Admin(admin_cmd)) => match &admin_cmd.command {
                        Some(admin) => commands::mdns::admin(admin, &cli),
                        None => {
                            help::print_category_catalog(
                                help::KoiCategory::Discovery,
                                Some(help::KoiScope::Admin),
                            )?;
                            Ok(())
                        }
                    },
                    Some(MdnsSubcommand::Discover { service_type }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::discover(
                            service_type.as_deref(),
                            cli.json,
                            cli.timeout,
                            mode,
                        )
                        .await
                    }
                    Some(MdnsSubcommand::Announce {
                        name,
                        service_type,
                        port,
                        ip,
                        txt,
                    }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::announce(
                            name,
                            service_type,
                            *port,
                            ip.as_deref(),
                            txt,
                            cli.json,
                            cli.timeout,
                            mode,
                        )
                        .await
                    }
                    Some(MdnsSubcommand::Unregister { id }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::unregister(id, cli.json, mode).await
                    }
                    Some(MdnsSubcommand::Resolve { instance }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::resolve(instance, cli.json, mode).await
                    }
                    Some(MdnsSubcommand::Subscribe { service_type }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::subscribe(service_type, cli.json, cli.timeout, mode).await
                    }
                }
            }
            Command::Certmesh(cm_cmd) => {
                config.require_capability("certmesh")?;
                let ep = cli.endpoint.as_deref();
                // Explicit access token for an explicit --endpoint (flag or
                // KOI_TOKEN). Never the breadcrumb token — see commands::cli_token.
                let tok = commands::cli_token(&cli);
                match &cm_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Trust, None)?;
                        Ok(())
                    }
                    Some(CertmeshSubcommand::Create {
                        profile,
                        operator,
                        enrollment,
                        require_approval,
                        passphrase,
                    }) => commands::certmesh::create(
                        profile.as_deref(),
                        operator.as_deref(),
                        enrollment.as_deref(),
                        *require_approval,
                        passphrase.as_deref(),
                        cli.json,
                        ep,
                        tok,
                    ),
                    Some(CertmeshSubcommand::Status) => {
                        commands::certmesh::status(cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Log) => commands::certmesh::log(ep, tok),
                    Some(CertmeshSubcommand::Unlock) => commands::certmesh::unlock(ep, tok),
                    Some(CertmeshSubcommand::SetHook { reload }) => {
                        commands::certmesh::set_hook(reload, cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Join {
                        ca_endpoint,
                        invite,
                    }) => {
                        // No `ep`/`tok` (global --endpoint/--token): `join` resolves its
                        // LOCAL key-custody daemon from the breadcrumb itself, and the CA
                        // is `ca_endpoint` (or mDNS). Threading the global endpoint here is
                        // what misrouted key custody to the CA (ADR-018 Tier 3).
                        commands::certmesh::join(
                            ca_endpoint.as_deref(),
                            invite.as_deref(),
                            cli.json,
                        )
                        .await
                    }
                    Some(CertmeshSubcommand::Invite { hostname, ttl }) => {
                        commands::certmesh::invite(hostname, *ttl, cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Promote { ca_endpoint }) => {
                        // Local standby daemon resolved from the breadcrumb inside
                        // `promote`; the CA is `ca_endpoint` (or mDNS). See `Join`.
                        commands::certmesh::promote(ca_endpoint.as_deref(), cli.json).await
                    }
                    Some(CertmeshSubcommand::OpenEnrollment) => {
                        commands::certmesh::open_enrollment(cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::CloseEnrollment) => {
                        commands::certmesh::close_enrollment(cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::RotateAuth) => {
                        commands::certmesh::rotate_auth(cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Backup { path }) => {
                        commands::certmesh::backup(path, cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Restore { path }) => {
                        commands::certmesh::restore(path, cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Revoke { hostname, reason }) => {
                        commands::certmesh::revoke(hostname, reason.as_deref(), cli.json, ep, tok)
                    }
                    Some(CertmeshSubcommand::Destroy) => {
                        commands::certmesh::destroy(cli.json, cli.yes, ep, tok)
                    }
                    Some(CertmeshSubcommand::Acme(acme_cmd)) => match &acme_cmd.command {
                        None | Some(crate::cli::AcmeSubcommand::Enable) => {
                            commands::certmesh::acme_enable(cli.json, ep, tok)
                        }
                        Some(crate::cli::AcmeSubcommand::Status) => {
                            commands::certmesh::acme_status(cli.json, ep, tok)
                        }
                    },
                }
            }
            Command::Dns(dns_cmd) => {
                config.require_capability("dns")?;
                let mode = commands::detect_mode(&cli);
                match &dns_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Dns, None)?;
                        Ok(())
                    }
                    Some(DnsSubcommand::Serve) => commands::dns::serve(&config, mode).await,
                    Some(DnsSubcommand::Stop) => commands::dns::stop(mode).await,
                    Some(DnsSubcommand::Status) => {
                        commands::dns::status(&config, mode, cli.json).await
                    }
                    Some(DnsSubcommand::Lookup { name, record_type }) => {
                        commands::dns::lookup(name, record_type, mode, cli.json, &config).await
                    }
                    Some(DnsSubcommand::Add { name, ip, ttl }) => {
                        commands::dns::add(name, ip, *ttl, mode, cli.json, &config.dns_zone)
                    }
                    Some(DnsSubcommand::Remove { name }) => {
                        commands::dns::remove(name, mode, cli.json, &config.dns_zone)
                    }
                    Some(DnsSubcommand::List) => commands::dns::list(mode, cli.json, &config).await,
                }
            }
            Command::Health(health_cmd) => {
                config.require_capability("health")?;
                let mode = commands::detect_mode(&cli);
                match &health_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Health, None)?;
                        Ok(())
                    }
                    Some(HealthSubcommand::Status) => {
                        commands::health::status(&config, mode, cli.json).await
                    }
                    Some(HealthSubcommand::Watch { interval }) => {
                        commands::health::watch(&config, mode, *interval).await
                    }
                    Some(HealthSubcommand::Add {
                        name,
                        http,
                        tcp,
                        interval,
                        timeout,
                    }) => {
                        commands::health::add(
                            name,
                            http.as_deref(),
                            tcp.as_deref(),
                            *interval,
                            *timeout,
                            mode,
                            cli.json,
                            &config,
                        )
                        .await
                    }
                    Some(HealthSubcommand::Remove { name }) => {
                        commands::health::remove(name, mode, cli.json, &config).await
                    }
                    Some(HealthSubcommand::Log) => commands::health::log(),
                }
            }
            Command::Proxy(proxy_cmd) => {
                config.require_capability("proxy")?;
                let mode = commands::detect_mode(&cli);
                match &proxy_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Proxy, None)?;
                        Ok(())
                    }
                    Some(ProxySubcommand::Add {
                        name,
                        listen,
                        backend,
                        backend_remote,
                    }) => {
                        commands::proxy::add(
                            name,
                            *listen,
                            backend,
                            *backend_remote,
                            mode,
                            cli.json,
                        )
                        .await
                    }
                    Some(ProxySubcommand::Remove { name }) => {
                        commands::proxy::remove(name, mode, cli.json).await
                    }
                    Some(ProxySubcommand::Status) => commands::proxy::status(mode, cli.json).await,
                    Some(ProxySubcommand::List) => commands::proxy::list(mode, cli.json).await,
                }
            }
            Command::Udp(udp_cmd) => {
                config.require_capability("udp")?;
                let mode = commands::detect_mode(&cli);
                match &udp_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::Udp, None)?;
                        Ok(())
                    }
                    Some(UdpSubcommand::Bind { port, addr, lease }) => {
                        commands::udp::bind(*port, addr, *lease, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Unbind { id }) => {
                        commands::udp::unbind(id, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Send { id, dest, payload }) => {
                        commands::udp::send(id, dest, payload, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Status) => commands::udp::status(mode, cli.json).await,
                    Some(UdpSubcommand::Heartbeat { id }) => {
                        commands::udp::heartbeat(id, mode, cli.json).await
                    }
                }
            }
            Command::Trust(trust_cmd) => {
                // Trust operations are local (OS cert store) — no daemon capability.
                match &trust_cmd.command {
                    None => {
                        help::print_category_catalog(help::KoiCategory::TrustStore, None)?;
                        Ok(())
                    }
                    Some(TrustSubcommand::Install { pem_path }) => {
                        commands::trust::install(pem_path, cli.json)
                    }
                    Some(TrustSubcommand::List) => commands::trust::list(cli.json),
                    Some(TrustSubcommand::Remove { name }) => {
                        commands::trust::remove(name, cli.json)
                    }
                    Some(TrustSubcommand::Export { ca }) => commands::trust::export(*ca, cli.json),
                }
            }
            Command::Mcp(mcp_cmd) => match &mcp_cmd.command {
                None => {
                    help::print_category_catalog(help::KoiCategory::Mcp, None)?;
                    Ok(())
                }
                Some(McpSubcommand::Serve) => commands::mcp::serve(&cli).await,
            },
            Command::Token(token_cmd) => commands::token::run(token_cmd, cli.json),
            // Install, Uninstall, Version, Launch, FactoryReset handled before runtime
            Command::Install
            | Command::Uninstall
            | Command::Version
            | Command::Launch
            | Command::FactoryReset => Ok(()),
        };
    }

    // ── No subcommand provided ─────────────────────────────────────

    // Explicit daemon request: start services
    if cli.daemon {
        return daemon_mode(config).await;
    }

    // Piped CLI mode still works without a subcommand
    if is_piped_stdin() {
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

    // Try to show daemon status if a healthy daemon is reachable; otherwise stay quiet
    if let Some(status_json) = try_daemon_status(&cli) {
        if cli.json {
            if let Ok(body) = serde_json::to_string_pretty(&status_json) {
                println!("{body}");
            }
        } else {
            print!("{}", format::unified_status(&status_json));
        }
    }

    // Always show available commands/help for discoverability
    let api_endpoint = cli
        .endpoint
        .clone()
        .or_else(koi_config::breadcrumb::read_breadcrumb_endpoint)
        .unwrap_or_else(|| "http://localhost:5641".to_string());
    print_top_level_help(&api_endpoint);
    Ok(())
}
