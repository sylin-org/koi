//! Bonjour session probe: real `dnssd.dll` DNS-SD operations through the
//! product's own `WindowsBonjourAdapter` provider session.
//!
//! Physical gate for the Bonjour read routes, which the armed composite does
//! not select while the higher-priority windows-dns-sd read provider is
//! healthy: the browse callbacks must classify add/remove with Apple's
//! `kDNSServiceFlagsAdd` bit (a misread bit turns quiet-LAN adds into
//! removes), resolved records must carry addresses completed through
//! `DNSServiceGetAddrInfo` with the interface identity the callbacks
//! reported, and a direct resolve must return the same fidelity on demand.
//!
//! Requires a genuinely installed and running Apple Bonjour. Every phase
//! prints one JSON evidence line; the process exits non-zero when a phase
//! fails its own observed contract.

#[cfg(target_os = "windows")]
mod windows {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use koi_mdns::adapter::{MdnsAdapter, ProviderAvailability};
    use koi_mdns::provider::ProviderEvent;
    use koi_mdns::windows_bonjour::WindowsBonjourAdapter;

    const META_QUERY: &str = "_services._dns-sd._udp.local.";

    const META_WINDOW: Duration = Duration::from_secs(8);
    const TYPE_WINDOW: Duration = Duration::from_secs(12);
    /// Browsed fallback count when `_mcp._tcp` is quiet at probe time.
    const TYPE_FALLBACKS: usize = 3;

    fn evidence(phase: &str, fields: &[(&str, serde_json::Value)]) {
        let mut map = BTreeMap::new();
        map.insert("phase".to_string(), phase.into());
        for (key, value) in fields {
            map.insert((*key).to_string(), value.clone());
        }
        println!(
            "{}",
            serde_json::to_string(&map).unwrap_or_else(|_| format!("{{\"phase\":\"{phase}\"}}"))
        );
    }

    #[derive(serde::Serialize)]
    struct Discovered {
        name: String,
        service_type: String,
        host: Option<String>,
        port: Option<u16>,
        addresses: Vec<(String, Option<u32>)>,
    }

    impl From<&koi_mdns::provider::ProviderService> for Discovered {
        fn from(service: &koi_mdns::provider::ProviderService) -> Self {
            Self {
                name: service.name.clone(),
                service_type: service.service_type.clone(),
                host: service.host.clone(),
                port: service.port,
                addresses: service
                    .addresses
                    .iter()
                    .map(|address| (address.address.to_string(), address.interface_index))
                    .collect(),
            }
        }
    }

    pub fn run() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            let adapter = WindowsBonjourAdapter;

            // ── assessment must find a real responder before anything else ──
            let report = adapter.assess().await;
            evidence(
                "assess",
                &[
                    ("availability", format!("{:?}", report.availability).into()),
                    ("running", report.running.to_string().into()),
                    ("detail", report.detail.into()),
                ],
            );
            if report.availability != ProviderAvailability::Ready {
                evidence("summary", &[("result", "FAIL: responder not ready".into())]);
                std::process::exit(1);
            }

            let session = match adapter.open().await {
                Ok(session) => session,
                Err(error) => {
                    evidence(
                        "summary",
                        &[("result", format!("FAIL: open: {error}").into())],
                    );
                    std::process::exit(1);
                }
            };

            // ── meta browse: adds must classify as Found ──
            let mut meta_browse = session
                .browse(META_QUERY, true)
                .await
                .expect("meta browse opens");
            let mut types: Vec<String> = Vec::new();
            let meta_deadline = Instant::now() + META_WINDOW;
            while Instant::now() < meta_deadline {
                match tokio::time::timeout(Duration::from_millis(250), meta_browse.recv()).await {
                    Ok(Some(ProviderEvent::Found(service))) => {
                        if !service.name.is_empty() && !types.contains(&service.name) {
                            types.push(service.name);
                        }
                    }
                    Ok(Some(other)) => {
                        evidence("meta_unexpected", &[("event", format!("{other:?}").into())]);
                    }
                    Ok(None) | Err(_) => {}
                }
            }
            meta_browse.close().await.expect("meta browse closes");
            evidence(
                "meta_browse",
                &[
                    ("types", types.len().into()),
                    (
                        "sample",
                        types.iter().take(8).cloned().collect::<Vec<_>>().into(),
                    ),
                ],
            );

            // ── type browse: resolved records must carry native addresses ──
            let mut candidates: Vec<String> = vec!["_mcp._tcp".to_string()];
            candidates.extend(
                types
                    .iter()
                    .filter(|t| !t.is_empty() && !t.starts_with("_services"))
                    .take(TYPE_FALLBACKS)
                    .cloned(),
            );
            let mut resolved: Vec<Discovered> = Vec::new();
            let mut removed_events = 0usize;
            'types: for service_type in &candidates {
                let mut browse = match session.browse(service_type, false).await {
                    Ok(browse) => browse,
                    Err(error) => {
                        evidence(
                            "type_browse_error",
                            &[
                                ("type", service_type.as_str().into()),
                                ("error", error.to_string().into()),
                            ],
                        );
                        continue;
                    }
                };
                let deadline = Instant::now() + TYPE_WINDOW;
                while Instant::now() < deadline {
                    match tokio::time::timeout(Duration::from_millis(250), browse.recv()).await {
                        Ok(Some(ProviderEvent::Resolved(service))) => {
                            if !resolved.iter().any(|found| found.name == service.name) {
                                resolved.push(Discovered::from(&service));
                            }
                        }
                        Ok(Some(ProviderEvent::Removed { .. })) => removed_events += 1,
                        Ok(Some(ProviderEvent::Found(_))) | Ok(None) | Err(_) => {}
                    }
                }
                browse.close().await.expect("type browse closes");
                if !resolved.is_empty() {
                    evidence(
                        "type_browse",
                        &[
                            ("type", service_type.as_str().into()),
                            ("resolved", resolved.len().into()),
                            (
                                "first",
                                serde_json::to_value(&resolved[0]).unwrap_or_default(),
                            ),
                            ("removed_events", removed_events.into()),
                        ],
                    );
                    break 'types;
                }
            }
            if resolved.is_empty() {
                evidence(
                    "summary",
                    &[(
                        "result",
                        "FAIL: no instance resolved with full fidelity".into(),
                    )],
                );
                std::process::exit(1);
            }

            // ── direct resolve: the same fidelity on demand ──
            let target = &resolved[0];
            let direct = session
                .resolve(&target.name, &target.service_type)
                .await
                .expect("direct resolve answers");
            let addresses_bearing_interface = direct
                .addresses
                .iter()
                .all(|address| address.interface_index.is_some());
            evidence(
                "direct_resolve",
                &[
                    ("name", direct.name.clone().into()),
                    ("host", direct.host.clone().into()),
                    ("port", direct.port.into()),
                    (
                        "addresses",
                        direct
                            .addresses
                            .iter()
                            .map(|address| address.address.to_string())
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    (
                        "txt_keys",
                        direct.txt.keys().cloned().collect::<Vec<_>>().into(),
                    ),
                    (
                        "addresses_bearing_interface",
                        addresses_bearing_interface.into(),
                    ),
                ],
            );

            let shutdown_ok = session.shutdown().await.is_ok();
            let resolved_with_addresses = resolved
                .iter()
                .filter(|found| !found.addresses.is_empty())
                .count();
            let passed = !types.is_empty()
                && resolved_with_addresses >= 1
                && direct.host.is_some()
                && !direct.addresses.is_empty()
                && addresses_bearing_interface
                && shutdown_ok;
            evidence(
                "summary",
                &[
                    ("result", if passed { "PASS" } else { "FAIL" }.into()),
                    ("meta_types", types.len().into()),
                    ("resolved_with_addresses", resolved_with_addresses.into()),
                    (
                        "direct_has_addresses",
                        (!direct.addresses.is_empty()).into(),
                    ),
                    ("shutdown_ok", shutdown_ok.into()),
                ],
            );
            if !passed {
                std::process::exit(1);
            }
        });
    }
}

#[cfg(target_os = "windows")]
fn main() {
    windows::run();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("win32_bonjour_session_probe is available only on Windows");
}
