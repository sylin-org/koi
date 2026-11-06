//! Invented catalog for offline renderer checks. Never substitute it for a live read.
use koi_common::service::*;

pub fn fixture() -> CatalogSnapshot {
    let host_names = [
        "this_device",
        "workshop-demo.local",
        "storage-demo.local",
        "lab-demo.local",
        "media-demo.local",
        "edge-demo.local",
    ];
    let addresses = [
        "192.0.2.11",
        "192.0.2.12",
        "2001:db8::13",
        "fe80::14%lan0",
        "media.example.invalid",
        "127.0.0.1",
    ];
    let names = [
        "Archive browser",
        "Archive worker",
        "Build dashboard",
        "Build registry",
        "Calendar",
        "Camera archive",
        "Container docs",
        "Database console",
        "Development API",
        "Document inbox",
        "Document search",
        "Download queue",
        "Energy dashboard",
        "Event viewer",
        "Family photos",
        "File browser",
        "Forge",
        "Garden monitor",
        "Home dashboard",
        "Image registry",
        "Issue tracker",
        "Kitchen display",
        "Library",
        "Media library",
        "Metrics",
        "Music library",
        "Network notes",
        "Node dashboard",
        "Notebook",
        "Notebook",
        "Package cache",
        "Print queue",
        "Project preview with a deliberately long distinguishing name alpha",
        "Project preview with a deliberately long distinguishing name beta",
        "Workshop sensors",
        "Zebra test application",
    ];
    let conditions = [
        ServiceCondition::Responding,
        ServiceCondition::Found,
        ServiceCondition::NotResponding,
        ServiceCondition::Stale,
        ServiceCondition::Starting,
        ServiceCondition::Absent,
        ServiceCondition::Ambiguous,
    ];
    let mut catalog = CatalogSnapshot {
        schema: CATALOG_SCHEMA,
        epoch: "invented-offline-fixture".into(),
        revision: 12,
        generated_at: "2026-09-12T12:00:00Z".parse().unwrap(),
        devices: vec![],
        services: vec![],
        local_candidates: vec![],
    };
    for (index, name) in host_names.iter().enumerate() {
        catalog.devices.push(Device {
            schema: CATALOG_SCHEMA,
            id: DeviceId::new(format!("fixture_device_{index}")).unwrap(),
            names: vec![NameEvidence {
                value: (*name).into(),
                observation_ids: vec![],
            }],
            addresses: vec![AddressEvidence {
                address: addresses[index].into(),
                network_scope_id: None,
                observation_ids: vec![],
            }],
            koi_presence: KoiPresence::Observed,
            mesh_identity: MeshIdentity {
                state: MeshIdentityState::Unknown,
                observation_ids: vec![],
            },
            condition: DeviceCondition::Present,
        });
    }
    for (index, name) in names.iter().enumerate() {
        let host_index = index % host_names.len();
        let condition = conditions[index % conditions.len()];
        let absent = condition == ServiceCondition::Absent;
        let observation_id = ObservationId::new(format!("fixture_observation_{index:02}")).unwrap();
        let endpoint_id = EndpointId::new(format!("fixture_endpoint_{index:02}")).unwrap();
        let tcp = index == 7;
        let check_kind = if tcp {
            CheckKind::TcpConnect
        } else {
            CheckKind::HttpResponse
        };
        let checks = if matches!(
            condition,
            ServiceCondition::Responding
                | ServiceCondition::NotResponding
                | ServiceCondition::Stale
        ) {
            vec![CheckEvidence {
                schema: CATALOG_SCHEMA,
                kind: check_kind,
                observer: "this_installation".into(),
                client_identity: None,
                target_endpoint_id: endpoint_id.clone(),
                checked_at: "2026-09-12T11:59:50Z".parse().unwrap(),
                deadline_ms: 30_000,
                timeout_ms: 2_000,
                valid_until: if condition == ServiceCondition::Stale {
                    "2026-09-12T11:59:55Z"
                } else {
                    "2026-09-12T12:00:20Z"
                }
                .parse()
                .unwrap(),
                result: if condition == ServiceCondition::NotResponding {
                    CheckResult::Failed
                } else {
                    CheckResult::Passed
                },
                reason_code: if condition == ServiceCondition::NotResponding {
                    "connection_timeout"
                } else {
                    "fixture_check_passed"
                }
                .into(),
                detail: Some(
                    if condition == ServiceCondition::NotResponding {
                        "No connection completed before the deadline; cause not established."
                    } else if tcp {
                        "A TCP connection was observed; no HTTP response was checked."
                    } else {
                        "Invented response for an offline display check."
                    }
                    .into(),
                ),
                source_revision: Some(12),
            }]
        } else {
            vec![]
        };
        let mut endpoints = if absent {
            vec![]
        } else {
            vec![Endpoint {
                schema: CATALOG_SCHEMA,
                id: endpoint_id,
                scheme: if tcp { "tcp" } else { "http" }.into(),
                host: addresses[host_index].into(),
                port: 8080 + index as u16,
                path: if tcp {
                    None
                } else {
                    Some(if index >= 32 {
                        format!("/projects/long-distinguishing-path/{index}/preview?mode=review")
                    } else {
                        format!("/apps/{index:02}")
                    })
                },
                network_scope: (host_index == 3).then(|| NetworkScope {
                    id: NetworkScopeId::new("fixture_scope_lan0").unwrap(),
                    family: AddressFamily::Ipv6,
                    interface: Some("lan0".into()),
                    local_address: None,
                    prefix_len: None,
                    route_source: "fixture".into(),
                    classification: NetworkClassification::LinkLocal,
                    provider_scope: None,
                }),
                source_observation_ids: vec![observation_id.clone()],
                owner: EndpointOwner::Domain {
                    name: "runtime".into(),
                },
                // Fixture Open controls never target this browser's own loopback.
                browser_usable: !tcp && host_index != 5,
                transport_encryption: TransportEncryption::None,
                expected_service_name: None,
                authority_needs: vec![],
                reachability: checks.clone(),
                client_tls: vec![],
            }]
        };
        if index % 10 == 0 && !endpoints.is_empty() {
            let mut alternate = endpoints[0].clone();
            alternate.id = EndpointId::new(format!("fixture_alternate_{index:02}")).unwrap();
            alternate.host = format!("service-{index}.example.invalid");
            alternate.reachability.clear();
            endpoints.push(alternate);
        }
        let mut available_actions = vec![AvailableAction::ViewDetails];
        if condition != ServiceCondition::Ambiguous {
            available_actions.push(AvailableAction::Favorite);
            available_actions.push(AvailableAction::SetFriendlyAlias);
        }
        if !matches!(
            condition,
            ServiceCondition::Absent | ServiceCondition::Stale
        ) && condition != ServiceCondition::Ambiguous
            && !endpoints.is_empty()
        {
            available_actions.push(AvailableAction::CopyEndpoint);
            if endpoints.iter().any(|endpoint| endpoint.browser_usable) {
                available_actions.push(AvailableAction::Open);
            }
        }
        catalog.services.push(Service {
            schema: CATALOG_SCHEMA,
            id: ServiceId::new(format!("fixture_service_{index:02}")).unwrap(),
            device_id: catalog.devices[host_index].id.clone(),
            display_name: (*name).into(),
            alias: (index == 0).then(|| "Archive browser — saved name".into()),
            kind: if tcp {
                ServiceKind::Database
            } else {
                ServiceKind::Web
            },
            condition,
            endpoints,
            observations: if absent {
                vec![]
            } else {
                vec![Observation {
                    schema: CATALOG_SCHEMA,
                    id: observation_id,
                    kind: ObservationKind::Runtime,
                    source: "offline-fixture".into(),
                    provider: "sample-runtime".into(),
                    source_revision: 12,
                    source_generation: 1,
                    network_scope_id: None,
                    observer_installation_id: InstallationId::new("fixture_installation").unwrap(),
                    observer_device_id: Some(catalog.devices[0].id.clone()),
                    observed_at: "2026-09-12T11:50:00Z".parse().unwrap(),
                    valid_until: if condition == ServiceCondition::Stale {
                        "2026-09-12T11:59:55Z"
                    } else {
                        "2026-09-12T12:00:30Z"
                    }
                    .parse()
                    .unwrap(),
                    state: if condition == ServiceCondition::Stale {
                        ObservationState::Stale
                    } else {
                        ObservationState::Current
                    },
                    raw_reference: Default::default(),
                }]
            },
            checks,
            available_actions,
            favorite: absent || index % 5 == 0,
            local_only: host_index == 5,
            managed: true,
            active_operations: vec![],
            identity_confidence: if condition == ServiceCondition::Ambiguous {
                IdentityConfidence::Ambiguous
            } else {
                IdentityConfidence::Explicit
            },
            ambiguity: (condition == ServiceCondition::Ambiguous).then(|| Ambiguity {
                reason: "conflicting_explicit_identity".into(),
                candidates: vec![format!("{name} on workshop"), format!("{name} on lab")],
            }),
            last_known: absent.then(|| LastKnownService {
                device_name: Some(host_names[host_index].into()),
                last_seen: "2026-09-12T11:40:00Z".parse().unwrap(),
                kind: ServiceKind::Web,
            }),
        });
    }
    catalog
}
