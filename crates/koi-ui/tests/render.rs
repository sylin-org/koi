use koi_common::service::*;
use koi_ui::{
    render, render_with_state, Destination, EndpointActions, Links, OperatorActions, ServiceFilter,
    ServiceSort, UiState, View,
};
use scraper::{Html, Selector};

#[path = "../examples/support/catalog.rs"]
mod sample_catalog;

fn links() -> Links<'static> {
    Links {
        refresh: Some("./"),
        endpoint_actions: EndpointActions::None,
        preference_actions: false,
        operator_actions: OperatorActions::None,
    }
}
fn browser_links() -> Links<'static> {
    Links {
        endpoint_actions: EndpointActions::Browser,
        preference_actions: true,
        ..links()
    }
}
fn selector(value: &str) -> Selector {
    Selector::parse(value).unwrap()
}
fn one_service(condition: ServiceCondition) -> CatalogSnapshot {
    let mut catalog = sample_catalog::fixture();
    catalog.services.truncate(1);
    catalog.services[0].condition = condition;
    catalog
}
fn row_ids(document: &Html) -> Vec<String> {
    document
        .select(&selector("#services table.service-table tr.service-row"))
        .map(|row| row.value().attr("data-service-id").unwrap().to_owned())
        .collect()
}
fn text(document: &Html, query: &str) -> String {
    document
        .select(&selector(query))
        .flat_map(|element| element.text())
        .collect()
}

#[test]
fn dense_inventory_renders_all_real_rows_and_defaults_to_services() {
    let catalog = sample_catalog::fixture();
    let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
    assert_eq!(row_ids(&document).len(), 36);
    assert_eq!(catalog.devices.len(), 6);
    assert_eq!(
        text(&document, "header nav [data-ui-tab]"),
        "ServicesmDNSCertmeshSettingsAbout"
    );
    assert_eq!(
        text(&document, "header nav [aria-current='page']"),
        "Services"
    );
    assert!(
        document
            .select(&selector("#services table.service-table thead th"))
            .count()
            >= 4
    );
    assert!(document
        .select(&selector("dialog#service-details"))
        .next()
        .is_none());
    assert!(document.select(&selector(".tcg")).next().is_none());
}

#[test]
fn hostile_ids_names_hosts_and_query_remain_data() {
    let mut catalog = one_service(ServiceCondition::Found);
    catalog.services[0].id = ServiceId::new("svc_\"><script>").unwrap();
    catalog.services[0].display_name = "<script>alert('name')</script>".into();
    catalog.devices[0].names[0].value = "<img src=x onerror=alert(1)> & host".into();
    for alias in [Some("<img src=x onerror=alert(1)> & Friends".into()), None] {
        catalog.services[0].alias = alias;
        let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
        assert!(document
            .select(&selector("script, [onerror], [onclick]"))
            .next()
            .is_none());
        let row = document.select(&selector("tr.service-row")).next().unwrap();
        assert_eq!(
            row.value().attr("data-service-id"),
            Some(catalog.services[0].id.as_str())
        );
        assert_eq!(
            row.select(&selector(".name-link strong"))
                .next()
                .unwrap()
                .text()
                .collect::<String>(),
            catalog.services[0]
                .alias
                .as_deref()
                .unwrap_or(&catalog.services[0].display_name)
        );
        assert!(row
            .text()
            .collect::<String>()
            .contains("<img src=x onerror=alert(1)> & host"));
    }
    let state = UiState {
        query: "\"><script>alert(1)</script>".into(),
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    assert!(document
        .select(&selector("script, [onerror], [onclick]"))
        .next()
        .is_none());
    assert!(document
        .select(&selector("input"))
        .any(|input| input.value().attr("value") == Some(state.query.as_str())));
}

#[test]
fn host_column_joins_only_declared_identity_and_preserves_saved_context() {
    let mut catalog = one_service(ServiceCondition::Found);
    catalog.devices[0].names[0].value = "Correct host".into();
    catalog.devices[1].names[0].value = "Unrelated host".into();
    let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
    assert!(text(&document, "tr.service-row").contains("Correct host"));
    assert!(!text(&document, "tr.service-row").contains("Unrelated host"));
    catalog.devices.remove(0);
    let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
    assert!(text(&document, "tr.service-row").contains("Unknown host"));
    catalog.services[0].condition = ServiceCondition::Absent;
    catalog.services[0].favorite = true;
    catalog.services[0].endpoints.clear();
    catalog.services[0].last_known = Some(LastKnownService {
        device_name: Some("Saved host".into()),
        last_seen: catalog.generated_at,
        kind: ServiceKind::Web,
    });
    let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
    assert!(text(&document, "tr.service-row").contains("Saved host"));
    assert!(text(&document, "tr.service-row").contains("Absent"));
}

#[test]
fn each_condition_is_displayed_without_reinterpreting_supplied_checks() {
    for (condition, label) in [
        (ServiceCondition::Starting, "Starting"),
        (ServiceCondition::Found, "Found"),
        (ServiceCondition::Responding, "Responding"),
        (ServiceCondition::NotResponding, "Not responding"),
        (ServiceCondition::Absent, "Absent"),
        (ServiceCondition::Stale, "Stale"),
        (ServiceCondition::Ambiguous, "Ambiguous"),
    ] {
        let catalog = one_service(condition);
        let document = Html::parse_document(&render(View::Snapshot(&catalog), links()));
        assert!(text(&document, "tr.service-row").contains(label));
        assert_eq!(
            document
                .select(&selector("tr.service-row"))
                .next()
                .unwrap()
                .value()
                .attr("data-condition"),
            Some(koi_ui::screens::services::condition_key(condition))
        );
    }
}

#[test]
fn details_show_complete_endpoints_as_text_without_granting_actions() {
    let mut catalog = one_service(ServiceCondition::Found);
    let service = &mut catalog.services[0];
    service.endpoints[0].host = "fe80::1%lan0".into();
    service.endpoints[0].port = 8080;
    service.endpoints[0].path = Some("/long/path?name=<img>&value=\"quoted\"".into());
    service.endpoints[1].scheme = "javascript:alert(1)".into();
    service.endpoints[1].host = "host\"><script>".into();
    service.available_actions = vec![
        AvailableAction::Open,
        AvailableAction::CopyEndpoint,
        AvailableAction::Diagnose,
    ];
    let state = UiState {
        selected: Some(service.id.clone()),
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    let addresses: Vec<_> = document
        .select(&selector("dialog#service-details .endpoint-list code"))
        .map(|code| code.text().collect::<String>())
        .collect();
    assert!(addresses.iter().any(
        |address| address == "http://[fe80::1%lan0]:8080/long/path?name=<img>&value=\"quoted\""
    ));
    assert!(addresses
        .iter()
        .any(|address| address.starts_with("javascript:alert(1)://host\"><script>")));
    assert!(document
        .select(&selector("script, [onerror], [onclick]"))
        .next()
        .is_none());
    for control in document.select(&selector("a, button")) {
        let label = control.text().collect::<String>();
        assert!(!matches!(
            label.trim(),
            "Open" | "Copy address" | "Diagnose" | "Check connection"
        ));
        if let Some(href) = control.value().attr("href") {
            assert!(!href.starts_with("javascript:"));
            assert!(!href.contains("fe80::1"));
            assert!(!href.contains("host\"><script>"));
        }
    }
}

#[test]
fn browser_endpoint_actions_require_catalog_eligibility_and_valid_http_targets() {
    let mut catalog = one_service(ServiceCondition::Found);
    let service = &mut catalog.services[0];
    service.endpoints.truncate(2);
    service.endpoints[0].scheme = "https".into();
    service.endpoints[0].host = "192.0.2.20".into();
    service.endpoints[0].port = 8443;
    service.endpoints[0].path = Some("/status?view=full".into());
    service.endpoints[0].browser_usable = true;
    service.endpoints[1].scheme = "http".into();
    service.endpoints[1].host = "safe.example@evil.example".into();
    service.endpoints[1].port = 8080;
    service.endpoints[1].path = Some("/do-not-open".into());
    service.endpoints[1].browser_usable = true;
    service.available_actions = vec![AvailableAction::Open, AvailableAction::CopyEndpoint];
    let state = UiState {
        selected: Some(service.id.clone()),
        ..UiState::default()
    };

    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_links(),
        &state,
    ));
    let open: Vec<_> = document.select(&selector(".endpoint-open")).collect();
    assert_eq!(open.len(), 1);
    assert_eq!(
        open[0].value().attr("href"),
        Some("https://192.0.2.20:8443/status?view=full")
    );
    assert_eq!(open[0].value().attr("target"), Some("_blank"));
    assert_eq!(open[0].value().attr("rel"), Some("noopener noreferrer"));
    let copied: Vec<_> = document
        .select(&selector("button[data-ui-copy]"))
        .filter_map(|button| button.value().attr("data-ui-copy"))
        .collect();
    assert_eq!(copied.len(), 2);
    assert!(copied.contains(&"http://safe.example@evil.example:8080/do-not-open"));
    assert!(document
        .select(&selector("button[data-ui-favorite]"))
        .next()
        .is_none());

    catalog.services[0]
        .available_actions
        .push(AvailableAction::Favorite);
    catalog.services[0]
        .available_actions
        .push(AvailableAction::SetFriendlyAlias);
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_links(),
        &state,
    ));
    let favorite = document
        .select(&selector("button[data-ui-favorite]"))
        .next()
        .unwrap();
    assert_eq!(
        favorite.value().attr("data-service-id"),
        Some("fixture_service_00")
    );
    assert_eq!(favorite.value().attr("data-ui-favorite"), Some("false"));
    let alias = document
        .select(&selector("form[data-ui-alias-form]"))
        .next()
        .expect("eligible service should expose alias editing");
    assert_eq!(
        alias.value().attr("data-service-id"),
        Some("fixture_service_00")
    );
    let alias_input = alias
        .select(&selector("input[data-ui-alias]"))
        .next()
        .unwrap();
    assert_eq!(
        alias_input.value().attr("value"),
        Some("Archive browser — saved name")
    );
    assert_eq!(alias_input.value().attr("maxlength"), Some("160"));

    catalog.services[0].available_actions.clear();
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_links(),
        &state,
    ));
    assert!(document
        .select(&selector(
            ".endpoint-open, button[data-ui-copy], button[data-ui-favorite], form[data-ui-alias-form]",
        ))
        .next()
        .is_none());
}

#[test]
fn details_keep_check_kind_result_and_observer_separate() {
    let mut catalog = one_service(ServiceCondition::Responding);
    let original = catalog.services[0].checks[0].clone();
    let kinds = [
        (CheckKind::NameResolution, "Name resolution"),
        (CheckKind::TcpConnect, "TCP connection"),
        (CheckKind::HttpResponse, "HTTP response"),
        (CheckKind::BackendHealth, "Backend health"),
        (CheckKind::ProxyListener, "Proxy listener"),
        (CheckKind::FirewallAssessment, "Firewall assessment"),
        (CheckKind::Certificate, "Certificate"),
        (CheckKind::OsRootPresence, "OS trust root presence"),
        (CheckKind::ClientTls, "Client TLS"),
    ];
    catalog.services[0].checks = kinds
        .iter()
        .enumerate()
        .map(|(index, (kind, _))| CheckEvidence {
            kind: *kind,
            result: if index % 2 == 0 {
                CheckResult::Unknown
            } else {
                CheckResult::NotRun
            },
            detail: Some("<evidence> & no inferred result".into()),
            ..original.clone()
        })
        .collect();
    catalog.services[0].observations.clear();
    for endpoint in &mut catalog.services[0].endpoints {
        endpoint.reachability.clear();
        endpoint.client_tls.clear();
    }
    let repeated = catalog.services[0].checks[0].clone();
    catalog.services[0].endpoints[0].reachability.push(repeated);
    let state = UiState {
        selected: Some(catalog.services[0].id.clone()),
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    let items: Vec<_> = document
        .select(&selector("dialog#service-details .evidence-item"))
        .map(|item| item.text().collect::<String>())
        .collect();
    assert_eq!(
        items.len(),
        kinds.len(),
        "A check repeated on its endpoint is shown once"
    );
    for (_, label) in kinds {
        assert!(
            items.iter().any(|item| item.contains(label)),
            "missing {label}"
        );
    }
    assert!(items.iter().any(|item| item.contains("Unknown")));
    assert!(items.iter().any(|item| item.contains("Not run")));
    assert!(items
        .iter()
        .all(|item| item.contains("This Koi installation")));
    assert!(items
        .iter()
        .all(|item| item.contains("<evidence> & no inferred result")));
    assert!(items.iter().all(|item| !item.contains("Passed")));
}

#[test]
fn combined_search_host_and_state_filter_select_matching_ids_and_sort_stably() {
    let mut catalog = sample_catalog::fixture();
    catalog.services.truncate(4);
    for (index, service) in catalog.services.iter_mut().enumerate() {
        service.alias = None;
        service.display_name = if index == 1 { "Zeta" } else { "Alpha" }.into();
        service.condition = if index == 2 {
            ServiceCondition::Found
        } else {
            ServiceCondition::Responding
        };
        service.device_id = catalog.devices[usize::from(index != 0)].id.clone();
        service.endpoints[0].host = "needle.example.invalid".into();
    }
    let state = UiState {
        query: "NEEDLE".into(),
        host: Some(catalog.devices[1].id.clone()),
        filter: ServiceFilter::Responding,
        sort: ServiceSort::Name,
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    assert_eq!(
        row_ids(&document),
        vec![
            catalog.services[3].id.to_string(),
            catalog.services[1].id.to_string()
        ]
    );
    catalog.services[1].display_name = "Alpha".into();
    catalog.services.swap(1, 3);
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    assert_eq!(
        row_ids(&document),
        vec!["fixture_service_01", "fixture_service_03"]
    );
}

#[test]
fn host_and_state_sorts_are_deterministic_without_changing_conditions() {
    let mut catalog = one_service(ServiceCondition::Found);
    catalog.devices[0].names[0].value = "Zulu host".into();
    catalog.devices[1].names[0].value = "Alpha host".into();
    let mut second = catalog.services[0].clone();
    second.id = ServiceId::new("second").unwrap();
    second.device_id = catalog.devices[1].id.clone();
    second.condition = ServiceCondition::Absent;
    second.endpoints.clear();
    catalog.services.push(second);
    let state = UiState {
        sort: ServiceSort::Host,
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    assert_eq!(row_ids(&document), vec!["second", "fixture_service_00"]);
    let state = UiState {
        sort: ServiceSort::State,
        ..UiState::default()
    };
    let first = render_with_state(View::Snapshot(&catalog), links(), &state);
    catalog.services.reverse();
    let second = render_with_state(View::Snapshot(&catalog), links(), &state);
    assert_eq!(
        row_ids(&Html::parse_document(&first)),
        row_ids(&Html::parse_document(&second))
    );
    assert!(text(&Html::parse_document(&second), "tr.service-row").contains("Absent"));
}

#[test]
fn empty_search_loading_and_unavailable_are_distinct() {
    let empty = render(View::Snapshot(&CatalogSnapshot::default()), links());
    let unavailable = render(View::Unavailable, links());
    let loading = render(View::Loading, links());
    let state = UiState {
        query: "no-such-fixture-service".into(),
        ..UiState::default()
    };
    let filtered = render_with_state(View::Snapshot(&sample_catalog::fixture()), links(), &state);
    assert!(empty.contains("No services"));
    assert!(!unavailable.contains("No services"));
    assert!(!loading.contains("No services"));
    assert!(unavailable.contains("Cannot read the local catalog"));
    assert!(loading.contains("Connecting") || loading.contains("Reading"));
    assert!(filtered.contains("No services match these filters"));
    assert!(row_ids(&Html::parse_document(&filtered)).is_empty());
}

#[test]
fn missing_selection_never_displays_another_services_endpoints() {
    let catalog = sample_catalog::fixture();
    let state = UiState {
        selected: Some(ServiceId::new("missing_service").unwrap()),
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    assert!(document
        .select(&selector("dialog#service-details .endpoint-list code"))
        .next()
        .is_none());
    assert_eq!(
        text(&document, ".selection-notice[role='status']"),
        "The selected service is no longer in this view."
    );
    let state = UiState {
        selected: Some(catalog.services[3].id.clone()),
        ..UiState::default()
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        links(),
        &state,
    ));
    let details = text(&document, "dialog#service-details");
    assert!(details.contains(&catalog.services[3].display_name));
    assert!(!details.contains(&catalog.services[0].display_name));
}

#[test]
fn destinations_render_only_the_active_page_and_keep_offline_family_assets() {
    for (destination, expected) in [
        (Destination::Services, "Services"),
        (Destination::Mdns, "mDNS"),
        (Destination::PrivateSpace, "Certmesh"),
        (Destination::Settings, "Settings"),
        (Destination::About, "About"),
    ] {
        let state = UiState {
            destination,
            ..UiState::default()
        };
        let document = Html::parse_document(&render_with_state(View::Loading, links(), &state));
        assert_eq!(
            document
                .select(&selector("header nav [data-ui-tab]"))
                .count(),
            5
        );
        assert_eq!(
            text(&document, "header nav [aria-current='page']"),
            expected
        );
        assert_eq!(document.select(&selector("main h1")).count(), 1);
        if expected == "About" {
            assert!(document.select(&selector(".tcg")).next().is_some());
        } else {
            assert!(document.select(&selector(".tcg")).next().is_none());
        }
        for image in document.select(&selector("img")) {
            assert!(image
                .value()
                .attr("src")
                .unwrap()
                .starts_with("data:image/png;base64,"));
        }
        assert!(document
            .select(&selector("script, link[rel='stylesheet']"))
            .next()
            .is_none());
    }
}

#[test]
fn future_catalog_schema_is_rejected_before_rendering() {
    let mut value = serde_json::to_value(CatalogSnapshot::default()).unwrap();
    value["schema"] = 999.into();
    assert!(serde_json::from_value::<CatalogSnapshot>(value).is_err());
}

#[test]
fn about_uses_snapshot_facts_and_keeps_documentation_available_without_catalog() {
    let catalog = sample_catalog::fixture();
    let state = UiState {
        destination: Destination::About,
        ..UiState::default()
    };
    for view in [View::Snapshot(&catalog), View::Unavailable, View::Loading] {
        let document = Html::parse_document(&render_with_state(view, links(), &state));
        assert_eq!(document.select(&selector("#about > .tcg")).count(), 1);
        assert!(document.select(&selector("#settings")).next().is_none());
        let facts = text(&document, ".about-facts");
        match view {
            View::Snapshot(_) => {
                assert!(facts.contains("36 in this snapshot"));
                assert!(facts.contains("6 in the catalog"));
                assert!(facts.contains(&format!(
                    "{} saved services",
                    catalog
                        .services
                        .iter()
                        .filter(|service| service.favorite)
                        .count()
                )));
            }
            View::Unavailable => {
                assert!(facts.contains("Unavailable"));
                assert!(!facts.contains("in this snapshot"));
            }
            View::Loading => assert!(facts.contains("Reading snapshot")),
        }
        for link in document.select(&selector(".about-link")) {
            assert!(koi_ui::screens::about::is_documentation_url(
                link.value().attr("href").unwrap()
            ));
            assert_eq!(link.value().attr("rel"), Some("noopener noreferrer"));
        }
    }
    for untrusted in [
        "https://sylin.org.evil.test/",
        "https://sylin.org/?redirect=evil",
        "http://sylin.org/",
        "https://github.com/sylin-org/koi/issues/1",
        "file:///C:/Windows",
    ] {
        assert!(!koi_ui::screens::about::is_documentation_url(untrusted));
    }
}

/// The authenticated browser adapter's Links, as mounted by koi-serve at /ui.
fn browser_adapter_links() -> Links<'static> {
    Links {
        refresh: None,
        endpoint_actions: EndpointActions::Browser,
        preference_actions: false,
        operator_actions: OperatorActions::Browser,
    }
}

fn notes_service(id: &str) -> Service {
    serde_json::from_value(serde_json::json!({
        "schema":1,"id":id,"device_id":"desk","display_name":"Forgotten Notes",
        "alias":"Notebook","kind":"web","condition":"found","favorite":false,
        "local_only":false,"managed":false,"identity_confidence":"observed",
        "observations":[],"checks":[],"active_operations":[],
        "available_actions":["open","view_details","favorite"],
        "endpoints":[{
            "schema":1,"id":"http","scheme":"https","host":"notes.local","port":8443,
            "path":"/notes?sort=recent&view=all#today","source_observation_ids":["mdns"],
            "owner":{"kind":"foreign"},"browser_usable":true,"transport_encryption":"tls",
            "authority_needs":[],"reachability":[],"client_tls":[]
        }]
    }))
    .unwrap()
}

/// Notes on device "Office Mac", with Open granted and a strictly valid target.
fn notes_catalog() -> CatalogSnapshot {
    CatalogSnapshot {
        services: vec![notes_service("notes")],
        devices: vec![serde_json::from_value(serde_json::json!({
            "schema":1,"id":"desk","names":[{"value":"Office Mac","observation_ids":[]}],
            "addresses":[{"address":"192.0.2.40","observation_ids":[]}],
            "koi_presence":{"state":"absent"},"mesh_identity":{"state":"unknown","observation_ids":[]},
            "condition":"present"
        }))
        .unwrap()],
        ..CatalogSnapshot::default()
    }
}

#[test]
fn discovery_status_is_reported_independently_of_rows() {
    for (availability, key, phrase) in [
        (
            DiscoveryAvailability::Unknown,
            "unknown",
            "Discovery status not reported.",
        ),
        (
            DiscoveryAvailability::Available,
            "available",
            "Discovery is observing the local network.",
        ),
        (
            DiscoveryAvailability::Partial,
            "partial",
            "Discovery is partially unavailable",
        ),
        (
            DiscoveryAvailability::Unavailable,
            "unavailable",
            "Discovery is unavailable;",
        ),
    ] {
        for has_services in [false, true] {
            let mut catalog = notes_catalog();
            catalog.discovery = availability;
            if !has_services {
                catalog.services.clear();
            }
            let document = Html::parse_document(&render_with_state(
                View::Snapshot(&catalog),
                browser_adapter_links(),
                &UiState::default(),
            ));
            let status = document
                .select(&selector("#discovery-status"))
                .next()
                .unwrap_or_else(|| panic!("{key}: no discovery status"));
            assert_eq!(status.value().attr("data-discovery"), Some(key));
            assert!(status.value().attr("role").is_none(), "{key}");
            let copy: String = status.text().collect();
            assert!(copy.contains(phrase), "{key}: {copy}");
            let inspect: Vec<_> = status.select(&selector("a")).collect();
            if matches!(
                availability,
                DiscoveryAvailability::Partial | DiscoveryAvailability::Unavailable
            ) {
                assert_eq!(inspect.len(), 1, "{key}");
                let href = inspect[0].value().attr("href").unwrap();
                let target = UiState::parse_query(href.trim_start_matches('?')).unwrap();
                assert_eq!(target.destination, Destination::Mdns);
            } else {
                assert!(inspect.is_empty(), "{key}");
            }
            let html = document.root_element().html();
            assert_eq!(
                html.contains("No services found yet"),
                !has_services && availability == DiscoveryAvailability::Available,
                "{key}/{has_services}"
            );
            assert_eq!(row_ids(&document).len(), usize::from(has_services), "{key}");
        }
    }
}

#[test]
fn search_select_and_open_in_services() {
    let mut catalog = notes_catalog();
    // Decoys: one matches only "office", the other only "web".
    let mut ledger = notes_service("ledger");
    ledger.display_name = "Ledger".into();
    ledger.alias = None;
    ledger.kind = ServiceKind::Api;
    let mut photos = notes_service("photos");
    photos.display_name = "Photos".into();
    photos.alias = None;
    photos.device_id = DeviceId::new("garage").unwrap();
    catalog.services.extend([ledger, photos]);
    let notes = &catalog.services[0];
    let label = koi_ui::catalog_view::endpoint_label(&notes.endpoints[0]).to_lowercase();
    for word in ["office", "web"] {
        assert!(!notes.display_name.to_lowercase().contains(word));
        assert!(!notes
            .alias
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains(word));
        assert!(!label.contains(word));
    }

    let state = UiState::parse_query("tab=services&q=office+web").unwrap();
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_adapter_links(),
        &state,
    ));
    assert_eq!(row_ids(&document), ["notes"]);
    let href = document
        .select(&selector("a.name-link"))
        .next()
        .unwrap()
        .value()
        .attr("href")
        .unwrap()
        .to_owned();
    let selected = UiState::parse_query(href.trim_start_matches('?')).unwrap();
    assert_eq!(
        selected.selected.as_ref().map(ServiceId::as_str),
        Some("notes")
    );
    assert_eq!(selected.query, "office web");

    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_adapter_links(),
        &selected,
    ));
    let details = document
        .select(&selector("#service-details"))
        .next()
        .expect("selection opens details");
    let open: Vec<_> = details.select(&selector("a.endpoint-open")).collect();
    assert_eq!(open.len(), 1);
    assert_eq!(
        open[0].value().attr("href"),
        Some("https://notes.local:8443/notes?sort=recent&view=all#today")
    );
    assert!(details.text().collect::<String>().contains("Office Mac"));

    let lost = UiState {
        query: "missing".into(),
        ..selected
    };
    let document = Html::parse_document(&render_with_state(
        View::Snapshot(&catalog),
        browser_adapter_links(),
        &lost,
    ));
    assert!(row_ids(&document).is_empty());
    assert!(text(&document, "#services").contains("No services match these filters"));
    assert_eq!(
        text(&document, ".selection-notice[role='status']"),
        "The selected service is no longer in this view."
    );
    assert!(document
        .select(&selector("#service-details, [aria-selected='true']"))
        .next()
        .is_none());
}

#[test]
fn api_absent_and_hostile_services_never_offer_open() {
    let hostile_name = "<script>hostile()</script>";
    let hostile_path = "/\"><img src=x onerror=evil()>";
    for (kind, condition) in [
        (ServiceKind::Api, ServiceCondition::Found),
        (ServiceKind::Web, ServiceCondition::Absent),
    ] {
        let mut catalog = notes_catalog();
        let service = &mut catalog.services[0];
        service.kind = kind.clone();
        service.condition = condition;
        service.display_name = hostile_name.into();
        service.alias = None;
        service.endpoints[0].path = Some(hostile_path.into());
        assert!(service.available_actions.contains(&AvailableAction::Open));
        let state = UiState {
            selected: Some(service.id.clone()),
            ..UiState::default()
        };
        // The native variant proves the typed open_url button is refused too.
        for endpoint_actions in [EndpointActions::Browser, EndpointActions::Native] {
            let links = Links {
                endpoint_actions,
                ..browser_adapter_links()
            };
            let document =
                Html::parse_document(&render_with_state(View::Snapshot(&catalog), links, &state));
            assert!(document
                .select(&selector("#service-details"))
                .next()
                .is_some());
            for forbidden in [
                "a.endpoint-open",
                "button[data-operator-action=\"open_url\"]",
                "script",
                "[onerror]",
            ] {
                assert_eq!(
                    document.select(&selector(forbidden)).count(),
                    0,
                    "{kind:?}/{condition:?}/{endpoint_actions:?}: {forbidden}"
                );
            }
            let visible = text(&document, "#services");
            assert!(visible.contains(hostile_name));
            assert!(visible.contains(hostile_path));
        }
    }
}
