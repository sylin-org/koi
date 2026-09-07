use koi_common::service::*;
use koi_ui::home::{project, BrowserDestination, EmptyState, HomeQuery};
use serde_json::json;

fn service(id: &str) -> Service {
    serde_json::from_value(json!({
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

fn snapshot() -> CatalogSnapshot {
    CatalogSnapshot {
        services: vec![service("notes")],
        devices: vec![serde_json::from_value(json!({
        "schema":1,"id":"desk","names":[{"value":"Office Mac","observation_ids":[]}],
        "addresses":[{"address":"192.0.2.40","observation_ids":[]}],
        "koi_presence":{"state":"absent"},"mesh_identity":{"state":"unknown","observation_ids":[]},
        "condition":"present"
    }))
    .unwrap()],
        ..CatalogSnapshot::default()
    }
}

fn destination(service: &Service) -> Option<BrowserDestination> {
    BrowserDestination::for_service(service, &EndpointId::new("http").unwrap())
}

#[test]
fn discovery_status_is_independent_of_empty_search_and_retained_rows() {
    use koi_ui::{render_home, Links, View};
    use scraper::{Html, Selector};
    for (availability, message) in [
        (DiscoveryAvailability::Unknown, "status is not reported"),
        (DiscoveryAvailability::Available, "discovery is observing"),
        (
            DiscoveryAvailability::Partial,
            "discovery is partially unavailable",
        ),
        (
            DiscoveryAvailability::Unavailable,
            "discovery is unavailable",
        ),
    ] {
        for has_services in [false, true] {
            let mut catalog = snapshot();
            catalog.discovery = availability;
            if !has_services {
                catalog.services.clear();
            }
            let html = render_home(
                View::Snapshot(&catalog),
                Links {
                    refresh: None,
                    advanced: "/",
                },
                &HomeQuery::default(),
            );
            let dom = Html::parse_document(&html);
            let status = dom
                .select(&Selector::parse("#discovery-status").unwrap())
                .next()
                .unwrap()
                .text()
                .collect::<String>();
            assert!(status.contains(message), "{status}");
            let text = dom.root_element().text().collect::<String>();
            assert_eq!(
                text.contains("No services discovered yet"),
                !has_services && availability == DiscoveryAvailability::Available
            );
            assert_eq!(
                dom.select(&Selector::parse("#home .service-row").unwrap())
                    .count(),
                usize::from(has_services)
            );
        }
    }
}

#[test]
fn query_links_round_trip_without_turning_text_into_navigation() {
    use koi_ui::home::HomeRequest;
    let id = ServiceId::new("notes&other=<tag>").unwrap();
    let query = HomeQuery {
        search: "Office & café #web",
        selected: Some(&id),
        favorites_only: true,
        peer: None,
    };
    let href = query.href(query.selected);
    let parsed =
        HomeRequest::parse(href.strip_prefix('?').unwrap().split('#').next().unwrap()).unwrap();
    assert_eq!(parsed.search, query.search);
    assert_eq!(parsed.selected.as_ref(), query.selected);
    assert!(parsed.favorites_only);
    for invalid in [
        "selected=",
        "selected=UPPER",
        "search=a&search=b",
        "favorites=0",
        "token=secret",
        "path=/etc/passwd",
    ] {
        assert!(HomeRequest::parse(invalid).is_err(), "{invalid}");
    }
    assert!(HomeRequest::parse(&"x".repeat(4097)).is_err());
}

#[test]
fn rendered_search_select_open_and_clear_use_the_real_shared_projection() {
    use koi_ui::{home::HomeRequest, render_home, Links, View};
    use scraper::{Html, Selector};
    let catalog = snapshot();
    let links = Links {
        refresh: None,
        advanced: "/",
    };
    let render = |query: &HomeQuery<'_>| {
        Html::parse_document(&render_home(View::Snapshot(&catalog), links, query))
    };
    let rows = Selector::parse("#home .service-row").unwrap();
    let initial = render(&HomeQuery {
        search: "Office web",
        ..Default::default()
    });
    let row = initial
        .select(&rows)
        .next()
        .expect("Notes is found by device/category");
    let select = row
        .select(&Selector::parse("a[data-home-link]").unwrap())
        .next()
        .unwrap();
    let href = select.value().attr("href").unwrap();
    let intent = HomeRequest::parse(href[1..].split('#').next().unwrap()).unwrap();
    let selected = render(&intent.query());
    let details = selected
        .select(&Selector::parse("#service-details").unwrap())
        .next()
        .unwrap();
    let open = details
        .select(&Selector::parse("a[data-external]").unwrap())
        .next()
        .unwrap();
    assert_eq!(
        open.value().attr("href"),
        Some("https://notes.local:8443/notes?sort=recent&view=all#today")
    );
    assert!(details.text().collect::<String>().contains("Office Mac"));
    let no_match = render(&HomeQuery {
        search: "missing",
        selected: intent.selected.as_ref(),
        favorites_only: false,
        peer: None,
    });
    assert_eq!(no_match.select(&rows).count(), 0);
    assert!(no_match
        .root_element()
        .text()
        .collect::<String>()
        .contains("No matches"));
    assert!(
        no_match
            .select(&Selector::parse("#service-details a[data-external]").unwrap())
            .next()
            .is_some(),
        "selection survives filtering"
    );
    assert_eq!(render(&HomeQuery::default()).select(&rows).count(), 1);
}

#[test]
fn rendered_api_absence_and_hostile_details_never_create_an_open_action() {
    use koi_ui::{render_home, Links, View};
    use scraper::{Html, Selector};
    for (kind, condition) in [
        (ServiceKind::Api, ServiceCondition::Found),
        (ServiceKind::Web, ServiceCondition::Absent),
    ] {
        let mut catalog = snapshot();
        catalog.services[0].kind = kind;
        catalog.services[0].condition = condition;
        catalog.services[0].display_name = "<script>hostile()</script>".into();
        catalog.services[0].alias = None;
        catalog.services[0].endpoints[0].path = Some("/\"><img src=x onerror=evil()>".into());
        let query = HomeQuery {
            selected: Some(&catalog.services[0].id),
            ..Default::default()
        };
        let dom = Html::parse_document(&render_home(
            View::Snapshot(&catalog),
            Links {
                refresh: None,
                advanced: "/",
            },
            &query,
        ));
        assert_eq!(
            dom.select(&Selector::parse("script, [onerror], [data-external]").unwrap())
                .count(),
            0
        );
        assert!(dom
            .root_element()
            .text()
            .collect::<String>()
            .contains("<script>hostile()</script>"));
        assert!(dom
            .root_element()
            .text()
            .collect::<String>()
            .contains("Connection endpoint"));
    }
}

#[test]
fn search_matches_name_alias_device_address_category_and_all_query_words() {
    let snapshot = snapshot();
    for search in [
        "forgotten",
        "NOTEBOOK",
        "office",
        "192.0.2.40",
        "web",
        "notes.local",
        " notebook  MAC web ",
    ] {
        let view = project(
            &snapshot,
            &HomeQuery {
                search,
                ..Default::default()
            },
        );
        assert_eq!(view.services.len(), 1, "{search}");
        assert_eq!(view.empty, None);
    }
    let view = project(
        &snapshot,
        &HomeQuery {
            search: "office printer",
            ..Default::default()
        },
    );
    assert_eq!(view.empty, Some(EmptyState::NoMatches));
    assert_eq!(
        project(&snapshot, &HomeQuery::default()).services.len(),
        1,
        "clear filter restores rows"
    );
    let mut unrelated = snapshot.clone();
    unrelated.devices[0].id = DeviceId::new("unrelated").unwrap();
    assert_eq!(
        project(
            &unrelated,
            &HomeQuery {
                search: "office",
                ..Default::default()
            }
        )
        .empty,
        Some(EmptyState::NoMatches)
    );
}

#[test]
fn selection_and_order_survive_snapshot_reordering_alias_changes_and_filtering() {
    let mut snapshot = snapshot();
    snapshot
        .services
        .extend([service("z-last"), service("a-first")]);
    let selected = ServiceId::new("notes").unwrap();
    let ids = |snapshot: &CatalogSnapshot| {
        project(snapshot, &HomeQuery::default())
            .services
            .iter()
            .map(|s| s.id.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&snapshot), ["a-first", "notes", "z-last"]);
    snapshot.services.reverse();
    snapshot.services[0].alias = Some("A new name".into());
    assert_eq!(ids(&snapshot), ["a-first", "notes", "z-last"]);
    let query = HomeQuery {
        search: "no matches",
        selected: Some(&selected),
        ..Default::default()
    };
    let view = project(&snapshot, &query);
    assert_eq!(view.selected.unwrap().id, selected);
    assert_eq!(view.empty, Some(EmptyState::NoMatches));
    assert!(!view.selection_missing);
    snapshot.services.retain(|s| s.id != selected);
    let view = project(&snapshot, &query);
    assert!(view.selection_missing);
    assert!(
        view.selected.is_none(),
        "never select a different service by row index"
    );
}

#[test]
fn stopped_favorite_and_last_known_device_remain_searchable_without_an_open_action() {
    let mut snapshot = snapshot();
    snapshot.devices.clear();
    let saved = &mut snapshot.services[0];
    saved.favorite = true;
    saved.condition = ServiceCondition::Absent;
    saved.endpoints.clear();
    saved.available_actions = vec![AvailableAction::Favorite, AvailableAction::ViewDetails];
    saved.last_known = Some(LastKnownService {
        device_name: Some("Old laptop".into()),
        last_seen: snapshot.generated_at,
        kind: ServiceKind::Web,
    });
    let selected = saved.id.clone();
    let view = project(
        &snapshot,
        &HomeQuery {
            search: "laptop",
            selected: Some(&selected),
            favorites_only: true,
            peer: None,
        },
    );
    assert_eq!(view.favorites.len(), 1);
    assert!(view.services.is_empty());
    assert_eq!(view.attention_total, 1);
    assert_eq!(view.selected.unwrap().condition, ServiceCondition::Absent);
    assert!(destination(view.selected.unwrap()).is_none());
}

#[test]
fn empty_filter_and_no_saved_favorites_are_distinct_and_attention_is_bounded() {
    assert_eq!(
        project(&CatalogSnapshot::default(), &HomeQuery::default()).empty,
        Some(EmptyState::NoDiscoveries)
    );
    let mut snapshot = snapshot();
    assert_eq!(
        project(
            &snapshot,
            &HomeQuery {
                favorites_only: true,
                ..Default::default()
            }
        )
        .empty,
        Some(EmptyState::NoFavorites)
    );
    for i in 0..12 {
        let mut bad = service(&format!("bad-{i:02}"));
        bad.condition = ServiceCondition::NotResponding;
        snapshot.services.push(bad);
    }
    let view = project(&snapshot, &HomeQuery::default());
    assert_eq!(view.attention_total, 12);
    assert_eq!(view.attention.len(), 5);
    assert_eq!(
        view.services.len(),
        13,
        "bounding attention must not hide ordinary rows"
    );
}

#[test]
fn browser_targets_preserve_real_ports_paths_queries_and_ipv6() {
    let mut notes = service("notes");
    assert_eq!(
        destination(&notes).unwrap().as_str(),
        "https://notes.local:8443/notes?sort=recent&view=all#today"
    );
    notes.endpoints[0].host = "2001:db8::7".into();
    notes.endpoints[0].path = Some("/my notes?mode=read only".into());
    assert_eq!(
        destination(&notes).unwrap().as_str(),
        "https://[2001:db8::7]:8443/my%20notes?mode=read%20only"
    );
    notes.endpoints[0].host = "[2001:db8::7]".into();
    assert!(destination(&notes).is_some());
    notes.endpoints[0].host = "bücher.local".into();
    assert!(destination(&notes)
        .unwrap()
        .as_str()
        .starts_with("https://xn--bcher-kva.local:8443/"));
}

#[test]
fn only_declared_browser_endpoints_can_open_never_api_or_unsafe_authority() {
    let notes = service("notes");
    for condition in [
        ServiceCondition::Absent,
        ServiceCondition::Stale,
        ServiceCondition::Ambiguous,
    ] {
        let mut bad = notes.clone();
        bad.condition = condition;
        assert!(destination(&bad).is_none());
    }
    let mut bad = notes.clone();
    bad.kind = ServiceKind::Api;
    assert!(destination(&bad).is_none());
    bad = notes.clone();
    bad.available_actions.clear();
    assert!(destination(&bad).is_none());
    bad = notes.clone();
    bad.endpoints[0].browser_usable = false;
    assert!(destination(&bad).is_none());
    for scheme in ["javascript", "file", "data", "custom", "tcp"] {
        bad = notes.clone();
        bad.endpoints[0].scheme = scheme.into();
        assert!(destination(&bad).is_none(), "{scheme}");
    }
    for host in [
        "",
        "0.0.0.0",
        "::",
        "[::]",
        "user@evil.local",
        "evil.local/path",
        "evil.local:80",
        "evil.local?x",
        "evil.local#x",
        "evil\\local",
        " host.local",
        "host\n.local",
        "fe80::1%eth0",
        "[fe80::1%25eth0]",
    ] {
        bad = notes.clone();
        bad.endpoints[0].host = host.into();
        assert!(destination(&bad).is_none(), "{host:?}");
    }
    for path in [
        "javascript:alert(1)",
        "//evil.local/path",
        "/\\evil.local",
        "/ok\nother",
        "https://evil.local",
    ] {
        bad = notes.clone();
        bad.endpoints[0].path = Some(path.into());
        assert!(destination(&bad).is_none(), "{path:?}");
    }
    assert!(BrowserDestination::for_service(&notes, &EndpointId::new("other").unwrap()).is_none());
}

#[test]
fn generic_opener_rejects_unsafe_schemes_credentials_controls_and_url_repairs() {
    for url in [
        "javascript:alert(1)",
        "file:///tmp/file",
        "custom://host/",
        "data:text/html,x",
        "http:host/path",
        "http:/host/path",
        "http:///host/path",
        "//host/path",
        "http://user:password@host/",
        "http://@host/",
        "http://host\\@evil/",
        "http://host/\n",
        "http://host/\0",
        " http://host/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://host:0/",
    ] {
        assert!(BrowserDestination::parse(url).is_none(), "{url:?}");
    }
    for url in [
        "http://localhost:8080/",
        "HTTPS://notes.local/",
        "https://host/?a=1&b=2",
        "http://[::1]/",
    ] {
        assert!(BrowserDestination::parse(url).is_some(), "{url}");
    }
}

#[test]
fn hostile_names_and_txt_do_not_influence_the_destination_or_invent_protocol() {
    let mut notes = service("notes");
    let before = destination(&notes).unwrap();
    notes.display_name = "<script>location='javascript:evil'</script>".into();
    notes.alias = Some("https://other.example".into());
    assert_eq!(destination(&notes), Some(before));
    notes.endpoints[0].scheme = "tcp".into();
    notes.endpoints[0].port = 443;
    assert!(
        destination(&notes).is_none(),
        "an HTTPS-looking name or port is not HTTP evidence"
    );
}
