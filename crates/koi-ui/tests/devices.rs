use koi_common::{integration::MdnsDiscoverySnapshot, service::*};
use koi_ui::{
    devices::{compare, peers, Comparison, Reading},
    home::HomeQuery,
    Links, View,
};
use scraper::{Html, Selector};
use serde_json::json;

fn catalog() -> CatalogSnapshot {
    let devices = ["local", "peer"].map(|id| serde_json::from_value(json!({
        "schema":1,"id":id,"names":[{"value":format!("Office {id}"),"observation_ids":[]}],"addresses":[],
        "koi_presence":{"state":"identified","installation_id":format!("installation-{id}")},
        "mesh_identity":{"state":"unknown","observation_ids":[]},"condition":"present"
    })).unwrap());
    let services = ["local", "peer"].map(|id| serde_json::from_value(json!({
        "schema":1,"id":format!("app-{id}"),"device_id":id,"display_name":"Notes","kind":"api","condition":"found", "favorite":false,"local_only":false,"managed":false,"identity_confidence":"explicit","checks":[],"active_operations":[],"available_actions":["view_details"],
        "observations":[{"schema":1,"id":"mdns","kind":"mdns","source":"mdns","provider":"test","source_revision":1,"source_generation":1,"observer_installation_id":"installation-local","observed_at":"2026-09-07T00:00:00Z","valid_until":"2026-09-08T00:00:00Z","state":"current","raw_reference":{"service_type":"_mcp._tcp.local."}}],
        "endpoints":[{"schema":1,"id":format!("endpoint-{id}"),"scheme":"http","host":format!("{id}.local"),"port":5641,"path":"/mcp","source_observation_ids":["mdns"],"owner":{"kind":"foreign"},"browser_usable":false,"transport_encryption":"none","authority_needs":[],"reachability":[],"client_tls":[]}]
    })).unwrap());
    CatalogSnapshot {
        local_device_id: Some(DeviceId::new("local").unwrap()),
        generated_at: "2026-09-07T01:00:00Z".parse().unwrap(),
        devices: devices.into(),
        services: services.into(),
        ..Default::default()
    }
}
fn snapshot() -> MdnsDiscoverySnapshot {
    serde_json::from_value(json!({"revision":1,"service_types":["_http._tcp.local."],"records":[{"name":"Notes._http._tcp.local.","type":"_http._tcp.local.","host":"notes.local.","port":8080,"txt":{}}],"sources":[{"query":"_http._tcp.local.","provider":"test","generation":1,"available":true}]})).unwrap()
}
fn render(catalog: &CatalogSnapshot, state: &Comparison) -> String {
    let peer = DeviceId::new("peer").unwrap();
    koi_ui::render_workbench(
        View::Snapshot(catalog),
        Links {
            refresh: None,
            advanced: "/advanced",
        },
        &HomeQuery {
            peer: Some(&peer),
            ..Default::default()
        },
        state,
    )
}
#[test]
fn device_services_keep_identity_and_existing_details_destinations() {
    let catalog = catalog();
    let output = render(&catalog, &Comparison::NotRun);
    let html = Html::parse_document(&output);
    for id in ["local", "peer"] {
        let row = html
            .select(&Selector::parse(&format!("#device-{id}")).unwrap())
            .next()
            .unwrap();
        let link = row
            .select(&Selector::parse("a.service-select").unwrap())
            .next()
            .unwrap();
        assert!(link
            .value()
            .attr("href")
            .unwrap()
            .contains(&format!("selected=app-{id}")));
        let text = row.text().collect::<String>();
        assert!(text.contains("1 services in this snapshot"));
        if id == "local" {
            assert!(text.contains("This device"));
        } else {
            assert!(text.contains("identity advertised; not authenticated"));
            assert!(!text.contains("Joined identity recorded"));
        }
    }
    assert_eq!(peers(&catalog)[0].endpoint, "http://peer.local:5641");
    assert!(!output.contains("No differences in these snapshots"));
}
#[test]
fn eligibility_never_guesses_local_identity_or_ambiguous_stale_peers() {
    let mut catalog = catalog();
    for state in [
        DeviceCondition::Ambiguous,
        DeviceCondition::Stale,
        DeviceCondition::Absent,
    ] {
        catalog.devices[1].condition = state;
        assert!(peers(&catalog).is_empty());
    }
    catalog.devices[1].condition = DeviceCondition::Present;
    catalog.services[1].endpoints[0].host = "127.0.0.1".into();
    assert!(peers(&catalog).is_empty());
    catalog.services[1].endpoints[0].host = "peer.local".into();
    catalog.local_device_id = None;
    assert!(peers(&catalog).is_empty());
    assert!(render(&catalog, &Comparison::NotRun).contains("Incomplete."));
    assert!(koi_ui::render(
        View::Snapshot(&catalog),
        Links {
            refresh: None,
            advanced: "/advanced"
        }
    )
    .contains("Not configured."));
}
#[test]
fn equal_empty_different_and_conflicting_records_are_distinct() {
    let left = snapshot();
    assert!(compare(&left, &left).unwrap().is_empty());
    let mut right = left.clone();
    right.records[0].port = Some(8081);
    assert_eq!(compare(&left, &right).unwrap().changed.len(), 1);
    right.records[0].name = "Other._http._tcp.local.".into();
    let diff = compare(&left, &right).unwrap();
    assert_eq!((diff.only_local.len(), diff.only_peer.len()), (1, 1));
    right.records.clear();
    assert!(compare(&right, &right).unwrap().is_empty());
    assert_eq!(compare(&left, &right).unwrap().only_local.len(), 1);
}
#[test]
fn missing_or_incompatible_coverage_is_incomplete() {
    let left = snapshot();
    let mut right = left.clone();
    right.sources.clear();
    assert!(compare(&left, &right).is_err());
    right = left.clone();
    right.sources[0].available = false;
    assert!(compare(&left, &right).is_err());
    right = left.clone();
    right.sources[0].query = "_ssh._tcp.local.".into();
    assert!(compare(&left, &right).is_err());
    right = left.clone();
    right.sources[0].query = "_http._tcp.example.com.".into();
    assert!(compare(&left, &right).is_err());
}
#[test]
fn rendering_never_labels_a_failed_read_as_no_differences() {
    let catalog = catalog();
    let read = |result| {
        Box::new(Reading {
            observer: "Office".into(),
            received_at: "2026-09-07T01:00:00Z".into(),
            result,
        })
    };
    let successful = Comparison::Finished {
        local: read(Ok(snapshot())),
        peer: read(Ok(snapshot())),
    };
    assert!(render(&catalog, &successful).contains("No differences in these snapshots"));
    for state in [
        Comparison::NotRun,
        Comparison::Comparing,
        Comparison::Incomplete("Access refused".into()),
        Comparison::Finished {
            local: read(Ok(snapshot())),
            peer: read(Err("Access refused".into())),
        },
    ] {
        let output = render(&catalog, &state);
        assert!(!output.contains("No differences in these snapshots"));
    }
    let mut old = serde_json::to_value(&catalog).unwrap();
    old.as_object_mut().unwrap().remove("local_device_id");
    let decoded: CatalogSnapshot = serde_json::from_value(old).unwrap();
    assert!(decoded.local_device_id.is_none());
    assert_eq!(
        serde_json::from_value::<CatalogSnapshot>(serde_json::to_value(&catalog).unwrap()).unwrap(),
        catalog
    );
}
#[test]
fn peer_intent_round_trips_opaque_ids_without_query_injection() {
    let peer = DeviceId::new("peer&selected=other").unwrap();
    let link = koi_ui::devices::peer_href(&peer);
    let intent =
        koi_ui::home::HomeRequest::parse(link.trim_start_matches('?').split('#').next().unwrap())
            .unwrap();
    assert_eq!(intent.peer, Some(peer));
    assert!(intent.selected.is_none());
}
