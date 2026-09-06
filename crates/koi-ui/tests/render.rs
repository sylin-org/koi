use koi_common::service::*;
use koi_ui::{components::condition::service_label, render, Links, View};
use scraper::{Html, Selector};

fn links() -> Links<'static> {
    Links {
        refresh: Some("./"),
        advanced: "/advanced",
        browser_access: None,
    }
}

fn fixture(condition: ServiceCondition) -> CatalogSnapshot {
    CatalogSnapshot {
        services: vec![Service {
            schema: CATALOG_SCHEMA,
            id: ServiceId::new("svc_\"><script>").unwrap(),
            device_id: DeviceId::new("dev_test").unwrap(),
            display_name: "<script>alert('name')</script>".into(),
            alias: Some("<img src=x onerror=alert(1)> & Friends".into()),
            kind: ServiceKind::Web,
            condition,
            endpoints: vec![],
            observations: vec![],
            checks: vec![],
            available_actions: vec![AvailableAction::Favorite],
            favorite: true,
            local_only: false,
            managed: false,
            active_operations: vec![],
            identity_confidence: IdentityConfidence::Observed,
            ambiguity: None,
            last_known: None,
        }],
        ..CatalogSnapshot::default()
    }
}

#[test]
fn hostile_text_ids_and_aliases_remain_text() {
    let mut catalog = fixture(ServiceCondition::Found);
    for alias in [Some("<img src=x onerror=alert(1)> & Friends".into()), None] {
        catalog.services[0].alias = alias;
        let html = render(View::Snapshot(&catalog), links());
        let dom = Html::parse_document(&html);
        assert!(dom
            .select(&Selector::parse("script, [onerror]").unwrap())
            .next()
            .is_none());
        let row = dom
            .select(&Selector::parse(".service-row").unwrap())
            .next()
            .unwrap();
        assert_eq!(
            row.value().attr("data-service-id"),
            Some(catalog.services[0].id.as_str())
        );
        assert_eq!(
            row.select(&Selector::parse("strong").unwrap())
                .next()
                .unwrap()
                .text()
                .collect::<String>(),
            catalog.services[0]
                .alias
                .as_deref()
                .unwrap_or(&catalog.services[0].display_name)
        );
    }
}

#[test]
fn every_condition_keeps_its_declared_meaning() {
    for condition in [
        ServiceCondition::Starting,
        ServiceCondition::Found,
        ServiceCondition::Responding,
        ServiceCondition::NotResponding,
        ServiceCondition::Absent,
        ServiceCondition::Stale,
        ServiceCondition::Ambiguous,
    ] {
        let html = render(View::Snapshot(&fixture(condition)), links());
        assert!(html.contains(service_label(condition)));
        if condition != ServiceCondition::Responding {
            assert!(!html.contains(">Responding<"));
        }
    }
}

#[test]
fn all_rows_render_without_inferred_actions_or_loss_of_favorites() {
    let mut catalog = fixture(ServiceCondition::Absent);
    let mut second = catalog.services[0].clone();
    second.id = ServiceId::new("second").unwrap();
    second.favorite = false;
    second.local_only = true;
    catalog.services.push(second);
    let html = render(View::Snapshot(&catalog), links());
    let dom = Html::parse_document(&html);
    assert_eq!(
        dom.select(&Selector::parse("#home .service-row").unwrap())
            .count(),
        2
    );
    assert!(html.contains("Favorite"));
    assert!(html.contains("Local only"));
    assert!(dom
        .select(&Selector::parse("[data-external]").unwrap())
        .next()
        .is_none());
    assert!(dom
        .select(&Selector::parse("#home-search").unwrap())
        .next()
        .is_some());
    assert!(!html.contains("javascript:"));
}

#[test]
fn device_details_join_only_the_declared_device_id_and_escape_names() {
    let mut catalog = fixture(ServiceCondition::Found);
    catalog.devices.push(Device {
        schema: CATALOG_SCHEMA,
        id: DeviceId::new("dev_test").unwrap(),
        names: vec![NameEvidence {
            value: "<img src=x onerror=alert(1)>".into(),
            observation_ids: vec![],
        }],
        addresses: vec![],
        koi_presence: KoiPresence::Absent,
        mesh_identity: MeshIdentity {
            state: MeshIdentityState::Unknown,
            observation_ids: vec![],
        },
        condition: DeviceCondition::Ambiguous,
    });
    let mut stranger = catalog.services[0].clone();
    stranger.id = ServiceId::new("stranger").unwrap();
    stranger.device_id = DeviceId::new("elsewhere").unwrap();
    catalog.services.push(stranger);
    let dom = Html::parse_document(&render(View::Snapshot(&catalog), links()));
    assert_eq!(
        dom.select(&Selector::parse("#devices .service-row").unwrap())
            .count(),
        1
    );
    let summary = dom
        .select(&Selector::parse("summary").unwrap())
        .next()
        .unwrap()
        .text()
        .collect::<String>();
    assert!(summary.contains("<img src=x onerror=alert(1)>"));
    assert!(summary.contains("Identity is ambiguous"));
    assert!(dom
        .select(&Selector::parse("[onerror]").unwrap())
        .next()
        .is_none());
}

#[test]
fn unavailable_loading_and_empty_are_distinct() {
    let empty = render(View::Snapshot(&CatalogSnapshot::default()), links());
    let unavailable = render(View::Unavailable, links());
    let loading = render(View::Loading, links());
    assert!(empty.contains("No services in this snapshot"));
    assert!(!unavailable.contains("No services in this snapshot"));
    assert!(unavailable.contains("Cannot read the local catalog"));
    assert!(loading.contains("Reading the local catalog"));
    assert!(!loading.contains("Snapshot revision"));
}

#[test]
fn navigation_destinations_and_original_card_work_without_scripts_or_network_assets() {
    let dom = Html::parse_document(&render(View::Loading, links()));
    for (id, label) in koi_ui::components::navigation::NAVIGATION {
        assert!(dom
            .select(&Selector::parse(&format!("#{id}")).unwrap())
            .next()
            .is_some());
        assert_eq!(
            dom.select(&Selector::parse(&format!("nav a[href='#{id}']")).unwrap())
                .next()
                .unwrap()
                .text()
                .collect::<String>(),
            label
        );
    }
    assert_eq!(dom.select(&Selector::parse(".tcg img").unwrap()).count(), 2);
    for image in dom.select(&Selector::parse("img").unwrap()) {
        assert!(image
            .value()
            .attr("src")
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }
    assert!(dom
        .select(&Selector::parse("script, link[rel='stylesheet']").unwrap())
        .next()
        .is_none());
}

#[test]
fn future_catalog_schema_is_rejected_before_rendering() {
    let mut value = serde_json::to_value(CatalogSnapshot::default()).unwrap();
    value["schema"] = 999.into();
    assert!(serde_json::from_value::<CatalogSnapshot>(value).is_err());
}
