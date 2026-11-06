use koi_ui::{
    Destination, EndpointActions, Links, OperatorActions, OperatorSnapshot, UiState, View,
};
use scraper::{Html, Selector};
#[path = "../examples/support/mdns.rs"]
mod sample;

fn document(state: &UiState, authenticated: bool) -> (String, Html) {
    let operator = OperatorSnapshot {
        mdns: Some(sample::fixture()),
        ..Default::default()
    };
    let value = koi_ui::render_with_operator_state(
        View::Unavailable,
        authenticated.then_some(&operator),
        Links {
            refresh: None,
            endpoint_actions: EndpointActions::None,
            preference_actions: false,
            operator_actions: if authenticated {
                OperatorActions::Browser
            } else {
                OperatorActions::None
            },
        },
        state,
    );
    let parsed = Html::parse_document(&value);
    (value, parsed)
}
fn count(doc: &Html, query: &str) -> usize {
    doc.select(&Selector::parse(query).unwrap()).count()
}

#[test]
fn local_filter_searches_every_displayed_source_record() {
    for query in [
        "198.51.100.42",
        "Alternate provider TXT",
        "STUDIO PRINTER 00._IPP._TCP.LOCAL.",
    ] {
        let (_, doc) = document(
            &UiState {
                destination: Destination::Mdns,
                mdns_filter: query.into(),
                ..Default::default()
            },
            true,
        );
        assert_eq!(count(&doc, ".mdns-instance"), 1, "query {query}");
        assert_eq!(
            count(&doc, ".mdns-instance .mdns-source"),
            2,
            "both provider records remain inspectable for {query}"
        );
    }
}

#[test]
fn mdns_interactive_controls_have_unique_stable_focus_identity() {
    let (_, doc) = document(
        &UiState {
            destination: Destination::Mdns,
            ..Default::default()
        },
        true,
    );
    let mut seen = std::collections::HashSet::new();
    for node in doc.select(&Selector::parse("#mdns-inspector summary, #mdns-inspector button, #mdns-inspector a, #mdns-inspector select, #mdns-inspector input:not([type='hidden'])").unwrap()) {
        let key = node.value().attr("data-focus-key").expect("every interactive mDNS control must survive refresh");
        assert!(seen.insert(key.to_owned()), "duplicate focus identity {key}");
    }
    let key = doc
        .select(&Selector::parse(".mdns-instance > summary").unwrap())
        .next()
        .unwrap()
        .value()
        .attr("data-focus-key")
        .unwrap();
    let (_, filtered) = document(
        &UiState {
            destination: Destination::Mdns,
            mdns_filter: "198.51.100.42".into(),
            ..Default::default()
        },
        true,
    );
    assert_eq!(
        filtered
            .select(&Selector::parse(".mdns-instance > summary").unwrap())
            .next()
            .unwrap()
            .value()
            .attr("data-focus-key"),
        Some(key)
    );
}

#[test]
fn mdns_preserves_full_network_evidence_and_escapes_txt() {
    let (html, doc) = document(
        &UiState {
            destination: Destination::Mdns,
            ..Default::default()
        },
        true,
    );
    assert_eq!(count(&doc, ".mdns-instance"), 14);
    assert_eq!(count(&doc, ".mdns-instance[data-removed='true']"), 1);
    assert_eq!(count(&doc, "form[data-mdns-kind]"), 3);
    assert_eq!(count(&doc, "script"), 0);
    for expected in [
        "_empty._udp",
        "0 current",
        "Unresolved",
        "Removed",
        "failed-provider",
        "Unavailable",
        "Studio printer 00._ipp._tcp.local.",
        "192.0.2.1",
        "631",
        "First observed",
        "not packet timestamps",
        "&lt;script&gt;alert",
        "alternate-provider",
        "198.51.100.42",
        "Alternate provider TXT",
    ] {
        assert!(html.contains(expected), "missing {expected}");
    }
}

#[test]
fn unresolved_observation_is_visible_without_becoming_a_resolved_catalog_record() {
    let snapshot = sample::fixture();
    let unresolved = &snapshot.instances[1];
    assert!(!snapshot
        .discovery
        .records
        .iter()
        .any(|record| record.name == unresolved.instance_name));
    assert!(snapshot.discovery.observations.iter().any(|observation| matches!(&observation.value, koi_common::integration::MdnsDiscoveryValue::UnresolvedInstance { record } if record.name == unresolved.instance_name)));
    let (_, doc) = document(
        &UiState {
            destination: Destination::Mdns,
            mdns_filter: unresolved.instance_name.clone(),
            ..Default::default()
        },
        true,
    );
    assert_eq!(count(&doc, ".mdns-instance"), 1);
    assert_eq!(count(&doc, ".mdns-instance[data-resolved='false']"), 1);
    assert_eq!(count(&doc, ".mdns-instance .mdns-source"), 1);
}

#[test]
fn local_filters_include_txt_and_do_not_hide_zero_instance_types() {
    let state = UiState {
        destination: Destination::Mdns,
        mdns_filter: "alert('TXT')".into(),
        ..Default::default()
    };
    assert_eq!(
        UiState::parse_query(&state.query_string()),
        Ok(state.clone())
    );
    let (_, doc) = document(&state, true);
    assert_eq!(count(&doc, ".mdns-instance"), 13);
    let (html, doc) = document(
        &UiState {
            mdns_type: "_empty._udp".into(),
            ..state
        },
        true,
    );
    assert_eq!(count(&doc, ".mdns-instance"), 0);
    assert!(html.contains("No matching instances"));
    assert!(html.contains("_empty._udp"));
}

#[test]
fn public_presentation_keeps_mdns_destination_without_inspection_data_or_query_controls() {
    let (html, doc) = document(
        &UiState {
            destination: Destination::Mdns,
            ..Default::default()
        },
        false,
    );
    assert_eq!(count(&doc, "header nav [data-ui-tab]"), 5);
    assert_eq!(count(&doc, "#mdns-inspector"), 0);
    assert_eq!(count(&doc, "form[data-mdns-kind]"), 0);
    assert!(!html.contains("failed-provider"));
}
