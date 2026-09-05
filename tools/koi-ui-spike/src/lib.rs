//! Non-shipping renderer comparison. No transport, domain state or mutation here.
use base64::Engine as _;
use koi_common::service::{CatalogSnapshot, ServiceCondition};

#[cfg(feature = "dioxus-renderer")]
pub mod dioxus_view;
#[cfg(feature = "maud-renderer")]
pub mod maud_view;

/// Shared rules for browser media queries and native preference fallbacks.
pub const REDUCED_MOTION_CSS: &str = include_str!("../assets/reduced-motion.css");

pub const NAVIGATION: [(&str, &str); 4] = [
    ("home", "Home"),
    ("devices", "Devices"),
    ("settings", "Settings"),
    ("about", "About"),
];

/// Presentation input only. Unavailable is never converted into an empty catalog.
#[derive(Clone, Copy)]
pub enum View<'a> {
    Loading,
    Unavailable,
    Snapshot(&'a CatalogSnapshot),
}

pub fn condition_label(condition: ServiceCondition) -> &'static str {
    match condition {
        ServiceCondition::Starting => "Starting",
        ServiceCondition::Found => "Found on the network",
        ServiceCondition::Responding => "Responding",
        ServiceCondition::NotResponding => "Not responding",
        ServiceCondition::Absent => "Absent",
        ServiceCondition::Stale => "Last observation is stale",
        ServiceCondition::Ambiguous => "Identity is ambiguous",
    }
}

/// Only source-controlled assets are inserted as trusted HTML, never catalog data.
pub fn original_card() -> String {
    let sprite =
        base64::engine::general_purpose::STANDARD.encode(include_bytes!("../assets/koi.png"));
    include_str!("../assets/card.html").replace(
        "src=\"koi.png\"",
        &format!("src=\"data:image/png;base64,{sprite}\""),
    )
}

/// Both experiments get identical offline assets and a deliberately script-free CSP.
pub fn document(rendered_body: String) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
         img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\
         <title>Koi renderer experiment</title><style>{}\n{}\n\
         @media (prefers-reduced-motion: reduce) {{ {REDUCED_MOTION_CSS} }}</style></head>\
         <body>{rendered_body}</body></html>",
        include_str!("../assets/family-v1.css"),
        include_str!("../assets/spike.css"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::service::*;

    fn renderers() -> Vec<fn(View<'_>) -> String> {
        vec![
            #[cfg(feature = "maud-renderer")]
            maud_view::render,
            #[cfg(feature = "dioxus-renderer")]
            dioxus_view::render,
        ]
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
    fn hostile_catalog_text_and_id_cannot_become_markup() {
        for render in renderers() {
            let catalog = fixture(ServiceCondition::Found);
            let html = render(View::Snapshot(&catalog));
            assert!(!html.contains("<img src=x"));
            assert!(!html.contains("<script>"));
            assert!(!html.contains("svc_<script>"));
            let dom = scraper::Html::parse_document(&html);
            let name = dom
                .select(&scraper::Selector::parse(".service-row strong").unwrap())
                .next()
                .unwrap()
                .text()
                .collect::<String>();
            assert_eq!(name, catalog.services[0].alias.as_deref().unwrap());
            let row = dom
                .select(&scraper::Selector::parse(".service-row").unwrap())
                .next()
                .unwrap();
            assert_eq!(
                row.value().attr("data-service-id"),
                Some(catalog.services[0].id.as_str())
            );
            assert!(dom
                .select(&scraper::Selector::parse("script, [onerror]").unwrap())
                .next()
                .is_none());
        }
    }

    #[test]
    fn every_declared_condition_keeps_its_meaning() {
        for render in renderers() {
            for condition in [
                ServiceCondition::Starting,
                ServiceCondition::Found,
                ServiceCondition::Responding,
                ServiceCondition::NotResponding,
                ServiceCondition::Absent,
                ServiceCondition::Stale,
                ServiceCondition::Ambiguous,
            ] {
                let html = render(View::Snapshot(&fixture(condition)));
                assert!(html.contains(condition_label(condition)));
                if condition != ServiceCondition::Responding {
                    assert!(!html.contains(">Responding<"));
                }
            }
        }
    }

    #[test]
    fn absent_alias_uses_escaped_display_name_without_losing_text() {
        for render in renderers() {
            let mut catalog = fixture(ServiceCondition::Found);
            catalog.services[0].alias = None;
            let dom = scraper::Html::parse_document(&render(View::Snapshot(&catalog)));
            let selector = scraper::Selector::parse(".service-row strong").unwrap();
            assert_eq!(
                dom.select(&selector)
                    .next()
                    .unwrap()
                    .text()
                    .collect::<String>(),
                catalog.services[0].display_name
            );
            assert!(dom
                .select(&scraper::Selector::parse("script").unwrap())
                .next()
                .is_none());
        }
    }

    #[test]
    fn empty_unavailable_and_loading_are_distinct() {
        for render in renderers() {
            let empty = render(View::Snapshot(&CatalogSnapshot::default()));
            let unavailable = render(View::Unavailable);
            let loading = render(View::Loading);
            assert!(empty.contains("No services in this snapshot"));
            assert!(!unavailable.contains("No services in this snapshot"));
            assert!(unavailable.contains("Cannot read the local catalog"));
            assert!(loading.contains("Reading the local catalog"));
        }
    }

    #[test]
    fn one_row_no_privileged_or_placeholder_actions() {
        for render in renderers() {
            let mut catalog = fixture(ServiceCondition::Found);
            catalog.services.push(catalog.services[0].clone());
            let html = render(View::Snapshot(&catalog));
            assert_eq!(html.matches("class=\"service-row\"").count(), 1);
            assert!(!html.contains("<button"));
            assert!(!html.contains("<form"));
            assert!(!html.contains("<script"));
            assert!(html.contains("One-row experiment"));
        }
    }

    #[test]
    fn original_card_and_all_navigation_destinations_exist_offline() {
        for render in renderers() {
            let html = render(View::Loading);
            for (id, label) in NAVIGATION {
                assert!(html.contains(&format!("href=\"#{id}\"")));
                assert!(html.contains(&format!("id=\"{id}\"")));
                assert!(html.contains(label));
            }
            assert!(html.contains("data:image/png;base64,"));
            assert!(html.contains("It knows every stone"));
            assert!(!html.contains("src=\"koi.png\""));
        }
    }

    #[test]
    fn shared_schema_decoder_rejects_future_catalog() {
        let mut json = serde_json::to_value(CatalogSnapshot::default()).unwrap();
        json["schema"] = 999.into();
        assert!(serde_json::from_value::<CatalogSnapshot>(json).is_err());
    }
}
