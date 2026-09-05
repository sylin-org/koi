use crate::{condition_label, document, original_card, View, NAVIGATION};
use dioxus::prelude::*;

pub fn render(view: View<'_>) -> String {
    let content = match view {
        View::Loading => rsx! { p { role: "status", "Reading the local catalog…" } },
        View::Unavailable => {
            rsx! { p { role: "alert", "Cannot read the local catalog. Check the installed service and its supported schema." } }
        }
        View::Snapshot(catalog) => {
            let row = if let Some(service) = catalog.services.first() {
                let name = service.alias.as_deref().unwrap_or(&service.display_name);
                let condition = condition_label(service.condition);
                let id = service.id.as_str();
                rsx! {
                    article { class: "service-row", "data-service-id": "{id}",
                        strong { "{name}" }
                        span { "{condition}" }
                    }
                }
            } else {
                rsx! { p { role: "status", "No services in this snapshot" } }
            };
            rsx! { {row} p { "Snapshot revision {catalog.revision}" } }
        }
    };
    let card = original_card();
    document(dioxus_ssr::render_element(rsx! {
        a { class: "skip", href: "#home", "Skip to content" }
        header { class: "lampband",
            span { class: "lamp", "aria-hidden": "true", span { class: "lamp-core" } }
            span { class: "state-word", "Koi" }
            nav { "aria-label": "Primary",
                for (id, label) in NAVIGATION {
                    a { class: "tab", href: "#{id}", "{label}" }
                }
            }
        }
        main {
            section { id: "home", "aria-labelledby": "home-title",
                h1 { id: "home-title", "Home" }
                p { "One-row experiment — a snapshot, not a continuously monitored view." }
                {content}
            }
            section { id: "devices", h2 { "Devices" }
                p { "This experiment renders one service; the device journey belongs to R08." }
            }
            section { id: "settings", h2 { "Settings" }
                p { "Read-only renderer experiment. No settings are changed." }
            }
            section { id: "about", h2 { "About" }
                // The only raw insertion is the source-owned card; never catalog input.
                div { dangerous_inner_html: "{card}" }
            }
        }
    }))
}
