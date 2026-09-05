use crate::{condition_label, document, original_card, View, NAVIGATION};
use maud::{html, PreEscaped};

pub fn render(view: View<'_>) -> String {
    document(html! {
        a.skip href="#home" { "Skip to content" }
        header.lampband {
            span.lamp aria-hidden="true" { span.lamp-core {} }
            span.state-word { "Koi" }
            nav aria-label="Primary" {
                @for (id, label) in NAVIGATION {
                    a.tab href=(format!("#{id}")) { (label) }
                }
            }
        }
        main {
            section #home aria-labelledby="home-title" {
                h1 #home-title { "Home" }
                p { "One-row experiment — a snapshot, not a continuously monitored view." }
                @match view {
                    View::Loading => { p role="status" { "Reading the local catalog…" } },
                    View::Unavailable => { p role="alert" { "Cannot read the local catalog. Check the installed service and its supported schema." } },
                    View::Snapshot(catalog) => {
                        @if let Some(service) = catalog.services.first() {
                            article.service-row data-service-id=(service.id) {
                                strong { (service.alias.as_deref().unwrap_or(&service.display_name)) }
                                span { (condition_label(service.condition)) }
                            }
                        } @else {
                            p role="status" { "No services in this snapshot" }
                        }
                        p { "Snapshot revision " (catalog.revision) }
                    }
                }
            }
            section #devices {
                h2 { "Devices" }
                p { "This experiment renders one service; the device journey belongs to R08." }
            }
            section #settings {
                h2 { "Settings" }
                p { "Read-only renderer experiment. No settings are changed." }
            }
            section #about {
                h2 { "About" }
                (PreEscaped(original_card()))
            }
        }
    }.into_string())
}
