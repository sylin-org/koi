use crate::{components::service_row, View};
use maud::{html, Markup};

pub fn render(view: View<'_>) -> Markup {
    html! {
        section #home aria-labelledby="home-title" {
            h1 #home-title { "Home" }
            p { "Services observed by Koi. Refresh to read the latest snapshot." }
            @match view {
                View::Loading => { p role="status" { "Reading the local catalog…" } },
                View::Unavailable => {
                    p role="alert" { "Cannot read the local catalog. Check the installed service, operator access and supported schema, then refresh." }
                },
                View::Snapshot(catalog) => {
                    p.snapshot-meta { "Snapshot revision " (catalog.revision) " · "
                        time datetime=(catalog.generated_at.to_rfc3339()) { (catalog.generated_at.to_rfc3339()) }
                    }
                    @if catalog.services.is_empty() {
                        p role="status" { "No services in this snapshot" }
                    }
                    div.service-list {
                        @for service in &catalog.services { (service_row::render(service)) }
                    }
                },
            }
        }
    }
}
