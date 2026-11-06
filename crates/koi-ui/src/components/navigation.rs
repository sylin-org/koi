use crate::{Destination, EndpointActions, Links, UiState, View};
use base64::Engine as _;
use maud::{html, Markup};

pub const NAVIGATION: [(&str, &str); 5] = [
    ("services", "Services"),
    ("mdns", "mDNS"),
    ("private-space", "Certmesh"),
    ("settings", "Settings"),
    ("about", "About"),
];

pub fn render() -> Markup {
    render_with_state(
        &UiState::default(),
        Links {
            refresh: None,
            endpoint_actions: EndpointActions::None,
            preference_actions: false,
            operator_actions: crate::OperatorActions::None,
        },
    )
}

pub fn render_with_state(state: &UiState, links: Links<'_>) -> Markup {
    render_with_view(state, links, View::Loading)
}

pub fn render_with_view(state: &UiState, links: Links<'_>, view: View<'_>) -> Markup {
    let sprite =
        base64::engine::general_purpose::STANDARD.encode(include_bytes!("../../assets/koi.png"));
    html! {
        a.skip href="#content" { "Skip to content" }
        header.app-header {
            a.brand href=(state.destination_href(Destination::Services)) data-ui-link data-ui-tab data-focus-key="brand" aria-label="Koi services" {
                img src=(format!("data:image/png;base64,{sprite}")) alt="" width="32" height="32";
                span { "Koi" }
            }
            div.header-observation {
                @match view {
                    View::Snapshot(catalog) => {
                        span.observation-word { "Snapshot" }
                        span.observation-facts { (catalog.services.len()) " services · " (catalog.devices.len()) " hosts" }
                    },
                    View::Loading => { span.observation-word { "Reading catalog…" } },
                    View::Unavailable => { span.observation-word { "Catalog unavailable" } },
                }
            }
            div.shell-tools {
                @if let Some(refresh) = links.refresh {
                    a.button.chrome-button href=(format!("{refresh}?{}", state.query_string())) data-focus-key="refresh" { span { "Refresh" } }
                }
            }
            nav.main-nav aria-label="Main navigation" {
                @for destination in [Destination::Services, Destination::Mdns, Destination::PrivateSpace, Destination::Settings, Destination::About] {
                    a.nav-link href=(state.destination_href(destination)) data-ui-link data-ui-tab
                        data-focus-key=(format!("nav:{}", destination.key()))
                        aria-current=[(state.destination == destination).then_some("page")] {
                        span { (destination.label()) }
                    }
                }
            }
        }
    }
}
