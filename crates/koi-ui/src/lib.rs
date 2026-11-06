//! Pure shared presentation. Transport, credentials and domain state stay outside.
pub mod catalog_view;
pub mod components;
pub mod operator;
pub mod screens;
mod state;
pub use koi_common::mdns_browser::{BrowserSnapshot, MdnsQueryResult};
pub use operator::OperatorSnapshot;
pub use state::{Destination, ServiceFilter, ServiceSort, UiState};

pub use koi_common::service::CatalogSnapshot;
use maud::{html, PreEscaped};

/// Native adapters may apply these same rules when their webview ignores media queries.
pub const REDUCED_MOTION_CSS: &str = include_str!("../assets/reduced-motion.css");
/// Adapter-applied pointer presentation for the shared Sylin trading card.
/// The rendered document remains script-free; browser/native adapters opt in.
pub const CARD_EFFECT_SCRIPT: &str = include_str!("../assets/card-effect.js");
/// Shared behavior for the one operator presentation. Adapters provide the
/// bounded command bridge; this asset owns forms, feedback and native service
/// actions without owning domain state.
pub const INTERACTION_SCRIPT: &str = include_str!("../assets/interaction.js");
pub const MDNS_INTERACTION_SCRIPT: &str = include_str!("../assets/mdns-interaction.js");
pub const DOCUMENT_CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// A failed or pending read is never an empty authoritative catalog.
#[derive(Clone, Copy)]
pub enum View<'a> {
    Loading,
    Unavailable,
    Snapshot(&'a CatalogSnapshot),
}

/// Adapter-owned navigation targets, never derived from untrusted catalog values.
#[derive(Clone, Copy)]
pub struct Links<'a> {
    /// None when the outer transport owns a refresh control (authenticated browser).
    pub refresh: Option<&'a str>,
    /// Browser transport can offer explicit endpoint actions. Native remains
    /// action-free until its typed opener and clipboard bridge are verified.
    pub endpoint_actions: EndpointActions,
    /// Personal preference controls are available only through an authenticated,
    /// machine-local adapter with the preference routes mounted.
    pub preference_actions: bool,
    /// Which bounded operation bridge the adapter supplies to the shared UI.
    pub operator_actions: OperatorActions,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EndpointActions {
    #[default]
    None,
    /// Read-only presentations may follow validated HTTP(S) links without a
    /// clipboard or command adapter.
    OpenOnly,
    Browser,
    Native,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OperatorActions {
    #[default]
    None,
    Browser,
    Native,
}

pub fn stylesheet() -> String {
    format!(
        "{}\n{}\n@media (prefers-reduced-motion: reduce) {{ {REDUCED_MOTION_CSS} }}",
        include_str!("../assets/family-v1.css"),
        include_str!("../assets/shell.css")
    )
}

/// Render a complete, script-free document; all dynamic catalog text is escaped.
pub fn render(view: View<'_>, links: Links<'_>) -> String {
    render_with_operator_state(view, None, links, &UiState::default())
}

pub fn render_with_state(view: View<'_>, links: Links<'_>, state: &UiState) -> String {
    render_with_operator_state(view, None, links, state)
}

/// Render the canonical Koi presentation with one coherent operational
/// projection. Native, authenticated browser and restricted LAN adapters all
/// use this renderer; access differences change controls, not information
/// architecture or screen ownership.
pub fn render_with_operator_state(
    view: View<'_>,
    operator: Option<&OperatorSnapshot>,
    links: Links<'_>,
    state: &UiState,
) -> String {
    html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "Koi" }
                style { (PreEscaped(stylesheet())) }
            }
            body { (PreEscaped(fragment_with_operator_state(view, operator, links, state))) }
        }
    }
    .into_string()
}

/// The browser transport only inserts this output; it does not interpret the DTO.
pub fn fragment(view: View<'_>, links: Links<'_>) -> String {
    fragment_with_state(view, links, &UiState::default())
}

pub fn fragment_with_state(view: View<'_>, links: Links<'_>, state: &UiState) -> String {
    fragment_with_operator_state(view, None, links, state)
}

pub fn fragment_with_operator_state(
    view: View<'_>,
    operator: Option<&OperatorSnapshot>,
    links: Links<'_>,
    state: &UiState,
) -> String {
    let mut state = state.clone();
    let visible = match view {
        View::Snapshot(catalog) => state.services(catalog),
        _ => Vec::new(),
    };
    // Removed and filtered-out services cannot retain a detail pane.
    let selection_lost = state.selected.is_some()
        && !visible
            .iter()
            .any(|service| Some(&service.id) == state.selected.as_ref());
    if state.destination != Destination::Services || selection_lost {
        state.selected = None;
    }
    html! {
        div.app-shell data-ui-query=(state.query_string()) {
            (components::navigation::render_with_view(&state, links, view))
            main #content tabindex="-1" {
                @if selection_lost && state.destination == Destination::Services {
                    p.selection-notice role="status" { "The selected service is no longer in this view." }
                }
                @match state.destination {
                    Destination::Services => (screens::services::render(view, &state, &visible, links)),
                    Destination::Mdns => (screens::mdns::render(operator, &state, links)),
                    Destination::PrivateSpace => (screens::private_space::render(operator, links)),
                    Destination::Settings => (screens::settings::render(view, operator, links)),
                    Destination::About => (screens::about::render(view)),
                }
            }
        }
    }
    .into_string()
}
