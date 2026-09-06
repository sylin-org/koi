use crate::{
    components::{condition::service_label, service_row},
    home::{project, BrowserDestination, EmptyState, HomeQuery},
    View,
};
use koi_common::service::{CatalogSnapshot, DiscoveryAvailability, Service};
use maud::{html, Markup};

pub fn render(view: View<'_>, query: &HomeQuery<'_>) -> Markup {
    html! {
        section #home tabindex="-1" aria-labelledby="home-title" {
            h1 #home-title { "Home" }
            p { "Find a service by name, device, address or category." }
            p #open-status role="status" {}
            p #catalog-status role="status" { "Dated snapshot; automatic updates depend on the active adapter." }
            form #home-search action="?" method="get" role="search" {
                label for="service-search" { "Search services" }
                input #service-search type="search" name="search" value=(query.search) maxlength="1000";
                @if let Some(id) = query.selected { input type="hidden" name="selected" value=(id); }
                label { input type="checkbox" name="favorites" value="1" checked[query.favorites_only]; " Favorites only" }
                button type="submit" { "Search" }
                a data-home-link href=(HomeQuery::default().href(query.selected)) { "Clear filters" }
            }
            @match view {
                View::Loading => { p role="status" { "Reading the local catalog…" } },
                View::Unavailable => {
                    p role="alert" { "Cannot read the local catalog. Check the installed service, operator access and supported schema, then retry. This is not an empty discovery result." }
                },
                View::Snapshot(catalog) => {
                    p.snapshot-meta { "Snapshot revision " (catalog.revision) " · "
                        time datetime=(catalog.generated_at.to_rfc3339()) { (catalog.generated_at.to_rfc3339()) }
                    }
                    p #discovery-status role="status" {
                        @match catalog.discovery {
                            DiscoveryAvailability::Unknown => { "Local network discovery status is not reported. An empty list does not establish discovery health." },
                            DiscoveryAvailability::Available => { "Local network discovery is observing. This does not prove service reachability." },
                            DiscoveryAvailability::Partial => { "Local network discovery is partially unavailable. Some services may be missing; inspect source status in Advanced tools." },
                            DiscoveryAvailability::Unavailable => { "Local network discovery is unavailable. Saved or other-source services may remain; inspect source status in Advanced tools." },
                        }
                    }
                    @let projection = project(catalog, query);
                    div.home-layout {
                        div.home-results {
                            @if let Some(empty) = projection.empty {
                                p role="status" {
                                    @match empty {
                                        EmptyState::NoDiscoveries => {
                                            @if catalog.discovery == DiscoveryAvailability::Available {
                                                "No services discovered yet. Local network discovery is observing."
                                            } @else {
                                                "No services in this snapshot. See discovery status above; this is not proof that the network is empty."
                                            }
                                        },
                                        EmptyState::NoFavorites => { "No favorites yet. Manage favorites in Advanced tools." },
                                        EmptyState::NoMatches => { "No matches. Clear filters to see other services." },
                                    }
                                }
                            }
                            @if !projection.favorites.is_empty() {
                                h2 { "Favorites" }
                                div.service-list { @for service in projection.favorites { (service_row::launchpad(service, query)) } }
                            }
                            @if !projection.services.is_empty() {
                                h2 { "Services" }
                                div.service-list { @for service in projection.services { (service_row::launchpad(service, query)) } }
                            }
                            @if projection.attention_total > 0 {
                                aside.attention aria-label="Needs attention" {
                                    h2 { "Needs attention" }
                                    p { (projection.attention_total) " services; showing up to 5." }
                                    @for service in projection.attention {
                                        p {
                                            a data-home-link href=(query.href(Some(&service.id))) { (service.alias.as_deref().unwrap_or(&service.display_name)) }
                                            " · " (service_label(service.condition))
                                        }
                                    }
                                }
                            }
                        }
                        section #service-details tabindex="-1" aria-labelledby="details-title" {
                            h2 #details-title { "Service details" }
                            a data-home-link href=(query.href(None)) { "Back to services" }
                            @if let Some(service) = projection.selected { (details(catalog, service)) }
                            @else if projection.selection_missing { p role="status" { "The selected service is no longer in this snapshot. It has not been replaced by another service." } }
                            @else { p { "Select a service to inspect its destination and evidence." } }
                        }
                    }
                },
            }
        }
    }
}

fn details(catalog: &CatalogSnapshot, service: &Service) -> Markup {
    html! {
        h3 { (service.alias.as_deref().unwrap_or(&service.display_name)) }
        p { (service_label(service.condition)) " · " (crate::home::category(&service.kind)) }
        @if let Some(device) = catalog.devices.iter().find(|device| device.id == service.device_id) {
            @for name in &device.names { p { "Device: " (name.value) } }
            @for address in &device.addresses { p { "Address: " code { (address.address) } } }
        }
        @if let Some(last) = &service.last_known {
            p { "Last seen: " time datetime=(last.last_seen.to_rfc3339()) { (last.last_seen.to_rfc3339()) } }
        }
        @if service.endpoints.is_empty() { p { "No current endpoint. A saved favorite is not proof that the service is available." } }
        @for endpoint in &service.endpoints {
            @if let Some(destination) = BrowserDestination::for_service(service, &endpoint.id) {
                p { a.button data-external href=(destination.as_str()) rel="noreferrer noopener" { "Open " (destination.as_str()) } }
            } @else {
                p { "Connection endpoint: " code { (endpoint.scheme) "://" (endpoint.host) ":" (endpoint.port) (endpoint.path.as_deref().unwrap_or("")) } }
            }
            @for check in endpoint.reachability.iter().chain(&endpoint.client_tls) { (check_evidence(check)) }
        }
        p { "A discovered link does not prove reachability, permission or this client's TLS trust." }
        @if service.checks.is_empty() { p { "No service-level checks recorded." } }
        @for check in &service.checks { (check_evidence(check)) }
        details #service-technical-details {
            summary { "Technical details and sources" }
            p { "Service ID: " code { (service.id) } }
            p { "Device ID: " code { (service.device_id) } }
            @if service.observations.is_empty() { p { "No current source observations." } }
            @for observation in &service.observations {
                p { (observation.source) " · " (observation.provider) " · " (format!("{:?}", observation.state))
                    " · observed " time datetime=(observation.observed_at.to_rfc3339()) { (observation.observed_at.to_rfc3339()) }
                }
                dl { @for (key, value) in &observation.raw_reference { dt { (key) } dd { (value) } } }
            }
        }
    }
}

fn check_evidence(check: &koi_common::service::CheckEvidence) -> Markup {
    html! {
        p { (format!("{:?}: {:?}", check.kind, check.result)) " · checked by " (check.observer)
            " at " time datetime=(check.checked_at.to_rfc3339()) { (check.checked_at.to_rfc3339()) }
            " · " (check.reason_code)
            @if let Some(detail) = &check.detail { " · " (detail) }
        }
    }
}
