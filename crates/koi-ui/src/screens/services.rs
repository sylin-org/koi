use crate::catalog_view::{condition_label, display_name, endpoint_label, host_name};
use crate::{
    components::service_details, Destination, Links, ServiceFilter, ServiceSort, UiState, View,
};
use koi_common::service::{CatalogSnapshot, DiscoveryAvailability, Service};
use maud::{html, Markup};

pub fn render(view: View<'_>, state: &UiState, visible: &[&Service], links: Links<'_>) -> Markup {
    html! {
        section #services aria-labelledby="services-title" {
            div.page-heading {
                div {
                    h1 #services-title data-ui-heading tabindex="-1" { "Services" }
                    p { "Your applications, across your network." }
                }
                @if let View::Snapshot(catalog) = view {
                    p.snapshot-meta { (catalog.services.len()) " services · " (catalog.devices.len()) " hosts" }
                }
            }
            @match view {
                View::Loading => {
                    div.empty-state role="status" { h2 { "Reading the local catalog" } p { "Your services will appear here when the snapshot arrives." } }
                },
                View::Unavailable => {
                    div.empty-state role="status" { h2 { "Cannot read the local catalog" } p { "Check that Koi is running, then refresh to try again." } }
                },
                View::Snapshot(catalog) => {
                    (discovery_status(catalog.discovery, state))
                    (filters(catalog, state))
                    div class={ "catalog-layout" @if state.selected.is_some() { " has-details" } } {
                        div.catalog-list {
                            @if catalog.services.is_empty() {
                                div.empty-state role="status" {
                                    @if catalog.discovery == DiscoveryAvailability::Available {
                                        h2 { "No services found yet" }
                                    } @else {
                                        h2 { "No services in this snapshot" }
                                        p { "This is not proof that the network is empty; see the discovery status above." }
                                    }
                                    p { "Start an application with Koi container labels, or let Koi discover services on your network. Refresh to check again." }
                                }
                            } @else if visible.is_empty() {
                                div.empty-state role="status" {
                                    h2 { "No services match these filters" }
                                    p { "Try a different name, host or state." }
                                    a.button href=(UiState::default().href()) data-ui-link data-focus-key="clear-filters" { "Clear filters" }
                                }
                            } @else {
                                div.table-scroll {
                                    table.service-table {
                                        caption.sr-only { "Services in the current catalog snapshot. Select a name to inspect its endpoints and evidence." }
                                        thead { tr {
                                            th scope="col" { "Name" }
                                            th scope="col" { "Host" }
                                            th scope="col" { "Endpoint" }
                                            th scope="col" { "State" }
                                            th scope="col" { span.sr-only { "Action" } }
                                        } }
                                        tbody { @for service in visible { (row(catalog, service, state)) } }
                                    }
                                }
                            }
                            div.list-footer {
                                span { (visible.len()) " of " (catalog.services.len()) " services" }
                                span { "Snapshot revision " (catalog.revision) " · "
                                    time datetime=(catalog.generated_at.to_rfc3339()) { (catalog.generated_at.format("%H:%M:%S UTC")) }
                                }
                            }
                        }
                        @if let Some(service) = visible.iter().find(|service| Some(&service.id) == state.selected.as_ref()) {
                            (service_details::render(catalog, service, state, links))
                        }
                    }
                },
            }
        }
    }
}

/// Discovery health is reported by the catalog, never inferred from row counts
/// or from an empty search. The transport status line announces failures, so
/// this sentence is not a live region.
fn discovery_status(discovery: DiscoveryAvailability, state: &UiState) -> Markup {
    let (key, copy) = match discovery {
        DiscoveryAvailability::Unknown => (
            "unknown",
            "Discovery status not reported. An empty list is not proof that the network is empty.",
        ),
        DiscoveryAvailability::Available => (
            "available",
            "Discovery is observing the local network. A listed service is not proof that it is reachable.",
        ),
        DiscoveryAvailability::Partial => (
            "partial",
            "Discovery is partially unavailable; some services may be missing.",
        ),
        DiscoveryAvailability::Unavailable => (
            "unavailable",
            "Discovery is unavailable; services from saved or other sources may remain.",
        ),
    };
    let inspect = matches!(
        discovery,
        DiscoveryAvailability::Partial | DiscoveryAvailability::Unavailable
    );
    html! {
        p #discovery-status .discovery-status data-discovery=(key) {
            (copy)
            @if inspect {
                " "
                a href=(state.destination_href(Destination::Mdns)) data-ui-link data-ui-tab { "Inspect mDNS sources" }
            }
        }
    }
}

fn filters(catalog: &CatalogSnapshot, state: &UiState) -> Markup {
    let mut hosts: Vec<_> = catalog
        .services
        .iter()
        .map(|service| (&service.device_id, host_name(catalog, service)))
        .collect();
    hosts.sort_by_key(|(id, name)| (name.to_lowercase(), (*id).clone()));
    hosts.dedup_by(|a, b| a.0 == b.0);
    html! {
        div.catalog-toolbar {
            form method="get" data-ui-form {
                input type="hidden" name="tab" value="services";
                @if let Some(selected) = &state.selected { input type="hidden" name="selected" value=(selected.as_str()); }
                div.search-field {
                    label.sr-only for="service-search" { "Search services" }
                    input #service-search type="search" name="q" value=(&state.query) placeholder="Search services, hosts or endpoints" maxlength="256" autocomplete="off" data-focus-key="search";
                }
                div.filter-field {
                    label.sr-only for="host-filter" { "Host" }
                    select #host-filter name="host" data-focus-key="host-filter" {
                        option value="" selected[state.host.is_none()] { "All hosts" }
                        @if let Some(host) = &state.host {
                            @if !hosts.iter().any(|(id, _)| *id == host) { option value=(host.as_str()) selected { "Previous host (unavailable)" } }
                        }
                        @for (id, name) in hosts { option value=(id.as_str()) selected[state.host.as_ref() == Some(id)] { (name) } }
                    }
                }
                div.filter-field {
                    label.sr-only for="state-filter" { "State" }
                    select #state-filter name="state" data-focus-key="state-filter" {
                        @for filter in [ServiceFilter::All, ServiceFilter::Responding, ServiceFilter::Attention, ServiceFilter::Absent] {
                            option value=(filter.key()) selected[state.filter == filter] { (filter.label()) }
                        }
                    }
                }
                div.filter-field {
                    label.sr-only for="sort-order" { "Sort services" }
                    select #sort-order name="sort" data-focus-key="sort-order" {
                        @for sort in [ServiceSort::Name, ServiceSort::Host, ServiceSort::State] {
                            option value=(sort.key()) selected[state.sort == sort] { (sort.label()) }
                        }
                    }
                }
                button.button type="submit" data-focus-key="apply-filters" { "Apply" }
            }
        }
    }
}

fn row(catalog: &CatalogSnapshot, service: &Service, state: &UiState) -> Markup {
    let selected = state.selected.as_ref() == Some(&service.id);
    let href = state.selecting(Some(service.id.clone())).href();
    html! {
        tr.service-row data-service-id=(service.id.as_str()) data-condition=(condition_key(service.condition)) aria-selected=(if selected { "true" } else { "false" }) {
            td.service-name {
                a.name-link href=(&href) data-ui-link data-open-details data-focus-key=(format!("service:{}", service.id)) aria-expanded=(if selected { "true" } else { "false" }) {
                    @if service.favorite { span.star aria-label="Favorite" { "★" } }
                    strong { (display_name(service)) }
                    @if service.local_only { span.pill { "Local only" } }
                }
            }
            td.host-cell { span { (host_name(catalog, service)) } }
            td.endpoint-cell {
                @if let Some(endpoint) = service.endpoints.first() {
                    code { (endpoint_label(endpoint)) }
                    @if service.endpoints.len() > 1 { span.endpoint-count { "+" (service.endpoints.len() - 1) } }
                } @else { span.muted { "No current endpoint" } }
            }
            td.state-cell { span.status-badge data-condition=(condition_key(service.condition)) { (condition_label(service.condition)) } }
            td.action-cell {
                a.row-details href=(&href) data-ui-link data-open-details data-focus-key=(format!("details:{}", service.id))
                    aria-label=(format!("Details for {}", display_name(service))) aria-expanded=(if selected { "true" } else { "false" }) {
                    span aria-hidden="true" { "›" }
                }
            }
        }
    }
}

pub fn condition_key(condition: koi_common::service::ServiceCondition) -> &'static str {
    use koi_common::service::ServiceCondition::*;
    match condition {
        Starting => "starting",
        Found => "found",
        Responding => "responding",
        NotResponding => "not-responding",
        Absent => "absent",
        Stale => "stale",
        Ambiguous => "ambiguous",
    }
}
