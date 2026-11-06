//! Inspection of the captured mDNS projection. Filters never issue network queries.
use crate::{Links, OperatorActions, OperatorSnapshot, UiState};
use koi_common::{
    integration::MdnsDiscoveryValue,
    mdns_browser::{BrowserSnapshot, ServiceInstance},
};
use maud::{html, Markup};

pub fn render(operator: Option<&OperatorSnapshot>, state: &UiState, links: Links<'_>) -> Markup {
    html! {
        section #mdns aria-labelledby="mdns-title" {
            div.page-heading { div {
                h1 #mdns-title data-ui-heading tabindex="-1" { "mDNS" }
                p { "Inspect what mDNS reports on your network." }
            } }
            (render_inspector(operator, state, links))
        }
    }
}

fn render_inspector(
    operator: Option<&OperatorSnapshot>,
    state: &UiState,
    links: Links<'_>,
) -> Markup {
    let Some(snapshot) = operator.and_then(|value| value.mdns.as_ref()) else {
        return html! { div.empty-state { h2 { "mDNS inspection is unavailable in this view" } p { "Use Koi on this machine or its authenticated browser connection to inspect network evidence and run queries." } } };
    };
    let needle = state.mdns_filter.trim().to_lowercase();
    let mut instances: Vec<_> = snapshot
        .instances
        .iter()
        .filter(|item| {
            (state.mdns_type.is_empty() || item.service_type == state.mdns_type)
                && (needle.is_empty()
                    || searchable(item).contains(&needle)
                    || snapshot
                        .discovery
                        .observations
                        .iter()
                        .filter_map(|observation| observation_record(&observation.value))
                        .any(|record| {
                            matches_instance(record, item)
                                && searchable_record(record).contains(&needle)
                        }))
        })
        .collect();
    instances.sort_by_key(|item| (&item.service_type, &item.name));
    html! {
        div #mdns-inspector data-mdns-revision=(snapshot.discovery.revision) {
            div.mdns-summary {
                p { strong { (snapshot.total_types) " reported types" } " · " (snapshot.total_instances) " current instances" }
                p data-mdns-live-status role="status" { @if snapshot.browse_active { "Browse active · view refreshes every 5 seconds" } @else { "Browse inactive · refresh or start discovery" } }
            }
            @if links.operator_actions != OperatorActions::None {
                details.mdns-queries data-mdns-detail="queries" {
                    summary #mdns-query-summary data-focus-key="mdns-query-summary" { "Query the network" }
                    p { "These actions send mDNS queries. Browse a service type, resolve a full instance name, or restart discovery of all reported types." }
                    div.mdns-query-forms {
                        form data-mdns-kind="browse" {
                            label for="mdns-browse-type" { "Service type to browse" }
                            input #mdns-browse-type name="value" required maxlength="253" placeholder="_ipp._tcp" autocomplete="off" data-focus-key="mdns-browse-type";
                            button.button #mdns-browse-submit type="submit" data-focus-key="mdns-browse-submit" { "Browse type" }
                        }
                        form data-mdns-kind="resolve" {
                            label for="mdns-resolve-name" { "Full instance name to resolve" }
                            input #mdns-resolve-name name="value" required maxlength="253" placeholder="Printer._ipp._tcp.local." autocomplete="off" data-focus-key="mdns-resolve-name";
                            button.button #mdns-resolve-submit type="submit" data-focus-key="mdns-resolve-submit" { "Resolve instance" }
                        }
                        form data-mdns-kind="requery" { button.button #mdns-requery-submit type="submit" data-focus-key="mdns-requery-submit" { "Restart discovery" } }
                    }
                }
                div #mdns-query-result role="status" aria-live="polite" {}
            }
            form.mdns-filters method="get" data-ui-form {
                input type="hidden" name="tab" value="mdns";
                label { "Filter this snapshot" input #mdns-filter type="search" name="mdns_filter" value=(&state.mdns_filter) placeholder="Name, address or TXT" maxlength="256" data-focus-key="mdns-filter"; }
                label { "Reported service type" select #mdns-type name="mdns_type" data-focus-key="mdns-type" {
                    option value="" selected[state.mdns_type.is_empty()] { "All types" }
                    @if !state.mdns_type.is_empty() && !snapshot.service_types.iter().any(|item| item.service_type == state.mdns_type) { option value=(&state.mdns_type) selected { (&state.mdns_type) " (no longer reported)" } }
                    @for item in &snapshot.service_types { option value=(&item.service_type) selected[state.mdns_type == item.service_type] { (&item.service_type) " · " (item.count) } }
                } }
                button.button #mdns-filter-submit type="submit" data-focus-key="mdns-filter-submit" { "Apply filters" }
            }
            div.mdns-records {
                @if instances.is_empty() { div.empty-state { h2 { "No matching instances" } p { "A reported type may have no resolved instances. Check the type list, adjust local filters, or query the network above." } } }
                @for item in &instances { (instance(item, snapshot)) }
            }
            div.list-footer { span { (instances.len()) " shown · includes recent removals" } span { "Discovery revision " (snapshot.discovery.revision) } }
            details.mdns-types data-mdns-detail="types" {
                summary #mdns-types-summary data-focus-key="mdns-types-summary" { "Reported types (" (snapshot.service_types.len()) ") · includes types with no instances" }
                @if snapshot.service_types.is_empty() { p { "No service types reported in this snapshot." } }
                @for item in &snapshot.service_types {
                    div.mdns-type-row {
                        a href=(UiState { mdns_type: item.service_type.clone(), ..state.clone() }.href()) data-ui-link data-focus-key=(format!("mdns-type:{}", item.service_type.to_ascii_lowercase())) { code { (&item.service_type) } }
                        span { (item.count) " current" }
                        span { (item.label.as_deref().unwrap_or("Unclassified type")) }
                        @if let Some(description) = &item.description { p { (description) } }
                    }
                }
            }
            details.mdns-evidence data-mdns-detail="sources" {
                summary #mdns-sources-summary data-focus-key="mdns-sources-summary" { "Browse sources and availability (" (snapshot.discovery.sources.len()) ")" }
                p { "Availability describes the provider route, not whether a service is reachable." }
                @for source in &snapshot.discovery.sources {
                    div.mdns-source { code { (&source.query) } span { (source.provider.as_deref().unwrap_or("Provider not reported")) } span { @if source.available { "Available" } @else { "Unavailable" } " · generation " (source.generation) } }
                }
                @for observation in &snapshot.discovery.observations {
                    @if let MdnsDiscoveryValue::ServiceType { service_type } = &observation.value {
                        div.mdns-source { code { (service_type) } span { (observation.source.provider.as_deref().unwrap_or("Provider not reported")) } span { "Reported via " (&observation.source.query) " · " @if observation.source.available { "Available" } @else { "Unavailable" } } }
                    }
                }
                @if snapshot.discovery.sources.is_empty() { p { "No browse source status reported." } }
            }
            details.mdns-evidence data-mdns-detail="timing" {
                summary #mdns-timing-summary data-focus-key="mdns-timing-summary" { "Observation timing and browse counters" }
                p { "First observed and last changed are browser projection times, not packet timestamps or service health. Recent removals are retained briefly; this is not a packet capture or a durable event log." }
                p { (snapshot.burst.bursts_sent) " browse bursts · " (snapshot.burst.answers_total) " answers · previous burst: " (snapshot.burst.last_burst_answers) " answers" }
                @if let Some(at) = &snapshot.burst.last_burst_at { p { "Last burst: " time datetime=(at) { (at) } } }
            }
        }
    }
}

fn searchable(item: &ServiceInstance) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        item.name,
        item.instance_name,
        item.service_type,
        item.host.as_deref().unwrap_or(""),
        item.ip.as_deref().unwrap_or(""),
        item.port.map(|p| p.to_string()).unwrap_or_default(),
        item.txt
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase()
}

fn observation_record(value: &MdnsDiscoveryValue) -> Option<&koi_common::types::ServiceRecord> {
    match value {
        MdnsDiscoveryValue::ServiceRecord { record }
        | MdnsDiscoveryValue::UnresolvedInstance { record } => Some(record),
        MdnsDiscoveryValue::ServiceType { .. } => None,
    }
}

fn matches_instance(record: &koi_common::types::ServiceRecord, item: &ServiceInstance) -> bool {
    let normalize_type = |value: &str| {
        value
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .trim_end_matches(".local")
            .to_owned()
    };
    record
        .name
        .trim_end_matches('.')
        .eq_ignore_ascii_case(item.instance_name.trim_end_matches('.'))
        && normalize_type(&record.service_type) == normalize_type(&item.service_type)
}

fn searchable_record(record: &koi_common::types::ServiceRecord) -> String {
    format!(
        "{} {} {} {} {} {}",
        record.name,
        record.service_type,
        record.host.as_deref().unwrap_or(""),
        record.ip.as_deref().unwrap_or(""),
        record.port.map(|port| port.to_string()).unwrap_or_default(),
        record
            .txt
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase()
}

fn instance(item: &ServiceInstance, snapshot: &BrowserSnapshot) -> Markup {
    let mut txt: Vec<_> = item.txt.iter().collect();
    txt.sort_by_key(|(key, _)| *key);
    html! {
        details.mdns-instance data-mdns-detail=(format!("instance:{}:{}", item.service_type, item.instance_name)) data-resolved=(item.resolved) data-removed=(item.removed_at.is_some()) {
            summary data-focus-key=(format!("mdns-instance:{}:{}", item.service_type.to_ascii_lowercase(), item.instance_name.to_ascii_lowercase())) {
                strong { (&item.name) }
                code { (&item.service_type) }
                span.mdns-endpoint {
                    code { (item.host.as_deref().or(item.ip.as_deref()).unwrap_or("Endpoint not reported")) @if let Some(port) = item.port { ":" (port) } }
                    @if item.host.is_some() { @if let Some(ip) = &item.ip { small { (ip) } } }
                }
                span { @if item.removed_at.is_some() { "Removed" } @else if item.resolved { "Resolved" } @else { "Unresolved" } }
            }
            div.mdns-record-body {
                dl.mdns-facts {
                    dt { "Reported instance name" } dd { code { (&item.instance_name) } }
                    dt { "Service type" } dd { code { (&item.service_type) } }
                    dt { "Host" } dd { code { (item.host.as_deref().unwrap_or("Not reported")) } }
                    dt { "IP address" } dd { code { (item.ip.as_deref().unwrap_or("Not reported")) } }
                    dt { "Port" } dd { @if let Some(port) = item.port { (port) } @else { "Not reported" } }
                    dt { "First observed" } dd { time datetime=(&item.first_seen) { (&item.first_seen) } }
                    dt { "Last changed / observed" } dd { time datetime=(&item.last_seen) { (&item.last_seen) } }
                    @if let Some(at) = &item.removed_at { dt { "Removal observed" } dd { time datetime=(at) { (at) } } }
                }
                h3 { "TXT records (" (txt.len()) ")" }
                @if txt.is_empty() { p { "No TXT values reported." } }
                dl.mdns-txt { @for (key, value) in txt { dt { code { (key) } } dd { code { (value) } } } }
                h3 { "Current source evidence" }
                @let observations = snapshot.discovery.observations.iter().filter(|observation| observation_record(&observation.value).is_some_and(|record| matches_instance(record, item))).collect::<Vec<_>>();
                @if observations.is_empty() { p { "No current source observation supplied for this instance." } }
                @for observation in observations {
                    div.mdns-source { code { (&observation.source.query) } span { (observation.source.provider.as_deref().unwrap_or("Provider not reported")) } span { @if observation.source.available { "Available" } @else { "Unavailable" } " · generation " (observation.source.generation) } }
                    @if let MdnsDiscoveryValue::ServiceRecord { record } | MdnsDiscoveryValue::UnresolvedInstance { record } = &observation.value {
                        (source_record(record))
                    }
                }
            }
        }
    }
}

fn source_record(record: &koi_common::types::ServiceRecord) -> Markup {
    let mut txt: Vec<_> = record.txt.iter().collect();
    txt.sort_by_key(|(key, _)| *key);
    html! {
        dl.mdns-facts {
            dt { "Reported name / type" } dd { code { (&record.name) " · " (&record.service_type) } }
            dt { "Reported endpoint" } dd { code { (record.host.as_deref().unwrap_or("Host not reported")) " · " (record.ip.as_deref().unwrap_or("IP not reported")) " · port " @if let Some(port) = record.port { (port) } @else { "not reported" } } }
            @for (key, value) in txt { dt { code { (key) } } dd { code { (value) } } }
        }
    }
}
