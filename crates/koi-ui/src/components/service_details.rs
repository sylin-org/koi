use crate::catalog_view::{
    check_kind_label, check_result_label, condition_label, display_name, endpoint_label,
    endpoint_open_url, host_name, observer_label,
};
use crate::{EndpointActions, Links, UiState};
use koi_common::service::{
    AvailableAction, CatalogSnapshot, CheckEvidence, Service, ServiceCondition, TransportEncryption,
};
use maud::{html, Markup};

pub fn render(
    catalog: &CatalogSnapshot,
    service: &Service,
    state: &UiState,
    links: Links<'_>,
) -> Markup {
    let endpoint_actions = links.endpoint_actions;
    let can_open = endpoint_actions != EndpointActions::None
        && service.available_actions.contains(&AvailableAction::Open);
    let can_copy = matches!(
        endpoint_actions,
        EndpointActions::Browser | EndpointActions::Native
    ) && service
        .available_actions
        .contains(&AvailableAction::CopyEndpoint);
    let can_favorite = links.preference_actions
        && service
            .available_actions
            .contains(&AvailableAction::Favorite);
    let can_alias = links.preference_actions
        && service
            .available_actions
            .contains(&AvailableAction::SetFriendlyAlias);
    html! {
        dialog #service-details .service-details open aria-labelledby="details-title" tabindex="-1" data-origin-key=(format!("service:{}", service.id)) {
            header.details-header {
                div {
                    span.eyebrow { "Service details" }
                    h2 #details-title data-ui-dialog-heading tabindex="-1" { (display_name(service)) }
                }
                a.icon-button.close-details href=(state.selecting(None).href()) data-ui-link data-restore-focus="origin" data-focus-key="close-details" aria-label="Close service details" { span aria-hidden="true" { "×" } }
            }
            div.details-body {
                section.detail-section {
                    h3 { "At a glance" }
                    dl.detail-facts {
                        dt { "Host" } dd { (host_name(catalog, service)) }
                        dt { "State" } dd { (condition_label(service.condition)) }
                    }
                    @if service.favorite { span.pill { "Favorite" } }
                    @if service.local_only { span.pill { "Local only" } }
                    @if can_favorite {
                        button.button.favorite-toggle type="button"
                            data-ui-favorite=(if service.favorite { "false" } else { "true" })
                            data-service-id=(service.id.as_str())
                            data-focus-key=(format!("favorite:{}", service.id))
                            aria-pressed=(if service.favorite { "true" } else { "false" }) {
                            @if service.favorite { "Remove favorite" } @else { "Add favorite" }
                        }
                    }
                    @if can_alias {
                        form.alias-form data-ui-alias-form data-service-id=(service.id.as_str()) {
                            label for="friendly-alias" { "Friendly name" }
                            div.alias-controls {
                                input #friendly-alias type="text" maxlength="160"
                                    value=(service.alias.as_deref().unwrap_or_default())
                                    placeholder=(service.display_name.as_str())
                                    data-ui-alias
                                    data-focus-key=(format!("alias:{}", service.id))
                                    aria-describedby="friendly-alias-help";
                                button.button type="submit" { "Save name" }
                            }
                            p #friendly-alias-help .muted { "Leave blank to use the discovered name." }
                        }
                    }
                    @if service.condition == ServiceCondition::Responding {
                        p.info-note { "A check from an observing Koi installation passed. See its type and target below; access from your browser has not been verified here." }
                    }
                    @if let Some(ambiguity) = &service.ambiguity {
                        p.info-note { (ambiguity.reason) }
                        @if !ambiguity.candidates.is_empty() { ul { @for candidate in &ambiguity.candidates { li { (candidate) } } } }
                    }
                    @if let Some(last) = &service.last_known {
                        p.muted { "Last seen " time datetime=(last.last_seen.to_rfc3339()) { (last.last_seen.format("%Y-%m-%d %H:%M:%S UTC")) } ". Saved context is not a current endpoint." }
                    }
                }
                section.detail-section {
                    h3 { "Endpoints" }
                    @if service.endpoints.is_empty() {
                        p.muted { "No current endpoint is supplied for this service." }
                    } @else {
                        ul.endpoint-list {
                            @for endpoint in &service.endpoints {
                                li {
                                    @let address = endpoint_label(endpoint);
                                    div.endpoint-heading {
                                        code { (&address) }
                                        @if can_open || can_copy {
                                            div.endpoint-actions {
                                                @if can_open {
                                                    @if let Some(target) = endpoint_open_url(endpoint) {
                                                        @if endpoint_actions == EndpointActions::Native {
                                                            button.button.endpoint-open type="button" data-operator-action="open_url" data-operator-url=(target)
                                                                aria-label=(format!("Open {address}")) { "Open" }
                                                        } @else {
                                                            a.button.endpoint-open href=(target) target="_blank" rel="noopener noreferrer"
                                                                aria-label=(format!("Open {address}")) { "Open" }
                                                        }
                                                    }
                                                }
                                                @if can_copy {
                                                    button.button.endpoint-copy type="button" data-ui-copy=(&address)
                                                        aria-label=(format!("Copy {address}")) { "Copy address" }
                                                }
                                            }
                                        }
                                    }
                                    dl.detail-facts {
                                        dt { "Endpoint ID" } dd { (endpoint.id.as_str()) }
                                        dt { "Transport" } dd {
                                            @match endpoint.transport_encryption {
                                                TransportEncryption::Tls => "TLS advertised; client trust not established",
                                                TransportEncryption::None => "Unencrypted",
                                                TransportEncryption::Unknown => "Unknown",
                                            }
                                        }
                                        @if let Some(name) = &endpoint.expected_service_name { dt { "Expected name" } dd { (name) } }
                                        @if let Some(scope) = &endpoint.network_scope {
                                            dt { "Network scope" } dd { (format!("{:?}", scope.classification)) }
                                            @if let Some(interface) = &scope.interface { dt { "Observing interface" } dd { (interface) } }
                                        }
                                    }
                                    @for check in endpoint.reachability.iter().chain(endpoint.client_tls.iter()) {
                                        @if !service.checks.contains(check) { (evidence(check, catalog)) }
                                    }
                                }
                            }
                        }
                    }
                }
                section.detail-section {
                    h3 { "Checks" }
                    @if service.checks.is_empty() { p.muted { "No service checks are available in this snapshot." } }
                    @for check in &service.checks { (evidence(check, catalog)) }
                }
                section.detail-section {
                    h3 { "Discovery evidence" }
                    @if service.observations.is_empty() { p.muted { "No discovery observations are available in this snapshot." } }
                    @for observation in &service.observations {
                        article.evidence-item {
                            h4 { (observation.provider) " · " (format!("{:?}", observation.state)) }
                            dl.detail-facts {
                                dt { "Source" } dd { (observation.source) }
                                dt { "Observer" } dd { (observer_label(observation.observer_installation_id.as_str())) }
                                dt { "Observed since" } dd { time datetime=(observation.observed_at.to_rfc3339()) { (observation.observed_at.format("%Y-%m-%d %H:%M:%S UTC")) } }
                                dt { "Valid until" } dd { time datetime=(observation.valid_until.to_rfc3339()) { (observation.valid_until.format("%Y-%m-%d %H:%M:%S UTC")) } }
                            }
                        }
                    }
                }
                details.identity-details {
                    summary { "Identity details" }
                    dl.detail-facts {
                        dt { "Service ID" } dd { code { (service.id.as_str()) } }
                        dt { "Host ID" } dd { code { (service.device_id.as_str()) } }
                        @if let Some(device) = catalog.devices.iter().find(|device| device.id == service.device_id) {
                            dt { "Observed host names" }
                            dd { @for name in &device.names { p { (name.value) } } }
                        }
                    }
                }
            }
        }
    }
}

fn evidence(check: &CheckEvidence, catalog: &CatalogSnapshot) -> Markup {
    html! {
        article.evidence-item {
            h4 { (check_kind_label(check.kind)) " · " (check_result_label(check.result)) }
            @if check.valid_until <= catalog.generated_at { p.info-note { "Expired at snapshot time" } }
            dl.detail-facts {
                dt { "Observer" } dd { (observer_label(&check.observer)) }
                dt { "Target" } dd { (check.target_endpoint_id.as_str()) }
                dt { "Checked" } dd { time datetime=(check.checked_at.to_rfc3339()) { (check.checked_at.format("%Y-%m-%d %H:%M:%S UTC")) } }
                dt { "Valid until" } dd { time datetime=(check.valid_until.to_rfc3339()) { (check.valid_until.format("%Y-%m-%d %H:%M:%S UTC")) } }
                dt { "Reason" } dd { (check.reason_code) }
                @if let Some(client) = &check.client_identity { dt { "Client" } dd { (client) } }
            }
            @if let Some(detail) = &check.detail { p { (detail) } }
        }
    }
}
