use koi_common::service::Service;
use maud::{html, Markup};

pub fn launchpad(service: &Service, query: &crate::home::HomeQuery<'_>) -> Markup {
    let selected = query.selected == Some(&service.id);
    html! {
        article.service-row data-service-id=(service.id) {
            a.service-select data-home-link href=(query.href(Some(&service.id))) aria-current=[selected.then_some("true")] {
                strong { (service.alias.as_deref().unwrap_or(&service.display_name)) }
            }
            span { (super::condition::service_label(service.condition)) }
            span { (crate::home::category(&service.kind)) }
            @if service.favorite { span { "Favorite" } }
            @if service.local_only { span { "Local only" } }
            @if let Some(destination) = service.endpoints.iter().find_map(|endpoint| crate::home::BrowserDestination::for_service(service, &endpoint.id)) {
                a.button data-external href=(destination.as_str()) rel="noreferrer noopener" { "Open" }
            } @else {
                a data-home-link href=(query.href(Some(&service.id))) { "Connection details" }
            }
        }
    }
}

pub fn render(service: &Service) -> Markup {
    html! {
        article.service-row data-service-id=(service.id) {
            strong { (service.alias.as_deref().unwrap_or(&service.display_name)) }
            span { (super::condition::service_label(service.condition)) }
            @if service.favorite { span { "Favorite" } }
            @if service.local_only { span { "Local only" } }
        }
    }
}
