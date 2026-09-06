use koi_common::service::Service;
use maud::{html, Markup};

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
