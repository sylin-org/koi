use crate::{Links, View};
use maud::{html, Markup};

pub fn render(view: View<'_>, links: Links<'_>) -> Markup {
    html! {
        section #settings aria-labelledby="settings-title" {
            h2 #settings-title { "Settings" }
            p { "Favorites and friendly names are stored by the Koi service. This snapshot view does not change them." }
            @if let View::Snapshot(catalog) = view {
                p { (catalog.services.iter().filter(|service| service.favorite).count()) " favorites in this snapshot." }
            }
            p { "Use " a href=(links.advanced) { "Advanced tools" }
                " for existing controls and diagnostics. Desktop startup controls remain in its About view." }
            p { "Motion follows your system's reduced-motion preference." }
            p { "Upgrading from watched items? Open Advanced tools to run the existing import. Unmatched items stay there for review." }
        }
    }
}
