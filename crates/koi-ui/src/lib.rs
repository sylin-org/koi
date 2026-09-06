//! Pure shared presentation. Transport, credentials and domain state stay outside.
pub mod components;
pub mod home;
pub mod screens;

pub use koi_common::service::CatalogSnapshot;
use maud::{html, PreEscaped};

/// Native adapters may apply these same rules when their webview ignores media queries.
pub const REDUCED_MOTION_CSS: &str = include_str!("../assets/reduced-motion.css");
pub const DOCUMENT_CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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
    pub advanced: &'a str,
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
    html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "Koi" }
                style { (PreEscaped(stylesheet())) }
            }
            body { (PreEscaped(fragment(view, links))) }
        }
    }
    .into_string()
}

/// The browser transport only inserts this output; it does not interpret the DTO.
pub fn fragment(view: View<'_>, links: Links<'_>) -> String {
    html! {
        (components::navigation::render())
        main #content tabindex="-1" {
            div.toolbar {
                @if let Some(refresh) = links.refresh {
                    a.button href=(refresh) { "Refresh snapshot" }
                }
                a.button href=(links.advanced) { "Advanced tools" }
            }
            (screens::home::render(view))
            (screens::devices::render(view))
            (screens::settings::render(view, links))
            (screens::about::render())
        }
    }
    .into_string()
}
