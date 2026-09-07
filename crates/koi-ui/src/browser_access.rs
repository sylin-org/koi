//! Browser connection and native management presentation; no credential handling.
use koi_common::browser_access::{BrowserAccessStatus, BrowserInvitation};
use maud::{html, PreEscaped};

fn page(
    title: &str,
    content: maud::Markup,
    scripts: bool,
    status: Option<&BrowserAccessStatus>,
) -> String {
    html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style { (PreEscaped(crate::stylesheet())) }
                @if status.is_some() { script defer src="/web/status.js" {} }
                @if scripts {
                    script defer src="/ui/refresh.js" {}
                    script defer src="/ui/access.js" {}
                }
            }
            body { main #browser-access data-status=[status.map(|s| serde_json::to_string(s).expect("browser status serializes"))] { (content) } }
        }
    }
    .into_string()
}

pub fn connect_page(hostname: &str) -> String {
    page(
        "Connect with Koi",
        html! {
            section #connect-panel aria-labelledby="connect-title" {
                h1 #connect-title { "Koi on " (hostname) }
                p { "Connect this browser to find and open your services. This access cannot change Koi settings." }
                form #connect-form {
                    label for="browser-label" { "Name this browser" }
                    input #browser-label name="label" maxlength="80" value="My browser" autocomplete="off";
                    label { input #remember-browser type="checkbox"; " Remember this browser for 30 days" }
                    p { "Otherwise, access lasts for this tab, up to 12 hours." }
                    button type="submit" { "Connect" }
                }
                p #connect-help { "Open Koi on this computer and choose Open in browser, or scan a new code from Browser access." }
            }
            p #browser-status role="status" aria-live="polite" { "Checking your connection…" }
            button #disconnect-browser type="button" hidden { "Disconnect this browser" }
            div #operator-view {}
            noscript { "Connecting requires browser scripting. You can also use the Koi desktop app." }
        },
        true,
        None,
    )
}

/// Native adapter supplies all action targets; network data never becomes a form URL.
pub fn settings_page(
    status: &BrowserAccessStatus,
    invitation: Option<&BrowserInvitation>,
    qr_data: Option<&str>,
    message: Option<&str>,
) -> String {
    page(
        "Browser access · Koi",
        html! {
            a href="/" { "Back to Home" }
            h1 { "Browser access" }
            p { "Open Koi here, or connect a phone to view your services. Connected browsers cannot change Koi settings." }
            @if let Some(message) = message { p role="status" { (message) } }
            form method="post" action="/web/settings" {
                label { input type="checkbox" name="enabled" checked[status.settings.enabled]; " Allow browser access" }
                label { input type="checkbox" name="phone" checked[status.settings.phone]; " Allow private phone access with CertMesh" }
                button type="submit" { "Save" }
            }
            @if status.settings.enabled {
                form method="post" action="/web/open" { button { "Open in browser" } }
                @if status.phone_ready {
                    form method="post" action="/web/invite" { button { "Connect a device · show QR" } }
                }
            }
            @if let Some(reason) = &status.reason { p role="status" { (reason) } }
            @if status.settings.phone {
                p { "The phone must trust this computer's CertMesh issuer and resolve its name. Never bypass a certificate warning." }
                @if let Some(port) = status.phone_port { p { "Private HTTPS port: " (port) ". Host firewall rules are not changed automatically." } }
            }
            @if let Some(invitation) = invitation {
                section aria-label="Connect a device" {
                    h2 { "Open Koi on your phone" }
                    p { "Scan, then tap Connect. This code works once and expires in two minutes." }
                    @if let Some(qr) = qr_data { img src=(qr) alt="One-use invitation QR code" width="280" height="280"; }
                    a href=(&invitation.url) { "Open invitation" }
                    p { "Keep this code private until the device connects." }
                    form method="post" action="/web/invite" { button { "Show a new code" } }
                }
            }
            h2 { "Connected browsers" }
            @if status.sessions.is_empty() { p { "No browsers connected yet." } }
            @for session in &status.sessions {
                article {
                    h3 { (&session.label) }
                    p { @if session.remembered { "Remembered browser" } @else { "Temporary access" } }
                    form method="post" action=(format!("/web/revoke/{}", session.id)) { button { "Disconnect" } }
                }
            }
            p { "Public, read-only Pond sharing is a separate setting in Advanced tools." }
        },
        false,
        Some(status),
    )
}

pub fn unavailable_page(message: &str) -> String {
    page(
        "Browser access · Koi",
        html! {
            a href="/" { "Back to Home" }
            h1 { "Cannot read browser access" }
            p role="alert" { (message) }
            a href="/web" { "Try again" }
        },
        false,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_names_are_text_and_waiting_access_never_offers_an_invitation() {
        let html = connect_page("<script>alert(1)</script>");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert"));
        let mut status = BrowserAccessStatus {
            schema: 1,
            settings: Default::default(),
            local_url: String::new(),
            phone_url: None,
            phone_port: Some(5645),
            phone_ready: false,
            reason: Some("Waiting for CertMesh".into()),
            sessions: vec![],
        };
        status.settings.enabled = true;
        status.settings.phone = true;
        let html = settings_page(&status, None, None, None);
        assert!(html.contains("Waiting for CertMesh"));
        assert!(html.contains("action=\"/web/open\""));
        assert!(!html.contains("action=\"/web/invite\""));
        status.phone_ready = true;
        assert!(settings_page(&status, None, None, None).contains("action=\"/web/invite\""));
    }
}
