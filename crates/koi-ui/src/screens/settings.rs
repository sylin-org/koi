use crate::{Destination, Links, OperatorActions, OperatorSnapshot, UiState, View};
use maud::{html, Markup};

pub fn render(view: View<'_>, operator: Option<&OperatorSnapshot>, links: Links<'_>) -> Markup {
    let can_operate = links.operator_actions != OperatorActions::None;
    let native = links.operator_actions == OperatorActions::Native;
    html! {
        section #settings.secondary-page aria-labelledby="settings-title" {
            div.page-heading { div {
                span.eyebrow { "This installation" }
                h1 #settings-title data-ui-heading tabindex="-1" { "Settings" }
                p { "Service preferences, name resolution, LAN sharing and host integration." }
            } }
            p.operation-status role="status" aria-live="polite" {}
            section.action-strip {
                div {
                    h2 { "Favorites & friendly names" }
                    p { "Personal labels stay attached to a service identity through address changes." }
                    @if let View::Snapshot(catalog) = view {
                        p.settings-fact { (catalog.services.iter().filter(|service| service.favorite).count()) " favorites in this snapshot" }
                    }
                }
                a.button href=(UiState::default().destination_href(Destination::Services)) data-ui-link data-ui-tab { "View services" }
            }
            @if let Some(snapshot) = operator {
                div.task-grid {
                    (dns_card(snapshot, can_operate))
                    (pond_card(snapshot, can_operate))
                    @if native { (host_card(snapshot)) }
                }
                (capabilities(snapshot))
            } @else {
                section.empty-state {
                    h2 { "Installation status is unavailable" }
                    p { "Koi could not read the current operational snapshot. Existing configuration has not been changed." }
                }
            }
            section.settings-note {
                h2 { "Comfort & accessibility" }
                p { "Motion follows your system preference. Keyboard focus remains visible, and operational results are announced without moving you to another screen." }
            }
        }
    }
}

fn dns_card(snapshot: &OperatorSnapshot, can_operate: bool) -> Markup {
    html! { section.content-card {
        div.section-heading { div { h2 { "Names & DNS" }
            @if let Some(dns) = &snapshot.dns {
                p { (if dns.running { "Running" } else { "Stopped" }) " · " (dns.zone) " · port " (dns.port) }
            } @else { p { "DNS is not configured in this installation." } }
        } }
        @if let Some(dns) = &snapshot.dns {
            dl.detail-facts {
                dt { "Desired state" } dd { (if dns.desired { "Running" } else { "Stopped" }) }
                dt { "Records" } dd { (dns.records.static_entries) " static · " (dns.records.certmesh_entries) " Certmesh · " (dns.records.mdns_entries) " discovered" }
                @if !dns.endpoints.is_empty() { dt { "Listening on" } dd { (dns.endpoints.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")) } }
                @if let Some(reason) = &dns.reason { dt { "Status detail" } dd { (reason) } }
            }
            @if can_operate {
                form.operation-form.compact-form data-operator-action="dns_add" {
                    label { "Name" input name="name" placeholder="app.koi." autocomplete="off" required; }
                    label { "IP address" input name="ip" placeholder="192.168.1.20" autocomplete="off" required; }
                    label { "TTL seconds" input type="number" name="ttl" min="1" placeholder="60"; }
                    button.button type="submit" { "Add static name" }
                }
            }
            @if let Some(catalog) = &snapshot.dns_catalog {
                @if !catalog.entries.is_empty() {
                    div.compact-list {
                        @for entry in &catalog.entries {
                            div.compact-list-row { div { strong { (entry.name) } code { (entry.ip)
                                @if let Some(ttl) = entry.ttl { " · " (ttl) "s" } } }
                                @if can_operate { form.inline-operation data-operator-action="dns_remove" data-confirm=(format!("Remove {}?", entry.name)) {
                                    input type="hidden" name="name" value=(entry.name); button.link-button type="submit" { "Remove" } } }
                            }
                        }
                    }
                }
            }
        }
    } }
}

fn pond_card(snapshot: &OperatorSnapshot, can_operate: bool) -> Markup {
    let restricted =
        !can_operate && snapshot.pond.is_none() && snapshot.capability("pond").is_some();
    html! { section.content-card {
        div.section-heading { div { h2 { "LAN sharing" }
            @if let Some(pond) = &snapshot.pond { p { (if pond.running { "Available on your LAN" } else if pond.desired { "Waiting to become available" } else { "Off" }) } }
            @else if restricted { p { "You are viewing Koi through the read-only LAN interface." } }
            @else { p { "LAN sharing is unavailable in this installation." } }
        } }
        @if let Some(pond) = &snapshot.pond {
            dl.detail-facts {
                dt { "State" } dd { (format!("{:?}", pond.state)) }
                dt { "Firewall" } dd { (format!("{:?}", pond.firewall.state)) " · " (pond.firewall.detail) }
                @if let Some(url) = &pond.url { dt { "Address" } dd { code { (url) } } }
                @if let Some(reason) = &pond.reason { dt { "Status detail" } dd { (reason) } }
            }
            @if can_operate {
                button.button type="button" data-operator-action=(if pond.desired { "pond_disable" } else { "pond_enable" }) {
                    (if pond.desired { "Stop LAN sharing" } else { "Share on LAN" })
                }
            }
        }
    } }
}

fn host_card(snapshot: &OperatorSnapshot) -> Markup {
    html! { section.content-card {
        h2 { "Host integration" }
        @if let Some(host) = &snapshot.host {
            p { (if host.service_installed { if host.service_running { "Koi is running as the system service." } else { "The Koi service is installed but stopped." } } else { "Koi is running as a desktop-owned process or is currently offline." }) }
            @if let Some(detail) = &host.service_detail { p.info-note { (detail) } }
            div.button-row {
                @if host.service_installed {
                    button.button type="button" data-operator-action=(if host.service_running { "service_stop" } else { "service_start" }) { (if host.service_running { "Stop service" } else { "Start service" }) }
                } @else { button.button type="button" data-operator-action="daemon_run_once" { "Start for this session" } }
            }
            @if let Some(enabled) = host.autostart_enabled {
                form.inline-operation data-operator-action="autostart_set" {
                    input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
                    button.link-button type="submit" { (if enabled { "Disable desktop startup" } else { "Enable desktop startup" }) }
                }
            }
            @if let Some(detail) = &host.autostart_detail { p.muted { (detail) } }
        } @else { p { "Host controls will appear after the desktop adapter reads the installation." } }
    } }
}

fn capabilities(snapshot: &OperatorSnapshot) -> Markup {
    html! { section.capability-section {
        div.section-heading { div { h2 { "Capability status" } p { "The current daemon report, in this interface." } } }
        div.capability-grid {
            @for capability in &snapshot.capabilities {
                article.capability-row data-condition=(if capability.healthy { "healthy" } else { "warning" }) {
                    span.status-badge { (capability.name) } p { (capability.summary) }
                }
            }
        }
    } }
}
