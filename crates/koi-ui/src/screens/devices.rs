use crate::{
    components::{condition::device_label, service_row},
    devices::{self, Comparison, Reading},
    home::HomeQuery,
    View,
};
use koi_common::service::{DeviceCondition, KoiPresence, MeshIdentityState};
use maud::{html, Markup};

pub fn render(view: View<'_>, query: &HomeQuery<'_>, comparison: &Comparison) -> Markup {
    html! {
        section #devices aria-labelledby="devices-title" {
            h2 #devices-title { "Devices" }
            p { "Find a device, then choose one of its services." }
            @if let View::Snapshot(catalog) = view {
                p { "Counts include all services in this computer’s catalog snapshot, including retained unavailable services. Home filters do not apply here." }
                @if catalog.local_device_id.is_none() { p { "This snapshot does not identify the observing computer. Update Koi to identify this device." } }
                @if catalog.devices.is_empty() { p { "No devices in this snapshot" } }
                @let peers = devices::peers(catalog);
                @for device in devices::ordered(catalog) {
                    @let local = catalog.local_device_id.as_ref() == Some(&device.id);
                    @let services: Vec<_> = catalog.services.iter().filter(|service| service.device_id == device.id).collect();
                    details.device id=(format!("device-{}", device.id)) data-device-id=(device.id) {
                        summary id=(format!("device-toggle-{}", device.id)) {
                            strong { (devices::label(device)) }
                            " · " @if local { "This device" } @else { (device_label(device.condition)) }
                            " · " (services.len()) @if services.len() == 1 { " service in this snapshot" } @else { " services in this snapshot" }
                        }
                        @if !local { p { "Discovered or recorded here. Discovery does not prove reachability, enrollment or permission." } }
                        @match device.condition {
                            DeviceCondition::Stale | DeviceCondition::Absent => { p { "Unavailable or no longer observed. These are retained details; rediscover the device before using it." } },
                            DeviceCondition::Ambiguous => { p { "Device correlation is uncertain. Similar names or addresses have not been treated as proof of the same machine." } },
                            _ => {},
                        }
                        p {
                            @match &device.koi_presence {
                                KoiPresence::Absent => { "Koi presence not observed." },
                                KoiPresence::Observed => { "Koi presence observed; installation identity unknown." },
                                KoiPresence::Identified { .. } => { @if local { "Local Koi installation." } @else { "Koi installation identity advertised; not authenticated by discovery." } },
                            }
                            " "
                            @match device.mesh_identity.state {
                                MeshIdentityState::Member => { "Joined identity recorded in CertMesh." },
                                MeshIdentityState::Authenticated => { "CertMesh identity authenticated." },
                                MeshIdentityState::Unhealthy => { "CertMesh identity needs attention." },
                                _ => { "No joined CertMesh identity established by this evidence." },
                            }
                        }
                        @for name in device.names.iter().skip(1) { p { "Also observed as " (name.value) } }
                        @for address in &device.addresses { p { (address.address) } }
                        @if local { p { a href="#comparison" { "Compare what devices can see" } } }
                        @else if peers.iter().any(|peer| peer.id == device.id) {
                            p { a href=(devices::peer_href(&device.id)) { "Compare what devices can see" } }
                        } @else { p { "Comparison needs a current, unambiguous Koi discovery endpoint from this device." } }
                        h3 { "Hosted services" }
                        @if services.is_empty() { p { "No services associated with this device in this snapshot." } }
                        @for service in services { (service_row::launchpad(service, &HomeQuery::default())) }
                        details { summary { "Identity evidence" } p { "Device ID: " code { (device.id) } } }
                    }
                }
                section #comparison tabindex="-1" aria-labelledby="comparison-title" {
                    h2 #comparison-title { "Compare what devices can see" }
                    details { summary { "How comparison works" }
                    p { "Compare this computer’s mDNS announcements with a discovered Koi peer. The peer must permit the existing read-only discovery API at its advertised endpoint. No local token is sent to the peer." }
                    p { "Scope: each observer’s active mDNS .local queries. Interfaces and physical network equivalence are not reported. Results describe these snapshots, not reachability or complete network agreement." }
                    }
                    @if peers.is_empty() {
                        @if query.peer.is_some() { p role="status" { "Incomplete. The selected peer is unavailable. Reconnect it and refresh Devices before comparing again." } }
                        @else { p role="status" { "Not configured. Connect another Koi device and let discovery find it. No eligible peer is currently available." } }
                    } @else {
                        p { "Choose a device:" }
                        ul { @for peer in &peers { li { a href=(devices::peer_href(&peer.id)) aria-current=[(query.peer == Some(&peer.id)).then_some("true")] { (peer.label) } " · " (peer.endpoint) } } }
                        @if let Some(peer) = query.peer.and_then(|id| peers.iter().find(|peer| &peer.id == id)) {
                            p { "This device and " strong { (peer.label) } }
                            form action="/compare" method="post" data-comparison {
                                input type="hidden" name="peer" value=(peer.id);
                                button #compare-now type="submit" disabled[matches!(comparison, Comparison::Comparing | Comparison::Unsupported)] { @if matches!(comparison, Comparison::NotRun) { "Compare now" } @else { "Compare again" } }
                            }
                            (result(comparison))
                        } @else if query.peer.is_some() {
                            p role="status" { "Incomplete. The selected peer is no longer eligible. Choose a currently discovered device or reconnect it." }
                        } @else { p role="status" { "Not run. Choose a device to compare with this computer." } }
                    }
                }
            } @else {
                p { "Device information is unavailable until the catalog can be read." }
            }
        }
    }
}

fn evidence(reading: &Reading) -> Markup {
    html! {
        p { strong { (reading.observer) } " · received on this computer at " (reading.received_at) }
        @match &reading.result {
            Ok(snapshot) => { p { "Discovery revision " (snapshot.revision) "; " (snapshot.records.len()) " records; " (snapshot.sources.len()) " query routes reported." } },
            Err(reason) => { p { (reason) } },
        }
    }
}

fn result(comparison: &Comparison) -> Markup {
    html! {
        div role="status" aria-live="polite" {
            @match comparison {
                Comparison::Unsupported => { p { "Open the native Koi workbench to compare devices." } },
                Comparison::NotRun => { p { "Not run. Ready when you are." } },
                Comparison::Comparing => { p { "Comparing… Reading both observers." } },
                Comparison::Incomplete(reason) => { p { "Incomplete. " (reason) } },
                Comparison::Finished { local, peer } => {
                    (evidence(local)) (evidence(peer))
                    @if let (Ok(left), Ok(right)) = (&local.result, &peer.result) {
                        @match devices::compare(left, right) {
                            Ok(diff) => {
                                @if diff.is_empty() { h3 { "No differences in these snapshots" } }
                                @else { h3 { "Differences found" } }
                                p { (diff.same) " matching announcements; " (diff.changed.len()) " with changed endpoint or TXT details." }
                                @for (title, rows) in [("Only this device sees", &diff.only_local), ("Only the peer sees", &diff.only_peer), ("Different details", &diff.changed)] {
                                    @if !rows.is_empty() { h4 { (title) } ul { @for row in rows { li { (row) } } } }
                                }
                                details { summary { "Compared query scope" } ul { @for name in &diff.queries { li { (name) } } } }
                            },
                            Err(reason) => { p { "Incomplete. " (reason) } },
                        }
                    } @else { p { "Incomplete. Both observers must return readable snapshots. Check the reported read failure, then compare again." } }
                },
            }
        }
    }
}
