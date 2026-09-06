use crate::{
    components::{condition::device_label, service_row},
    View,
};
use maud::{html, Markup};

pub fn render(view: View<'_>) -> Markup {
    html! {
        section #devices aria-labelledby="devices-title" {
            h2 #devices-title { "Devices" }
            p { "Devices host services. Presence does not prove reachability or permission." }
            @if let View::Snapshot(catalog) = view {
                @if catalog.devices.is_empty() { p { "No devices in this snapshot" } }
                @for device in &catalog.devices {
                    details.device data-device-id=(device.id) {
                        summary {
                            @if let Some(name) = device.names.first() { (name.value) }
                            @else { "Unnamed device" }
                            " · " (device_label(device.condition))
                        }
                        p { "Device ID: " code { (device.id) } }
                        @for address in &device.addresses { p { (address.address) } }
                        @for service in catalog.services.iter().filter(|service| service.device_id == device.id) {
                            (service_row::render(service))
                        }
                    }
                }
            } @else {
                p { "Device information is unavailable until the catalog can be read." }
            }
        }
    }
}
