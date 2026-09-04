//! Host-network observations shared by serving adapters.
//!
//! This module observes routing and interfaces; it never changes them. Keeping the
//! observation here prevents presentation adapters from guessing independently.

use std::net::Ipv4Addr;

/// A LAN-routable IPv4 interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanInterface {
    pub name: String,
    pub address: Ipv4Addr,
}

/// Return the IPv4 interface the kernel selected for its default route. If the
/// host has no default route, fall back to every non-loopback, non-link-local
/// address. This keeps virtual bridges out of advertised cross-device URLs on
/// ordinary workstations without maintaining an OS-specific interface blacklist.
pub fn lan_ipv4_interfaces() -> std::io::Result<Vec<LanInterface>> {
    let all = if_addrs::get_if_addrs()?;
    let preferred = default_route_ipv4();
    let mut interfaces = all
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .filter_map(|interface| match interface.addr.ip() {
            std::net::IpAddr::V4(address) if !address.is_link_local() => Some(LanInterface {
                name: interface.name,
                address,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    if let Some(preferred) = preferred {
        if let Some(interface) = interfaces
            .iter()
            .find(|interface| interface.address == preferred)
            .cloned()
        {
            return Ok(vec![interface]);
        }
    }
    interfaces.sort_by_key(|interface| interface.address);
    interfaces.dedup_by_key(|interface| interface.address);
    Ok(interfaces)
}

/// Ask the kernel which IPv4 source address it would use for the default route.
/// Connecting a UDP socket performs route selection without sending a packet.
fn default_route_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_never_advertise_loopback_or_link_local() {
        for interface in lan_ipv4_interfaces().expect("enumerate host interfaces") {
            assert!(!interface.address.is_loopback());
            assert!(!interface.address.is_link_local());
        }
    }
}
