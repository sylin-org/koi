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
    /// CIDR prefix length of the interface's subnet.
    pub prefix_len: u8,
    /// Subnet-directed broadcast address, when the subnet has one (not /31 or /32).
    pub broadcast: Option<Ipv4Addr>,
}

/// Directed broadcast for `address/prefix_len`; `None` for /31 and /32, which
/// have no broadcast address.
fn directed_broadcast(address: Ipv4Addr, prefix_len: u8) -> Option<Ipv4Addr> {
    if prefix_len >= 31 {
        return None;
    }
    let host_bits = u32::MAX >> prefix_len;
    Some(Ipv4Addr::from(u32::from(address) | host_bits))
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
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_link_local() => Some(LanInterface {
                name: interface.name,
                address: v4.ip,
                prefix_len: v4.prefixlen,
                broadcast: directed_broadcast(v4.ip, v4.prefixlen),
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
    fn directed_broadcast_sets_host_bits() {
        let ip = Ipv4Addr::new(192, 168, 1, 37);
        assert_eq!(
            directed_broadcast(ip, 24),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            directed_broadcast(ip, 22),
            Some(Ipv4Addr::new(192, 168, 3, 255))
        );
        assert_eq!(directed_broadcast(ip, 31), None);
        assert_eq!(directed_broadcast(ip, 32), None);
    }

    #[test]
    fn observations_never_advertise_loopback_or_link_local() {
        for interface in lan_ipv4_interfaces().expect("enumerate host interfaces") {
            assert!(!interface.address.is_loopback());
            assert!(!interface.address.is_link_local());
        }
    }
}
