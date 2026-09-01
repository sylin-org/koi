//! Cooperative DNS socket acquisition.
//!
//! Koi first asks for the operator's exact bind. The default wildcard intent
//! may collide with a resolver bound only to a particular address (notably
//! systemd-resolved's stub). In that one case Koi serves every useful IPv4
//! address whose UDP+TCP pair it can own, without reconfiguring the incumbent.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::{TcpListener, UdpSocket};

use crate::resolver::DnsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingMode {
    Wildcard,
    Exact,
    Cooperative,
}

pub(crate) struct ListenerSet {
    pub udp: Vec<UdpSocket>,
    pub tcp: Vec<TcpListener>,
    pub endpoints: Vec<SocketAddr>,
    pub observation: BindingObservation,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub(crate) struct BindingObservation {
    mode: BindingMode,
    interfaces: Vec<Ipv4Addr>,
    bound_addresses: Vec<Ipv4Addr>,
    port: u16,
}

impl BindingObservation {
    /// A wildcard socket follows interface changes automatically. Cooperative
    /// per-address sockets need a reconciliation pass when that set changes.
    pub async fn changed(&self) -> bool {
        if self.mode != BindingMode::Cooperative {
            return false;
        }
        let current = useful_ipv4_addresses();
        if current != self.interfaces {
            return true;
        }
        // An address rejected during the previous pass may become available
        // without an interface change. Probe only those missing pairs; Koi's
        // live sockets remain untouched until a complete replacement is ready.
        for address in current {
            if !self.bound_addresses.contains(&address)
                && bind_pair_io(SocketAddr::new(IpAddr::V4(address), self.port))
                    .await
                    .is_ok()
            {
                return true;
            }
        }
        false
    }
}

pub(crate) async fn bind(bind_addr: IpAddr, port: u16) -> Result<ListenerSet, DnsError> {
    if !bind_addr.is_unspecified() {
        let (udp, tcp, endpoint) = bind_pair(SocketAddr::new(bind_addr, port)).await?;
        return Ok(ListenerSet {
            udp: vec![udp],
            tcp: vec![tcp],
            endpoints: vec![endpoint],
            observation: BindingObservation {
                mode: BindingMode::Exact,
                interfaces: Vec::new(),
                bound_addresses: Vec::new(),
                port: endpoint.port(),
            },
            reason: None,
        });
    }

    let wildcard = SocketAddr::new(bind_addr, port);
    match bind_pair_io(wildcard).await {
        Ok((udp, tcp, endpoint)) => Ok(ListenerSet {
            udp: vec![udp],
            tcp: vec![tcp],
            endpoints: vec![endpoint],
            observation: BindingObservation {
                mode: BindingMode::Wildcard,
                interfaces: Vec::new(),
                bound_addresses: Vec::new(),
                port: endpoint.port(),
            },
            reason: None,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            bind_cooperatively(port, error).await
        }
        Err(error) => Err(DnsError::Bind(format!("{wildcard}: {error}"))),
    }
}

async fn bind_cooperatively(
    port: u16,
    wildcard_error: std::io::Error,
) -> Result<ListenerSet, DnsError> {
    let interfaces = useful_ipv4_addresses();
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    let mut endpoints = Vec::new();
    let mut bound_addresses = Vec::new();
    let mut rejected = Vec::new();

    for address in &interfaces {
        let endpoint = SocketAddr::new(IpAddr::V4(*address), port);
        match bind_pair_io(endpoint).await {
            Ok((udp_socket, tcp_listener, bound)) => {
                udp.push(udp_socket);
                tcp.push(tcp_listener);
                endpoints.push(bound);
                bound_addresses.push(*address);
            }
            Err(error) => rejected.push(format!("{endpoint}: {error}")),
        }
    }

    if endpoints.is_empty() {
        let detail = if rejected.is_empty() {
            "no useful IPv4 addresses were found".to_string()
        } else {
            rejected.join("; ")
        };
        return Err(DnsError::Bind(format!(
            "wildcard {wildcard_error}; cooperative address set unavailable: {detail}"
        )));
    }

    Ok(ListenerSet {
        udp,
        tcp,
        endpoints,
        observation: BindingObservation {
            mode: BindingMode::Cooperative,
            interfaces,
            bound_addresses,
            port,
        },
        reason: Some(format!(
            "wildcard bind unavailable ({wildcard_error}); serving a cooperative address set"
        )),
    })
}

async fn bind_pair(addr: SocketAddr) -> Result<(UdpSocket, TcpListener, SocketAddr), DnsError> {
    bind_pair_io(addr)
        .await
        .map_err(|error| DnsError::Bind(format!("{addr}: {error}")))
}

async fn bind_pair_io(addr: SocketAddr) -> std::io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    // The UDP socket is deliberately exclusive. Port zero is resolved once
    // and the TCP listener is bound to that same kernel-selected port.
    let udp = UdpSocket::bind(addr).await?;
    let bound = udp.local_addr()?;
    let tcp = TcpListener::bind(bound).await?;
    Ok((udp, tcp, bound))
}

fn useful_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = BTreeSet::from([Ipv4Addr::LOCALHOST]);
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if let if_addrs::IfAddr::V4(v4) = interface.addr {
                if !v4.ip.is_unspecified() && !v4.ip.is_broadcast() {
                    addresses.insert(v4.ip);
                }
            }
        }
    }
    addresses.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_zero_is_one_real_udp_tcp_pair() {
        let listeners = bind(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).await.unwrap();
        assert_eq!(listeners.endpoints.len(), 1);
        assert_eq!(
            listeners.udp[0].local_addr().unwrap(),
            listeners.endpoints[0]
        );
        assert_eq!(
            listeners.tcp[0].local_addr().unwrap(),
            listeners.endpoints[0]
        );
    }

    #[tokio::test]
    async fn explicit_bind_never_falls_back_to_another_address() {
        let blocker = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = blocker.local_addr().unwrap().port();
        let error = bind(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            .await
            .err()
            .expect("exact collision must fail");
        assert!(matches!(error, DnsError::Bind(_)));
    }
}
