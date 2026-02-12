/// Firewall port metadata reported by capability modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallPort {
    pub name: String,
    pub protocol: FirewallProtocol,
    pub port: u16,
}

impl FirewallPort {
    pub fn new(name: impl Into<String>, protocol: FirewallProtocol, port: u16) -> Self {
        Self {
            name: name.into(),
            protocol,
            port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallProtocol {
    Tcp,
    Udp,
}

impl FirewallProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            FirewallProtocol::Tcp => "TCP",
            FirewallProtocol::Udp => "UDP",
        }
    }
}
