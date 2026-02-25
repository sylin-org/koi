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

/// Format a firewall rule name: `"{prefix} {port.name} ({PROTO} {port})"`.
pub fn firewall_rule_name(prefix: &str, port: &FirewallPort) -> String {
    format!(
        "{} {} ({} {})",
        prefix,
        port.name,
        port.protocol.as_str(),
        port.port
    )
}

/// Best-effort ensure that Windows Firewall inbound-allow rules exist for
/// every port in the list.  Rules are **port-based** (not program-scoped) so
/// they work regardless of which exe path is running.
///
/// * Idempotent – deletes then recreates each rule.
/// * Non-fatal  – logs warnings but never panics or returns errors.
/// * No-op on non-Windows platforms.
///
/// Returns the number of rules successfully created.
#[cfg(windows)]
pub fn ensure_firewall_rules(prefix: &str, ports: &[FirewallPort]) -> usize {
    use std::collections::HashSet;
    use std::process::Command;

    // Deduplicate by (protocol, port)
    let mut seen = HashSet::new();
    let unique: Vec<_> = ports
        .iter()
        .filter(|p| seen.insert((p.protocol, p.port)))
        .collect();

    let mut ok_count = 0usize;

    for port in &unique {
        let rule_name = firewall_rule_name(prefix, port);

        // Delete first for idempotency (ignore errors – rule may not exist)
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule"])
            .arg(format!("name={rule_name}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let result = Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule"])
            .arg(format!("name={rule_name}"))
            .args(["dir=in", "action=allow"])
            .arg(format!("protocol={}", port.protocol.as_str()))
            .arg(format!("localport={}", port.port))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        match result {
            Ok(status) if status.success() => {
                tracing::info!(
                    rule = %rule_name,
                    "Firewall rule ensured"
                );
                ok_count += 1;
            }
            Ok(status) => {
                tracing::warn!(
                    rule = %rule_name,
                    exit_code = ?status.code(),
                    "Could not create firewall rule (not elevated?)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    rule = %rule_name,
                    error = %e,
                    "Failed to run netsh"
                );
            }
        }
    }

    ok_count
}

/// No-op on non-Windows platforms – always returns 0.
#[cfg(not(windows))]
pub fn ensure_firewall_rules(_prefix: &str, _ports: &[FirewallPort]) -> usize {
    0
}
