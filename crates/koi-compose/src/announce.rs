//! Per-host mDNS announce records, built once and shared by every boot path.
//!
//! The `_http._tcp` self-announcement is published by three callers — the foreground
//! daemon (`daemon_mode`), the Windows service (`run_service`), and `koi-embedded`. Each
//! used to hand-build the TXT map, and the Windows path had silently dropped the ADR-020
//! posture stamp (`posture=`/`fp=`/`expires=`), so a Windows node advertised itself as
//! Open even when it held a CA leaf — exactly the parity-defect class `koi-compose` exists
//! to prevent. [`http_record`] is the one body all three now call, so the stamp is present
//! by construction.

use crate::cores::Cores;

/// Register this host's `_http._tcp` self-announcement (path `/`, the dashboard hint, and
/// the ADR-020 trust stamp) and return the mDNS registration id, or `None` when it was not
/// published.
///
/// `enabled` folds in the caller's gate (`--announce-http` + HTTP on); a `None` is returned
/// without touching mDNS when it is false, when mDNS is disabled, or when registration
/// fails. `dashboard_enabled` is the value the caller actually serves — the daemon and the
/// Windows service always host the dashboard (`true`); embedded passes its config flag.
///
/// The trust stamp (`koi_common::peer::stamp`) writes the node's posture, CA fingerprint,
/// and leaf expiry so peers discovering it read the mesh's trust map directly (ADR-020 §8).
/// These are advisory hints; `verify`/mTLS adjudicates actual trust.
pub async fn http_record(
    cores: &Cores,
    http_port: u16,
    dashboard_enabled: bool,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }
    let mdns = cores.mdns.as_ref()?;

    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let mut txt = std::collections::HashMap::new();
    txt.insert("path".to_string(), "/".to_string());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("api".to_string(), "v1".to_string());
    txt.insert("dashboard".to_string(), dashboard_enabled.to_string());

    // Stamp this node's trust posture so peers discovering it read the mesh's trust map
    // directly (ADR-020 §8). Advisory hints; verify/mTLS adjudicates actual trust.
    if let Some(ref certmesh) = cores.certmesh {
        let id = certmesh.local_identity().await;
        koi_common::peer::stamp(
            &mut txt,
            certmesh.posture(),
            id.as_ref().map(|i| i.ca_fingerprint.as_str()),
            id.as_ref().map(|i| i.renewal.expires_at),
        );
    }

    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi ({hostname})"),
        service_type: "_http._tcp".to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
        Ok(result) => {
            tracing::info!(
                id = %result.id,
                port = http_port,
                "HTTP server announced via mDNS"
            );
            Some(result.id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to announce HTTP server via mDNS");
            None
        }
    }
}

/// Register this host's `_mcp._tcp` transport-discovery record (plus the in-zone
/// `_mcp.<host>.<zone>` unicast DNS TXT when DNS serves the zone) and return the mDNS
/// registration id, or `None` when it was not published.
///
/// Publishes EXACTLY ONE `_mcp._tcp` record per host (never one per service, which would
/// flood the link). Unlike [`http_record`] it carries **no posture stamp** — the MCP endpoint
/// is transport-discovery, not trust-gated — so it does not need re-announcing on posture
/// flips. `enabled` folds the caller's gate (MCP transport mounted + HTTP on). Pair with
/// [`withdraw_mcp`] for a clean shutdown (the prior one-shot announce leaked the record).
pub async fn mcp_record(
    cores: &Cores,
    hostname: &str,
    http_port: u16,
    dns_zone: &str,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }

    // Unicast in-zone descriptor (only meaningful when DNS serves the zone).
    if let Some(ref dns) = cores.dns {
        let name = mcp_dns_name(hostname, dns_zone);
        dns.core()
            .add_txt(&name, "transport=streamable-http;path=/v1/mcp");
        tracing::debug!(name = %name, "published in-zone MCP TXT descriptor");
    }

    // One `_mcp._tcp` record per host. TXT vocabulary matches what koi-mcp's own
    // `mcp_servers_on_lan` tool reads back (transport=/path=/name=).
    let mdns = cores.mdns.as_ref()?;
    let mut txt = std::collections::HashMap::new();
    txt.insert("transport".to_string(), "streamable-http".to_string());
    txt.insert("path".to_string(), "/v1/mcp".to_string());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi MCP ({hostname})"));
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi MCP ({hostname})"),
        service_type: "_mcp._tcp".to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
        Ok(result) => {
            tracing::info!(id = %result.id, port = http_port, "MCP endpoint announced via mDNS (_mcp._tcp)");
            Some(result.id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to announce MCP endpoint via mDNS");
            None
        }
    }
}

/// Withdraw the `_mcp._tcp` mDNS record (by `mcp_id`) and remove the in-zone
/// `_mcp.<host>.<zone>` DNS TXT. `hostname` must be the one used at registration (the caller
/// captures it once) so the removed name matches even if the OS hostname changed mid-run.
/// Best-effort; safe to call when nothing was published.
pub fn withdraw_mcp(cores: &Cores, hostname: &str, dns_zone: &str, mcp_id: Option<&str>) {
    if let (Some(id), Some(mdns)) = (mcp_id, cores.mdns.as_ref()) {
        if let Err(e) = mdns.unregister(id) {
            tracing::debug!(error = %e, "failed to withdraw _mcp._tcp announce");
        }
    }
    if let Some(ref dns) = cores.dns {
        dns.core().remove_txt(&mcp_dns_name(hostname, dns_zone));
    }
}

/// This host's name for the announce records (`"unknown"` if it can't be read).
pub(crate) fn local_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The in-zone unicast DNS name for the MCP descriptor.
fn mcp_dns_name(hostname: &str, zone: &str) -> String {
    format!("_mcp.{hostname}.{zone}")
}
