//! Per-host mDNS announce records, built once and shared by every boot path.
//!
//! The `_http._tcp` self-announcement is published by three callers — the foreground
//! daemon (`daemon_mode`), the Windows service (`run_service`), and `koi-embedded`. Each
//! used to hand-build the TXT map, and the Windows path had silently dropped the ADR-020
//! posture stamp (`posture=`/`fp=`/`expires=`), so a Windows node advertised itself as
//! Open even when it held a CA leaf — exactly the parity-defect class `koi-compose` exists
//! to prevent. [`crate::announce::http_record`] is the one body all three now call, so the stamp is present
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
/// `session` owns this process-derived record and provides fail-safe reaping if an explicit
/// withdrawal cannot settle during provider churn.
///
/// The trust stamp (`koi_common::peer::stamp`) writes the node's posture, CA fingerprint,
/// and leaf expiry so peers discovering it read the mesh's trust map directly (ADR-020 §8).
/// These are advisory hints; `verify`/mTLS adjudicates actual trust.
pub async fn http_record(
    cores: &Cores,
    session: &koi_mdns::RegistrationSession,
    hostname: &str,
    http_port: u16,
    dashboard_enabled: bool,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }
    let mdns = cores.mdns.as_ref()?;

    let mut txt = std::collections::HashMap::new();
    txt.insert("path".to_string(), "/".to_string());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("api".to_string(), "v1".to_string());
    txt.insert("dashboard".to_string(), dashboard_enabled.to_string());
    stamp_catalog_identity(&mut txt, cores, "http");

    // Stamp this node's trust posture so peers discovering it read the mesh's trust map
    // directly (ADR-020 §8). Advisory hints; verify/mTLS adjudicates actual trust.
    if let Some(ref certmesh) = cores.certmesh {
        let status = certmesh.status();
        let identity = status.identity.info.as_ref();
        koi_common::peer::stamp(
            &mut txt,
            status.posture,
            identity.map(|info| info.ca_fingerprint.as_str()),
            identity.map(|info| info.renewal.expires_at),
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
    match mdns
        .register_with_policy(
            payload,
            koi_mdns::LeasePolicy::Session {
                grace: std::time::Duration::ZERO,
            },
            Some(session.id().clone()),
        )
        .await
    {
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

/// Register this host's `_mcp._tcp` transport-discovery record and return the
/// mDNS registration id, or `None` when it was not published. The independent
/// in-zone DNS descriptor is owned by [`mcp_txt_lease`].
///
/// Publishes EXACTLY ONE `_mcp._tcp` record per host (never one per service, which would
/// flood the link). Unlike [`crate::announce::http_record`] it carries **no posture stamp** — the MCP endpoint
/// is transport-discovery, not trust-gated — so it does not need re-announcing on posture
/// flips. `enabled` folds the caller's gate (MCP transport mounted + HTTP on). Pair with
/// [`withdraw_mcp`] for a clean shutdown (the prior one-shot announce leaked the record).
/// The supplied registration session remains the fallback owner on every abnormal exit.
pub async fn mcp_record(
    cores: &Cores,
    session: &koi_mdns::RegistrationSession,
    hostname: &str,
    http_port: u16,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }

    // One `_mcp._tcp` record per host. TXT vocabulary matches what koi-mcp's own
    // `mcp_servers_on_lan` tool reads back (transport=/path=/name=).
    let mdns = cores.mdns.as_ref()?;
    let mut txt = std::collections::HashMap::new();
    txt.insert("transport".to_string(), "streamable-http".to_string());
    txt.insert("path".to_string(), "/v1/mcp".to_string());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi MCP ({hostname})"));
    stamp_catalog_identity(&mut txt, cores, "mcp");
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi MCP ({hostname})"),
        service_type: "_mcp._tcp".to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns
        .register_with_policy(
            payload,
            koi_mdns::LeasePolicy::Session {
                grace: std::time::Duration::ZERO,
            },
            Some(session.id().clone()),
        )
        .await
    {
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

/// Publish the process-derived in-zone MCP descriptor under synchronous lease
/// ownership. Aborting its supervisor drops the lease and removes exactly this
/// value without disturbing another TXT value at the same owner name.
pub fn mcp_txt_lease(
    cores: &Cores,
    hostname: &str,
    dns_zone: &str,
    enabled: bool,
) -> Option<koi_dns::DnsTxtLease> {
    if !enabled {
        return None;
    }
    let dns = cores.dns.as_ref()?;
    let name = mcp_dns_name(hostname, dns_zone);
    let lease = dns.publish_txt(&name, "transport=streamable-http;path=/v1/mcp");
    tracing::debug!(name = %name, "published in-zone MCP TXT descriptor");
    Some(lease)
}

/// Withdraw the `_mcp._tcp` mDNS record. The in-zone TXT has its own
/// [`koi_dns::DnsTxtLease`] and is removed when its supervisor exits on every
/// graceful, panic, and abort path.
pub async fn withdraw_mcp(cores: &Cores, mcp_id: Option<&str>) {
    if let (Some(id), Some(mdns)) = (mcp_id, cores.mdns.as_ref()) {
        if let Err(e) = mdns.unregister(id).await {
            tracing::debug!(error = %e, "failed to withdraw _mcp._tcp announce");
        }
    }
}

/// The in-zone unicast DNS name for the MCP descriptor.
fn mcp_dns_name(hostname: &str, zone: &str) -> String {
    format!("_mcp.{hostname}.{zone}")
}

fn stamp_catalog_identity(
    txt: &mut std::collections::HashMap<String, String>,
    cores: &Cores,
    role: &str,
) {
    let (installation_id, service_id) = cores.system_status.catalog_identity(role);
    txt.insert(
        koi_common::service::INSTALLATION_ID_TXT_KEY.to_string(),
        installation_id.to_string(),
    );
    txt.insert(
        koi_common::service::SERVICE_ID_TXT_KEY.to_string(),
        service_id.to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koi_owned_advertisements_get_stable_distinct_catalog_identity() {
        let cores = Cores::default();
        let mut http = std::collections::HashMap::new();
        let mut mcp = std::collections::HashMap::new();
        stamp_catalog_identity(&mut http, &cores, "http");
        stamp_catalog_identity(&mut mcp, &cores, "mcp");
        assert_eq!(
            http[koi_common::service::INSTALLATION_ID_TXT_KEY],
            mcp[koi_common::service::INSTALLATION_ID_TXT_KEY]
        );
        assert_ne!(
            http[koi_common::service::SERVICE_ID_TXT_KEY],
            mcp[koi_common::service::SERVICE_ID_TXT_KEY]
        );
    }
}
