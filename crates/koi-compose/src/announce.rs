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
