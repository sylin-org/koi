//! Coherent automation inventory projected from one product status revision.
//!
//! Both the HTTP endpoint used by transport-backed MCP and the in-process MCP
//! source call this pure projector. It has no access to domain facades, so a
//! joined response cannot accidentally mix independently timed reads.

use koi_compose::status::KoiStatus;
use serde_json::{json, Value};

fn project_status(status: &KoiStatus, uptime_secs: u64, http_bind: &str, daemon: bool) -> Value {
    let capabilities: Vec<_> = status
        .capabilities
        .iter()
        .map(|capability| capability.status.clone())
        .collect();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "uptime_secs": uptime_secs,
        "revision": status.revision,
        "daemon": daemon,
        "http_bind": http_bind,
        "capabilities": capabilities,
        "catalog": &status.catalog,
        "mdns": &status.domains.mdns,
        "dns": &status.domains.dns,
    })
}

pub(crate) fn project(
    status: &KoiStatus,
    include: Option<&[String]>,
    uptime_secs: u64,
    http_bind: &str,
    daemon: bool,
) -> Result<Value, serde_json::Error> {
    let want = |source: &str| koi_mcp::inventory_includes(include, source);
    let unified = want("status").then(|| project_status(status, uptime_secs, http_bind, daemon));
    let health = if want("health") {
        status
            .domains
            .health
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
    } else {
        None
    };
    let dns = want("dns")
        .then(|| {
            status
                .domains
                .dns_catalog
                .as_ref()
                .map(|snapshot| json!({ "names": &snapshot.names }))
        })
        .flatten();
    Ok(json!({
        "status": unified,
        "health": health,
        "dns": dns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_status_projects_the_same_catalog_revision() {
        let status = KoiStatus {
            revision: 11,
            capabilities: Vec::new(),
            catalog: std::sync::Arc::new(koi_common::service::CatalogSnapshot {
                revision: 7,
                ..koi_common::service::CatalogSnapshot::default()
            }),
            domains: koi_compose::status::DomainStatuses::default(),
        };
        let value = project(&status, None, 5, "127.0.0.1:5641", true).unwrap();
        assert_eq!(value["status"]["revision"], 11);
        assert_eq!(value["status"]["catalog"]["revision"], 7);
    }
}
