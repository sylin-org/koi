//! Prometheus HTTP service discovery — `GET /v1/sd/prometheus`.
//!
//! Implements Prometheus' [`http_sd`] contract (verified against Prometheus 3.12;
//! `http_sd` has existed since 2.28): respond **200** with
//! `Content-Type: application/json`, body is a JSON array of *target groups*
//! `{"targets": ["host:port", …], "labels": {…}}`. An empty result is `[]`, and the
//! full target list is returned on every poll (Prometheus does not diff).
//!
//! Charter principle 10 (collaboration): this is *their* format. A user points
//! Prometheus at Koi with no Koi-specific config on the Prometheus side — see
//! `docs/guides/integrations.md`.
//!
//! ## Slices
//!
//! - **Default = Koi-managed**: health-checked services + runtime instances with a
//!   published port. These are the services the operator told Koi about.
//! - `?include=discovered` **also** adds LAN-discovered `_http._tcp` mDNS records.
//!
//! The differentiator label is `__meta_koi_cert_expiry_days`: the days until a
//! certmesh member certificate expires, matched to a target by name/hostname. No
//! other LAN SD source carries this — it lets Prometheus alert on expiring mesh
//! certs with a single relabel rule.
//!
//! [`http_sd`]: https://prometheus.io/docs/prometheus/latest/http_sd/

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use koi_common::integration::MemberSummary;
use koi_common::types::ServiceRecord;
use koi_compose::status::KoiStatus;
use koi_health::{ServiceHealth, ServiceStatus};
use koi_runtime::Instance;

/// One Prometheus target group: a set of `host:port` targets sharing a label set.
///
/// Serialized exactly as Prometheus' `http_sd` expects (a flat object with
/// `targets` and `labels`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TargetGroup {
    pub targets: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// Whether to include LAN-discovered (not Koi-managed) services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slice {
    /// Koi-managed only (health checks + runtime instances). The default.
    Managed,
    /// Koi-managed plus discovered mDNS `_http._tcp` records.
    WithDiscovered,
}

impl Slice {
    /// Parse the `?include=` query value. `include=discovered` opts into the wider
    /// slice; anything else (absent, empty, unknown) stays on the managed slice.
    pub fn from_query(include: Option<&str>) -> Self {
        match include {
            Some(v) if v.eq_ignore_ascii_case("discovered") => Slice::WithDiscovered,
            _ => Slice::Managed,
        }
    }
}

const LABEL_NAME: &str = "__meta_koi_name";
const LABEL_SOURCE: &str = "__meta_koi_source";
const LABEL_SERVICE_TYPE: &str = "__meta_koi_service_type";
const LABEL_HEALTH: &str = "__meta_koi_health";
const LABEL_CERT_EXPIRY_DAYS: &str = "__meta_koi_cert_expiry_days";

/// Build the full list of Prometheus target groups from one accepted product snapshot.
///
/// Pure function (no I/O, no locks) so it is unit-testable without standing up a
/// daemon. The caller obtains exactly one [`KoiStatus`] `Arc`; this adapter never
/// rereads individual cores or reconstructs a cross-domain view.
///
/// - Health targets come from `status.domains.health.services`.
/// - Runtime targets come from `status.domains.runtime.instances`.
/// - Certificate labels come from `status.domains.certmesh_roster.active_members`;
///   Certmesh has already decided membership semantics and normalized expiry.
/// - Discovered targets come from `status.domains.mdns_discovery.records` and are
///   included only when `slice == WithDiscovered`.
/// - `now` — injected so the cert-expiry math is deterministic in tests.
pub fn build_target_groups(
    status: &KoiStatus,
    slice: Slice,
    now: DateTime<Utc>,
) -> Vec<TargetGroup> {
    let health = status
        .domains
        .health
        .as_ref()
        .map_or(&[][..], |snapshot| snapshot.services.as_slice());
    let instances = status
        .domains
        .runtime
        .as_ref()
        .map_or(&[][..], |snapshot| snapshot.instances.as_slice());
    let members = status
        .domains
        .certmesh_roster
        .as_ref()
        .map_or(&[][..], |snapshot| snapshot.active_members.as_slice());
    let discovered = status
        .domains
        .mdns_discovery
        .as_ref()
        .map_or(&[][..], |snapshot| snapshot.records.as_slice());

    build_target_groups_from_sources(health, instances, members, discovered, slice, now)
}

fn build_target_groups_from_sources(
    health: &[ServiceHealth],
    instances: &[Instance],
    members: &[MemberSummary],
    discovered: &[ServiceRecord],
    slice: Slice,
    now: DateTime<Utc>,
) -> Vec<TargetGroup> {
    let mut groups = Vec::new();

    // ── Health-checked services ──
    for svc in health {
        let Some(host_port) = host_port_from_target(&svc.target) else {
            continue; // No usable host:port — skip rather than emit a broken target.
        };
        let mut labels = base_labels(&svc.name, "health", None, Some(svc.status));
        attach_cert_expiry(&mut labels, &svc.name, members, now);
        groups.push(TargetGroup {
            targets: vec![host_port],
            labels,
        });
    }

    // ── Runtime instances with a published port ──
    for inst in instances {
        let Some(host_port) = host_port_from_instance(inst) else {
            continue; // No published host port — skip.
        };
        let name = inst
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| inst.name.clone());
        let service_type = inst.metadata.service_type.as_deref();
        let mut labels = base_labels(&name, "runtime", service_type, None);
        attach_cert_expiry(&mut labels, &name, members, now);
        groups.push(TargetGroup {
            targets: vec![host_port],
            labels,
        });
    }

    // ── Discovered mDNS `_http._tcp` (opt-in) ──
    if slice == Slice::WithDiscovered {
        for rec in discovered {
            if !is_http_tcp(&rec.service_type) {
                continue;
            }
            let Some(host_port) = host_port_from_record(rec) else {
                continue;
            };
            let mut labels = base_labels(&rec.name, "mdns", Some(&rec.service_type), None);
            attach_cert_expiry(&mut labels, &rec.name, members, now);
            groups.push(TargetGroup {
                targets: vec![host_port],
                labels,
            });
        }
    }

    groups
}

/// The label set every target shares. `status` maps to `__meta_koi_health`.
fn base_labels(
    name: &str,
    source: &str,
    service_type: Option<&str>,
    status: Option<ServiceStatus>,
) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_NAME.to_string(), name.to_string());
    labels.insert(LABEL_SOURCE.to_string(), source.to_string());
    if let Some(st) = service_type {
        labels.insert(LABEL_SERVICE_TYPE.to_string(), st.to_string());
    }
    if let Some(status) = status {
        labels.insert(LABEL_HEALTH.to_string(), health_str(status).to_string());
    }
    labels
}

/// Attach `__meta_koi_cert_expiry_days` when `name` matches a certmesh member that
/// has a known expiry. Match is case-insensitive on the full name or its first
/// DNS label (so `grafana` matches member `grafana.lan`). Omitted otherwise.
fn attach_cert_expiry(
    labels: &mut BTreeMap<String, String>,
    name: &str,
    members: &[MemberSummary],
    now: DateTime<Utc>,
) {
    let Some(expires) = members
        .iter()
        .find(|m| hostname_matches(&m.hostname, name))
        .and_then(|m| m.cert_expires)
    else {
        return;
    };
    let days = (expires - now).num_days();
    labels.insert(LABEL_CERT_EXPIRY_DAYS.to_string(), days.to_string());
}

/// Whether a certmesh member `hostname` refers to the service named `name`.
/// Matches the full name or the leading DNS label, case-insensitively.
fn hostname_matches(hostname: &str, name: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    let n = name.to_ascii_lowercase();
    if h == n {
        return true;
    }
    let h_label = h.split('.').next().unwrap_or(&h);
    let n_label = n.split('.').next().unwrap_or(&n);
    h_label == n_label && !h_label.is_empty()
}

fn health_str(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Up => "up",
        ServiceStatus::Down => "down",
        ServiceStatus::Unknown => "unknown",
    }
}

/// `_http._tcp` (optionally with a trailing `.local.` / `.`). Tolerant of the
/// trailing-dot forms mDNS records carry.
fn is_http_tcp(service_type: &str) -> bool {
    let t = service_type
        .trim_end_matches('.')
        .trim_end_matches(".local");
    t == "_http._tcp"
}

/// Extract a `host:port` from a health-check target, which is either an
/// `http(s)://host:port/...` URL or a bare `host:port` TCP target. Returns `None`
/// when no host:port can be recovered.
fn host_port_from_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
    {
        // Authority is up to the first '/', '?', or '#'.
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(rest)
            .trim_end_matches('.');
        let scheme_default = if trimmed.starts_with("https://") {
            443
        } else {
            80
        };
        return normalize_authority(authority, Some(scheme_default));
    }
    // Bare TCP target: must already be host:port.
    normalize_authority(trimmed.trim_end_matches('.'), None)
}

/// Normalize an authority (`host`, `host:port`, or `[v6]:port`) into `host:port`.
/// When no explicit port is present, `default_port` supplies one (used for URLs);
/// a bare host with no default yields `None`.
fn normalize_authority(authority: &str, default_port: Option<u16>) -> Option<String> {
    if authority.is_empty() {
        return None;
    }
    // Strip userinfo if present (user@host) — health URLs shouldn't carry it, but
    // be defensive.
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    // IPv6 literal: [::1]:port or [::1]
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, rest) = after_bracket.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        if let Some(port) = rest.strip_prefix(':') {
            if !port.is_empty() {
                return Some(format!("[{host}]:{port}"));
            }
        }
        let port = default_port?;
        return Some(format!("[{host}]:{port}"));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            Some(format!("{host}:{port}"))
        }
        _ => {
            // No port present.
            let port = default_port?;
            Some(format!("{authority}:{port}"))
        }
    }
}

/// Build `host:port` from a runtime instance: the first published host port and
/// a concrete address observed by Runtime. A wildcard bind without any observed
/// instance address is absence, not permission to invent a loopback target.
fn host_port_from_instance(inst: &Instance) -> Option<String> {
    let port = inst.ports.first()?;
    let host = pick_instance_host(&port.host_ip, inst)?;
    Some(format_host_port(host, port.host_port))
}

/// Choose a reachable host for a runtime target. A `0.0.0.0` / `::` / empty bind
/// means "all interfaces" — Prometheus needs a concrete address, so prefer the
/// first concrete instance address. If Runtime observed neither, there is no
/// truthful target to publish.
fn pick_instance_host<'a>(host_ip: &'a str, inst: &'a Instance) -> Option<&'a str> {
    if is_concrete_host(host_ip) {
        return Some(host_ip);
    }
    inst.ips
        .iter()
        .map(String::as_str)
        .find(|candidate| is_concrete_host(candidate))
}

fn is_concrete_host(host: &str) -> bool {
    let host = host.trim();
    !host.is_empty() && !matches!(host, "0.0.0.0" | "::" | "[::]")
}

fn format_host_port(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.starts_with('[') || !host.contains(':') {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}

/// Build `host:port` from an mDNS record. Prefer the resolved IP, fall back to the
/// host; require a port.
fn host_port_from_record(rec: &ServiceRecord) -> Option<String> {
    let port = rec.port?;
    let host = rec
        .ip
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(rec.host.as_deref())
        .map(|h| h.trim_end_matches('.'))
        .filter(|h| !h.is_empty())?;
    Some(format_host_port(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use koi_common::integration::{CertmeshRosterSnapshot, MdnsDiscoverySnapshot};
    use koi_common::types::ServiceCheckKind;
    use koi_compose::status::DomainStatuses;
    use koi_runtime::instance::PortProtocol;
    use koi_runtime::{InstanceState, KoiMetadata, PortMapping, RuntimeStatus};
    use std::collections::HashMap;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 15, 0, 0, 0).unwrap()
    }

    fn health_service(name: &str, target: &str, status: ServiceStatus) -> ServiceHealth {
        ServiceHealth {
            name: name.to_string(),
            kind: ServiceCheckKind::Http,
            target: target.to_string(),
            interval_secs: 30,
            timeout_secs: 5,
            status,
            last_checked: None,
            last_ok: None,
            message: None,
        }
    }

    fn instance(name: &str, ports: Vec<PortMapping>, ips: Vec<String>) -> Instance {
        Instance {
            id: format!("id-{name}"),
            name: name.to_string(),
            ports,
            ips,
            metadata: KoiMetadata::default(),
            backend: "docker".to_string(),
            state: InstanceState::Running,
            discovered_at: fixed_now(),
            image: None,
        }
    }

    fn tcp_port(host_port: u16, host_ip: &str) -> PortMapping {
        PortMapping {
            host_port,
            container_port: host_port,
            protocol: PortProtocol::Tcp,
            host_ip: host_ip.to_string(),
        }
    }

    fn member(hostname: &str, expires: Option<DateTime<Utc>>) -> MemberSummary {
        MemberSummary {
            hostname: hostname.to_string(),
            sans: vec![],
            cert_expires: expires,
            last_seen: None,
            status: "active".to_string(),
            proxy_entries: vec![],
        }
    }

    #[test]
    fn aggregate_projection_reads_every_source_from_one_revision() {
        let health = health_service(
            "health-only",
            "http://10.0.0.1:8001/health",
            ServiceStatus::Up,
        );
        let runtime = instance("runtime-only", vec![tcp_port(8002, "10.0.0.2")], Vec::new());
        let discovered = ServiceRecord {
            name: "mdns-only".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("mdns-only.local.".to_string()),
            ip: Some("10.0.0.3".to_string()),
            port: Some(8003),
            txt: HashMap::new(),
        };
        let expires = Utc.with_ymd_and_hms(2026, 7, 15, 0, 0, 0).unwrap();
        let status = KoiStatus {
            revision: 42,
            capabilities: Vec::new(),
            domains: DomainStatuses {
                health: Some(
                    koi_health::HealthSnapshot {
                        revision: 3,
                        running: true,
                        machines: Vec::new(),
                        services: vec![health],
                    }
                    .into(),
                ),
                runtime: Some(
                    RuntimeStatus {
                        revision: 5,
                        instances: vec![runtime],
                        instance_count: 1,
                        ..RuntimeStatus::default()
                    }
                    .into(),
                ),
                certmesh_roster: Some(
                    CertmeshRosterSnapshot {
                        revision: 7,
                        active_members: vec![member("health-only.lan", Some(expires))],
                    }
                    .into(),
                ),
                mdns_discovery: Some(
                    MdnsDiscoverySnapshot {
                        revision: 9,
                        service_types: vec!["_http._tcp".to_string()],
                        records: vec![discovered],
                    }
                    .into(),
                ),
                ..DomainStatuses::default()
            },
        };

        let groups = build_target_groups(&status, Slice::WithDiscovered, fixed_now());
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].targets, ["10.0.0.1:8001"]);
        assert_eq!(groups[0].labels[LABEL_SOURCE], "health");
        assert_eq!(groups[0].labels[LABEL_CERT_EXPIRY_DAYS], "30");
        assert_eq!(groups[1].targets, ["10.0.0.2:8002"]);
        assert_eq!(groups[1].labels[LABEL_SOURCE], "runtime");
        assert_eq!(groups[2].targets, ["10.0.0.3:8003"]);
        assert_eq!(groups[2].labels[LABEL_SOURCE], "mdns");
    }

    // ── Empty → [] ──

    #[test]
    fn empty_sources_yield_no_groups() {
        let groups =
            build_target_groups_from_sources(&[], &[], &[], &[], Slice::Managed, fixed_now());
        assert!(groups.is_empty());
        // And the empty array serializes to "[]".
        assert_eq!(serde_json::to_string(&groups).unwrap(), "[]");
    }

    // ── Health targets ──

    #[test]
    fn health_url_target_parses_host_port() {
        let svc = health_service("grafana", "http://10.0.0.5:3000/health", ServiceStatus::Up);
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].targets, vec!["10.0.0.5:3000"]);
        assert_eq!(groups[0].labels.get(LABEL_NAME).unwrap(), "grafana");
        assert_eq!(groups[0].labels.get(LABEL_SOURCE).unwrap(), "health");
        assert_eq!(groups[0].labels.get(LABEL_HEALTH).unwrap(), "up");
    }

    #[test]
    fn health_https_url_without_port_uses_443() {
        let svc = health_service("api", "https://api.lan/health", ServiceStatus::Down);
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["api.lan:443"]);
        assert_eq!(groups[0].labels.get(LABEL_HEALTH).unwrap(), "down");
    }

    #[test]
    fn health_bare_host_port_target() {
        let svc = health_service("db", "10.0.0.9:5432", ServiceStatus::Unknown);
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["10.0.0.9:5432"]);
        assert_eq!(groups[0].labels.get(LABEL_HEALTH).unwrap(), "unknown");
    }

    #[test]
    fn health_target_without_port_is_skipped() {
        // A bare hostname (no scheme, no port) cannot become a Prometheus target.
        let svc = health_service("bad", "just-a-host", ServiceStatus::Up);
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[], &[], Slice::Managed, fixed_now());
        assert!(groups.is_empty(), "groups: {groups:?}");
    }

    // ── Runtime instances ──

    #[test]
    fn runtime_instance_uses_first_published_port() {
        let inst = instance(
            "whoami",
            vec![tcp_port(8080, "192.168.1.10")],
            vec!["192.168.1.10".to_string()],
        );
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["192.168.1.10:8080"]);
        assert_eq!(groups[0].labels.get(LABEL_SOURCE).unwrap(), "runtime");
    }

    #[test]
    fn runtime_instance_zero_bind_falls_back_to_instance_ip() {
        let inst = instance(
            "svc",
            vec![tcp_port(9000, "0.0.0.0")],
            vec!["10.1.1.1".to_string()],
        );
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["10.1.1.1:9000"]);
    }

    #[test]
    fn runtime_wildcard_without_observed_address_is_omitted() {
        let inst = instance("svc", vec![tcp_port(9000, "0.0.0.0")], vec![]);
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert!(groups.is_empty(), "must not manufacture a loopback target");
    }

    #[test]
    fn runtime_wildcard_ignores_non_concrete_instance_addresses() {
        let inst = instance(
            "svc",
            vec![tcp_port(9000, "::")],
            vec![String::new(), "0.0.0.0".to_string(), "10.1.1.9".to_string()],
        );
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["10.1.1.9:9000"]);
    }

    #[test]
    fn runtime_ipv6_address_is_bracketed() {
        let inst = instance("svc", vec![tcp_port(9000, "2001:db8::5")], vec![]);
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["[2001:db8::5]:9000"]);
    }

    #[test]
    fn runtime_instance_without_ports_is_skipped() {
        let inst = instance("noports", vec![], vec!["10.1.1.1".to_string()]);
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert!(groups.is_empty());
    }

    #[test]
    fn runtime_instance_metadata_name_and_service_type_used() {
        let mut inst = instance("container-abc", vec![tcp_port(80, "127.0.0.1")], vec![]);
        inst.metadata.name = Some("My Web".to_string());
        inst.metadata.service_type = Some("_http._tcp".to_string());
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].labels.get(LABEL_NAME).unwrap(), "My Web");
        assert_eq!(
            groups[0].labels.get(LABEL_SERVICE_TYPE).unwrap(),
            "_http._tcp"
        );
    }

    // ── Discovered (opt-in) ──

    #[test]
    fn discovered_excluded_by_default() {
        let rec = ServiceRecord {
            name: "Printer".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("printer.local.".to_string()),
            ip: Some("10.0.0.50".to_string()),
            port: Some(631),
            txt: HashMap::new(),
        };
        let recs = std::slice::from_ref(&rec);
        let managed =
            build_target_groups_from_sources(&[], &[], &[], recs, Slice::Managed, fixed_now());
        assert!(managed.is_empty());

        let discovered = build_target_groups_from_sources(
            &[],
            &[],
            &[],
            recs,
            Slice::WithDiscovered,
            fixed_now(),
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].targets, vec!["10.0.0.50:631"]);
        assert_eq!(discovered[0].labels.get(LABEL_SOURCE).unwrap(), "mdns");
    }

    #[test]
    fn discovered_non_http_type_skipped() {
        let rec = ServiceRecord {
            name: "Database".to_string(),
            service_type: "_postgresql._tcp".to_string(),
            host: Some("db.local.".to_string()),
            ip: Some("10.0.0.51".to_string()),
            port: Some(5432),
            txt: HashMap::new(),
        };
        let groups = build_target_groups_from_sources(
            &[],
            &[],
            &[],
            &[rec],
            Slice::WithDiscovered,
            fixed_now(),
        );
        assert!(groups.is_empty());
    }

    // ── Cert expiry differentiator ──

    #[test]
    fn cert_expiry_days_attached_when_member_matches() {
        let svc = health_service("grafana", "http://grafana.lan:3000/", ServiceStatus::Up);
        let expires = Utc.with_ymd_and_hms(2026, 7, 15, 0, 0, 0).unwrap(); // +30 days
        let m = member("grafana.lan", Some(expires));
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[m], &[], Slice::Managed, fixed_now());
        assert_eq!(
            groups[0].labels.get(LABEL_CERT_EXPIRY_DAYS).unwrap(),
            "30",
            "labels: {:?}",
            groups[0].labels
        );
    }

    #[test]
    fn cert_expiry_omitted_when_no_member_matches() {
        let svc = health_service("lonely", "http://lonely.lan:80/", ServiceStatus::Up);
        let m = member("other.lan", Some(fixed_now()));
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[m], &[], Slice::Managed, fixed_now());
        assert!(!groups[0].labels.contains_key(LABEL_CERT_EXPIRY_DAYS));
    }

    #[test]
    fn cert_expiry_is_omitted_when_the_domain_has_no_expiry() {
        let svc = health_service("grafana", "http://grafana.lan:3000/", ServiceStatus::Up);
        let groups = build_target_groups_from_sources(
            &[svc],
            &[],
            &[member("grafana.lan", None)],
            &[],
            Slice::Managed,
            fixed_now(),
        );
        assert!(!groups[0].labels.contains_key(LABEL_CERT_EXPIRY_DAYS));
    }

    #[test]
    fn cert_expiry_matches_on_first_label() {
        // service named "grafana", member "grafana.lan" — should still match.
        let inst = instance("grafana", vec![tcp_port(3000, "127.0.0.1")], vec![]);
        let expires = Utc.with_ymd_and_hms(2026, 6, 25, 0, 0, 0).unwrap(); // +10 days
        let m = member("grafana.lan", Some(expires));
        let groups =
            build_target_groups_from_sources(&[], &[inst], &[m], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].labels.get(LABEL_CERT_EXPIRY_DAYS).unwrap(), "10");
    }

    // ── Slice parsing ──

    #[test]
    fn slice_from_query_parsing() {
        assert_eq!(Slice::from_query(None), Slice::Managed);
        assert_eq!(Slice::from_query(Some("")), Slice::Managed);
        assert_eq!(Slice::from_query(Some("managed")), Slice::Managed);
        assert_eq!(Slice::from_query(Some("discovered")), Slice::WithDiscovered);
        assert_eq!(Slice::from_query(Some("DISCOVERED")), Slice::WithDiscovered);
    }

    // ── IPv6 authority ──

    #[test]
    fn ipv6_url_target_keeps_brackets() {
        let svc = health_service("v6", "http://[::1]:8080/health", ServiceStatus::Up);
        let groups =
            build_target_groups_from_sources(&[svc], &[], &[], &[], Slice::Managed, fixed_now());
        assert_eq!(groups[0].targets, vec!["[::1]:8080"]);
    }
}
