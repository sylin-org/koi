//! Normalized instance and metadata types.
//!
//! Every runtime backend converts its native types into these
//! runtime-agnostic representations.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A runtime-managed instance (container, VM, or service unit).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Instance {
    /// Unique identifier from the runtime (container ID, pod UID, unit name).
    pub id: String,
    /// Human-readable name (container name, pod name, unit description).
    pub name: String,
    /// Resolved host-side port mappings.
    pub ports: Vec<PortMapping>,
    /// IP addresses reachable from the host network (as strings for serde/OpenAPI).
    pub ips: Vec<String>,
    /// Koi-specific metadata extracted from labels/annotations/config.
    pub metadata: KoiMetadata,
    /// Runtime backend that discovered this instance.
    pub backend: String,
    /// Current lifecycle state.
    pub state: InstanceState,
    /// When the instance was first observed.
    pub discovered_at: DateTime<Utc>,
    /// Image or unit source (e.g., "grafana/grafana:latest").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// A host-side port mapping.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PortMapping {
    /// Host port (the one reachable from the network).
    pub host_port: u16,
    /// Container/internal port.
    pub container_port: u16,
    /// Protocol (tcp or udp).
    pub protocol: PortProtocol,
    /// Host IP the port is bound to (0.0.0.0, 127.0.0.1, etc.).
    pub host_ip: String,
}

/// Port protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

/// Lifecycle state of a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceState {
    Running,
    Stopped,
    Paused,
    Restarting,
    Unknown,
}

/// Koi-specific metadata extracted from runtime labels/annotations.
///
/// All fields are optional — when absent, the adapter uses heuristics
/// or skips the corresponding Koi capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct KoiMetadata {
    /// Opt-in flag. When `Some(false)`, the instance is ignored.
    /// When `None`, the adapter uses its default policy (opt-in or opt-out).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,

    /// mDNS service type override (e.g., `_http._tcp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,

    /// Service name override for mDNS/DNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// DNS name override (without zone suffix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,

    /// TXT record key-value pairs for mDNS.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub txt: HashMap<String, String>,

    /// Health check HTTP path (e.g., `/healthz`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,

    /// Health check kind override (`http` or `tcp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_kind: Option<String>,

    /// Health check interval in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_interval: Option<u64>,

    /// Health check timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_timeout: Option<u64>,

    /// TLS proxy listen port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,

    /// Allow remote proxy connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_remote: Option<bool>,

    /// Enable certmesh cert injection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certmesh: Option<bool>,

    /// Where the routing metadata came from, for the inventory projection.
    /// `"traefik-labels"` / `"caddy-labels"` when the hostname/port were derived
    /// from a partner tool's labels; absent when only `koi.*` labels or port
    /// heuristics were used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl KoiMetadata {
    /// Parse from a flat key-value map (Docker labels, Incus user.* config).
    ///
    /// Keys use the `koi.` prefix: `koi.type`, `koi.name`, `koi.dns.name`,
    /// `koi.txt.key`, `koi.health.path`, etc.
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        Self::from_labels_and_env(labels, &[])
    }

    /// Parse from labels with optional environment variable overrides.
    ///
    /// Environment variables provide a lower-precedence shorthand:
    /// - `KOI_MDNS_ANNOUNCE=<name>` — equivalent to `koi.announce=<name>` label
    ///
    /// The `koi.announce=<name>` shorthand (label or env var) sets:
    /// - `enable = true`
    /// - `name = <name>`
    /// - `dns_name = <name>`
    ///
    /// Explicit `koi.*` labels always override the shorthand.
    pub fn from_labels_and_env(labels: &HashMap<String, String>, env: &[String]) -> Self {
        let mut meta = Self::default();

        // 1. Check env var shorthand (lowest precedence)
        let env_announce = env
            .iter()
            .find_map(|e| e.strip_prefix("KOI_MDNS_ANNOUNCE=").map(|v| v.to_string()));

        // 2. Check label shorthand (overrides env var)
        let label_announce = labels.get("koi.announce").cloned();

        // Apply announce shorthand: label > env var
        if let Some(announce_name) = label_announce.or(env_announce) {
            meta.enable = Some(true);
            meta.name = Some(announce_name.clone());
            meta.dns_name = Some(announce_name);
        }

        // 3. Apply explicit labels (highest precedence — override shorthand)
        for (key, value) in labels {
            match key.as_str() {
                "koi.enable" => meta.enable = value.parse().ok(),
                "koi.type" => meta.service_type = Some(value.clone()),
                "koi.name" => meta.name = Some(value.clone()),
                "koi.dns.name" => meta.dns_name = Some(value.clone()),
                "koi.health.path" => meta.health_path = Some(value.clone()),
                "koi.health.kind" => meta.health_kind = Some(value.clone()),
                "koi.health.interval" => meta.health_interval = value.parse().ok(),
                "koi.health.timeout" => meta.health_timeout = value.parse().ok(),
                "koi.proxy.port" => meta.proxy_port = value.parse().ok(),
                "koi.proxy.remote" => meta.proxy_remote = value.parse().ok(),
                "koi.certmesh" => meta.certmesh = value.parse().ok(),
                "koi.announce" => {} // already handled above
                k if k.starts_with("koi.txt.") => {
                    if let Some(txt_key) = k.strip_prefix("koi.txt.") {
                        meta.txt.insert(txt_key.to_string(), value.clone());
                    }
                }
                _ => {}
            }
        }

        // 4. Partner-tool routing labels (traefik / caddy). Precedence: explicit
        // `koi.*` > traefik/caddy-derived > port heuristics; `koi.enable=false`
        // wins over all (handled by `is_disabled()` downstream — we never override
        // it here). The derived values only FILL fields the operator left unset, so
        // an explicit `koi.dns.name`/`koi.type`/`koi.proxy.port` always wins.
        //
        // This is passive and safe (we read labels the user already wrote for their
        // proxy), so it is on by default; `koi.enable=false` opts a container out.
        if meta.enable != Some(false) {
            apply_partner_labels(&mut meta, labels);
        }

        meta
    }

    /// Whether this instance is explicitly opted out.
    pub fn is_disabled(&self) -> bool {
        self.enable == Some(false)
    }
}

/// Apply Traefik/Caddy routing labels, filling only fields the operator left
/// unset (explicit `koi.*` always wins). Derived hostname → `dns_name` (and a
/// `name` when none was given); derived port → `proxy_port`. Sets `source` so the
/// inventory shows where the routing came from.
///
/// Never panics on any label value — malformed rules yield `None`.
fn apply_partner_labels(meta: &mut KoiMetadata, labels: &HashMap<String, String>) {
    // Traefik first, then Caddy as a fallback source. A container almost never
    // carries both; if it does, traefik (checked first) wins, matching the
    // "first source that yields a hostname" rule.
    let derived = extract_traefik(labels).or_else(|| extract_caddy(labels));
    let Some(derived) = derived else {
        return;
    };

    let mut used = false;
    if let Some(host) = derived.host {
        if meta.dns_name.is_none() {
            meta.dns_name = Some(host.clone());
            used = true;
        }
        if meta.name.is_none() {
            meta.name = Some(host);
            used = true;
        }
    }
    if let Some(port) = derived.port {
        if meta.proxy_port.is_none() {
            meta.proxy_port = Some(port);
            used = true;
        }
    }

    // Marking the instance as managed makes a labeled-but-not-koi.enabled container
    // discoverable, which is the point of reading partner labels. We only do this
    // when we actually derived something and the operator did not opt out.
    if used {
        if meta.enable.is_none() {
            meta.enable = Some(true);
        }
        if meta.source.is_none() {
            meta.source = Some(derived.source.to_string());
        }
    }
}

/// Routing facts derived from a partner tool's labels.
struct DerivedRouting {
    host: Option<String>,
    port: Option<u16>,
    source: &'static str,
}

/// Extract Traefik v3 routing facts. Returns `None` unless at least one
/// `traefik.*` label is present (so we only treat genuinely Traefik-managed
/// containers as such) and `traefik.enable` is not `false`.
fn extract_traefik(labels: &HashMap<String, String>) -> Option<DerivedRouting> {
    let has_traefik = labels.keys().any(|k| k.starts_with("traefik."));
    if !has_traefik {
        return None;
    }
    // `traefik.enable=false` means Traefik ignores it — so should we. Absent or
    // any other value is treated leniently as enabled.
    if let Some(enable) = labels.get("traefik.enable") {
        if enable.trim().eq_ignore_ascii_case("false") {
            return None;
        }
    }

    let host = labels
        .iter()
        .filter(|(k, _)| is_traefik_rule_key(k))
        .find_map(|(_, rule)| first_traefik_host(rule));

    let port = labels
        .iter()
        .find(|(k, _)| is_traefik_port_key(k))
        .and_then(|(_, v)| v.trim().parse::<u16>().ok());

    if host.is_none() && port.is_none() {
        return None;
    }
    Some(DerivedRouting {
        host,
        port,
        source: "traefik-labels",
    })
}

/// `traefik.http.routers.<r>.rule` (the `<r>` segment is arbitrary).
fn is_traefik_rule_key(key: &str) -> bool {
    key.starts_with("traefik.http.routers.") && key.ends_with(".rule")
}

/// `traefik.http.services.<s>.loadbalancer.server.port` (the `<s>` is arbitrary).
fn is_traefik_port_key(key: &str) -> bool {
    key.starts_with("traefik.http.services.") && key.ends_with(".loadbalancer.server.port")
}

/// Extract the FIRST ``Host(`name`)`` value from a Traefik v3 rule string.
///
/// v3 `Host()` takes a single argument. We scan for `Host(` then read the first
/// back-tick- or double-quote-delimited token. Tolerates `||`, `&&`,
/// `PathPrefix(...)`, and malformed rules (returns `None` when no parseable
/// `Host` is present). Never panics. The router/service name is never used as a
/// hostname source — only the `Host(...)` argument is.
fn first_traefik_host(rule: &str) -> Option<String> {
    let bytes = rule.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = rule[search_from..].find("Host(") {
        let open = search_from + rel + "Host(".len();
        // Skip whitespace before the delimiter.
        let mut i = open;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let delim = bytes[i] as char;
        if delim == '`' || delim == '"' {
            let value_start = i + 1;
            if let Some(end_rel) = rule[value_start..].find(delim) {
                let value = rule[value_start..value_start + end_rel].trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
            // Unterminated delimiter → malformed; stop.
            return None;
        }
        // `Host(` not followed by a string delimiter (e.g. `HostRegexp(`-style or
        // malformed) — keep scanning past this occurrence.
        search_from = open;
    }
    None
}

/// Extract Caddy (caddy-docker-proxy) routing facts. Returns `None` unless a
/// `caddy` label is present.
fn extract_caddy(labels: &HashMap<String, String>) -> Option<DerivedRouting> {
    let caddy = labels.get("caddy")?;
    // Hostname = first comma-separated entry (a site address), trimmed.
    let host = caddy
        .split(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Port = the numeric token inside `caddy.reverse_proxy`'s upstream directive.
    let port = labels
        .get("caddy.reverse_proxy")
        .and_then(|v| caddy_upstream_port(v));

    if host.is_none() && port.is_none() {
        return None;
    }
    Some(DerivedRouting {
        host,
        port,
        source: "caddy-labels",
    })
}

/// Parse the port out of a caddy-docker-proxy `reverse_proxy` value such as
/// `{{upstreams 8080}}`, `{{upstreams http 8080}}`, or `{{upstreams https}}`.
///
/// Strips the `{{`/`}}` and the `upstreams` keyword, then returns the first
/// numeric token (the port). Returns `None` when no numeric token is present
/// (e.g. `{{upstreams https}}`). Never panics.
fn caddy_upstream_port(value: &str) -> Option<u16> {
    let inner = value.trim().trim_start_matches("{{").trim_end_matches("}}");
    inner
        .split_whitespace()
        .filter(|tok| !tok.eq_ignore_ascii_case("upstreams"))
        .find_map(|tok| tok.parse::<u16>().ok())
}

/// Compose metadata extracted from Docker Compose labels.
#[derive(Debug, Clone, Default)]
pub struct ComposeInfo {
    pub project: Option<String>,
    pub service: Option<String>,
}

impl ComposeInfo {
    /// Extract from Docker labels.
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        Self {
            project: labels.get("com.docker.compose.project").cloned(),
            service: labels.get("com.docker.compose.service").cloned(),
        }
    }

    /// Best available service name: Compose service > container name.
    pub fn effective_name<'a>(&'a self, container_name: &'a str) -> &'a str {
        self.service.as_deref().unwrap_or(container_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_labels_extracts_all_fields() {
        let mut labels = HashMap::new();
        labels.insert("koi.enable".into(), "true".into());
        labels.insert("koi.type".into(), "_http._tcp".into());
        labels.insert("koi.name".into(), "My App".into());
        labels.insert("koi.dns.name".into(), "myapp".into());
        labels.insert("koi.txt.version".into(), "1.0".into());
        labels.insert("koi.txt.env".into(), "production".into());
        labels.insert("koi.health.path".into(), "/healthz".into());
        labels.insert("koi.health.kind".into(), "http".into());
        labels.insert("koi.health.interval".into(), "30".into());
        labels.insert("koi.health.timeout".into(), "5".into());
        labels.insert("koi.proxy.port".into(), "443".into());
        labels.insert("koi.proxy.remote".into(), "true".into());
        labels.insert("koi.certmesh".into(), "true".into());

        let meta = KoiMetadata::from_labels(&labels);

        assert_eq!(meta.enable, Some(true));
        assert_eq!(meta.service_type.as_deref(), Some("_http._tcp"));
        assert_eq!(meta.name.as_deref(), Some("My App"));
        assert_eq!(meta.dns_name.as_deref(), Some("myapp"));
        assert_eq!(meta.txt.get("version").map(|s| s.as_str()), Some("1.0"));
        assert_eq!(meta.txt.get("env").map(|s| s.as_str()), Some("production"));
        assert_eq!(meta.health_path.as_deref(), Some("/healthz"));
        assert_eq!(meta.health_kind.as_deref(), Some("http"));
        assert_eq!(meta.health_interval, Some(30));
        assert_eq!(meta.health_timeout, Some(5));
        assert_eq!(meta.proxy_port, Some(443));
        assert_eq!(meta.proxy_remote, Some(true));
        assert_eq!(meta.certmesh, Some(true));
    }

    #[test]
    fn empty_labels_produce_defaults() {
        let meta = KoiMetadata::from_labels(&HashMap::new());
        assert!(meta.enable.is_none());
        assert!(meta.service_type.is_none());
        assert!(meta.txt.is_empty());
    }

    #[test]
    fn is_disabled_when_enable_false() {
        let mut labels = HashMap::new();
        labels.insert("koi.enable".into(), "false".into());
        let meta = KoiMetadata::from_labels(&labels);
        assert!(meta.is_disabled());
    }

    #[test]
    fn announce_label_sets_enable_name_dns() {
        let mut labels = HashMap::new();
        labels.insert("koi.announce".into(), "pi-hole".into());
        let meta = KoiMetadata::from_labels(&labels);

        assert_eq!(meta.enable, Some(true));
        assert_eq!(meta.name.as_deref(), Some("pi-hole"));
        assert_eq!(meta.dns_name.as_deref(), Some("pi-hole"));
        // service_type left to heuristics
        assert!(meta.service_type.is_none());
    }

    #[test]
    fn env_var_announce_sets_enable_name_dns() {
        let labels = HashMap::new();
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "KOI_MDNS_ANNOUNCE=grafana".to_string(),
        ];
        let meta = KoiMetadata::from_labels_and_env(&labels, &env);

        assert_eq!(meta.enable, Some(true));
        assert_eq!(meta.name.as_deref(), Some("grafana"));
        assert_eq!(meta.dns_name.as_deref(), Some("grafana"));
    }

    #[test]
    fn label_announce_overrides_env_var() {
        let mut labels = HashMap::new();
        labels.insert("koi.announce".into(), "from-label".into());
        let env = vec!["KOI_MDNS_ANNOUNCE=from-env".to_string()];
        let meta = KoiMetadata::from_labels_and_env(&labels, &env);

        assert_eq!(meta.name.as_deref(), Some("from-label"));
    }

    #[test]
    fn explicit_labels_override_announce_shorthand() {
        let mut labels = HashMap::new();
        labels.insert("koi.announce".into(), "pi-hole".into());
        labels.insert("koi.name".into(), "Pi-Hole DNS".into());
        labels.insert("koi.dns.name".into(), "pihole".into());
        labels.insert("koi.type".into(), "_dns._tcp".into());
        let meta = KoiMetadata::from_labels(&labels);

        assert_eq!(meta.enable, Some(true)); // from announce
        assert_eq!(meta.name.as_deref(), Some("Pi-Hole DNS")); // overridden
        assert_eq!(meta.dns_name.as_deref(), Some("pihole")); // overridden
        assert_eq!(meta.service_type.as_deref(), Some("_dns._tcp")); // explicit
    }

    #[test]
    fn no_announce_no_env_leaves_defaults() {
        let labels = HashMap::new();
        let env = vec!["PATH=/usr/bin".to_string()];
        let meta = KoiMetadata::from_labels_and_env(&labels, &env);

        assert!(meta.enable.is_none());
        assert!(meta.name.is_none());
        assert!(meta.dns_name.is_none());
    }

    #[test]
    fn compose_info_prefers_service_over_container_name() {
        let mut labels = HashMap::new();
        labels.insert("com.docker.compose.service".into(), "grafana".into());
        labels.insert("com.docker.compose.project".into(), "monitoring".into());
        let info = ComposeInfo::from_labels(&labels);
        assert_eq!(info.effective_name("random-container-name"), "grafana");
    }

    #[test]
    fn compose_info_falls_back_to_container_name() {
        let info = ComposeInfo::from_labels(&HashMap::new());
        assert_eq!(info.effective_name("my-container"), "my-container");
    }

    // ── Traefik / Caddy label ingestion (Door 2) ──────────────────────

    fn labels_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // first_traefik_host: extraction units (never panic on any input).

    #[test]
    fn traefik_host_simple() {
        assert_eq!(
            first_traefik_host("Host(`grafana.lab.internal`)").as_deref(),
            Some("grafana.lab.internal")
        );
    }

    #[test]
    fn traefik_host_with_and_pathprefix() {
        let rule = "Host(`api.lab.internal`) && PathPrefix(`/v1`)";
        assert_eq!(
            first_traefik_host(rule).as_deref(),
            Some("api.lab.internal")
        );
    }

    #[test]
    fn traefik_host_with_or_takes_first() {
        let rule = "Host(`a.lab.internal`) || Host(`b.lab.internal`)";
        assert_eq!(first_traefik_host(rule).as_deref(), Some("a.lab.internal"));
    }

    #[test]
    fn traefik_host_double_quote_form() {
        assert_eq!(
            first_traefik_host("Host(\"grafana.lab.internal\")").as_deref(),
            Some("grafana.lab.internal")
        );
    }

    #[test]
    fn traefik_host_no_host_clause_is_none() {
        // PathPrefix-only rule: no Host() to extract.
        assert_eq!(first_traefik_host("PathPrefix(`/api`)"), None);
    }

    #[test]
    fn traefik_host_malformed_does_not_panic() {
        // Unterminated backtick, empty Host, stray Host( — all must be safe.
        assert_eq!(first_traefik_host("Host(`unterminated"), None);
        assert_eq!(first_traefik_host("Host(``)"), None);
        assert_eq!(first_traefik_host("Host("), None);
        assert_eq!(first_traefik_host("HostSNI(`x`)"), None);
        assert_eq!(first_traefik_host(""), None);
    }

    #[test]
    fn traefik_full_labels_derive_host_and_port() {
        let labels = labels_of(&[
            ("traefik.enable", "true"),
            (
                "traefik.http.routers.grafana.rule",
                "Host(`grafana.lab.internal`)",
            ),
            (
                "traefik.http.services.grafana.loadbalancer.server.port",
                "3000",
            ),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("grafana.lab.internal"));
        assert_eq!(meta.proxy_port, Some(3000));
        assert_eq!(meta.source.as_deref(), Some("traefik-labels"));
        assert_eq!(meta.enable, Some(true));
    }

    #[test]
    fn traefik_enable_false_is_not_managed() {
        let labels = labels_of(&[
            ("traefik.enable", "false"),
            ("traefik.http.routers.x.rule", "Host(`x.lab.internal`)"),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        // Traefik disabled → we derive nothing from its labels.
        assert!(meta.dns_name.is_none());
        assert!(meta.source.is_none());
    }

    #[test]
    fn no_traefik_labels_no_derivation() {
        // A rule key alone without the `traefik.` namespace is not Traefik.
        let labels = labels_of(&[("some.other.label", "Host(`x`)")]);
        let meta = KoiMetadata::from_labels(&labels);
        assert!(meta.dns_name.is_none());
        assert!(meta.source.is_none());
    }

    #[test]
    fn caddy_bare_host() {
        let labels = labels_of(&[("caddy", "grafana.lab.internal")]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("grafana.lab.internal"));
        assert_eq!(meta.source.as_deref(), Some("caddy-labels"));
    }

    #[test]
    fn caddy_comma_list_takes_first() {
        let labels = labels_of(&[("caddy", " a.lab.internal , b.lab.internal ")]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("a.lab.internal"));
    }

    #[test]
    fn caddy_upstreams_port_variants() {
        assert_eq!(caddy_upstream_port("{{upstreams 8080}}"), Some(8080));
        assert_eq!(caddy_upstream_port("{{upstreams http 8080}}"), Some(8080));
        assert_eq!(caddy_upstream_port("{{upstreams https 8443}}"), Some(8443));
        // No numeric token → no port.
        assert_eq!(caddy_upstream_port("{{upstreams https}}"), None);
        assert_eq!(caddy_upstream_port("{{upstreams}}"), None);
    }

    #[test]
    fn caddy_full_labels_derive_host_and_port() {
        let labels = labels_of(&[
            ("caddy", "grafana.lab.internal"),
            ("caddy.reverse_proxy", "{{upstreams 3000}}"),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("grafana.lab.internal"));
        assert_eq!(meta.proxy_port, Some(3000));
        assert_eq!(meta.source.as_deref(), Some("caddy-labels"));
    }

    // ── Precedence ──

    #[test]
    fn explicit_koi_labels_beat_traefik() {
        let labels = labels_of(&[
            ("koi.dns.name", "explicit"),
            ("koi.name", "Explicit Name"),
            ("koi.type", "_http._tcp"),
            ("koi.proxy.port", "9999"),
            (
                "traefik.http.routers.x.rule",
                "Host(`from-traefik.lab.internal`)",
            ),
            ("traefik.http.services.x.loadbalancer.server.port", "3000"),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        // Every explicit koi.* field wins; traefik fills nothing because all the
        // fields it could supply were already set.
        assert_eq!(meta.dns_name.as_deref(), Some("explicit"));
        assert_eq!(meta.name.as_deref(), Some("Explicit Name"));
        assert_eq!(meta.service_type.as_deref(), Some("_http._tcp"));
        assert_eq!(meta.proxy_port, Some(9999));
        // Nothing was derived from traefik → no source marker.
        assert!(meta.source.is_none());
    }

    #[test]
    fn explicit_dns_name_wins_but_traefik_fills_free_fields() {
        // Operator pinned the DNS name but left name/port to the proxy labels.
        let labels = labels_of(&[
            ("koi.dns.name", "pinned"),
            (
                "traefik.http.routers.x.rule",
                "Host(`from-traefik.lab.internal`)",
            ),
            ("traefik.http.services.x.loadbalancer.server.port", "3000"),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("pinned")); // explicit wins
        assert_eq!(meta.name.as_deref(), Some("from-traefik.lab.internal")); // free
        assert_eq!(meta.proxy_port, Some(3000)); // free
        assert_eq!(meta.source.as_deref(), Some("traefik-labels"));
    }

    #[test]
    fn traefik_beats_heuristics_marker() {
        // No explicit koi.* → traefik provides the hostname; the source marker
        // proves traefik (not heuristics) supplied it.
        let labels = labels_of(&[("traefik.http.routers.x.rule", "Host(`svc.lab.internal`)")]);
        let meta = KoiMetadata::from_labels(&labels);
        assert_eq!(meta.dns_name.as_deref(), Some("svc.lab.internal"));
        assert_eq!(meta.source.as_deref(), Some("traefik-labels"));
    }

    #[test]
    fn koi_enable_false_beats_everything() {
        let labels = labels_of(&[
            ("koi.enable", "false"),
            ("traefik.http.routers.x.rule", "Host(`x.lab.internal`)"),
            ("caddy", "y.lab.internal"),
        ]);
        let meta = KoiMetadata::from_labels(&labels);
        // Opt-out wins: no partner derivation at all.
        assert!(meta.is_disabled());
        assert!(meta.dns_name.is_none());
        assert!(meta.source.is_none());
    }

    #[test]
    fn partner_parsing_never_panics_on_arbitrary_labels() {
        // Throw a pile of pathological values at the parser; it must not panic.
        let labels = labels_of(&[
            ("traefik.enable", "maybe"),
            ("traefik.http.routers.r.rule", "Host(`)(`weird"),
            (
                "traefik.http.services.s.loadbalancer.server.port",
                "not-a-number",
            ),
            ("caddy", ",,, , "),
            ("caddy.reverse_proxy", "{{garbage"),
        ]);
        // Just must not panic; result correctness for these is unspecified.
        let _ = KoiMetadata::from_labels(&labels);
    }
}
