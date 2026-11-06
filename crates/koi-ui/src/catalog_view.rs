//! Presentation labels for the authoritative service catalog.
//!
//! These helpers format supplied facts. They do not infer current state, action
//! eligibility, reachability, trust, or a preferred endpoint.

use std::net::Ipv6Addr;

use koi_common::service::{
    CatalogSnapshot, CheckKind, CheckResult, Endpoint, Service, ServiceCondition,
};

pub fn display_name(service: &Service) -> &str {
    service.alias.as_deref().unwrap_or(&service.display_name)
}

/// Find a host only through the service's declared device identity.
pub fn host_name<'a>(catalog: &'a CatalogSnapshot, service: &'a Service) -> &'a str {
    let name = catalog
        .devices
        .iter()
        .find(|device| device.id == service.device_id)
        .and_then(|device| device.names.first())
        .map(|name| name.value.as_str())
        .or_else(|| {
            service
                .last_known
                .as_ref()
                .and_then(|known| known.device_name.as_deref())
        });
    match name {
        Some("this_device") => "This Koi host",
        Some(name) => name,
        None => "Unknown host",
    }
}

/// Format the complete supplied address as text, never as an eligible href.
///
/// The caller must pass this string through ordinary escaped rendering. This
/// deliberately preserves hostile or malformed input for inspection; it is not
/// URL validation and must not be used to authorize browser or native dispatch.
pub fn endpoint_label(endpoint: &Endpoint) -> String {
    let host = &endpoint.host;
    let address = host.split_once('%').map_or(host.as_str(), |(ip, _)| ip);
    let displayed_host = if address.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let mut label = format!("{}://{}:{}", endpoint.scheme, displayed_host, endpoint.port);
    if let Some(path) = &endpoint.path {
        if !path.is_empty() && !path.starts_with('/') {
            label.push('/');
        }
        label.push_str(path);
    }
    label
}

/// Return a browser navigation target only after validating the complete,
/// renderer-built address. Catalog action eligibility remains a separate gate.
pub fn endpoint_open_url(endpoint: &Endpoint) -> Option<String> {
    if !endpoint.browser_usable
        || !matches!(endpoint.scheme.as_str(), "http" | "https")
        || endpoint.port == 0
    {
        return None;
    }
    let candidate = endpoint_label(endpoint);
    browser_open_url(&candidate)
}

/// Validate an exact browser target for adapters that dispatch outside HTML.
/// The returned value is URL-parser canonical output and contains no credentials.
pub fn browser_open_url(candidate: &str) -> Option<String> {
    if candidate != candidate.trim()
        || candidate.chars().any(char::is_control)
        || candidate.contains('\\')
    {
        return None;
    }
    let authority = candidate
        .strip_prefix("http://")
        .or_else(|| candidate.strip_prefix("https://"))?;
    if authority.is_empty() || authority.starts_with('/') {
        return None;
    }
    let parsed = url::Url::parse(candidate).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port() == Some(0)
    {
        return None;
    }
    Some(parsed.into())
}

pub fn condition_label(condition: ServiceCondition) -> &'static str {
    match condition {
        ServiceCondition::Starting => "Starting",
        ServiceCondition::Found => "Found",
        ServiceCondition::Responding => "Responding",
        ServiceCondition::NotResponding => "Not responding",
        ServiceCondition::Absent => "Absent",
        ServiceCondition::Stale => "Stale",
        ServiceCondition::Ambiguous => "Ambiguous",
    }
}

pub fn check_kind_label(kind: CheckKind) -> &'static str {
    match kind {
        CheckKind::NameResolution => "Name resolution",
        CheckKind::TcpConnect => "TCP connection",
        CheckKind::HttpResponse => "HTTP response",
        CheckKind::BackendHealth => "Backend health",
        CheckKind::ProxyListener => "Proxy listener",
        CheckKind::FirewallAssessment => "Firewall assessment",
        CheckKind::Certificate => "Certificate",
        CheckKind::OsRootPresence => "OS trust root presence",
        CheckKind::ClientTls => "Client TLS",
    }
}

pub fn check_result_label(result: CheckResult) -> &'static str {
    match result {
        CheckResult::Passed => "Passed",
        CheckResult::Failed => "Failed",
        CheckResult::Unknown => "Unknown",
        CheckResult::NotRun => "Not run",
    }
}

pub fn observer_label(observer: &str) -> &str {
    match observer {
        "this_installation" => "This Koi installation",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::service::{
        Device, DeviceCondition, DeviceId, EndpointId, EndpointOwner, IdentityConfidence,
        KoiPresence, LastKnownService, MeshIdentity, MeshIdentityState, NameEvidence, ServiceId,
        ServiceKind, TransportEncryption, CATALOG_SCHEMA,
    };

    fn service() -> Service {
        Service {
            schema: CATALOG_SCHEMA,
            id: ServiceId::new("service").unwrap(),
            device_id: DeviceId::new("hosting_device").unwrap(),
            display_name: "Workshop".into(),
            alias: None,
            kind: ServiceKind::Web,
            condition: ServiceCondition::Found,
            endpoints: vec![],
            observations: vec![],
            checks: vec![],
            available_actions: vec![],
            favorite: false,
            local_only: false,
            managed: false,
            active_operations: vec![],
            identity_confidence: IdentityConfidence::Observed,
            ambiguity: None,
            last_known: None,
        }
    }

    fn device(id: &str, names: &[&str]) -> Device {
        Device {
            schema: CATALOG_SCHEMA,
            id: DeviceId::new(id).unwrap(),
            names: names
                .iter()
                .map(|name| NameEvidence {
                    value: (*name).into(),
                    observation_ids: vec![],
                })
                .collect(),
            addresses: vec![],
            koi_presence: KoiPresence::Absent,
            mesh_identity: MeshIdentity {
                state: MeshIdentityState::Unknown,
                observation_ids: vec![],
            },
            condition: DeviceCondition::Present,
        }
    }

    fn endpoint(scheme: &str, host: &str, port: u16, path: Option<&str>) -> Endpoint {
        Endpoint {
            schema: CATALOG_SCHEMA,
            id: EndpointId::new("endpoint").unwrap(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: path.map(str::to_owned),
            network_scope: None,
            source_observation_ids: vec![],
            owner: EndpointOwner::Foreign,
            browser_usable: false,
            transport_encryption: TransportEncryption::Unknown,
            expected_service_name: Some("different-name.internal".into()),
            authority_needs: vec![],
            reachability: vec![],
            client_tls: vec![],
        }
    }

    #[test]
    fn names_preserve_supplied_personal_intent_and_exact_device_join() {
        let mut service = service();
        service.alias = Some("<img src=x onerror=alert(1)> & Friends".into());
        assert_eq!(display_name(&service), service.alias.as_deref().unwrap());
        service.alias = None;
        assert_eq!(display_name(&service), "Workshop");
        let catalog = CatalogSnapshot {
            devices: vec![
                device("stranger", &["Workshop"]),
                device("hosting_device", &["<host> & real", "another-name"]),
            ],
            ..CatalogSnapshot::default()
        };
        assert_eq!(host_name(&catalog, &service), "<host> & real");
    }

    #[test]
    fn host_fallbacks_do_not_guess_from_service_names_or_addresses() {
        let mut service = service();
        let mut catalog = CatalogSnapshot {
            devices: vec![device("stranger", &["Workshop"])],
            ..CatalogSnapshot::default()
        };
        assert_eq!(host_name(&catalog, &service), "Unknown host");
        service.last_known = Some(LastKnownService {
            device_name: Some("Saved host".into()),
            last_seen: CatalogSnapshot::default().generated_at,
            kind: ServiceKind::Web,
        });
        assert_eq!(host_name(&catalog, &service), "Saved host");
        catalog.devices.push(device("hosting_device", &[]));
        assert_eq!(host_name(&catalog, &service), "Saved host");
        catalog.devices[1] = device("hosting_device", &["this_device"]);
        assert_eq!(host_name(&catalog, &service), "This Koi host");
    }

    #[test]
    fn endpoint_text_preserves_host_port_path_and_ipv6_scope() {
        for (host, path, expected) in [
            ("app.local.", None, "http://app.local.:8080"),
            ("192.168.1.20", Some(""), "http://192.168.1.20:8080"),
            (
                "192.168.1.20",
                Some("/app?view=all#top"),
                "http://192.168.1.20:8080/app?view=all#top",
            ),
            ("app.local", Some("health"), "http://app.local:8080/health"),
            ("2001:db8::1", Some("/"), "http://[2001:db8::1]:8080/"),
            ("[2001:db8::1]", None, "http://[2001:db8::1]:8080"),
            ("fe80::1%eth0", None, "http://[fe80::1%eth0]:8080"),
            ("[fe80::1%eth0]", None, "http://[fe80::1%eth0]:8080"),
        ] {
            assert_eq!(
                endpoint_label(&endpoint("http", host, 8080, path)),
                expected
            );
        }
        assert_eq!(
            endpoint_label(&endpoint("https", "actual.local", 443, None)),
            "https://actual.local:443"
        );
    }

    #[test]
    fn malformed_addresses_remain_inspectable_text_not_validated_links() {
        for (scheme, host, path) in [
            ("javascript:alert(1)", "user@host", "/<script>&\"'"),
            ("http", "host\r\n<script>", "//other-host/path"),
            ("https", "0.0.0.0", "/"),
            ("https", "", "?token=example"),
        ] {
            let endpoint = endpoint(scheme, host, 0, Some(path));
            let label = endpoint_label(&endpoint);
            assert!(label.starts_with(&format!("{scheme}://{host}:0")));
            assert!(label.ends_with(path));
            assert!(!endpoint.browser_usable);
        }
    }

    #[test]
    fn native_browser_targets_use_the_same_closed_validation_boundary() {
        assert_eq!(
            browser_open_url("https://192.0.2.20:8443/status?view=full"),
            Some("https://192.0.2.20:8443/status?view=full".into())
        );
        for candidate in [
            "javascript:alert(1)",
            "http://user@example.invalid/",
            "http://user:pass@example.invalid/",
            "http://example.invalid:0/",
            " http://example.invalid/",
            "http://example.invalid/\r\ncommand",
            "http:///missing-host",
        ] {
            assert_eq!(browser_open_url(candidate), None, "accepted {candidate:?}");
        }
    }

    #[test]
    fn evidence_labels_keep_check_kind_result_and_observer_distinct() {
        assert_eq!(check_kind_label(CheckKind::TcpConnect), "TCP connection");
        assert_eq!(check_kind_label(CheckKind::HttpResponse), "HTTP response");
        assert_eq!(check_kind_label(CheckKind::ProxyListener), "Proxy listener");
        assert_eq!(check_result_label(CheckResult::Unknown), "Unknown");
        assert_eq!(check_result_label(CheckResult::NotRun), "Not run");
        assert_eq!(observer_label("this_installation"), "This Koi installation");
        assert_eq!(observer_label("browser-on-laptop"), "browser-on-laptop");
        assert_eq!(observer_label("<observer>"), "<observer>");
        for (condition, expected) in [
            (ServiceCondition::Starting, "Starting"),
            (ServiceCondition::Found, "Found"),
            (ServiceCondition::Responding, "Responding"),
            (ServiceCondition::NotResponding, "Not responding"),
            (ServiceCondition::Absent, "Absent"),
            (ServiceCondition::Stale, "Stale"),
            (ServiceCondition::Ambiguous, "Ambiguous"),
        ] {
            assert_eq!(condition_label(condition), expected);
        }
    }
}
