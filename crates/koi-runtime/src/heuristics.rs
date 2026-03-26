//! Port-to-service-type heuristic mapping.
//!
//! When a container/service publishes a port without a `koi.type` label,
//! the adapter infers the mDNS service type from the port number.

/// Infer an mDNS service type from a TCP port number.
///
/// Returns `None` for ports that don't have a well-known mapping,
/// in which case the caller should use `_koi-managed._tcp` as a fallback.
pub fn service_type_for_tcp_port(port: u16) -> Option<&'static str> {
    match port {
        // HTTP
        80 | 3000 | 5000 | 8000 | 8080 | 8888 | 9000 => Some("_http._tcp"),
        443 | 8443 => Some("_https._tcp"),

        // Databases
        3306 => Some("_mysql._tcp"),
        5432 => Some("_postgresql._tcp"),
        6379 => Some("_redis._tcp"),
        27017 => Some("_mongodb._tcp"),
        9042 => Some("_cassandra._tcp"),
        26257 => Some("_cockroachdb._tcp"),

        // Messaging
        1883 => Some("_mqtt._tcp"),
        5672 => Some("_amqp._tcp"),
        9092 => Some("_kafka._tcp"),
        4222 => Some("_nats._tcp"),

        // Observability
        9090 => Some("_prometheus._tcp"),
        3100 => Some("_loki._tcp"),
        4317 => Some("_otel-grpc._tcp"),
        4318 => Some("_otel-http._tcp"),
        9200 => Some("_elasticsearch._tcp"),
        16686 => Some("_jaeger._tcp"),

        // Infrastructure
        53 => Some("_dns._tcp"),
        22 => Some("_ssh._tcp"),
        25 | 587 => Some("_smtp._tcp"),
        143 | 993 => Some("_imap._tcp"),
        389 | 636 => Some("_ldap._tcp"),

        // Development
        5900 | 5901 => Some("_vnc._tcp"),
        3389 => Some("_rdp._tcp"),
        8384 => Some("_syncthing._tcp"),

        _ => None,
    }
}

/// Infer an mDNS service type from a UDP port number.
pub fn service_type_for_udp_port(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("_dns._udp"),
        5353 => Some("_mdns._udp"),
        1900 => Some("_ssdp._udp"),
        51820 => Some("_wireguard._udp"),
        _ => None,
    }
}

/// Fallback service type for ports with no known mapping.
pub const FALLBACK_SERVICE_TYPE: &str = "_koi-managed._tcp";

/// Determine the service type for a port, using heuristics with label override.
pub fn resolve_service_type(port: u16, is_udp: bool, label_override: Option<&str>) -> &str {
    if let Some(override_type) = label_override {
        return override_type;
    }

    if is_udp {
        service_type_for_udp_port(port).unwrap_or(FALLBACK_SERVICE_TYPE)
    } else {
        service_type_for_tcp_port(port).unwrap_or(FALLBACK_SERVICE_TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_http_ports_resolve() {
        assert_eq!(service_type_for_tcp_port(80), Some("_http._tcp"));
        assert_eq!(service_type_for_tcp_port(3000), Some("_http._tcp"));
        assert_eq!(service_type_for_tcp_port(8080), Some("_http._tcp"));
        assert_eq!(service_type_for_tcp_port(443), Some("_https._tcp"));
    }

    #[test]
    fn database_ports_resolve() {
        assert_eq!(service_type_for_tcp_port(5432), Some("_postgresql._tcp"));
        assert_eq!(service_type_for_tcp_port(3306), Some("_mysql._tcp"));
        assert_eq!(service_type_for_tcp_port(6379), Some("_redis._tcp"));
    }

    #[test]
    fn unknown_port_returns_none() {
        assert_eq!(service_type_for_tcp_port(12345), None);
    }

    #[test]
    fn udp_ports_resolve() {
        assert_eq!(service_type_for_udp_port(53), Some("_dns._udp"));
        assert_eq!(service_type_for_udp_port(51820), Some("_wireguard._udp"));
    }

    #[test]
    fn resolve_with_label_override() {
        assert_eq!(
            resolve_service_type(80, false, Some("_custom._tcp")),
            "_custom._tcp"
        );
    }

    #[test]
    fn resolve_falls_back_to_managed() {
        assert_eq!(
            resolve_service_type(12345, false, None),
            FALLBACK_SERVICE_TYPE
        );
    }
}
