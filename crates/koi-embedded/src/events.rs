use koi_common::types::ServiceRecord;
use koi_health::HealthStatus;
use koi_proxy::ProxyEntry;

#[derive(Debug, Clone)]
pub enum KoiEvent {
    MdnsFound(ServiceRecord),
    MdnsResolved(ServiceRecord),
    MdnsRemoved {
        name: String,
        service_type: String,
    },
    DnsEntryUpdated {
        name: String,
        ip: String,
    },
    DnsEntryRemoved {
        name: String,
    },
    HealthChanged {
        name: String,
        status: HealthStatus,
    },
    CertmeshMemberJoined {
        hostname: String,
        fingerprint: String,
    },
    CertmeshMemberRevoked {
        hostname: String,
    },
    CertmeshDestroyed,
    ProxyEntryUpdated {
        entry: ProxyEntry,
    },
    ProxyEntryRemoved {
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_record() -> ServiceRecord {
        ServiceRecord {
            name: "My App".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("server.local".to_string()),
            ip: Some("192.168.1.42".to_string()),
            port: Some(8080),
            txt: HashMap::new(),
        }
    }

    #[test]
    fn mdns_found_variant_construction() {
        let event = KoiEvent::MdnsFound(sample_record());
        assert!(matches!(event, KoiEvent::MdnsFound(ref r) if r.name == "My App"));
    }

    #[test]
    fn mdns_resolved_variant_construction() {
        let event = KoiEvent::MdnsResolved(sample_record());
        assert!(matches!(event, KoiEvent::MdnsResolved(ref r) if r.port == Some(8080)));
    }

    #[test]
    fn mdns_removed_variant_construction() {
        let event = KoiEvent::MdnsRemoved {
            name: "Old Service".to_string(),
            service_type: "_http._tcp".to_string(),
        };
        assert!(
            matches!(event, KoiEvent::MdnsRemoved { ref name, .. } if name == "Old Service")
        );
    }

    #[test]
    fn dns_entry_updated_variant() {
        let event = KoiEvent::DnsEntryUpdated {
            name: "grafana".to_string(),
            ip: "10.0.0.5".to_string(),
        };
        assert!(matches!(event, KoiEvent::DnsEntryUpdated { ref name, ref ip } if name == "grafana" && ip == "10.0.0.5"));
    }

    #[test]
    fn dns_entry_removed_variant() {
        let event = KoiEvent::DnsEntryRemoved {
            name: "grafana".to_string(),
        };
        assert!(matches!(event, KoiEvent::DnsEntryRemoved { ref name } if name == "grafana"));
    }

    #[test]
    fn health_changed_variant() {
        let event = KoiEvent::HealthChanged {
            name: "web-api".to_string(),
            status: HealthStatus::Up,
        };
        assert!(
            matches!(event, KoiEvent::HealthChanged { ref name, status: HealthStatus::Up } if name == "web-api")
        );
    }

    #[test]
    fn certmesh_member_joined_variant() {
        let event = KoiEvent::CertmeshMemberJoined {
            hostname: "node1".to_string(),
            fingerprint: "abc123".to_string(),
        };
        assert!(
            matches!(event, KoiEvent::CertmeshMemberJoined { ref hostname, .. } if hostname == "node1")
        );
    }

    #[test]
    fn certmesh_member_revoked_variant() {
        let event = KoiEvent::CertmeshMemberRevoked {
            hostname: "node2".to_string(),
        };
        assert!(
            matches!(event, KoiEvent::CertmeshMemberRevoked { ref hostname } if hostname == "node2")
        );
    }

    #[test]
    fn certmesh_destroyed_variant() {
        let event = KoiEvent::CertmeshDestroyed;
        assert!(matches!(event, KoiEvent::CertmeshDestroyed));
    }

    #[test]
    fn proxy_entry_updated_variant() {
        let entry = ProxyEntry {
            name: "grafana".to_string(),
            listen_port: 443,
            backend: "http://localhost:3000".to_string(),
            allow_remote: false,
        };
        let event = KoiEvent::ProxyEntryUpdated {
            entry: entry.clone(),
        };
        assert!(
            matches!(event, KoiEvent::ProxyEntryUpdated { ref entry } if entry.name == "grafana")
        );
    }

    #[test]
    fn proxy_entry_removed_variant() {
        let event = KoiEvent::ProxyEntryRemoved {
            name: "grafana".to_string(),
        };
        assert!(
            matches!(event, KoiEvent::ProxyEntryRemoved { ref name } if name == "grafana")
        );
    }

    #[test]
    fn clone_preserves_data() {
        let event = KoiEvent::MdnsFound(sample_record());
        let cloned = event.clone();
        match (&event, &cloned) {
            (KoiEvent::MdnsFound(a), KoiEvent::MdnsFound(b)) => {
                assert_eq!(a.name, b.name);
                assert_eq!(a.port, b.port);
                assert_eq!(a.service_type, b.service_type);
            }
            _ => panic!("clone should preserve variant"),
        }
    }

    #[test]
    fn debug_does_not_panic() {
        let events = vec![
            KoiEvent::MdnsFound(sample_record()),
            KoiEvent::MdnsRemoved {
                name: "x".to_string(),
                service_type: "y".to_string(),
            },
            KoiEvent::DnsEntryUpdated {
                name: "a".to_string(),
                ip: "1.2.3.4".to_string(),
            },
            KoiEvent::DnsEntryRemoved {
                name: "a".to_string(),
            },
            KoiEvent::HealthChanged {
                name: "svc".to_string(),
                status: HealthStatus::Down,
            },
            KoiEvent::CertmeshMemberJoined {
                hostname: "h".to_string(),
                fingerprint: "f".to_string(),
            },
            KoiEvent::CertmeshMemberRevoked {
                hostname: "h".to_string(),
            },
            KoiEvent::CertmeshDestroyed,
            KoiEvent::ProxyEntryUpdated {
                entry: ProxyEntry {
                    name: "p".to_string(),
                    listen_port: 443,
                    backend: "http://localhost".to_string(),
                    allow_remote: false,
                },
            },
            KoiEvent::ProxyEntryRemoved {
                name: "p".to_string(),
            },
        ];
        for event in &events {
            let _ = format!("{event:?}");
        }
    }
}
