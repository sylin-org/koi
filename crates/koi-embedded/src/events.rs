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
