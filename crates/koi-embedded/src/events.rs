use std::net::IpAddr;

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
    DnsUpdated {
        name: String,
        ips: Vec<IpAddr>,
        source: String,
    },
    HealthChanged {
        name: String,
        status: HealthStatus,
    },
    CertmeshMemberJoined {
        hostname: String,
        fingerprint: String,
    },
    ProxyUpdated {
        entry: ProxyEntry,
    },
}
