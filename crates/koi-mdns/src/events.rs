use koi_common::types::ServiceRecord;

/// Events emitted by the mDNS domain.
/// Subscribers react to service discovery lifecycle changes.
#[derive(Debug, Clone)]
pub enum MdnsEvent {
    Found(ServiceRecord),
    Resolved(ServiceRecord),
    Removed { name: String, service_type: String },
}
