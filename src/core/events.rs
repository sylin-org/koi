use crate::protocol::ServiceRecord;

/// Events emitted by browse and subscribe operations.
/// This mirrors mdns-sd's ServiceEvent but uses our ServiceRecord.
#[derive(Debug, Clone)]
pub enum ServiceEvent {
    Found(ServiceRecord),
    Resolved(ServiceRecord),
    Removed { name: String, service_type: String },
}
