use koi_common::service::{DeviceCondition, ServiceCondition};

pub fn service_label(condition: ServiceCondition) -> &'static str {
    match condition {
        ServiceCondition::Starting => "Starting",
        ServiceCondition::Found => "Found on the network",
        ServiceCondition::Responding => "Responding",
        ServiceCondition::NotResponding => "Not responding",
        ServiceCondition::Absent => "Absent",
        ServiceCondition::Stale => "Last observation is stale",
        ServiceCondition::Ambiguous => "Identity is ambiguous",
    }
}

pub fn device_label(condition: DeviceCondition) -> &'static str {
    match condition {
        DeviceCondition::Present => "Present",
        DeviceCondition::Stale => "Last observation is stale",
        DeviceCondition::Absent => "Absent",
        DeviceCondition::Ambiguous => "Identity is ambiguous",
    }
}
