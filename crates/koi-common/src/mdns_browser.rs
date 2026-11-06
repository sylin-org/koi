//! Shared mDNS inspection projection and bounded query contracts.
//! Membership is projected from authoritative discovery; removal timestamps
//! are short-lived presentation metadata, never another inventory.
use crate::{integration::MdnsDiscoverySnapshot, types::ServiceRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub name: String,
    pub instance_name: String,
    pub service_type: String,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub txt: HashMap<String, String>,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserSnapshot {
    pub discovery: MdnsDiscoverySnapshot,
    pub browse_active: bool,
    /// Revision of the authoritative mDNS discovery snapshot projected here.
    /// `None` means no domain snapshot has been accepted yet; revision zero is
    /// a distinct, valid domain fact.
    pub revision: Option<u64>,
    pub total_types: usize,
    pub total_instances: usize,
    pub service_types: Vec<TypeSummary>,
    pub instances: Vec<ServiceInstance>,
    pub cache_age_secs: u64,
    /// Browse worker starts and observed answer counters. Silence does not diagnose its cause.
    pub burst: BurstStats,
}

/// Browse activity counters; these cannot establish a firewall diagnosis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstStats {
    pub bursts_sent: u64,
    pub answers_total: u64,
    /// RFC3339 timestamp of the most recent burst, absent before the first.
    pub last_burst_at: Option<String>,
    /// Answers the previous burst heard; zero means only that none were observed.
    pub last_burst_answers: u64,
    /// Seconds since that burst started, so the pane knows if it is fresh
    /// enough to judge answers against.
    pub last_burst_age_secs: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSummary {
    pub service_type: String,
    pub count: usize,
    pub first_seen: String,
    /// Friendly label for a well-known type (`_hap._tcp` → "HomeKit"), absent for
    /// unrecognized types so the UI falls back to the raw type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// One-line description of a well-known type, paired with `label`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Only these read-side discovery operations are admitted by the UI bridge.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MdnsQueryRequest {
    Requery,
    Browse { value: String },
    Resolve { value: String },
}

impl<'de> Deserialize<'de> for MdnsQueryRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Requery {},
            Browse { value: String },
            Resolve { value: String },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Requery {} => Self::Requery,
            Wire::Browse { value } => Self::Browse { value },
            Wire::Resolve { value } => Self::Resolve { value },
        })
    }
}

impl MdnsQueryRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Requery => Ok(()),
            Self::Browse { value } => {
                bounded_name(value)?;
                if value.eq_ignore_ascii_case(crate::types::META_QUERY) {
                    return Ok(());
                }
                crate::types::ServiceType::parse_browse(value)
                    .map(|_| ())
                    .map_err(|_| "Enter a valid DNS-SD service type.")
            }
            Self::Resolve { value } => {
                bounded_name(value)?;
                let labels = crate::types::split_presentation_labels(value.trim_end_matches('.'))
                    .ok_or("Enter a valid full service instance name.")?;
                if labels.len() != 4
                    || labels[0].is_empty()
                    || !labels[3].eq_ignore_ascii_case("local")
                {
                    return Err("Enter a full instance name in the local domain.");
                }
                crate::types::ServiceType::parse(&format!("{}.{}", labels[1], labels[2]))
                    .map(|_| ())
                    .map_err(|_| "Enter a valid service instance type.")
            }
        }
    }
}
fn bounded_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 253 || value.chars().any(char::is_control) {
        Err("Query names must contain 1 to 253 bytes and no control characters.")
    } else {
        // Match the provider presentation-escape rule: three decimal digits
        // represent one byte; all other escapes quote the following byte.
        let bytes = value.as_bytes();
        let mut cursor = 0;
        while cursor < bytes.len() {
            if bytes[cursor] != b'\\' {
                cursor += 1;
                continue;
            }
            cursor += 1;
            if cursor == bytes.len() {
                return Err("A DNS escape must have a following character.");
            }
            if cursor + 2 < bytes.len() && bytes[cursor..cursor + 3].iter().all(u8::is_ascii_digit)
            {
                let number = (bytes[cursor] - b'0') as u16 * 100
                    + (bytes[cursor + 1] - b'0') as u16 * 10
                    + (bytes[cursor + 2] - b'0') as u16;
                if number > 255 {
                    return Err("Decimal DNS escapes must be between 000 and 255.");
                }
                cursor += 3;
            } else {
                cursor += 1;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdnsQueryOutcome {
    Started,
    Answers,
    NoAnswer,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsQueryResult {
    pub outcome: MdnsQueryOutcome,
    pub message: String,
    pub records: Vec<ServiceRecord>,
    pub service_types: Vec<String>,
    pub query: String,
    pub observed_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_queries_reject_surplus_fields_and_validate_dns_names() {
        for value in [
            serde_json::json!({"kind":"requery","value":"bad"}),
            serde_json::json!({"kind":"requery","url":"https://attacker.test"}),
            serde_json::json!({"kind":"browse","value":"_ipp._tcp","extra":true}),
        ] {
            assert!(serde_json::from_value::<MdnsQueryRequest>(value).is_err());
        }
        for name in [
            "Printer._ipp._tcp.LOCAL",
            "Printer._ipp._tcp.local.",
            r"Printer\.One._ipp._tcp.local.",
        ] {
            assert!(
                MdnsQueryRequest::Resolve { value: name.into() }
                    .validate()
                    .is_ok(),
                "{name}"
            );
        }
        for name in [
            "Printer._ipp._bogus.local.",
            "Printer.One._ipp._tcp.local.",
            "Printer._ipp._tcp.example.",
            r"Printer\999._ipp._tcp.local.",
            r"Printer\256._ipp._tcp.local.",
        ] {
            assert!(
                MdnsQueryRequest::Resolve { value: name.into() }
                    .validate()
                    .is_err(),
                "{name}"
            );
        }
    }
}
