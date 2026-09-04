use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ErrorCode;

/// Standard error body for API responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorCode,
    pub message: String,
}

/// Successful DNS address-lookup result shared by every transport adapter.
///
/// Absence is represented outside this DTO as `None`/HTTP 404/NXDOMAIN. A
/// successfully decoded value therefore always carries the domain result
/// rather than an adapter-specific reconstruction of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsLookupResult {
    pub name: String,
    #[schema(value_type = Vec<String>)]
    pub ips: Vec<IpAddr>,
    pub source: String,
}

pub fn error_body(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        error: code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_lookup_result_round_trips_strictly() {
        let result = DnsLookupResult {
            name: "api.internal.".into(),
            ips: vec!["10.0.0.7".parse().expect("test IP")],
            source: "static".into(),
        };
        let encoded = serde_json::to_vec(&result).expect("encode DNS lookup result");
        assert_eq!(
            serde_json::from_slice::<DnsLookupResult>(&encoded).expect("decode DNS lookup result"),
            result
        );

        for malformed in [
            serde_json::json!({"name":"api.internal.","ips":["not-an-ip"],"source":"static"}),
            serde_json::json!({"name":"api.internal.","ips":["10.0.0.7"]}),
        ] {
            assert!(serde_json::from_value::<DnsLookupResult>(malformed).is_err());
        }

        let future = serde_json::json!({
            "name": "api.internal.",
            "ips": ["10.0.0.7"],
            "source": "static",
            "future_metadata": { "observed_at": "later" }
        });
        assert_eq!(
            serde_json::from_value::<DnsLookupResult>(future)
                .expect("unknown additive fields remain compatible"),
            result
        );
    }
}
