//! Schema-1 browser access values; authority lives in the serving owner.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const OPERATOR_PATH: &str = "/v1/browser-access";
pub const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserAccessSettings {
    pub enabled: bool,
    pub phone: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BrowserSession {
    pub id: String,
    pub label: String,
    pub origin: String,
    pub remembered: bool,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BrowserAccessStatus {
    pub schema: u32,
    pub settings: BrowserAccessSettings,
    pub local_url: String,
    pub phone_url: Option<String>,
    pub phone_port: Option<u16>,
    pub phone_ready: bool,
    pub reason: Option<String>,
    pub sessions: Vec<BrowserSession>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserInviteRequest {
    #[serde(default)]
    pub phone: bool,
}

// No Debug: a one-use invitation is still authority until consumed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BrowserInvitation {
    pub url: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConnectRequest {
    pub invitation: String,
    pub public_key: String,
    pub label: String,
    pub remember: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserChallengeRequest {
    pub session: String,
}

#[derive(Serialize, Deserialize)]
pub struct BrowserChallenge {
    pub challenge: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_round_trips_and_rejects_unknown_settings() {
        let settings = BrowserAccessSettings {
            enabled: true,
            phone: false,
        };
        assert_eq!(
            serde_json::from_str::<BrowserAccessSettings>(
                &serde_json::to_string(&settings).unwrap()
            )
            .unwrap(),
            settings
        );
        let invite = BrowserInvitation {
            url: "https://node:5645/ui#invite=example".into(),
            expires_at: 42,
        };
        assert!(
            serde_json::from_str::<BrowserInvitation>(&serde_json::to_string(&invite).unwrap())
                .unwrap()
                == invite
        );
        let status = BrowserAccessStatus {
            schema: SCHEMA,
            settings,
            local_url: "http://127.0.0.1:5641/ui".into(),
            phone_url: None,
            phone_port: Some(5645),
            phone_ready: false,
            reason: Some("Waiting for CertMesh".into()),
            sessions: vec![BrowserSession {
                id: "example".into(),
                label: "Phone".into(),
                origin: "https://node.local:5645".into(),
                remembered: true,
                expires_at: 123,
            }],
        };
        let value = serde_json::to_value(&status).unwrap();
        assert_eq!(
            serde_json::from_value::<BrowserAccessStatus>(value).unwrap(),
            status
        );
        let connect = BrowserConnectRequest {
            invitation: "example".into(),
            public_key: "public".into(),
            label: "Phone".into(),
            remember: false,
        };
        let value = serde_json::to_value(&connect).unwrap();
        let roundtrip: BrowserConnectRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
        let mut expanded = value;
        expanded["operator"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BrowserConnectRequest>(expanded).is_err());
        assert!(serde_json::from_str::<BrowserAccessSettings>(
            r#"{"enabled":true,"phone":true,"public":true}"#
        )
        .is_err());
    }
}
