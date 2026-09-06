//! Typed local-operator browser access client. Session credentials never become DAT.
use crate::{ClientError, KoiClient, Result};
pub use koi_common::browser_access::*;
impl KoiClient {
    pub fn browser_access_status(&self) -> Result<BrowserAccessStatus> {
        decode_status(self.get_json(OPERATOR_PATH)?)
    }
    pub fn browser_access_settings(
        &self,
        settings: &BrowserAccessSettings,
    ) -> Result<BrowserAccessStatus> {
        let body =
            serde_json::to_value(settings).map_err(|e| ClientError::Decode(e.to_string()))?;
        decode_status(self.put_json(OPERATOR_PATH, &body)?)
    }
    pub fn browser_invitation(&self, phone: bool) -> Result<BrowserInvitation> {
        serde_json::from_value(self.post_json(
            &format!("{OPERATOR_PATH}/invitations"),
            &serde_json::json!({"phone":phone}),
        )?)
        .map_err(|e| ClientError::Decode(e.to_string()))
    }
    pub fn browser_disconnect(&self, id: &str) -> Result<BrowserAccessStatus> {
        if id.len() != 43
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ClientError::Decode("invalid browser identifier".into()));
        }
        decode_status(self.delete_json(
            &format!("{OPERATOR_PATH}/sessions/{id}"),
            &serde_json::json!({}),
        )?)
    }
}
fn decode_status(value: serde_json::Value) -> Result<BrowserAccessStatus> {
    let status: BrowserAccessStatus =
        serde_json::from_value(value).map_err(|e| ClientError::Decode(e.to_string()))?;
    if status.schema != SCHEMA {
        return Err(ClientError::UnsupportedSchema {
            message: "unsupported browser access schema".into(),
            found: status.schema,
            minimum: SCHEMA,
            maximum: SCHEMA,
        });
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn future_schema_and_unsafe_revoke_path_are_rejected() {
        let value = serde_json::json!({"schema": SCHEMA + 1,"settings":{"enabled":true,"phone":false},"local_url":"http://127.0.0.1:5641/ui","phone_url":null,"phone_port":5645,"phone_ready":false,"reason":null,"sessions":[]});
        assert!(matches!(
            decode_status(value),
            Err(ClientError::UnsupportedSchema { .. })
        ));
        let client = KoiClient::with_token("http://127.0.0.1:1", "fixture");
        for id in ["../all", "", "?admin=1"] {
            assert!(matches!(
                client.browser_disconnect(id),
                Err(ClientError::Decode(_))
            ));
        }
    }
}
