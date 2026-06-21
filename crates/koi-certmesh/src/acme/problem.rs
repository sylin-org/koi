//! RFC 8555 `application/problem+json` error responder.
//!
//! ACME errors are NOT the flat `{error,message}` shape the rest of certmesh
//! uses. Section 6.7 mandates a problem document
//! (`urn:ietf:params:acme:error:<type>`, RFC 7807) returned with content-type
//! `application/problem+json`. This module is the single, dedicated responder
//! for that shape — every ACME handler funnels its errors through here so the
//! wire format stays conformant.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// An RFC 8555 ACME error type (the `urn:ietf:params:acme:error:*` namespace).
///
/// Only the subset Koi actually emits is modelled; each maps to a fixed HTTP
/// status per RFC 8555 §6.7 and the IANA ACME error registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeErrorType {
    /// The request message was malformed.
    Malformed,
    /// The JWS was unacceptable (e.g. bad signature, wrong url/nonce binding).
    Unauthorized,
    /// The client's nonce was unrecognized or already used.
    BadNonce,
    /// The JWS signature algorithm is not supported (we accept ES256 only).
    BadSignatureAlgorithm,
    /// The CSR was unacceptable (e.g. carries an unauthorized identifier).
    BadCsr,
    /// The server will not issue for the requested identifier (out-of-zone).
    RejectedIdentifier,
    /// A required external account binding was missing (closed-mode enrollment).
    ExternalAccountRequired,
    /// The referenced account does not exist.
    AccountDoesNotExist,
    /// The CA is not in a state to serve ACME (not initialized / locked).
    ServerInternal,
    /// The request exceeded a rate limit.
    RateLimited,
    /// The order/authorization is not in a state for the requested action.
    OrderNotReady,
}

impl AcmeErrorType {
    /// The full `urn:ietf:params:acme:error:*` URN for this type.
    pub fn urn(self) -> &'static str {
        match self {
            Self::Malformed => "urn:ietf:params:acme:error:malformed",
            Self::Unauthorized => "urn:ietf:params:acme:error:unauthorized",
            Self::BadNonce => "urn:ietf:params:acme:error:badNonce",
            Self::BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
            Self::BadCsr => "urn:ietf:params:acme:error:badCSR",
            Self::RejectedIdentifier => "urn:ietf:params:acme:error:rejectedIdentifier",
            Self::ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
            Self::AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
            Self::ServerInternal => "urn:ietf:params:acme:error:serverInternal",
            Self::RateLimited => "urn:ietf:params:acme:error:rateLimited",
            Self::OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
        }
    }

    /// The HTTP status code RFC 8555 pairs with this error type.
    pub fn status(self) -> StatusCode {
        match self {
            Self::Malformed
            | Self::BadNonce
            | Self::BadSignatureAlgorithm
            | Self::BadCsr
            | Self::RejectedIdentifier => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::ExternalAccountRequired
            | Self::AccountDoesNotExist
            | Self::OrderNotReady => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::ServerInternal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// An ACME problem document plus the fresh `Replay-Nonce` that must accompany
/// every ACME response (RFC 8555 §6.5 — even errors hand out a usable nonce).
#[derive(Debug)]
pub struct AcmeProblem {
    error_type: AcmeErrorType,
    detail: String,
    /// Fresh replay nonce to attach to the error response, if available.
    nonce: Option<String>,
}

/// The serialized RFC 7807 problem body.
#[derive(Debug, Serialize)]
struct ProblemBody {
    #[serde(rename = "type")]
    type_: &'static str,
    detail: String,
    status: u16,
}

impl AcmeProblem {
    /// Construct a problem document with the given type and human detail.
    pub fn new(error_type: AcmeErrorType, detail: impl Into<String>) -> Self {
        Self {
            error_type,
            detail: detail.into(),
            nonce: None,
        }
    }

    /// Attach a fresh replay nonce (RFC 8555 requires one on every response,
    /// including errors — otherwise a `badNonce` would be unrecoverable).
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// The error type (for tests / introspection).
    pub fn error_type(&self) -> AcmeErrorType {
        self.error_type
    }
}

impl IntoResponse for AcmeProblem {
    fn into_response(self) -> Response {
        let status = self.error_type.status();
        let body = ProblemBody {
            type_: self.error_type.urn(),
            detail: self.detail,
            status: status.as_u16(),
        };
        // serde_json::to_string never fails for this fixed struct; fall back to a
        // minimal literal rather than unwrap (production no-panic rule).
        let json = serde_json::to_string(&body).unwrap_or_else(|_| {
            format!(
                "{{\"type\":\"{}\",\"status\":{}}}",
                self.error_type.urn(),
                status.as_u16()
            )
        });

        let mut resp = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/problem+json");
        if let Some(nonce) = self.nonce {
            resp = resp.header("Replay-Nonce", nonce);
        }
        resp.body(json.into())
            .unwrap_or_else(|_| status.into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urns_are_rfc8555_namespaced() {
        assert_eq!(
            AcmeErrorType::BadNonce.urn(),
            "urn:ietf:params:acme:error:badNonce"
        );
        assert_eq!(
            AcmeErrorType::RejectedIdentifier.urn(),
            "urn:ietf:params:acme:error:rejectedIdentifier"
        );
        assert_eq!(
            AcmeErrorType::BadCsr.urn(),
            "urn:ietf:params:acme:error:badCSR"
        );
    }

    #[test]
    fn statuses_match_rfc() {
        assert_eq!(AcmeErrorType::BadNonce.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            AcmeErrorType::RejectedIdentifier.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(AcmeErrorType::Unauthorized.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            AcmeErrorType::RateLimited.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn body_serializes_to_problem_json() {
        let body = ProblemBody {
            type_: AcmeErrorType::Malformed.urn(),
            detail: "bad request".into(),
            status: 400,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"type\":\"urn:ietf:params:acme:error:malformed\""));
        assert!(json.contains("\"detail\":\"bad request\""));
        assert!(json.contains("\"status\":400"));
    }
}
