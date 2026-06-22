//! The RFC 8555 ACME HTTP router and handlers.
//!
//! Mounted by the binary's server-auth TLS listener under `/acme`. Every handler
//! that takes a JWS (everything except the directory and new-nonce GETs):
//! 1. parses the flattened JWS (`application/jose+json`),
//! 2. verifies the ES256 signature (against the embedded jwk for new-account, or
//!    the account's stored jwk by kid otherwise),
//! 3. redeems the replay nonce (reuse → `badNonce` + a fresh nonce),
//! 4. checks the protected `url` equals the request URL,
//! 5. dispatches.
//!
//! Every response — success or error — carries a fresh `Replay-Nonce`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;

use crate::acme::account::Account;
use crate::acme::challenge as ch;
use crate::acme::jws::{self, FlattenedJws, JwsError, KeyId, ParsedJws};
use crate::acme::order::{AuthzStatus, OrderStatus};
use crate::acme::problem::{AcmeErrorType, AcmeProblem};
use crate::acme::state::AcmeState;

// ── Route paths (relative; the binary nests this whole router under /acme) ──

mod paths {
    pub const DIRECTORY: &str = "/directory";
    pub const NEW_NONCE: &str = "/new-nonce";
    pub const NEW_ACCOUNT: &str = "/new-account";
    pub const NEW_ORDER: &str = "/new-order";
    pub const AUTHZ: &str = "/authz/{id}";
    pub const CHALLENGE: &str = "/chall/{id}";
    pub const ORDER: &str = "/order/{id}";
    pub const FINALIZE: &str = "/order/{id}/finalize";
    pub const CERT: &str = "/cert/{id}";
    pub const REVOKE: &str = "/revoke-cert";
    pub const ACCOUNT: &str = "/acct/{id}";
}

/// Build the ACME router. The binary mounts this under `/acme`.
pub fn routes(state: Arc<AcmeState>) -> Router {
    Router::new()
        .route(paths::DIRECTORY, get(directory))
        .route(paths::NEW_NONCE, head(new_nonce).get(new_nonce))
        .route(paths::NEW_ACCOUNT, post(new_account))
        .route(paths::NEW_ORDER, post(new_order))
        .route(paths::AUTHZ, post(authz))
        .route(paths::CHALLENGE, post(challenge))
        .route(paths::ORDER, post(get_order))
        .route(paths::FINALIZE, post(finalize))
        .route(paths::CERT, post(get_cert))
        .route(paths::REVOKE, post(revoke_cert))
        .route(paths::ACCOUNT, post(account))
        .with_state(state)
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Attach a fresh `Replay-Nonce` header to a response value, returning a Response.
fn with_nonce(state: &AcmeState, mut resp: Response) -> Response {
    let nonce = state.nonces().issue();
    if let Ok(v) = header::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("Replay-Nonce", v);
    }
    resp
}

/// Build a JSON response with content-type and a fresh Replay-Nonce.
fn json_response(state: &AcmeState, status: StatusCode, body: impl Serialize) -> Response {
    let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    let nonce = state.nonces().issue();
    if let Ok(v) = header::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("Replay-Nonce", v);
    }
    resp
}

/// Emit an ACME problem with a fresh nonce.
fn problem(state: &AcmeState, error_type: AcmeErrorType, detail: impl Into<String>) -> Response {
    AcmeProblem::new(error_type, detail)
        .with_nonce(state.nonces().issue())
        .into_response()
}

/// The outcome of full JWS preprocessing: the parsed JWS plus the resolved
/// account (None for new-account, which has no account yet).
struct VerifiedRequest {
    jws: ParsedJws,
    account: Option<Account>,
}

/// Parse + verify a JWS request body end-to-end:
/// JWS parse → signature verify → nonce redeem → url binding.
///
/// `expected_url` is the absolute URL of this endpoint (built from the base URL);
/// the protected `url` must equal it (RFC 8555 §6.4).
///
/// On any failure returns the appropriate `AcmeProblem` (as an Err Response).
///
/// The `Err` arm carries an axum `Response` (large), but it is constructed and
/// immediately returned by the calling handler — never stored or propagated up a
/// deep stack — so boxing it would only add an allocation + a deref at every call
/// site for no benefit.
#[allow(clippy::result_large_err)]
fn verify_request(
    state: &AcmeState,
    body: &Bytes,
    expected_url: &str,
) -> Result<VerifiedRequest, Response> {
    // Parse the flattened JWS JSON.
    let flat: FlattenedJws = serde_json::from_slice(body).map_err(|e| {
        problem(
            state,
            AcmeErrorType::Malformed,
            format!("request body is not a flattened JWS: {e}"),
        )
    })?;

    let parsed = jws::parse(&flat).map_err(|e| map_jws_error(state, e))?;

    // Resolve the verifying key + account.
    let (jwk, account) = match &parsed.key_id {
        KeyId::Jwk(jwk) => (jwk.clone(), None),
        KeyId::Kid(kid) => {
            // The kid is the account URL; the account id is its last path segment.
            let acct_id = kid.rsplit('/').next().unwrap_or("");
            let Some(acct) = state.accounts().get(acct_id) else {
                return Err(problem(
                    state,
                    AcmeErrorType::AccountDoesNotExist,
                    "unknown account (kid)",
                ));
            };
            (acct.jwk.clone(), Some(acct))
        }
    };

    // Verify the signature against the resolved key (wrong-key gate).
    parsed
        .verify_with(&jwk)
        .map_err(|e| map_jws_error(state, e))?;

    // Redeem the nonce (replay gate). A reused/unknown nonce → badNonce, still
    // with a fresh nonce so the client can recover.
    if !state.nonces().redeem(&parsed.nonce) {
        return Err(problem(
            state,
            AcmeErrorType::BadNonce,
            "nonce was unknown or already used",
        ));
    }

    // Bind the protected url to the request url (RFC 8555 §6.4).
    if parsed.url != expected_url {
        return Err(problem(
            state,
            AcmeErrorType::Malformed,
            format!(
                "protected url '{}' does not match request url '{}'",
                parsed.url, expected_url
            ),
        ));
    }

    Ok(VerifiedRequest {
        jws: parsed,
        account,
    })
}

/// Map a JWS parsing/verification error to the right ACME problem.
fn map_jws_error(state: &AcmeState, e: JwsError) -> Response {
    match e {
        JwsError::Malformed(d) => problem(state, AcmeErrorType::Malformed, d),
        JwsError::BadAlgorithm(d) => problem(state, AcmeErrorType::BadSignatureAlgorithm, d),
        JwsError::BadSignature => problem(
            state,
            AcmeErrorType::Unauthorized,
            "JWS signature did not verify",
        ),
    }
}

// ── Directory + new-nonce ────────────────────────────────────────────

#[derive(Serialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "revokeCert")]
    revoke_cert: String,
    meta: DirectoryMeta,
}

#[derive(Serialize)]
struct DirectoryMeta {
    #[serde(rename = "externalAccountRequired", skip_serializing_if = "is_false")]
    external_account_required: bool,
    #[serde(rename = "termsOfService", skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

async fn directory(State(state): State<Arc<AcmeState>>) -> Response {
    let external_account_required = !state.enrollment_open().await;
    let dir = Directory {
        new_nonce: state.url("/acme/new-nonce"),
        new_account: state.url("/acme/new-account"),
        new_order: state.url("/acme/new-order"),
        revoke_cert: state.url("/acme/revoke-cert"),
        meta: DirectoryMeta {
            external_account_required,
            terms_of_service: None,
        },
    };
    json_response(&state, StatusCode::OK, dir)
}

async fn new_nonce(State(state): State<Arc<AcmeState>>, method: axum::http::Method) -> Response {
    // HEAD → 200, GET → 204 (RFC 8555 §7.2). Both carry a fresh Replay-Nonce.
    let status = if method == axum::http::Method::HEAD {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    };
    let mut resp = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| status.into_response());
    let nonce = state.nonces().issue();
    if let Ok(v) = header::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("Replay-Nonce", v);
    }
    resp
}

// ── new-account ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct AccountResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contact: Vec<String>,
    orders: String,
}

async fn new_account(State(state): State<Arc<AcmeState>>, body: Bytes) -> Response {
    let expected = state.url("/acme/new-account");
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // newAccount must carry an embedded jwk (not a kid).
    let Some(jwk) = req.jws.embedded_jwk().cloned() else {
        return problem(
            &state,
            AcmeErrorType::Malformed,
            "newAccount must use an embedded jwk, not kid",
        );
    };

    // Closed enrollment: External Account Binding would be the gate, but Koi does
    // not yet implement an EAB key store / HMAC verification. A presence-only check
    // (`externalAccountBinding` is Some) is NO gate at all — any value passes — so
    // while closed the ACME server issues NO new accounts rather than falsely admit
    // one. Fail closed. The directory still advertises `externalAccountRequired`
    // so compliant clients know an EAB is required; we simply cannot verify one yet.
    if !state.enrollment_open().await {
        return problem(
            &state,
            AcmeErrorType::ExternalAccountRequired,
            "this mesh is in closed enrollment; the ACME server does not accept new \
             accounts while closed (external account binding is not yet supported)",
        );
    }

    // Parse contacts (optional).
    let payload: Value = serde_json::from_slice(&req.jws.payload).unwrap_or(Value::Null);
    let contacts: Vec<String> = payload
        .get("contact")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let (account, created) = match state.accounts().register(jwk, contacts.clone()) {
        Ok(v) => v,
        Err(e) => return problem(&state, AcmeErrorType::ServerInternal, e.to_string()),
    };

    let location = state.url(&format!("/acme/acct/{}", account.id));
    let resp_body = AccountResponse {
        status: "valid",
        contact: account.contacts.clone(),
        orders: state.url(&format!("/acme/acct/{}/orders", account.id)),
    };
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut resp = json_response(&state, status, resp_body);
    if let Ok(v) = header::HeaderValue::from_str(&location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

async fn account(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    // POST-as-GET / update on an existing account: just echo status.
    let expected = state.url(&format!("/acme/acct/{id}"));
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(account) = req.account.or_else(|| state.accounts().get(&id)) else {
        return problem(
            &state,
            AcmeErrorType::AccountDoesNotExist,
            "unknown account",
        );
    };
    json_response(
        &state,
        StatusCode::OK,
        AccountResponse {
            status: "valid",
            contact: account.contacts.clone(),
            orders: state.url(&format!("/acme/acct/{}/orders", account.id)),
        },
    )
}

// ── new-order ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OrderResponse {
    status: String,
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
}

#[derive(Serialize)]
struct Identifier {
    #[serde(rename = "type")]
    type_: &'static str,
    value: String,
}

async fn new_order(State(state): State<Arc<AcmeState>>, body: Bytes) -> Response {
    let expected = state.url("/acme/new-order");
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(account) = req.account else {
        return problem(
            &state,
            AcmeErrorType::Malformed,
            "new-order requires a kid (registered account)",
        );
    };

    if let Err(e) = state.ca_ready().await {
        return problem(&state, AcmeErrorType::ServerInternal, e.to_string());
    }

    // Parse the requested identifiers.
    let payload: Value = match serde_json::from_slice(&req.jws.payload) {
        Ok(v) => v,
        Err(e) => {
            return problem(
                &state,
                AcmeErrorType::Malformed,
                format!("order payload: {e}"),
            )
        }
    };
    let Some(idents) = payload.get("identifiers").and_then(|v| v.as_array()) else {
        return problem(
            &state,
            AcmeErrorType::Malformed,
            "order missing identifiers",
        );
    };

    let mut names = Vec::new();
    for ident in idents {
        let type_ = ident.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let value = ident.get("value").and_then(|v| v.as_str()).unwrap_or("");
        if type_ != "dns" || value.is_empty() {
            return problem(
                &state,
                AcmeErrorType::Malformed,
                "only dns identifiers are supported",
            );
        }
        // ── ZONE BOUNDARY (the critical gate) ──
        if !state.is_issuable(value) {
            return problem(
                &state,
                AcmeErrorType::RejectedIdentifier,
                format!("'{value}' is outside the Koi DNS zone '{}'", state.zone()),
            );
        }
        names.push(value.to_lowercase());
    }
    if names.is_empty() {
        return problem(&state, AcmeErrorType::Malformed, "no identifiers in order");
    }

    let order = state.orders().create_order(&account.id, names.clone());
    let resp_body = order_to_response(&state, &order);
    let location = state.url(&format!("/acme/order/{}", order.id));
    let mut resp = json_response(&state, StatusCode::CREATED, resp_body);
    if let Ok(v) = header::HeaderValue::from_str(&location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

fn order_to_response(state: &AcmeState, order: &crate::acme::order::Order) -> OrderResponse {
    OrderResponse {
        status: format!("{:?}", order.status).to_lowercase(),
        identifiers: order
            .identifiers
            .iter()
            .map(|v| Identifier {
                type_: "dns",
                value: v.clone(),
            })
            .collect(),
        authorizations: order
            .authz_ids
            .iter()
            .map(|id| state.url(&format!("/acme/authz/{id}")))
            .collect(),
        finalize: state.url(&format!("/acme/order/{}/finalize", order.id)),
        certificate: order
            .certificate_id
            .as_ref()
            .map(|cid| state.url(&format!("/acme/cert/{cid}"))),
    }
}

// ── authz (POST-as-GET) ──────────────────────────────────────────────

#[derive(Serialize)]
struct AuthzResponse {
    status: String,
    identifier: Identifier,
    challenges: Vec<ChallengeResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wildcard: Option<bool>,
}

#[derive(Serialize)]
struct ChallengeResponse {
    #[serde(rename = "type")]
    type_: &'static str,
    url: String,
    status: String,
    token: String,
}

async fn authz(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let expected = state.url(&format!("/acme/authz/{id}"));
    if let Err(resp) = verify_request(&state, &body, &expected) {
        return resp;
    }
    let Some(authz) = state.orders().get_authz(&id) else {
        return problem(&state, AcmeErrorType::Malformed, "unknown authorization");
    };
    json_response(&state, StatusCode::OK, authz_to_response(&state, &authz))
}

fn authz_to_response(state: &AcmeState, authz: &crate::acme::order::Authz) -> AuthzResponse {
    AuthzResponse {
        status: format!("{:?}", authz.status).to_lowercase(),
        identifier: Identifier {
            type_: "dns",
            value: authz.identifier.clone(),
        },
        challenges: vec![ChallengeResponse {
            type_: "dns-01",
            url: state.url(&format!("/acme/chall/{}", authz.challenge.id)),
            status: format!("{:?}", authz.challenge.status).to_lowercase(),
            token: authz.challenge.token.clone(),
        }],
        wildcard: authz.wildcard.then_some(true),
    }
}

// ── challenge (trigger dns-01 validation) ────────────────────────────

async fn challenge(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let expected = state.url(&format!("/acme/chall/{id}"));
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let Some(authz) = state.orders().authz_by_challenge(&id) else {
        return problem(&state, AcmeErrorType::Malformed, "unknown challenge");
    };

    // The account that owns the order must be the one triggering validation.
    let account = match req.account {
        Some(a) => a,
        None => return problem(&state, AcmeErrorType::Malformed, "challenge requires a kid"),
    };
    if account.id != authz.account_id {
        return problem(
            &state,
            AcmeErrorType::Unauthorized,
            "account does not own this authorization",
        );
    }

    // Compute the expected dns-01 TXT and validate it in-process.
    let thumbprint = jws::jwk_thumbprint(&account.jwk);
    let key_auth = ch::key_authorization(&authz.challenge.token, &thumbprint);
    let expected_txt = ch::dns_txt_value(&key_auth);
    let dns_name = ch::challenge_dns_name(&authz.identifier);

    // Self-serve: write → read-back → compare → clear. (The client writes the
    // same value via its own provider in the real world; here the client and the
    // server share the SAME DnsCore, so writing it here mirrors that.)
    let published = state.dns().get_txt(&dns_name);
    let valid = published.iter().any(|v| v == &expected_txt);

    if valid {
        state.orders().mark_challenge_valid(&authz.id);
    } else {
        state.orders().mark_challenge_invalid(&authz.id);
    }
    // Clear the challenge record either way — it served its purpose.
    state.dns().clear_txt(&dns_name);

    // Return the (now-updated) challenge object.
    let updated = state
        .orders()
        .get_authz(&authz.id)
        .map(|a| a.challenge)
        .unwrap_or(authz.challenge);
    let status_str = format!("{:?}", updated.status).to_lowercase();
    let mut body = ChallengeResponse {
        type_: "dns-01",
        url: state.url(&format!("/acme/chall/{}", updated.id)),
        status: status_str,
        token: updated.token.clone(),
    };
    // If invalid, surface why — but a bare object is RFC-acceptable.
    let _ = &mut body;
    json_response(&state, StatusCode::OK, body)
}

// ── order (POST-as-GET) ──────────────────────────────────────────────

async fn get_order(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let expected = state.url(&format!("/acme/order/{id}"));
    if let Err(resp) = verify_request(&state, &body, &expected) {
        return resp;
    }
    let Some(order) = state.orders().get_order(&id) else {
        return problem(&state, AcmeErrorType::Malformed, "unknown order");
    };
    json_response(&state, StatusCode::OK, order_to_response(&state, &order))
}

// ── finalize ─────────────────────────────────────────────────────────

async fn finalize(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let expected = state.url(&format!("/acme/order/{id}/finalize"));
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(account) = req.account else {
        return problem(&state, AcmeErrorType::Malformed, "finalize requires a kid");
    };
    let Some(order) = state.orders().get_order(&id) else {
        return problem(&state, AcmeErrorType::Malformed, "unknown order");
    };
    if order.account_id != account.id {
        return problem(
            &state,
            AcmeErrorType::Unauthorized,
            "order belongs to another account",
        );
    }
    // The order must be ready (all authorizations valid) before finalize.
    if order.status != OrderStatus::Ready {
        // Recompute one more time in case validation just completed.
        let all_valid = order.authz_ids.iter().all(|aid| {
            state
                .orders()
                .get_authz(aid)
                .map(|a| a.status == AuthzStatus::Valid)
                .unwrap_or(false)
        });
        if !all_valid {
            return problem(
                &state,
                AcmeErrorType::OrderNotReady,
                "order is not ready; not all authorizations are valid",
            );
        }
    }

    // Decode the CSR (base64url DER) from the finalize payload.
    let payload: Value = serde_json::from_slice(&req.jws.payload).unwrap_or(Value::Null);
    let Some(csr_b64) = payload.get("csr").and_then(|v| v.as_str()) else {
        return problem(&state, AcmeErrorType::Malformed, "finalize missing csr");
    };
    let csr_der = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(csr_b64) {
        Ok(d) => d,
        Err(_) => return problem(&state, AcmeErrorType::BadCsr, "csr is not valid base64url"),
    };

    // Sign — enforcing the SAN-authorization gate against the order's names.
    let authorized = order.authorized_names().to_vec();
    match state
        .sign_finalize_csr(&account.id, &authorized, &csr_der)
        .await
    {
        Ok(chain_pem) => {
            let cert_id = state.orders().record_certificate(&order.id, chain_pem);
            let updated = state.orders().get_order(&order.id).unwrap_or(order);
            let mut body = order_to_response(&state, &updated);
            body.certificate = Some(state.url(&format!("/acme/cert/{cert_id}")));
            json_response(&state, StatusCode::OK, body)
        }
        Err(e) => {
            // Unauthorized SANs / bad CSR → badCSR; CA problems → serverInternal.
            let etype = match &e {
                crate::error::CertmeshError::InvalidPayload(_) => AcmeErrorType::BadCsr,
                crate::error::CertmeshError::CaLocked
                | crate::error::CertmeshError::CaNotInitialized => AcmeErrorType::ServerInternal,
                _ => AcmeErrorType::ServerInternal,
            };
            problem(&state, etype, e.to_string())
        }
    }
}

// ── certificate download (POST-as-GET) ───────────────────────────────

async fn get_cert(
    State(state): State<Arc<AcmeState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let expected = state.url(&format!("/acme/cert/{id}"));
    if let Err(resp) = verify_request(&state, &body, &expected) {
        return resp;
    }
    let Some(cert) = state.orders().get_certificate(&id) else {
        return problem(&state, AcmeErrorType::Malformed, "unknown certificate");
    };
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pem-certificate-chain")
        .body(cert.chain_pem.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    let nonce = state.nonces().issue();
    if let Ok(v) = header::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("Replay-Nonce", v);
    }
    resp
}

// ── revoke-cert ──────────────────────────────────────────────────────

async fn revoke_cert(State(state): State<Arc<AcmeState>>, body: Bytes) -> Response {
    let expected = state.url("/acme/revoke-cert");
    let req = match verify_request(&state, &body, &expected) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let payload: Value = serde_json::from_slice(&req.jws.payload).unwrap_or(Value::Null);
    let Some(cert_b64) = payload.get("certificate").and_then(|v| v.as_str()) else {
        return problem(
            &state,
            AcmeErrorType::Malformed,
            "revoke missing certificate",
        );
    };
    let der = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cert_b64) {
        Ok(d) => d,
        Err(_) => {
            return problem(
                &state,
                AcmeErrorType::Malformed,
                "certificate is not base64url",
            )
        }
    };
    let fingerprint = koi_crypto::pinning::fingerprint_sha256(&der);
    let revoked = state.revoke_by_fingerprint(&fingerprint).await;
    if !revoked {
        return problem(
            &state,
            AcmeErrorType::Malformed,
            "certificate not found in this CA's roster",
        );
    }
    // RFC 8555: a successful revocation returns 200 with an empty body.
    with_nonce(
        &state,
        (StatusCode::OK, Json(serde_json::json!({}))).into_response(),
    )
}
