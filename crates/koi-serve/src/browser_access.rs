//! ADR-046: limited browser authority, independent of the daemon access token.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use koi_common::browser_access::*;
use koi_common::integration::TlsIdentitySource;
use koi_common::persist::{self, AtomicCommit, AtomicWriteOptions};
use koi_compose::catalog::ServiceCatalogRuntime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

const INVITE_SECONDS: u64 = 120;
const TEMP_SECONDS: u64 = 12 * 60 * 60;
const REMEMBER_SECONDS: u64 = 30 * 24 * 60 * 60;
const CHALLENGE_SECONDS: u64 = 30;
const MAX_SESSIONS: usize = 64;
const MAX_INVITES: usize = 32;
const MAX_CHALLENGES: usize = 128;
const CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("Browser access is off. Enable it in Koi first.")]
    Disabled,
    #[error("Phone access is not ready. Check Browser access in Koi.")]
    NotReady,
    #[error("This invitation expired or was already used. Show a new code in Koi.")]
    Invitation,
    #[error("Browser access ended. Connect again from Koi.")]
    Unauthorized,
    #[error("The connection request is invalid.")]
    Invalid,
    #[error("Too many pending connections. Disconnect an unused browser or try again shortly.")]
    Limit,
    #[error("Browser access could not be saved: {0}")]
    Storage(#[from] std::io::Error),
}
impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Disabled | Self::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "browser_access_required")
            }
            Self::NotReady => (StatusCode::SERVICE_UNAVAILABLE, "browser_access_waiting"),
            Self::Invitation => (StatusCode::GONE, "invitation_unavailable"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_browser_request"),
            Self::Limit => (StatusCode::TOO_MANY_REQUESTS, "browser_access_limit"),
            Self::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "browser_access_storage"),
        };
        (
            status,
            Json(serde_json::json!({"error": code, "message": self.to_string()})),
        )
            .into_response()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    info: BrowserSession,
    public_key: String,
    // None identifies the loopback session, never a remote session without trust.
    authority: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    schema: u32,
    settings: BrowserAccessSettings,
    sessions: Vec<StoredSession>,
}
struct Invitation {
    origin: String,
    authority: Option<String>,
    expires: u64,
}
struct Challenge {
    session: String,
    expires: u64,
}
struct StateData {
    repository: Repository,
    invitations: HashMap<String, Invitation>,
    challenges: HashMap<String, Challenge>,
    phone_ready: bool,
    phone_reason: Option<String>,
    shutting_down: bool,
}
struct Inner {
    path: PathBuf,
    local_origin: String,
    hostname: String,
    phone_port: Option<u16>,
    identity: Option<Arc<dyn TlsIdentitySource>>,
    data: Mutex<StateData>,
    changed: Notify,
}
#[derive(Clone)]
pub struct BrowserAccess(Arc<Inner>);

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

impl BrowserAccess {
    pub fn new(
        path: PathBuf,
        local_origin: String,
        hostname: String,
        phone_port: Option<u16>,
        identity: Option<Arc<dyn TlsIdentitySource>>,
    ) -> Result<Self, AccessError> {
        let repository = persist::read_json_if_exists::<Repository>(&path)?.unwrap_or(Repository {
            schema: SCHEMA,
            settings: BrowserAccessSettings::default(),
            sessions: vec![],
        });
        if repository.schema != SCHEMA
            || repository.sessions.len() > MAX_SESSIONS
            || (repository.settings.phone && !repository.settings.enabled)
        {
            return Err(AccessError::Storage(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported or invalid browser access repository; preserved unchanged",
            )));
        }
        if !valid_origin(&local_origin, false)
            || repository.sessions.iter().any(|s| {
                !koi_crypto::browser::valid_public_key(&s.public_key)
                    || !valid_origin(&s.info.origin, s.authority.is_some())
            })
        {
            return Err(AccessError::Invalid);
        }
        Ok(Self(Arc::new(Inner {
            path,
            local_origin,
            hostname,
            phone_port,
            identity,
            changed: Notify::new(),
            data: Mutex::new(StateData {
                repository,
                invitations: HashMap::new(),
                challenges: HashMap::new(),
                phone_ready: false,
                phone_reason: None,
                shutting_down: false,
            }),
        })))
    }
    pub(crate) fn identity(&self) -> Option<&Arc<dyn TlsIdentitySource>> {
        self.0.identity.as_ref()
    }
    pub(crate) fn port(&self) -> Option<u16> {
        self.0.phone_port
    }
    pub(crate) async fn changed(&self) {
        self.0.changed.notified().await
    }
    pub fn hostname(&self) -> &str {
        &self.0.hostname
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, StateData> {
        self.0.data.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub(crate) fn phone_identity(&self) -> Option<(String, String)> {
        let snapshot = self.0.identity.as_ref()?.tls_identity();
        let material = snapshot.material.as_ref()?;
        // The identity hostname is covered by the issued certificate. Inventing
        // a .local suffix can produce a reachable URL that fails TLS validation.
        let origin = format!("https://{}:{}", material.hostname, self.0.phone_port?);
        valid_origin(&origin, true).then(|| (origin, digest(&material.trust_anchor_pem)))
    }
    pub(crate) fn observed(&self, ready: bool, reason: Option<String>) {
        let mut state = self.lock();
        state.phone_ready = ready;
        state.phone_reason = reason;
    }
    pub(crate) fn shutdown(&self) {
        let mut state = self.lock();
        state.shutting_down = true;
        state.phone_ready = false;
        state.invitations.clear();
        state.challenges.clear();
    }
    pub fn status(&self) -> BrowserAccessStatus {
        let state = self.lock();
        let phone = self.phone_identity();
        BrowserAccessStatus {
            schema: SCHEMA,
            settings: state.repository.settings.clone(),
            local_url: format!("{}/ui", self.0.local_origin),
            phone_url: phone.as_ref().map(|(origin, _)| format!("{origin}/ui")),
            phone_port: self.0.phone_port,
            phone_ready: phone.is_some()
                && state.phone_ready
                && state.repository.settings.phone
                && !state.shutting_down,
            reason: state.phone_reason.clone(),
            sessions: state
                .repository
                .sessions
                .iter()
                .filter(|s| s.info.expires_at > now())
                .map(|s| s.info.clone())
                .collect(),
        }
    }
    // All callers that may write run on a blocking executor. Commit before exposing
    // success; a failed pre-rename write never consumes an invitation or revocation.
    fn commit(&self, state: &mut StateData, repository: Repository) -> Result<(), AccessError> {
        if state.shutting_down {
            return Err(AccessError::Disabled);
        }
        let bytes = serde_json::to_vec_pretty(&repository).map_err(|_| AccessError::Invalid)?;
        #[cfg(windows)]
        let prepare = persist::restrict_windows_local_secret_acl;
        #[cfg(not(windows))]
        let prepare = |_: &std::path::Path| Ok(());
        let outcome = persist::write_bytes_atomic_with_options_and_prepare_stage(
            &self.0.path,
            &bytes,
            AtomicWriteOptions::new().with_unix_mode(0o600),
            prepare,
        )?;
        state.repository = repository;
        if let AtomicCommit::DurabilityUncertain(error) = outcome {
            tracing::error!(%error, "browser access commit visible; crash durability uncertain");
        }
        Ok(())
    }
    pub fn settings(
        &self,
        settings: BrowserAccessSettings,
    ) -> Result<BrowserAccessStatus, AccessError> {
        if settings.phone && !settings.enabled {
            return Err(AccessError::Invalid);
        }
        // Enabling desire without identity is allowed; readiness remains explicit.
        let mut state = self.lock();
        let mut next = state.repository.clone();
        next.settings = settings.clone();
        next.sessions.retain(|s| {
            settings.enabled
                && s.info.expires_at > now()
                && (settings.phone || s.authority.is_none())
        });
        self.commit(&mut state, next)?;
        state.invitations.clear();
        state.challenges.clear();
        if !settings.phone {
            state.phone_ready = false;
            state.phone_reason = None;
        }
        drop(state);
        self.0.changed.notify_one();
        Ok(self.status())
    }
    pub fn invite(&self, phone: bool) -> Result<BrowserInvitation, AccessError> {
        let mut state = self.lock();
        if !state.repository.settings.enabled || state.shutting_down {
            return Err(AccessError::Disabled);
        }
        let (origin, authority) = if phone {
            if !state.repository.settings.phone || !state.phone_ready {
                return Err(AccessError::NotReady);
            }
            let (origin, authority) = self.phone_identity().ok_or(AccessError::NotReady)?;
            (origin, Some(authority))
        } else {
            (self.0.local_origin.clone(), None)
        };
        state.invitations.retain(|_, i| i.expires > now());
        if state.invitations.len() >= MAX_INVITES {
            return Err(AccessError::Limit);
        }
        let secret = koi_crypto::browser::random_secret();
        let expires = now() + INVITE_SECONDS;
        state.invitations.insert(
            digest(&secret),
            Invitation {
                origin: origin.clone(),
                authority,
                expires,
            },
        );
        Ok(BrowserInvitation {
            url: format!("{origin}/ui#invite={secret}"),
            expires_at: expires,
        })
    }
    pub fn connect(
        &self,
        origin: &str,
        request: BrowserConnectRequest,
    ) -> Result<BrowserSession, AccessError> {
        if request.invitation.len() != 43
            || request.public_key.len() > 128
            || !koi_crypto::browser::valid_public_key(&request.public_key)
            || request.label.len() > 80
            || request.label.chars().any(char::is_control)
        {
            return Err(AccessError::Invalid);
        }
        let mut state = self.lock();
        self.admit(&state, origin)?;
        let key = digest(&request.invitation);
        let invitation = state
            .invitations
            .get(&key)
            .filter(|i| i.expires > now() && i.origin == origin)
            .ok_or(AccessError::Invitation)?;
        if invitation.authority != self.authority(origin)? {
            return Err(AccessError::Invitation);
        }
        let authority = invitation.authority.clone();
        let mut next = state.repository.clone();
        next.sessions.retain(|s| s.info.expires_at > now());
        if next.sessions.len() >= MAX_SESSIONS {
            return Err(AccessError::Limit);
        }
        let info = BrowserSession {
            id: koi_crypto::browser::random_secret(),
            label: if request.label.trim().is_empty() {
                "Browser".into()
            } else {
                request.label.trim().into()
            },
            origin: origin.into(),
            remembered: request.remember,
            expires_at: now()
                + if request.remember {
                    REMEMBER_SECONDS
                } else {
                    TEMP_SECONDS
                },
        };
        next.sessions.push(StoredSession {
            info: info.clone(),
            public_key: request.public_key,
            authority,
        });
        self.commit(&mut state, next)?;
        state.invitations.remove(&key);
        Ok(info)
    }
    fn authority(&self, origin: &str) -> Result<Option<String>, AccessError> {
        if origin == self.0.local_origin {
            return Ok(None);
        }
        let (phone, anchor) = self.phone_identity().ok_or(AccessError::Unauthorized)?;
        if origin != phone {
            return Err(AccessError::Unauthorized);
        }
        Ok(Some(anchor))
    }
    fn admit(&self, state: &StateData, origin: &str) -> Result<(), AccessError> {
        if !state.repository.settings.enabled || state.shutting_down {
            return Err(AccessError::Disabled);
        }
        if origin != self.0.local_origin {
            if !state.repository.settings.phone {
                return Err(AccessError::Unauthorized);
            }
            if !state.phone_ready || self.phone_identity().is_none() {
                return Err(AccessError::NotReady);
            }
            self.authority(origin)?;
        }
        Ok(())
    }
    fn session<'a>(
        &self,
        state: &'a StateData,
        origin: &str,
        id: &str,
    ) -> Result<&'a StoredSession, AccessError> {
        self.admit(state, origin)?;
        let authority = self.authority(origin)?;
        state
            .repository
            .sessions
            .iter()
            .find(|s| {
                s.info.id == id
                    && s.info.origin == origin
                    && s.info.expires_at > now()
                    && s.authority == authority
            })
            .ok_or(AccessError::Unauthorized)
    }
    pub fn challenge(&self, origin: &str, session: &str) -> Result<BrowserChallenge, AccessError> {
        let mut state = self.lock();
        self.session(&state, origin, session)?;
        state.challenges.retain(|_, c| c.expires > now());
        if state.challenges.len() >= MAX_CHALLENGES
            || state
                .challenges
                .values()
                .filter(|c| c.session == session)
                .count()
                >= 8
        {
            return Err(AccessError::Limit);
        }
        let challenge = koi_crypto::browser::random_secret();
        state.challenges.insert(
            challenge.clone(),
            Challenge {
                session: session.into(),
                expires: now() + CHALLENGE_SECONDS,
            },
        );
        Ok(BrowserChallenge { challenge })
    }
    pub fn authorize(
        &self,
        origin: &str,
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
    ) -> Result<String, AccessError> {
        let header = |name| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .ok_or(AccessError::Unauthorized)
        };
        let id = header("x-koi-browser")?;
        let nonce = header("x-koi-challenge")?;
        let signature = header("x-koi-proof")?;
        if id.len() != 43 || nonce.len() != 43 || signature.len() > 128 {
            return Err(AccessError::Unauthorized);
        }
        let mut state = self.lock();
        let session = self.session(&state, origin, id)?;
        let challenge = state
            .challenges
            .get(nonce)
            .filter(|c| c.session == id && c.expires > now())
            .ok_or(AccessError::Unauthorized)?;
        if !koi_crypto::browser::verify(
            &session.public_key,
            signature,
            id,
            nonce,
            method.as_str(),
            uri.path_and_query().map_or(uri.path(), |p| p.as_str()),
        ) || challenge.session != id
        {
            return Err(AccessError::Unauthorized);
        }
        state.challenges.remove(nonce);
        Ok(id.into())
    }
    pub fn revoke(&self, id: &str) -> Result<BrowserAccessStatus, AccessError> {
        let mut state = self.lock();
        let mut next = state.repository.clone();
        next.sessions
            .retain(|s| s.info.id != id && s.info.expires_at > now());
        self.commit(&mut state, next)?;
        state.challenges.retain(|_, c| c.session != id);
        drop(state);
        Ok(self.status())
    }
}

fn valid_origin(origin: &str, phone: bool) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    url.origin().ascii_serialization() == origin
        && url.username().is_empty()
        && url.password().is_none()
        && if phone {
            url.scheme() == "https" && url.host_str().is_some()
        } else {
            url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
        }
}

#[derive(Clone)]
pub(crate) struct BrowserSurface {
    pub access: BrowserAccess,
    pub origin: String,
    pub catalog: Arc<ServiceCatalogRuntime>,
    pub local: bool,
}

pub(crate) fn public_routes(surface: BrowserSurface) -> Router {
    Router::new()
        .route("/ui", get(bootstrap))
        .route("/ui/access.js", get(script))
        .route("/ui/refresh.js", get(refresh))
        .route("/ui/connect", post(connect))
        .route("/ui/challenge", post(challenge))
        .route("/ui/session/shell", get(shell))
        .route("/ui/disconnect", post(disconnect))
        .layer(DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn_with_state(
            surface.clone(),
            browser_guard,
        ))
        .with_state(surface)
}

async fn browser_guard(
    State(surface): State<BrowserSurface>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let authority = url::Url::parse(&surface.origin).ok().and_then(|u| {
        u.host_str()
            .map(|_| u[url::Position::BeforeHost..url::Position::AfterPort].to_string())
    });
    let host_matches =
        req.headers().get("host").and_then(|v| v.to_str().ok()) == authority.as_deref();
    let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
    let origin_matches = origin.is_none_or(|o| o == surface.origin);
    let post_matches = req.method() != Method::POST || origin == Some(surface.origin.as_str());
    let local_matches = !surface.local
        || req
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .is_some_and(|p| p.0.ip().is_loopback());
    let mut response = if !host_matches || !origin_matches || !post_matches || !local_matches {
        (
            StatusCode::FORBIDDEN,
            "Open this page through Koi's own address.",
        )
            .into_response()
    } else {
        next.run(req).await
    };
    for (key, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", CSP),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(key),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}
async fn bootstrap(State(surface): State<BrowserSurface>) -> Response {
    let html = koi_ui::browser_access::connect_page(surface.access.hostname());
    ([("content-type", "text/html; charset=utf-8")], html).into_response()
}
async fn script() -> Response {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../assets/browser-access.js"),
    )
        .into_response()
}
async fn refresh() -> Response {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        koi_ui::REFRESH_JS,
    )
        .into_response()
}
async fn connect(
    State(surface): State<BrowserSurface>,
    Json(request): Json<BrowserConnectRequest>,
) -> Result<Json<BrowserSession>, AccessError> {
    blocking(move || surface.access.connect(&surface.origin, request))
        .await
        .map(Json)
}
async fn challenge(
    State(surface): State<BrowserSurface>,
    Json(request): Json<BrowserChallengeRequest>,
) -> Result<Json<BrowserChallenge>, AccessError> {
    surface
        .access
        .challenge(&surface.origin, &request.session)
        .map(Json)
}
async fn shell(
    State(surface): State<BrowserSurface>,
    headers: HeaderMap,
    uri: Uri,
    RawQuery(query): RawQuery,
) -> Result<Response, AccessError> {
    surface
        .access
        .authorize(&surface.origin, &headers, &Method::GET, &uri)?;
    let intent = koi_ui::home::HomeRequest::parse(query.as_deref().unwrap_or(""))
        .map_err(|_| AccessError::Invalid)?;
    let snapshot = surface.catalog.status();
    let html = koi_ui::render_home(
        koi_ui::View::Snapshot(&snapshot),
        koi_ui::Links {
            refresh: None,
            advanced: "",
            browser_access: None,
        },
        &intent.query(),
    );
    Ok(([("content-type", "text/html; charset=utf-8")], html).into_response())
}
async fn disconnect(
    State(surface): State<BrowserSurface>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<serde_json::Value>, AccessError> {
    let id = surface
        .access
        .authorize(&surface.origin, &headers, &Method::POST, &uri)?;
    blocking(move || surface.access.revoke(&id)).await?;
    Ok(Json(serde_json::json!({"disconnected": true})))
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, AccessError> + Send + 'static,
) -> Result<T, AccessError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| AccessError::Storage(std::io::Error::other("browser operation interrupted")))?
}

/// Mounted inside DAT middleware. No remote operator can create invitations.
pub(crate) fn operator_routes(access: BrowserAccess) -> Router {
    Router::new()
        .route(OPERATOR_PATH, get(operator_status).put(operator_settings))
        .route("/v1/browser-access/invitations", post(operator_invite))
        .route("/v1/browser-access/sessions/{id}", delete(operator_revoke))
        .layer(DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn(local_operator))
        .with_state(access)
}
async fn local_operator(req: axum::extract::Request, next: Next) -> Response {
    if !req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .is_some_and(|p| p.0.ip().is_loopback())
    {
        return (
            StatusCode::FORBIDDEN,
            "Browser access is managed on this computer.",
        )
            .into_response();
    }
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
#[utoipa::path(get, path = "/v1/browser-access", tag = "browser-access",
    responses((status = 200, description = "Local operator result", body = BrowserAccessStatus),
        (status = 401, description = "Daemon token required"), (status = 403, description = "Loopback operator required")))]
pub(crate) async fn operator_status(
    State(access): State<BrowserAccess>,
) -> Json<BrowserAccessStatus> {
    Json(access.status())
}
#[utoipa::path(put, path = "/v1/browser-access", tag = "browser-access",
    request_body = BrowserAccessSettings,
    responses((status = 200, description = "Local operator result", body = BrowserAccessStatus),
        (status = 401, description = "Daemon token required"), (status = 403, description = "Loopback operator required")))]
pub(crate) async fn operator_settings(
    State(access): State<BrowserAccess>,
    Json(settings): Json<BrowserAccessSettings>,
) -> Result<Json<BrowserAccessStatus>, AccessError> {
    blocking(move || access.settings(settings)).await.map(Json)
}
#[utoipa::path(post, path = "/v1/browser-access/invitations", tag = "browser-access",
    request_body = BrowserInviteRequest,
    responses((status = 200, description = "Local operator result", body = BrowserInvitation),
        (status = 401, description = "Daemon token required"), (status = 403, description = "Loopback operator required")))]
pub(crate) async fn operator_invite(
    State(access): State<BrowserAccess>,
    Json(request): Json<BrowserInviteRequest>,
) -> Result<Json<BrowserInvitation>, AccessError> {
    access.invite(request.phone).map(Json)
}
#[utoipa::path(delete, path = "/v1/browser-access/sessions/{id}", tag = "browser-access",
    params(("id" = String, Path, description = "Browser session identifier")),
    responses((status = 200, description = "Local operator result", body = BrowserAccessStatus),
        (status = 401, description = "Daemon token required"), (status = 403, description = "Loopback operator required")))]
pub(crate) async fn operator_revoke(
    State(access): State<BrowserAccess>,
    Path(id): Path<String>,
) -> Result<Json<BrowserAccessStatus>, AccessError> {
    blocking(move || access.revoke(&id)).await.map(Json)
}

#[cfg(test)]
mod tests;
