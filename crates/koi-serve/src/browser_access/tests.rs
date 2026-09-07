use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:5641";
fn runtime() -> BrowserAccess {
    let path = std::env::temp_dir()
        .join(format!(
            "koi-browser-test-{}",
            koi_crypto::browser::random_secret()
        ))
        .join("state.json");
    let runtime =
        BrowserAccess::new(path, ORIGIN.into(), "Workshop".into(), Some(5645), None).unwrap();
    runtime
        .settings(BrowserAccessSettings {
            enabled: true,
            phone: false,
        })
        .unwrap();
    runtime
}
fn key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}
fn request(invite: &BrowserInvitation, key: &SigningKey, remember: bool) -> BrowserConnectRequest {
    BrowserConnectRequest {
        invitation: invite.url.split("#invite=").nth(1).unwrap().into(),
        public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        label: "My phone".into(),
        remember,
    }
}
fn proof(
    runtime: &BrowserAccess,
    session: &BrowserSession,
    key: &SigningKey,
    method: &str,
    path: &str,
) -> HeaderMap {
    let challenge = runtime.challenge(ORIGIN, &session.id).unwrap().challenge;
    let signature: Signature =
        key.sign(koi_crypto::browser::message(&session.id, &challenge, method, path).as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert("x-koi-browser", session.id.parse().unwrap());
    headers.insert("x-koi-challenge", challenge.parse().unwrap());
    headers.insert(
        "x-koi-proof",
        URL_SAFE_NO_PAD
            .encode(signature.to_bytes())
            .parse()
            .unwrap(),
    );
    headers
}
#[test]
fn atomic_single_use_and_wrong_origin_does_not_spend() {
    let runtime = runtime();
    let key = key();
    let invite = runtime.invite(false).unwrap();
    assert!(runtime
        .connect("https://elsewhere", request(&invite, &key, false))
        .is_err());
    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| runtime.connect(ORIGIN, request(&invite, &key, false)));
        let second = scope.spawn(|| runtime.connect(ORIGIN, request(&invite, &key, false)));
        [
            first.join().unwrap().is_ok(),
            second.join().unwrap().is_ok(),
        ]
    });
    assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1);
    assert_eq!(runtime.status().sessions.len(), 1);
}
#[test]
fn remembered_and_temporary_sessions_survive_daemon_restart_but_not_revocation() {
    for remember in [false, true] {
        let runtime = runtime();
        let key = key();
        let session = runtime
            .connect(
                ORIGIN,
                request(&runtime.invite(false).unwrap(), &key, remember),
            )
            .unwrap();
        assert_eq!(session.remembered, remember);
        let restarted = BrowserAccess::new(
            runtime.0.path.clone(),
            ORIGIN.into(),
            "Workshop".into(),
            Some(5645),
            None,
        )
        .unwrap();
        let headers = proof(&restarted, &session, &key, "GET", "/ui/session/shell");
        assert!(restarted
            .authorize(
                ORIGIN,
                &headers,
                &Method::GET,
                &"/ui/session/shell".parse().unwrap()
            )
            .is_ok());
        restarted.revoke(&session.id).unwrap();
        assert!(restarted.challenge(ORIGIN, &session.id).is_err());
        let again = BrowserAccess::new(
            runtime.0.path.clone(),
            ORIGIN.into(),
            "Workshop".into(),
            Some(5645),
            None,
        )
        .unwrap();
        assert!(again.status().sessions.is_empty());
    }
}

#[test]
fn signatures_bind_key_method_query_and_nonce_is_single_use() {
    let runtime = runtime();
    let key = key();
    let other = SigningKey::random(&mut OsRng);
    let session = runtime
        .connect(
            ORIGIN,
            request(&runtime.invite(false).unwrap(), &key, false),
        )
        .unwrap();
    let path: Uri = "/ui/session/shell?search=notes".parse().unwrap();
    let bad = proof(&runtime, &session, &other, "GET", &path.to_string());
    assert!(runtime
        .authorize(ORIGIN, &bad, &Method::GET, &path)
        .is_err());
    let headers = proof(&runtime, &session, &key, "GET", &path.to_string());
    assert!(runtime
        .authorize(ORIGIN, &headers, &Method::POST, &path)
        .is_err());
    assert!(runtime
        .authorize(
            ORIGIN,
            &headers,
            &Method::GET,
            &"/ui/session/shell?search=other".parse().unwrap()
        )
        .is_err());
    assert!(runtime
        .authorize(ORIGIN, &headers, &Method::GET, &path)
        .is_ok());
    assert!(runtime
        .authorize(ORIGIN, &headers, &Method::GET, &path)
        .is_err());
}
#[test]
fn expiry_limits_disable_and_unusable_certmesh_fail_closed() {
    let runtime = runtime();
    let key = key();
    assert!(runtime.invite(true).is_err());
    let invite = runtime.invite(false).unwrap();
    runtime
        .lock()
        .invitations
        .values_mut()
        .for_each(|i| i.expires = 0);
    assert!(runtime
        .connect(ORIGIN, request(&invite, &key, false))
        .is_err());
    let session = runtime
        .connect(
            ORIGIN,
            request(&runtime.invite(false).unwrap(), &key, false),
        )
        .unwrap();
    for _ in 0..8 {
        runtime.challenge(ORIGIN, &session.id).unwrap();
    }
    assert!(matches!(
        runtime.challenge(ORIGIN, &session.id),
        Err(AccessError::Limit)
    ));
    runtime.settings(BrowserAccessSettings::default()).unwrap();
    assert!(runtime.status().sessions.is_empty());
    assert!(runtime.invite(false).is_err());
    runtime
        .settings(BrowserAccessSettings {
            enabled: true,
            phone: true,
        })
        .unwrap();
    assert!(runtime.invite(true).is_err());
    assert!(runtime.challenge(ORIGIN, &session.id).is_err());
}
#[test]
fn failed_persistence_does_not_spend_invitation_and_future_schema_is_preserved() {
    let runtime = runtime();
    let key = key();
    let invite = runtime.invite(false).unwrap();
    let before = std::fs::read(&runtime.0.path).unwrap();
    std::fs::remove_file(&runtime.0.path).unwrap();
    std::fs::create_dir(&runtime.0.path).unwrap();
    assert!(runtime
        .connect(ORIGIN, request(&invite, &key, false))
        .is_err());
    assert!(runtime.status().sessions.is_empty());
    std::fs::remove_dir(&runtime.0.path).unwrap();
    std::fs::write(&runtime.0.path, before).unwrap();
    assert!(runtime
        .connect(ORIGIN, request(&invite, &key, false))
        .is_ok());
    let future = br#"{"schema":99,"settings":{"enabled":true,"phone":false},"sessions":[]}"#;
    std::fs::write(&runtime.0.path, future).unwrap();
    assert!(BrowserAccess::new(
        runtime.0.path.clone(),
        ORIGIN.into(),
        "Workshop".into(),
        Some(5645),
        None
    )
    .is_err());
    assert_eq!(std::fs::read(&runtime.0.path).unwrap(), future);
}
fn surface(runtime: BrowserAccess) -> Router {
    public_routes(BrowserSurface {
        access: runtime,
        origin: ORIGIN.into(),
        catalog: Arc::new(ServiceCatalogRuntime::default()),
        local: true,
    })
}
fn http_request(method: &str, path: &str, origin: &str) -> axum::http::Request<axum::body::Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:5641")
        .header("origin", origin)
        .body(axum::body::Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
    ));
    request
}
#[tokio::test]
async fn preview_is_safe_and_browser_router_has_no_operator_doors() {
    let runtime = runtime();
    let key = key();
    let invite = runtime.invite(false).unwrap();
    let app = surface(runtime.clone());
    assert_eq!(
        app.clone()
            .oneshot(http_request("GET", "/ui", ORIGIN))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for path in [
        "/v1/browser-access",
        "/v1/catalog",
        "/v1/mcp",
        "/v1/preferences",
        "/v1/admin/shutdown",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(http_request("GET", path, ORIGIN))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert!(runtime
        .connect(ORIGIN, request(&invite, &key, false))
        .is_ok());
    assert_eq!(
        app.clone()
            .oneshot(http_request("GET", "/ui/session/shell", ORIGIN))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(http_request("GET", "/ui", "https://evil.example"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut wrong_host = http_request("GET", "/ui", ORIGIN);
    wrong_host
        .headers_mut()
        .insert("host", "localhost.evil".parse().unwrap());
    assert_eq!(
        app.oneshot(wrong_host).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn operator_routes_require_dat_even_on_loopback_and_reject_remote_valid_dat() {
    let app = operator_routes(runtime()).layer(axum::middleware::from_fn(|request, next| {
        crate::http::dat_auth_middleware(request, next, Arc::new("test-dat".into()))
    }));
    assert_eq!(
        app.clone()
            .oneshot(http_request("GET", OPERATOR_PATH, ORIGIN))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut request = http_request("GET", OPERATOR_PATH, ORIGIN);
    request
        .headers_mut()
        .insert("x-koi-token", "test-dat".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut remote = http_request("GET", OPERATOR_PATH, ORIGIN);
    remote
        .headers_mut()
        .insert("x-koi-token", "test-dat".parse().unwrap());
    remote.extensions_mut().insert(ConnectInfo(
        "192.0.2.10:4321".parse::<std::net::SocketAddr>().unwrap(),
    ));
    assert_eq!(
        app.oneshot(remote).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

/// Explicit browser integration gate; requires Chromium and Node on the executor.
#[tokio::test]
#[ignore = "run explicitly with Chromium installed; isolated browser integration, not native acceptance"]
async fn chromium_browser_exchange_reload_and_disconnect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let runtime = BrowserAccess::new(
        std::env::temp_dir()
            .join(format!(
                "koi-browser-chromium-{}",
                koi_crypto::browser::random_secret()
            ))
            .join("state.json"),
        origin.clone(),
        "Browser fixture".into(),
        None,
        None,
    )
    .unwrap();
    runtime
        .settings(BrowserAccessSettings {
            enabled: true,
            phone: false,
        })
        .unwrap();
    let app = public_routes(BrowserSurface {
        access: runtime.clone(),
        origin: origin.clone(),
        catalog: Arc::new(ServiceCatalogRuntime::default()),
        local: true,
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    let stop = cancel.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
        .unwrap();
    });
    let invitation = runtime.invite(false).unwrap();
    let output = tokio::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/browser-access.mjs"
        ))
        .env("KOI_TEST_INVITATION", &invitation.url)
        .env(
            "KOI_TEST_TEMP_INVITATION",
            &runtime.invite(false).unwrap().url,
        )
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    cancel.cancel();
    server.await.unwrap();
    assert!(
        output.status.success(),
        "browser test failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        runtime.status().sessions.is_empty(),
        "Disconnect must revoke server-side access"
    );
}

struct Identity(tokio::sync::watch::Sender<Arc<koi_common::integration::TlsIdentitySnapshot>>);
impl TlsIdentitySource for Identity {
    fn tls_identity(&self) -> Arc<koi_common::integration::TlsIdentitySnapshot> {
        self.0.borrow().clone()
    }
    fn watch_tls_identity(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<koi_common::integration::TlsIdentitySnapshot>> {
        self.0.subscribe()
    }
}
#[test]
fn private_access_waits_on_identity_loss_and_rejects_new_trust_anchor() {
    use koi_common::integration::{TlsIdentityMaterial, TlsIdentitySnapshot};
    let material = TlsIdentityMaterial {
        hostname: "workshop".into(),
        certificate_chain_pem: "test-cert".into(),
        private_key_pem: "test-key".into(),
        trust_anchor_pem: "first-authority".into(),
    };
    let (tx, _) = tokio::sync::watch::channel(Arc::new(TlsIdentitySnapshot {
        revision: 1,
        material: Some(material.clone()),
    }));
    let source = Arc::new(Identity(tx));
    let runtime = BrowserAccess::new(
        std::env::temp_dir()
            .join(format!(
                "koi-browser-trust-{}",
                koi_crypto::browser::random_secret()
            ))
            .join("state.json"),
        ORIGIN.into(),
        "workshop".into(),
        Some(5645),
        Some(source.clone()),
    )
    .unwrap();
    runtime
        .settings(BrowserAccessSettings {
            enabled: true,
            phone: true,
        })
        .unwrap();
    runtime.observed(true, None);
    let key = key();
    let origin = "https://workshop:5645";
    assert_eq!(
        runtime.status().phone_url.as_deref(),
        Some("https://workshop:5645/ui")
    );
    assert!(runtime
        .invite(true)
        .unwrap()
        .url
        .starts_with("https://workshop:5645/ui#invite="));
    let session = runtime
        .connect(origin, request(&runtime.invite(true).unwrap(), &key, true))
        .unwrap();
    source.0.send_replace(Arc::new(TlsIdentitySnapshot {
        revision: 2,
        material: None,
    }));
    assert!(matches!(
        runtime.challenge(origin, &session.id),
        Err(AccessError::NotReady)
    ));
    assert!(runtime.invite(true).is_err());
    // Same authority recovers, without re-pairing or downgrading to HTTP.
    source.0.send_replace(Arc::new(TlsIdentitySnapshot {
        revision: 3,
        material: Some(material.clone()),
    }));
    assert!(runtime.challenge(origin, &session.id).is_ok());
    let mut other = material;
    other.trust_anchor_pem = "replacement-authority".into();
    source.0.send_replace(Arc::new(TlsIdentitySnapshot {
        revision: 4,
        material: Some(other),
    }));
    assert!(matches!(
        runtime.challenge(origin, &session.id),
        Err(AccessError::Unauthorized)
    ));
    assert!(runtime
        .challenge("http://workshop:5645", &session.id)
        .is_err());
}
