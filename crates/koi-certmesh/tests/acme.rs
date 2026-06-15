//! ACME (RFC 8555) server tests — the security gate + the instant-acme
//! conformance test.
//!
//! This file is the **objective acceptance gate** for the ACME facade. It has
//! two layers:
//!
//! 1. **Handler-level security tests** (`raw_*`) drive raw flattened-JWS requests
//!    against the axum router over plain HTTP on `127.0.0.1:0`. They prove the
//!    zone boundary, the wrong-key rejection, the nonce-replay rejection, the
//!    out-of-zone `rejectedIdentifier`, the wildcard-in-zone acceptance, and the
//!    unauthorized-SAN finalize rejection — deterministically, no TLS.
//!
//! 2. **The instant-acme conformance test** (`conformance_issues_cert_via_dns01`)
//!    drives the full RFC 8555 flow end-to-end with a real ACME client over TLS,
//!    proving newAccount → order → dns-01 → finalize → download issues a cert
//!    that chains to the Koi CA.
//!
//! Run serialized: `cargo test -p koi-certmesh -- --test-threads=1`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use koi_certmesh::acme::{AcmeState, AcmeStateConfig};
use koi_certmesh::{ca, roster::Roster, CertmeshCore, CertmeshPaths};
use koi_common::integration::AcmeDnsSolver;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

// ── In-memory dns-01 solver (mirrors DnsCore's TXT semantics) ─────────
//
// koi-certmesh must not depend on koi-dns (domain isolation). The real bridge
// (AcmeDnsBridge → DnsCore) is unit-tested in koi-dns; here we use a HashMap
// solver with the same normalize(lowercase + strip trailing dot)/append/get
// contract DnsCore implements, so the ACME validation logic is exercised
// identically. The conformance test writes the challenge value into THIS solver,
// which is the same instance the AcmeState reads from.
#[derive(Default)]
struct MemSolver {
    txt: Mutex<HashMap<String, Vec<String>>>,
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

impl AcmeDnsSolver for MemSolver {
    fn set_txt(&self, name: &str, value: &str) {
        let mut g = self.txt.lock().unwrap();
        let v = g.entry(normalize(name)).or_default();
        if !v.iter().any(|e| e == value) {
            v.push(value.to_string());
        }
    }
    fn clear_txt(&self, name: &str) {
        self.txt.lock().unwrap().remove(&normalize(name));
    }
    fn get_txt(&self, name: &str) -> Vec<String> {
        self.txt
            .lock()
            .unwrap()
            .get(&normalize(name))
            .cloned()
            .unwrap_or_default()
    }
}

// ── CA fixture ───────────────────────────────────────────────────────

/// A built CA fixture: the core (over a fresh unlocked CA in open mode) plus the
/// CA cert PEM and a daemon leaf for the TLS conformance server.
struct CaFixture {
    core: CertmeshCore,
    ca_pem: String,
}

/// Create a CertmeshCore with a freshly-created, unlocked CA in OPEN enrollment.
fn build_ca() -> CaFixture {
    let tmp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(tmp.path().to_path_buf());
    std::mem::forget(tmp); // keep the data dir alive for the test

    let entropy = vec![9u8; 32];
    let (ca_state, _master) = ca::create_ca("acme-test-pass", &entropy, &paths).unwrap();
    let ca_pem = ca_state.cert_pem.clone();
    let roster = Roster::new(/* open */ true, /* approval */ false, None);
    let core = CertmeshCore::new_with_paths(ca_state, roster, None, paths);
    CaFixture { core, ca_pem }
}

/// Build an AcmeState over a CA fixture for the given base URL + zone, returning
/// the state and the shared solver.
fn acme_state_for(
    fixture: &CaFixture,
    base_url: &str,
    zone: &str,
) -> (Arc<AcmeState>, Arc<MemSolver>) {
    let solver = Arc::new(MemSolver::default());
    let dns: Arc<dyn AcmeDnsSolver> = solver.clone();
    let state = fixture.core.acme_state(AcmeStateConfig {
        base_url: base_url.to_string(),
        zone: zone.to_string(),
        dns,
    });
    (state, solver)
}

// ── Plain-HTTP server (bind first → learn addr → build state → serve) ─

/// Bind a plain-HTTP listener, build the AcmeState with the real bound base URL,
/// spawn the server, and return (base_url, solver). The two-step bind lets the
/// protected-`url` binding match the actual request URL.
async fn spawn_http(fixture: &CaFixture, zone: &str) -> (String, Arc<MemSolver>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let (state, solver) = acme_state_for(fixture, &base, zone);
    let app = axum::Router::new().nest("/acme", koi_certmesh::acme::routes(state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, solver)
}

// ── Raw JWS request builders ─────────────────────────────────────────

struct ClientKey {
    sk: SigningKey,
}

impl ClientKey {
    fn new() -> Self {
        Self {
            sk: SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
        }
    }

    fn jwk_value(&self) -> Value {
        let point = self.sk.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64().encode(point.x().unwrap()),
            "y": b64().encode(point.y().unwrap()),
        })
    }

    fn thumbprint(&self) -> String {
        let v = self.jwk_value();
        let canonical = format!(
            "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
            v["crv"].as_str().unwrap(),
            v["kty"].as_str().unwrap(),
            v["x"].as_str().unwrap(),
            v["y"].as_str().unwrap(),
        );
        b64().encode(Sha256::digest(canonical.as_bytes()))
    }

    fn sign_jwk(&self, nonce: &str, url: &str, payload: &Value) -> Value {
        let protected =
            json!({"alg": "ES256", "nonce": nonce, "url": url, "jwk": self.jwk_value()});
        self.finish(protected, payload)
    }

    fn sign_kid(&self, nonce: &str, url: &str, kid: &str, payload: &Value) -> Value {
        let protected = json!({"alg": "ES256", "nonce": nonce, "url": url, "kid": kid});
        self.finish(protected, payload)
    }

    fn finish(&self, protected: Value, payload: &Value) -> Value {
        let protected_b64 = b64().encode(serde_json::to_vec(&protected).unwrap());
        let payload_b64 = if payload.is_null() {
            String::new()
        } else {
            b64().encode(serde_json::to_vec(payload).unwrap())
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: Signature = self.sk.sign(signing_input.as_bytes());
        json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64().encode(sig.to_bytes()),
        })
    }
}

// ── HTTP helpers ─────────────────────────────────────────────────────

struct Resp {
    status: u16,
    nonce: Option<String>,
    location: Option<String>,
    body: Vec<u8>,
}

async fn post_jose(client: &reqwest::Client, url: &str, jws: &Value) -> Resp {
    let r = client
        .post(url)
        .header("content-type", "application/jose+json")
        .body(serde_json::to_vec(jws).unwrap())
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let nonce = r
        .headers()
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let location = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = r.bytes().await.unwrap().to_vec();
    Resp {
        status,
        nonce,
        location,
        body,
    }
}

async fn fresh_nonce(client: &reqwest::Client, base: &str) -> String {
    let r = client
        .get(format!("{base}/acme/new-nonce"))
        .send()
        .await
        .unwrap();
    r.headers()
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("new-nonce must return a Replay-Nonce")
}

fn body_json(resp: &Resp) -> Value {
    serde_json::from_slice(&resp.body).unwrap_or(Value::Null)
}

async fn register_account(
    client: &reqwest::Client,
    base: &str,
    key: &ClientKey,
) -> (String, String) {
    let nonce = fresh_nonce(client, base).await;
    let url = format!("{base}/acme/new-account");
    let jws = key.sign_jwk(&nonce, &url, &json!({"termsOfServiceAgreed": true}));
    let resp = post_jose(client, &url, &jws).await;
    assert!(
        resp.status == 200 || resp.status == 201,
        "newAccount should succeed, got {} body={}",
        resp.status,
        String::from_utf8_lossy(&resp.body)
    );
    (resp.location.expect("account Location"), key.thumbprint())
}

fn make_csr_der(sans: &[&str]) -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    let dns: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = rcgen::CertificateParams::new(dns).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, sans[0]);
    let csr = params.serialize_request(&key).unwrap();
    csr.der().to_vec()
}

// ── SECURITY GATE TEST 3: out-of-zone identifier → rejectedIdentifier ─

#[tokio::test]
async fn raw_out_of_zone_identifier_is_rejected() {
    let ca = build_ca();
    let (base, _solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, _tp) = register_account(&client, &base, &key).await;

    let nonce = fresh_nonce(&client, &base).await;
    let url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "evil.example.com"}]});
    let jws = key.sign_kid(&nonce, &url, &acct, &payload);
    let resp = post_jose(&client, &url, &jws).await;

    assert_eq!(resp.status, 400, "out-of-zone order must be 400");
    let body = body_json(&resp);
    assert_eq!(
        body["type"].as_str(),
        Some("urn:ietf:params:acme:error:rejectedIdentifier"),
        "out-of-zone identifier must be rejectedIdentifier, got {body}"
    );
    assert!(
        resp.nonce.is_some(),
        "even errors carry a fresh Replay-Nonce"
    );
}

// ── SECURITY GATE TEST 2: wildcard in-zone order succeeds ────────────

#[tokio::test]
async fn raw_wildcard_in_zone_order_succeeds() {
    let ca = build_ca();
    let (base, _solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, _tp) = register_account(&client, &base, &key).await;

    let nonce = fresh_nonce(&client, &base).await;
    let url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "*.lan"}]});
    let jws = key.sign_kid(&nonce, &url, &acct, &payload);
    let resp = post_jose(&client, &url, &jws).await;

    assert_eq!(
        resp.status,
        201,
        "wildcard in-zone order must be created, body={}",
        String::from_utf8_lossy(&resp.body)
    );
    let body = body_json(&resp);
    assert_eq!(body["identifiers"][0]["value"].as_str(), Some("*.lan"));
}

// ── SECURITY GATE TEST 4: wrong-key JWS rejected ─────────────────────

#[tokio::test]
async fn raw_wrong_key_jws_is_rejected() {
    let ca = build_ca();
    let (base, _solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, _tp) = register_account(&client, &base, &key).await;

    // Sign with a DIFFERENT key than the account, but claim the account's kid.
    let attacker = ClientKey::new();
    let nonce = fresh_nonce(&client, &base).await;
    let url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "host.lan"}]});
    let forged = attacker.sign_kid(&nonce, &url, &acct, &payload);
    let resp = post_jose(&client, &url, &forged).await;

    assert_eq!(resp.status, 403, "wrong-key JWS must be rejected (403)");
    let body = body_json(&resp);
    assert_eq!(
        body["type"].as_str(),
        Some("urn:ietf:params:acme:error:unauthorized"),
        "wrong-key signature must be unauthorized, got {body}"
    );
}

// ── SECURITY GATE TEST 5: nonce replay → badNonce ────────────────────

#[tokio::test]
async fn raw_nonce_replay_is_bad_nonce() {
    let ca = build_ca();
    let (base, _solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, _tp) = register_account(&client, &base, &key).await;

    let nonce = fresh_nonce(&client, &base).await;
    let url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "host.lan"}]});

    let jws1 = key.sign_kid(&nonce, &url, &acct, &payload);
    let r1 = post_jose(&client, &url, &jws1).await;
    assert_eq!(r1.status, 201, "first use of the nonce succeeds");

    // Reuse the SAME nonce.
    let jws2 = key.sign_kid(&nonce, &url, &acct, &payload);
    let r2 = post_jose(&client, &url, &jws2).await;
    assert_eq!(r2.status, 400, "replayed nonce must be 400");
    let body = body_json(&r2);
    assert_eq!(
        body["type"].as_str(),
        Some("urn:ietf:params:acme:error:badNonce"),
        "replayed nonce must be badNonce, got {body}"
    );
    assert!(
        r2.nonce.is_some(),
        "badNonce response must STILL carry a fresh Replay-Nonce (recoverable)"
    );
}

// ── SECURITY GATE TEST 6: unauthorized SAN at finalize rejected ──────

#[tokio::test]
async fn raw_finalize_with_unauthorized_san_is_rejected() {
    let ca = build_ca();
    let (base, solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, thumbprint) = register_account(&client, &base, &key).await;

    // Order ONE name: authorized.lan.
    let nonce = fresh_nonce(&client, &base).await;
    let order_url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "authorized.lan"}]});
    let order_resp = post_jose(
        &client,
        &order_url,
        &key.sign_kid(&nonce, &order_url, &acct, &payload),
    )
    .await;
    assert_eq!(order_resp.status, 201);
    let order = body_json(&order_resp);
    let order_loc = order_resp.location.unwrap();
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let finalize_url = order["finalize"].as_str().unwrap().to_string();

    // Fetch the authz to get the challenge token + url.
    let nonce = fresh_nonce(&client, &base).await;
    let authz_resp = post_jose(
        &client,
        &authz_url,
        &key.sign_kid(&nonce, &authz_url, &acct, &Value::Null),
    )
    .await;
    let authz = body_json(&authz_resp);
    let chall = &authz["challenges"][0];
    let token = chall["token"].as_str().unwrap();
    let chall_url = chall["url"].as_str().unwrap().to_string();

    // Write the correct dns-01 TXT into the shared solver, then validate.
    let key_auth = format!("{token}.{thumbprint}");
    let txt = b64().encode(Sha256::digest(key_auth.as_bytes()));
    solver.set_txt("_acme-challenge.authorized.lan", &txt);

    let nonce = fresh_nonce(&client, &base).await;
    let chall_resp = post_jose(
        &client,
        &chall_url,
        &key.sign_kid(&nonce, &chall_url, &acct, &json!({})),
    )
    .await;
    assert_eq!(chall_resp.status, 200, "challenge trigger ok");

    // Confirm the order is now ready.
    let nonce = fresh_nonce(&client, &base).await;
    let order_resp = post_jose(
        &client,
        &order_loc,
        &key.sign_kid(&nonce, &order_loc, &acct, &Value::Null),
    )
    .await;
    assert_eq!(body_json(&order_resp)["status"].as_str(), Some("ready"));

    // CSR asks for an EXTRA, unauthorized name (evil.lan). Finalize must reject.
    let csr_der = make_csr_der(&["authorized.lan", "evil.lan"]);
    let nonce = fresh_nonce(&client, &base).await;
    let finalize_payload = json!({"csr": b64().encode(&csr_der)});
    let fin_resp = post_jose(
        &client,
        &finalize_url,
        &key.sign_kid(&nonce, &finalize_url, &acct, &finalize_payload),
    )
    .await;

    assert_eq!(
        fin_resp.status,
        400,
        "a CSR with an unauthorized SAN must be rejected at finalize, body={}",
        String::from_utf8_lossy(&fin_resp.body)
    );
    let body = body_json(&fin_resp);
    assert_eq!(
        body["type"].as_str(),
        Some("urn:ietf:params:acme:error:badCSR"),
        "unauthorized SAN must be badCSR, got {body}"
    );
}

// ── A positive end-to-end raw issuance (proves the happy path works at the
//    handler level even without instant-acme) ──────────────────────────

#[tokio::test]
async fn raw_full_issuance_chains_to_ca() {
    let ca = build_ca();
    let (base, solver) = spawn_http(&ca, "lan").await;
    let client = reqwest::Client::new();
    let key = ClientKey::new();
    let (acct, thumbprint) = register_account(&client, &base, &key).await;

    // Order grafana.lan.
    let nonce = fresh_nonce(&client, &base).await;
    let order_url = format!("{base}/acme/new-order");
    let payload = json!({"identifiers": [{"type": "dns", "value": "grafana.lan"}]});
    let order_resp = post_jose(
        &client,
        &order_url,
        &key.sign_kid(&nonce, &order_url, &acct, &payload),
    )
    .await;
    assert_eq!(order_resp.status, 201);
    let order = body_json(&order_resp);
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let finalize_url = order["finalize"].as_str().unwrap().to_string();

    // dns-01.
    let nonce = fresh_nonce(&client, &base).await;
    let authz_resp = post_jose(
        &client,
        &authz_url,
        &key.sign_kid(&nonce, &authz_url, &acct, &Value::Null),
    )
    .await;
    let authz = body_json(&authz_resp);
    let token = authz["challenges"][0]["token"].as_str().unwrap();
    let chall_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
    let key_auth = format!("{token}.{thumbprint}");
    let txt = b64().encode(Sha256::digest(key_auth.as_bytes()));
    solver.set_txt("_acme-challenge.grafana.lan", &txt);

    let nonce = fresh_nonce(&client, &base).await;
    post_jose(
        &client,
        &chall_url,
        &key.sign_kid(&nonce, &chall_url, &acct, &json!({})),
    )
    .await;

    // Finalize with a matching CSR.
    let csr_der = make_csr_der(&["grafana.lan"]);
    let nonce = fresh_nonce(&client, &base).await;
    let fin_resp = post_jose(
        &client,
        &finalize_url,
        &key.sign_kid(
            &nonce,
            &finalize_url,
            &acct,
            &json!({"csr": b64().encode(&csr_der)}),
        ),
    )
    .await;
    assert_eq!(
        fin_resp.status,
        200,
        "finalize must succeed, body={}",
        String::from_utf8_lossy(&fin_resp.body)
    );
    let fin = body_json(&fin_resp);
    assert_eq!(fin["status"].as_str(), Some("valid"));
    let cert_url = fin["certificate"].as_str().unwrap().to_string();

    // Download the cert chain (POST-as-GET).
    let nonce = fresh_nonce(&client, &base).await;
    let cert_resp = post_jose(
        &client,
        &cert_url,
        &key.sign_kid(&nonce, &cert_url, &acct, &Value::Null),
    )
    .await;
    assert_eq!(cert_resp.status, 200);
    let chain = String::from_utf8(cert_resp.body).unwrap();
    assert!(chain.contains("BEGIN CERTIFICATE"));
    assert_verifies_to_ca(&chain, &ca.ca_pem, "grafana.lan");
}

// ── CONFORMANCE TEST 1 (the headline): instant-acme end-to-end over TLS ──
//
// instant-acme 0.8.5's `Account::builder_with_root(pem_path)` requires HTTPS and
// pins a custom CA root (hyper-rustls). So we stand up the ACME router behind a
// rustls TLS server using the daemon's self-issued leaf (SAN includes `localhost`
// + `127.0.0.1`), set the directory base to `https://localhost:<port>`, and write
// the CA PEM to a temp file for `builder_with_root`. The dns-01 challenge value is
// written into the SAME solver the AcmeState reads from, so validation is
// in-process. This proves the full RFC 8555 issuance path with a real client.

#[tokio::test]
async fn conformance_issues_cert_via_dns01() {
    // Install the default crypto provider for rustls (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = build_ca();

    // Daemon leaf for the TLS server (SAN covers localhost + 127.0.0.1).
    let enrollment = ca
        .core
        .self_enroll()
        .await
        .expect("self-enroll daemon leaf");

    // Bind first to learn the port, then build the state with the matching base.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("https://localhost:{}", addr.port());
    let (state, solver) = acme_state_for(&ca, &base, "lan");
    let app = axum::Router::new().nest("/acme", koi_certmesh::acme::routes(state));

    // rustls server config from the daemon leaf.
    let tls = server_tls_config(&enrollment.cert_pem, &enrollment.key_pem);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    // Serve TLS connections in the background.
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper_util::service::TowerToHyperService::new(app);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await;
            });
        }
    });

    // Write the CA root to a temp PEM file for builder_with_root.
    let ca_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ca_file.path(), ca.ca_pem.as_bytes()).unwrap();

    // ── Drive the full ACME flow with instant-acme ──
    use instant_acme::{
        Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
    };

    let directory_url = format!("{base}/acme/directory");
    let (account, _credentials): (Account, _) = Account::builder_with_root(ca_file.path())
        .expect("builder_with_root")
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .expect("newAccount");

    let identifiers = [Identifier::Dns("grafana.lan".to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .expect("new_order");

    // Iterate authorizations (stream API), set the dns-01 TXT, mark ready. The
    // iteration is scoped so the mutable borrow of `order` ends before poll_ready.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.expect("authorization");
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .expect("dns-01 challenge");
            let identifier = challenge.identifier().to_string();
            let dns_value = challenge.key_authorization().dns_value();
            // Write the TXT into the SAME solver the server reads from.
            solver.set_txt(&format!("_acme-challenge.{identifier}"), &dns_value);
            challenge.set_ready().await.expect("set_ready");
        }
    }

    // Poll the order to ready, finalize (instant-acme auto-generates key+CSR),
    // and download the certificate.
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .expect("poll_ready");
    assert_eq!(status, OrderStatus::Ready, "order must reach ready");

    let _private_key_pem = order.finalize().await.expect("finalize");
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .expect("poll_certificate");

    assert!(
        chain.contains("BEGIN CERTIFICATE"),
        "downloaded a PEM certificate chain"
    );
    // The headline assertion: the issued chain validates to the Koi CA.
    assert_verifies_to_ca(&chain, &ca.ca_pem, "grafana.lan");

    let _ = ca_file; // keep the temp CA file alive until here
}

/// Build a rustls ServerConfig (server-auth only) from a leaf PEM + key PEM.
fn server_tls_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
}

/// Assert the leaf in `chain_pem` is signed by the CA and carries `expected_san`.
fn assert_verifies_to_ca(chain_pem: &str, ca_pem: &str, expected_san: &str) {
    use x509_parser::prelude::*;

    let pems: Vec<_> = ::pem::parse_many(chain_pem).unwrap();
    assert!(pems.len() >= 2, "chain must include leaf + CA");
    let ca_pem_parsed = ::pem::parse(ca_pem).unwrap();
    let (_, leaf) = X509Certificate::from_der(pems[0].contents()).unwrap();
    let (_, ca) = X509Certificate::from_der(ca_pem_parsed.contents()).unwrap();

    assert_eq!(
        leaf.issuer().to_string(),
        ca.subject().to_string(),
        "leaf issuer must equal CA subject"
    );
    assert!(
        leaf.verify_signature(Some(ca.public_key())).is_ok(),
        "leaf must be signed by the CA"
    );
    // SAN check.
    let sans: Vec<String> = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        sans.iter().any(|s| s == expected_san),
        "leaf must carry the authorized SAN {expected_san}, has {sans:?}"
    );
}
