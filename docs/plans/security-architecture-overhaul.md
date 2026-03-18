# Security & Architecture Overhaul Plan

> Generated from full codebase review (87 findings: 17 CRITICAL, 25 HIGH, 45 MEDIUM)

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Network model | LAN-accessible | Multi-machine certmesh, mDNS browsing |
| Local auth | Daemon Access Token (DAT) | Simple, no TLS needed for CLI |
| Inter-node auth | mTLS via certmesh certs | Eat our own dogfood |
| Port architecture | 5641 (HTTP+DAT) + 5642 (HTTPS/mTLS) | Clean separation |
| `/join` bootstrap | TOTP on HTTP port (5641) | Pre-cert, can't do mTLS yet |
| FIDO2 unlock | Gate behind `feature = "fido2-unlock"` | Experimental, needs redesign |
| Cross-domain deps | Trait injection via koi-common | Greenfield, no back-compat |
| Promotion protocol | Ephemeral X25519 DH key agreement | Forward secrecy, no passphrase on wire |
| Key material | `SecretBytes`/`SecretString` newtypes | Zeroize-on-drop everywhere |

---

## Work Streams

### WS-1: Foundation Types (koi-crypto + koi-common)

**Goal**: Establish the building blocks everything else depends on.

#### 1a. `SecretBytes` / `SecretString` newtypes (koi-crypto)

New file: `crates/koi-crypto/src/secret.rs`

```rust
use zeroize::Zeroizing;

/// Zeroize-on-drop byte container for key material.
/// Debug prints [REDACTED]. No Clone.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

/// Zeroize-on-drop string container for PEM keys, hex-encoded secrets.
/// Debug prints [REDACTED]. No Clone.
pub struct SecretString(Zeroizing<String>);
```

Migrate all key material flows:
- `derive_aes_key` → returns `SecretBytes`
- `encrypt_bytes` / `decrypt_bytes` → accept `&SecretBytes` for key
- `EncryptedKey` → remove `Clone`, `Debug` prints `[REDACTED]`
- `BackupPayload.ca_key_pem` → `SecretString`
- `private_key_pem()` → returns `SecretString` (already does via `Zeroizing<String>`)
- All hex-encoded key strings in unlock_slots → `SecretString`

#### 1b. Argon2 explicit params (koi-crypto)

Add to `EncryptedKey` struct:
```rust
pub struct EncryptedKey {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    // NEW: explicit KDF params stored with ciphertext
    #[serde(default = "default_argon2_params")]
    pub kdf_params: KdfParams,
}

pub struct KdfParams {
    pub algorithm: String,  // "argon2id"
    pub m_cost: u32,        // 65536 (64 MiB)
    pub t_cost: u32,        // 3
    pub p_cost: u32,        // 4
}
```

`derive_aes_key` reads params from `KdfParams`, not library defaults.

#### 1c. File permission helper (koi-common or koi-crypto)

```rust
/// Write bytes to file with 0600 permissions on Unix.
pub fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()>
```

Used by: `save_encrypted_key`, `SlotTable::save`, `save_auto_unlock_key`, audit log.

#### 1d. Integration traits (koi-common)

New file: `crates/koi-common/src/integration.rs`

```rust
// Summary types (live in koi-common, no domain imports needed)
pub struct MemberSummary {
    pub hostname: String,
    pub sans: Vec<String>,
    pub cert_expires: Option<DateTime<Utc>>,
    pub status: String,
    pub proxy_entries: Vec<ProxyConfigSummary>,
}
pub struct ProxyConfigSummary { pub name: String, pub listen_port: u16, pub backend: String, pub allow_remote: bool }
pub struct ProxyEntrySummary { pub name: String, pub listen_port: u16, pub backend: String }

// Traits implemented by binary crate bridge types
pub trait CertmeshSnapshot: Send + Sync {
    fn active_members(&self) -> Vec<MemberSummary>;
}
pub trait MdnsSnapshot: Send + Sync {
    fn host_ips(&self) -> HashMap<String, IpAddr>;
    fn subscribe_browse(&self) -> Option<broadcast::Receiver<ServiceRecord>>;
}
pub trait DnsProbe: Send + Sync {
    fn resolve_local(&self, name: &str) -> Option<Vec<IpAddr>>;
}
pub trait ProxySnapshot: Send + Sync {
    fn entries(&self) -> Vec<ProxyEntrySummary>;
}
```

---

### WS-2: Auth Infrastructure (koi + koi-common + koi-config)

**Goal**: DAT for local clients, mTLS for inter-node.

#### 2a. DAT generation and breadcrumb

`koi-config/src/breadcrumb.rs`:
- New format: `endpoint\ndat:<base64-token>`
- `write_breadcrumb(endpoint: &str, token: &str)`
- `read_breadcrumb() -> Option<BreadcrumbInfo>` where `BreadcrumbInfo { endpoint, token }`
- File permissions: 0600 on Unix, restricted ACL on Windows

`koi/src/main.rs` (daemon_mode):
- Generate 256-bit token via `OsRng`
- Pass to `write_breadcrumb`
- Pass to HTTP adapter for middleware

#### 2b. Auth middleware (koi/src/adapters/http.rs)

```rust
// axum middleware layer
async fn dat_auth(
    State(expected_token): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Response {
    // Read-only GET endpoints: pass through
    // Mutation endpoints: require X-Koi-Token header or ?token= query param
    // Reject with 401 if missing/invalid
}
```

Route classification:
- **Public** (no auth): `GET /healthz`, `GET /docs`, `GET /openapi.json`, `GET /` (dashboard HTML shell)
- **DAT required**: everything else

#### 2c. CORS lockdown

Replace `CorsLayer::permissive()` with:
```rust
CorsLayer::new()
    .allow_origin([
        "http://localhost".parse().unwrap(),
        "http://127.0.0.1".parse().unwrap(),
        format!("http://localhost:{port}").parse().unwrap(),
        format!("http://127.0.0.1:{port}").parse().unwrap(),
    ])
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-koi-token")])
```

#### 2d. Dashboard token injection

In `get_dashboard` handler: inject DAT into HTML via `<meta name="koi-token" content="...">`.
Dashboard JS reads it and attaches to all fetch calls.

#### 2e. KoiClient token attachment

`koi-client/src/lib.rs`:
- `KoiClient::new(endpoint, token)` — store token
- All requests: `.set("X-Koi-Token", &self.token)`
- `KoiClient::from_breadcrumb()` — reads both endpoint and token

#### 2f. mTLS listener (koi/src/adapters/mtls.rs)

New file. Second axum listener on port 5642:
- `rustls::ServerConfig` with certmesh CA cert as client CA
- `verify_peer = required` (except `/join` which has `verify_peer = optional`)
- Routes: only certmesh inter-node endpoints
- Extract client cert CN → use as authenticated hostname

```rust
pub async fn start_mtls(
    port: u16,
    certmesh_core: Arc<CertmeshCore>,
    ca_cert_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
    cancel: CancellationToken,
) -> anyhow::Result<()>
```

Certmesh inter-node routes on mTLS port:
- `POST /v1/certmesh/promote` — mTLS + TOTP
- `POST /v1/certmesh/health` — mTLS (CN = authenticated hostname)
- `GET /v1/certmesh/roster` — mTLS
- `POST /v1/certmesh/renew` — mTLS (CN = authenticated hostname)
- `PUT /v1/certmesh/set-hook` — mTLS (CN must match request hostname)

`/join` stays on HTTP port 5641, DAT + TOTP auth.

---

### WS-3: Key Material Hardening (koi-crypto + koi-certmesh)

**Goal**: All secrets zeroized, properly encrypted, platform-sealed where possible.

#### 3a. TOTP secret encryption in slot table

Currently: `shared_secret_hex: String` (plaintext).
Fix: encrypt with passphrase-derived KEK (same mechanism as passphrase slot).

```rust
UnlockSlot::Totp {
    encrypted_shared_secret: EncryptedKey,  // was: shared_secret_hex: String
    wrapped_master_key: EncryptedKey,
}
```

`add_totp_slot(passphrase, shared_secret, master_key)`:
1. Derive KEK from passphrase via Argon2id
2. Encrypt shared_secret with KEK → `encrypted_shared_secret`
3. Encrypt master_key with shared_secret-derived key → `wrapped_master_key`

`unwrap_with_totp(passphrase, totp_code)`:
1. Derive KEK from passphrase
2. Decrypt shared_secret from `encrypted_shared_secret`
3. Verify TOTP code against decrypted secret
4. Derive key from shared_secret, decrypt `wrapped_master_key`

#### 3b. FIDO2 gating

- Add `fido2-unlock` feature to `koi-crypto/Cargo.toml`
- Gate all FIDO2 slot code behind `#[cfg(feature = "fido2-unlock")]`
- Default features: do NOT include `fido2-unlock`
- Add `// TODO: redesign FIDO2 slot — assertion-gated unlock with platform sealing` comment

#### 3c. Auto-unlock via platform credential store

Replace plaintext file with platform sealing:
```rust
// koi-crypto/src/auto_unlock.rs
pub fn seal_auto_unlock(passphrase: &str) -> Result<(), CryptoError> {
    #[cfg(windows)]
    { dpapi::encrypt_and_store(passphrase) }
    #[cfg(target_os = "macos")]
    { keychain::store("org.sylin.koi.auto-unlock", passphrase) }
    #[cfg(target_os = "linux")]
    { secret_service::store("koi-auto-unlock", passphrase) }
}

pub fn unseal_auto_unlock() -> Result<SecretString, CryptoError> { ... }
```

Fallback: if no platform store available, write to file with `write_secret_file` (0600 perms) + log warning.

#### 3d. Promotion protocol — X25519 DH

Add `x25519-dalek` dependency to koi-crypto.

New file: `crates/koi-crypto/src/key_agreement.rs`
```rust
pub struct EphemeralKeyPair { secret: x25519_dalek::EphemeralSecret, public: x25519_dalek::PublicKey }
pub fn generate_ephemeral() -> EphemeralKeyPair
pub fn derive_shared_secret(our_secret: EphemeralSecret, their_public: &[u8; 32]) -> SecretBytes
// HKDF-SHA256(shared_secret, info="koi-promote-v1") → 256-bit encryption key
```

Protocol change:
```rust
// Request (from standby CLI)
pub struct PromoteRequest {
    pub auth: AuthChallenge,          // TOTP code
    pub ephemeral_public: [u8; 32],   // X25519 public key
}

// Response (from primary)
pub struct PromoteResponse {
    pub ephemeral_public: [u8; 32],     // Server's X25519 public key
    pub encrypted_ca_key: Vec<u8>,      // CA key encrypted with DH-derived key
    pub encrypted_auth_data: Vec<u8>,   // Auth state encrypted with DH-derived key
    pub encrypted_roster: Vec<u8>,      // Roster encrypted with DH-derived key
    pub ca_fingerprint: String,
}
```

#### 3e. `expect()`/`unwrap()` on PEM methods

`keys.rs`: `public_key_pem()` and `private_key_pem()` → return `Result<_, CryptoError>`.

#### 3f. TOTP constant-time fix

Remove length short-circuit:
```rust
fn verify_code(code: &str, expected: &str) -> bool {
    let code_bytes = code.as_bytes();
    let expected_bytes = expected.as_bytes();
    // Pad shorter to match length, then ct_eq
    let len_match = code_bytes.len().ct_eq(&expected_bytes.len());
    let content_match = if code_bytes.len() == expected_bytes.len() {
        code_bytes.ct_eq(expected_bytes)
    } else {
        0u8.ct_eq(&1u8)  // always false, constant time
    };
    (len_match & content_match).into()
}
```

---

### WS-4: Cross-Domain Architecture Rebuild

**Goal**: Remove ALL cross-domain Cargo.toml dependencies. Domain crates depend only on koi-common.

#### 4a. Remove cross-domain deps from Cargo.toml

- `koi-health/Cargo.toml`: remove `koi-certmesh`, `koi-dns`, `koi-mdns`, `koi-proxy`
- `koi-dns/Cargo.toml`: remove `koi-certmesh`, `koi-mdns`
- `koi-proxy/Cargo.toml`: remove `koi-certmesh`

#### 4b. Refactor koi-health constructors

```rust
// Before:
pub fn new(mdns: Option<Arc<MdnsCore>>, dns: Option<Arc<DnsRuntime>>, ...) -> Self

// After:
pub fn new(
    mdns: Option<Arc<dyn MdnsSnapshot>>,
    dns: Option<Arc<dyn DnsProbe>>,
    certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    proxy: Option<Arc<dyn ProxySnapshot>>,
    ...
) -> Self
```

- `machine.rs`: use `CertmeshSnapshot::active_members()` instead of `koi_certmesh::roster::load_roster()`
- `machine.rs`: use `MdnsSnapshot::subscribe_browse()` instead of `koi_mdns::MdnsCore::browse()`
- `machine.rs`: use `DnsProbe::resolve_local()` instead of `koi_dns::DnsRuntime::core().resolve_local()`
- `lib.rs` + `checker.rs`: use `ProxySnapshot::entries()` instead of `koi_proxy::config::load_entries()`
- Delete duplicate `proxy_checks()` from `checker.rs` (M-37)

#### 4c. Refactor koi-dns constructors

```rust
// Before:
pub fn new(config, certmesh: Option<Arc<CertmeshCore>>, mdns_cache: Option<MdnsCache>)

// After:
pub fn new(config, certmesh: Option<Arc<dyn CertmeshSnapshot>>, mdns: Option<Arc<dyn MdnsSnapshot>>)
```

- `records.rs`: use `CertmeshSnapshot::active_members()` + `MdnsSnapshot::host_ips()`
- `resolver.rs`: remove direct roster/mdns imports

#### 4d. Refactor koi-proxy config loading

```rust
// Before: koi_proxy::config::load_entries_from_roster() imports koi_certmesh
// After: ProxyCore receives Option<Arc<dyn CertmeshSnapshot>> at construction

pub fn new(certmesh: Option<Arc<dyn CertmeshSnapshot>>, ...) -> Self
```

`load_entries` becomes a method on `ProxyCore` that merges local config + `certmesh.proxy_entries()`.

Move `ProxyConfigEntry` → `koi_common::integration::ProxyConfigSummary`.

#### 4e. Binary crate bridge implementations

New file: `crates/koi/src/integrations.rs`

```rust
struct CertmeshBridge(Arc<CertmeshCore>);
impl CertmeshSnapshot for CertmeshBridge { ... }

struct MdnsBridge(Arc<MdnsCore>);
impl MdnsSnapshot for MdnsBridge { ... }

struct DnsBridge(Arc<DnsRuntime>);
impl DnsProbe for DnsBridge { ... }

struct ProxyBridge(Arc<ProxyCore>);
impl ProxySnapshot for ProxyBridge { ... }
```

Wire in `daemon_mode` and `run_service`:
```rust
let certmesh_snap: Option<Arc<dyn CertmeshSnapshot>> = certmesh_core.as_ref().map(|c| Arc::new(CertmeshBridge(c.clone())) as _);
let mdns_snap: Option<Arc<dyn MdnsSnapshot>> = mdns_core.as_ref().map(|c| Arc::new(MdnsBridge(c.clone())) as _);
// ... pass to domain constructors
```

---

### WS-5: Panic Elimination

**Goal**: Zero `unwrap()`/`expect()` in production code paths.

#### 5a. Mutex poison recovery pattern

Apply across all crates. Mechanical replacement:
```rust
// Before:
self.state.lock().unwrap()
// After:
self.state.lock().unwrap_or_else(|e| { tracing::warn!("mutex poisoned, recovering"); e.into_inner() })
```

Files: `koi-mdns/daemon.rs`, `koi-mdns/registry.rs` (12 sites), `koi-dns/resolver.rs` (9 sites), `koi-dns/safety.rs`, `koi-common/ceremony.rs` (4 sites).

For ceremony.rs specifically: switch to `tokio::sync::Mutex` and restructure `evaluate` to run outside the lock.

#### 5b. Serialization safety

SSE paths in `koi-mdns/http.rs` (3 sites):
```rust
// Before:
let data = serde_json::to_string(&resp).unwrap();
// After:
let data = match serde_json::to_string(&resp) {
    Ok(d) => d,
    Err(e) => { tracing::error!(error = %e, "SSE serialization failed"); break; }
};
```

Admin inspect handler: `Json(admin).into_response()` instead of `Json(to_value(admin).unwrap())`.

#### 5c. Other panics

- `DnsCore::clone()`: store `DnsZone` directly (it should derive `Clone`), don't re-validate
- `forwarder.rs`: `body()` → `map_err(|e| ProxyError::Forward(e.to_string()))?`
- `truncate_str`: use `s.chars().take(max-1).collect::<String>()` + `"…"`
- `totp.rs:295`: `to_bytes().map_err(...)? ` instead of `.unwrap()`
- `keys.rs:91`: `from_bytes` → return `CryptoError` instead of `expect`
- `http.rs` OpenAPI serialization: propagate error via `?`

---

### WS-6: Async/Blocking Hygiene

#### 6a. `detect_mode` → `spawn_blocking`

```rust
pub(crate) async fn detect_mode(cli: &Cli) -> Mode {
    // ... breadcrumb read is fast (file I/O)
    // ... health check is blocking ureq
    tokio::task::spawn_blocking(move || {
        let c = KoiClient::from_breadcrumb()?;
        c.health().ok().map(|_| Mode::Client { endpoint })
    }).await.ok().flatten().unwrap_or(Mode::Standalone)
}
```

#### 6b. Reload hook — release lock before exec

```rust
// certmesh/lib.rs receive_renewal
let hook = {
    let roster = state.roster.lock().await;
    roster.find_member(&hostname).and_then(|m| m.reload_hook.clone())
};
// Lock dropped here
if let Some(hook) = hook {
    tokio::task::spawn_blocking(move || lifecycle::execute_reload_hook(&hook)).await??;
}
```

#### 6c. Set-hook input validation (defense-in-depth)

```rust
fn validate_reload_hook(hook: &str) -> Result<(), CertmeshError> {
    // Must be an absolute path to an executable, no shell metacharacters
    // Reject: pipes, semicolons, backticks, $(), &&, ||
    let forbidden = ['|', ';', '`', '$', '&', '>', '<', '\n', '\r'];
    if hook.chars().any(|c| forbidden.contains(&c)) {
        return Err(CertmeshError::InvalidPayload("hook contains shell metacharacters".into()));
    }
    // Must start with / (Unix) or drive letter (Windows)
    #[cfg(unix)]
    if !hook.starts_with('/') {
        return Err(CertmeshError::InvalidPayload("hook must be absolute path".into()));
    }
    Ok(())
}
```

Execute without shell:
```rust
// Before: Command::new("sh").args(["-c", hook])
// After:  Command::new(hook_path).args(hook_args)  // split on whitespace, no shell
```

#### 6d. Other async fixes

- `koi-proxy/safety.rs`: `tokio::net::lookup_host` instead of `to_socket_addrs`
- `koi-health/log.rs`: `tokio::fs::OpenOptions` + `.await`
- `koi-embedded/lib.rs`: remove `set_var`, pass `data_dir` through `RuntimeConfig` struct
- `commands/mdns.rs`: store `JoinHandle`, `.join()` after signal, use `Acquire`/`Release` ordering

---

### WS-7: Resource Leaks & Correctness

#### 7a. mdns-sd boundary fix (browse.rs)

Move event conversion into `daemon.rs`. `MdnsDaemon::browse()` returns `tokio::sync::mpsc::Receiver<MdnsEvent>` (Koi's own type). Worker thread pumps mdns-sd events, converts to Koi types, sends on tokio channel. `browse.rs` never imports mdns-sd.

#### 7b. Resolve leak fix (daemon.rs)

Add `stop_browse` call on channel close path:
```rust
Err(_) => {
    let _ = self.stop_browse(service_type);
    break;
}
```

#### 7c. Bounded worker channel (daemon.rs)

```rust
let (op_tx, op_rx) = std::sync::mpsc::sync_channel(256);
```

#### 7d. pump_tasks drain (browser.rs)

```rust
pump_tasks.retain(|h| !h.is_finished());
```
Add after each new task push or on a periodic timer.

#### 7e. Proxy config file locking

Use `fs2::FileExt::lock_exclusive()` in `save_entries` / `load_entries`.

#### 7f. UDP max lease cap

```rust
const MAX_LEASE_SECS: u64 = 86400; // 24h
let lease = request.lease_secs.unwrap_or(300).min(MAX_LEASE_SECS);
```

#### 7g. Heartbeat touch — use AtomicI64

```rust
pub fn touch(&self) {
    self.last_heartbeat_epoch.store(Utc::now().timestamp(), Ordering::Release);
}
```

#### 7h. Truststore path sanitization

```rust
fn sanitize_name(name: &str) -> Result<String, TruststoreError> {
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Ok(name.to_string())
    } else {
        Err(TruststoreError::InvalidName(name.into()))
    }
}
```

---

### WS-8: Binary Crate Cleanup

#### 8a. Daemon startup dedup

Extract from `main.rs` and `platform/windows.rs`:
```rust
// crates/koi/src/daemon.rs (new file)
pub struct DaemonRuntime { cores: DaemonCores, cancel: CancellationToken, ... }

pub async fn start_daemon(config: &Config, cancel: CancellationToken) -> anyhow::Result<DaemonRuntime>
pub async fn shutdown_daemon(runtime: DaemonRuntime) -> anyhow::Result<()>
```

Both `daemon_mode` and `run_service` call these.

#### 8b. Background task decomposition

Split `spawn_certmesh_background_tasks` into:
```rust
async fn run_renewal_loop(core: Arc<CertmeshCore>, cancel: CancellationToken)
async fn run_roster_sync_loop(core: Arc<CertmeshCore>, client: KoiClient, cancel: CancellationToken)
async fn run_health_heartbeat_loop(core: Arc<CertmeshCore>, client: KoiClient, cancel: CancellationToken)
async fn run_failover_loop(core: Arc<CertmeshCore>, client: KoiClient, cancel: CancellationToken)
```

#### 8c. Dashboard event forwarder dedup

Move `spawn_event_forwarder` to `koi-common::dashboard` (it already lives partially there).

#### 8d. Misc fixes

- `check_root`: use `libc::getuid()` on Unix
- `visible_width`: use `unicode-width` crate
- `lease_secs=0` → reject with 400 on HTTP (permanent only via session/pipe)
- `reqwest::Client` in health checker → shared client in `HealthCore`
- `proxy config.toml` parse error → propagate, don't silently discard
- `koi-client` URL encoding: `urlencoding::encode(name)` in path params
- Broadcast lag: log `tracing::warn!` on `Lagged` in SSE streams
- `SessionId` inner field → `pub(crate)`
- FQDN construction: only append `.local` if hostname has no dots
- `BrowserSnapshot` fields → `pub`
- `test.rs` → gate behind `#[cfg(any(test, feature = "test-utils"))]`, remove `OnceLock`
- `Builder` in koi-embedded → `#[must_use]`
- `MdnsHandle::subscribe` on Remote → return `Result` with error

---

## Execution Order

```
WS-1 (foundation) ──────────────────────────┐
                                             ├─→ WS-3 (key hardening)
WS-5 (panic elimination) ───────────────────┤
                                             ├─→ WS-2 (auth infra)
WS-4 (cross-domain rebuild) ────────────────┤
                                             ├─→ WS-6 (async hygiene)
WS-7 (resource leaks) ─────────────────────┤
                                             └─→ WS-8 (binary cleanup)
```

WS-1 and WS-5 have no deps and can run first (in parallel).
WS-4 depends on WS-1 (integration traits).
WS-2, WS-3 depend on WS-1 (SecretBytes).
WS-6, WS-7, WS-8 are mostly independent.

## Verification

After all changes:
```bash
cargo check
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

Then re-run the 6-agent review to verify all findings are resolved.
