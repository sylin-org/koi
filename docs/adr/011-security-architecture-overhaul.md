# ADR-011: Security & Architecture Overhaul

**Status:** Proposed
**Date:** 2026-03-18
**Supersedes:** Partially supersedes ADR-003 (envelope encryption slot details)

## Context

A full codebase review of all 14 workspace crates identified 87 findings: 17 CRITICAL, 25 HIGH, and 45 MEDIUM. The findings collapse into six root causes that require coordinated architectural fixes rather than isolated patches.

### Root Cause 1: Zero Authentication on a Network-Exposed Daemon

The HTTP adapter binds `0.0.0.0:5641` with no authentication middleware, no TLS, and `CorsLayer::permissive()`. Any device on the LAN can invoke every endpoint, including `POST /v1/admin/shutdown`, `POST /v1/certmesh/destroy`, and `PUT /v1/certmesh/set-hook` (which stores an arbitrary string later executed via `sh -c` — a direct remote code execution vector). Browsers on the LAN can exploit the permissive CORS to make cross-origin mutation requests from any web page.

### Root Cause 2: No Unified Key Material Lifecycle

Secrets appear as `String`, `Vec<u8>`, hex-encoded `String`, and raw `[u8; 32]` throughout koi-crypto and koi-certmesh. None are consistently zeroized on drop. The CA passphrase is written to disk in plaintext for auto-unlock. The TOTP shared secret is stored as plaintext hex in `unlock-slots.json`. `EncryptedKey` derives `Clone` and `Debug`, enabling silent duplication and log exposure of ciphertext. Argon2 parameters use library defaults and are not stored with the ciphertext, making cross-version decryption fragile.

### Root Cause 3: FIDO2 Unlock Slot Is Cryptographically Broken

The FIDO2 slot derives its storage key from `credential_id` via SHA-256. The WebAuthn specification defines `credential_id` as a public value transmitted in the clear during every authentication ceremony. Any observer of authentication traffic can reconstruct the storage key, decrypt the `slot_kek`, and recover the master key — bypassing the FIDO2 assertion entirely. The `sign_count` field exists for clone detection but is never enforced during unlock.

### Root Cause 4: Cross-Domain Cargo Dependencies Violate the Architecture Rule

The architecture document states: "Domain crates depend on `koi-common` but never on each other." In practice, `koi-health` imports four domain crates (`koi-proxy`, `koi-dns`, `koi-certmesh`, `koi-mdns`), `koi-dns` imports two (`koi-certmesh`, `koi-mdns`), and `koi-proxy` imports one (`koi-certmesh`). All violations are one-way, read-only data flows (roster member lists, proxy config entries, mDNS host IPs, DNS resolution probes), but they break the independence guarantee that enables crates to evolve, test, and publish independently.

### Root Cause 5: Promotion Protocol Encrypts CA Key With Empty Passphrase

The `promote_handler` calls `prepare_promotion(ca, auth, roster, "")`, encrypting the CA private key with an empty passphrase before returning it in the HTTP response. The CLI collects a passphrase locally and uses it to decrypt, but the server-side encryption with `""` means the key material is effectively unprotected in transit. Combined with the lack of TLS, the CA private key traverses the network in a trivially-decryptable form.

### Root Cause 6: Systematic `unwrap()`/`expect()` in Production Paths

Approximately 30 locations across the codebase use `unwrap()` or `expect()` on `Mutex::lock()`, `serde_json::to_string()`, `Response::body()`, string slicing, and key generation — all in production code paths (not tests). A poisoned mutex in the DNS rate limiter kills the entire DNS server. A serialization failure in an SSE stream panics the Tokio task. A multi-byte hostname in `truncate_str` panics on a char boundary.

## Decision

### 1. Dual-Port Architecture with Daemon Access Token and mTLS

The daemon serves two listeners:

```
Port 5641 (HTTP)                          Port 5642 (HTTPS/mTLS)
┌─────────────────────────┐               ┌─────────────────────────┐
│ Public tier (no auth):  │               │ All routes require      │
│   GET /healthz          │               │ client cert signed by   │
│   GET /docs             │               │ the certmesh CA.        │
│   GET /openapi.json     │               │                         │
│   GET / (dashboard)     │               │ Routes:                 │
│                         │               │   POST /v1/certmesh/    │
│ DAT tier (X-Koi-Token): │               │     promote             │
│   All other endpoints   │               │     health              │
│   SSE via ?token=...    │               │     renew               │
│                         │               │   GET /v1/certmesh/     │
│ Bootstrap exception:    │               │     roster              │
│   POST /v1/certmesh/    │               │   PUT /v1/certmesh/     │
│     join (DAT + TOTP)   │               │     set-hook            │
└─────────────────────────┘               └─────────────────────────┘
```

**Daemon Access Token (DAT):** On startup, the daemon generates a 256-bit random token, writes it to the breadcrumb file alongside the endpoint URL, and restricts the breadcrumb file to owner-only permissions (0600 on Unix, restricted ACL on Windows). The axum middleware rejects mutation requests that lack a matching `X-Koi-Token` header. SSE connections (which use `EventSource` and cannot set custom headers) pass the token as a `?token=` query parameter. The embedded dashboard receives the token via a `<meta>` tag injected into the HTML. `KoiClient` reads the token from the breadcrumb and attaches it to every request.

**mTLS for inter-node traffic:** Certmesh endpoints that are called machine-to-machine (`/promote`, `/health`, `/roster`, `/renew`, `/set-hook`) are served exclusively on port 5642 with TLS client certificate verification against the certmesh CA. The authenticated client certificate CN is used as the caller's hostname identity. `/set-hook` enforces that the CN matches the target hostname — a node can only set its own reload hook.

**`/join` bootstrap exception:** A new node calling `koi certmesh join` does not yet have a certmesh-issued certificate. The `/join` endpoint lives on the HTTP port (5641), requires both a valid DAT and a TOTP code, and is the only certmesh mutation endpoint on the non-mTLS port. After enrollment succeeds, all subsequent inter-node traffic uses the mTLS port.

**CORS lockdown:** `CorsLayer::permissive()` is replaced with an explicit origin allowlist restricted to `localhost` and `127.0.0.1` on the daemon's port.

### 2. `SecretBytes` and `SecretString` Newtypes

A new module `koi-crypto/src/secret.rs` introduces two newtypes wrapping `zeroize::Zeroizing<Vec<u8>>` and `zeroize::Zeroizing<String>`. Both implement `Deref` to their inner slice/str, print `[REDACTED]` from `Debug`, and do not implement `Clone`. All key material flows are migrated: `derive_aes_key` returns `SecretBytes`, `private_key_pem()` returns `SecretString`, backup payloads use `SecretString` for PEM data, and hex-encoded key material in the slot table uses `SecretString`.

`EncryptedKey` loses its `Clone` derive and its `Debug` implementation is replaced with one that prints `[REDACTED]`.

A helper `write_secret_file(path, data)` is added to enforce 0600 permissions on Unix for all sensitive file writes (`ca-key.enc`, `unlock-slots.json`, auto-unlock material, audit log).

### 3. Explicit Argon2 Parameters Stored With Ciphertext

`EncryptedKey` gains a `kdf_params` field recording the exact Argon2id parameters (`m_cost`, `t_cost`, `p_cost`) used for derivation. The parameters are set to explicit production values (64 MiB memory, 3 iterations, 4-way parallelism) and stored with every encrypted blob. `derive_aes_key` reads parameters from the `KdfParams` struct rather than relying on library defaults. Existing blobs without `kdf_params` are handled via `#[serde(default)]` using the current library defaults, and re-encrypted with explicit parameters on next unlock.

### 4. FIDO2 Gated Behind Feature Flag

All FIDO2 unlock slot code is gated behind `#[cfg(feature = "fido2-unlock")]`. The feature is not included in default features. The existing FIDO2 design (credential_id-derived storage key, unenforced sign_count) is documented as broken and marked for redesign. The future design should use the platform credential store to seal the `slot_kek` and gate its release strictly on a verified WebAuthn assertion, with sign_count enforced as strictly increasing.

### 5. TOTP Shared Secret Encrypted at Rest

The TOTP unlock slot changes from storing `shared_secret_hex: String` (plaintext) to `encrypted_shared_secret: EncryptedKey`. The shared secret is encrypted with a KEK derived from the operator's passphrase via Argon2id. Unlocking with TOTP requires the passphrase (to decrypt the shared secret), the TOTP code (verified against the decrypted secret), and the secret-derived key (to unwrap the master key). This eliminates the plaintext TOTP secret from disk.

### 6. Auto-Unlock Via Platform Credential Store

The plaintext passphrase file is replaced with platform-sealed storage: DPAPI on Windows, Keychain on macOS, Secret Service (D-Bus) on Linux. The passphrase is sealed during `create_ca` when the operator selects auto-unlock and unsealed at daemon startup. If no platform store is available, the system falls back to a file written with `write_secret_file` (0600 permissions) with a logged warning.

### 7. Ephemeral X25519 Key Agreement for Promotion

The empty-passphrase promotion protocol is replaced with ephemeral Diffie-Hellman key agreement using X25519:

1. The standby CLI generates an ephemeral X25519 keypair and sends the public key with the TOTP-authenticated `PromoteRequest`.
2. The primary generates its own ephemeral keypair, computes the shared secret via DH, derives an encryption key via HKDF-SHA256 with info string `"koi-promote-v1"`, encrypts the CA key material, and returns the encrypted payload along with its ephemeral public key.
3. The standby computes the same shared secret, decrypts the CA key, and re-encrypts it locally with the operator's passphrase for storage.

This provides forward secrecy (ephemeral keys are discarded after the exchange) and eliminates the empty passphrase entirely. The `x25519-dalek` crate is added as a dependency to koi-crypto.

### 8. Trait-Based Cross-Domain Data Injection

Cross-domain data flows are mediated through traits defined in `koi-common/src/integration.rs`. Each trait represents a read-only snapshot capability:

```rust
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

Summary types (`MemberSummary`, `ProxyConfigSummary`, `ProxyEntrySummary`) live in `koi-common` and carry only the data downstream domains need — no domain-internal types cross crate boundaries.

The binary crate implements bridge types (`CertmeshBridge`, `MdnsBridge`, `DnsBridge`, `ProxyBridge`) that wrap `Arc<DomainCore>` and implement the corresponding trait. Domain crate constructors accept `Option<Arc<dyn Trait>>` instead of `Option<Arc<DomainCore>>`. All direct cross-domain `Cargo.toml` dependencies are removed: `koi-health` no longer depends on `koi-proxy`, `koi-dns`, `koi-certmesh`, or `koi-mdns`; `koi-dns` no longer depends on `koi-certmesh` or `koi-mdns`; `koi-proxy` no longer depends on `koi-certmesh`.

### 9. Reload Hook Input Validation and Direct Execution

The `set-hook` endpoint validates hook strings against a strict allowlist: absolute paths only (must start with `/` on Unix or a drive letter on Windows), no shell metacharacters (`|;&$\`>< \n\r`). The hook is executed directly via `Command::new(path).args(args)` without shell interpolation (`sh -c` / `cmd /C` is removed). On the mTLS port, the authenticated client CN must match the target hostname — nodes can only set their own hooks.

### 10. Panic Elimination

All `unwrap()` and `expect()` calls in production code paths are replaced:

- **Mutex/RwLock poisoning**: `.unwrap_or_else(|e| e.into_inner())` with a `tracing::warn!`. Ceremony handlers switch to `tokio::sync::Mutex` (which does not poison) and restructure `evaluate` to run outside the lock scope.
- **Serialization**: SSE paths match on the `Result` and break the stream on error with a logged message. Handler paths use `Json(value)` directly (axum handles serialization internally).
- **String slicing**: `truncate_str` uses `s.chars().take(max-1)` instead of byte indexing.
- **Key generation**: `SigningKey::from_bytes` returns `Result` propagated as `CryptoError`.
- **HTTP response building**: `body()` errors propagated as `ProxyError::Forward`.

### 11. Async/Blocking Hygiene

- `detect_mode` wraps the blocking `KoiClient::health()` call in `spawn_blocking`.
- `execute_reload_hook` is called after releasing the roster mutex lock (clone hook string, drop guard, then spawn_blocking).
- `koi-proxy/safety.rs` uses `tokio::net::lookup_host` instead of blocking `to_socket_addrs`.
- `koi-health/log.rs` uses `tokio::fs` instead of `std::fs`.
- `koi-embedded` removes `std::env::set_var` (unsound in multi-threaded contexts) and propagates the data directory through a `RuntimeConfig` struct.
- The heartbeat thread in `commands/mdns.rs` stores its `JoinHandle` and joins on shutdown, using `Acquire`/`Release` ordering on the stop flag.

### 12. Resource Leak and Correctness Fixes

- **mdns-sd boundary**: `MdnsDaemon::browse()` returns a `tokio::sync::mpsc::Receiver<MdnsEvent>` (Koi's own type). The worker thread converts mdns-sd events to Koi types before sending. `browse.rs` no longer imports `mdns_sd`.
- **Resolve leak**: `stop_browse` is called on the channel-close path in `daemon.rs`.
- **Bounded channels**: The mDNS worker op channel uses `sync_channel(256)`.
- **Browser pump tasks**: Completed `JoinHandle`s are drained via `retain(|h| !h.is_finished())`.
- **Proxy config locking**: File-level locking via `fs2::FileExt` prevents concurrent write corruption.
- **UDP lease cap**: Maximum lease duration capped at 86400 seconds (24 hours).
- **Heartbeat touch**: `RwLock<DateTime>` replaced with `AtomicI64` epoch timestamp using `Release`/`Acquire` ordering.
- **Truststore path sanitization**: `name` parameter validated to contain only ASCII alphanumerics, hyphens, and underscores before embedding in filesystem paths.

### 13. Binary Crate Structural Cleanup

- **Daemon startup dedup**: A shared `start_daemon` / `shutdown_daemon` function pair is extracted from `main.rs::daemon_mode` and `platform/windows.rs::run_service`, eliminating ~300 lines of duplicated initialization and shutdown logic.
- **Background task decomposition**: `spawn_certmesh_background_tasks` (~374 lines) is split into four named async functions: `run_renewal_loop`, `run_roster_sync_loop`, `run_health_heartbeat_loop`, `run_failover_loop`.
- **Dashboard event forwarder dedup**: The event subscription and mapping logic duplicated between `adapters/dashboard.rs` and `koi-embedded/src/lib.rs` is moved to `koi-common::dashboard`.

## Consequences

### Positive

- The daemon is no longer an unauthenticated RCE vector on the LAN. DAT protects local operations; mTLS protects inter-node operations; `/join` uses TOTP for the bootstrap case.
- CA key material is zeroized on drop at every stage of its lifecycle. Passphrase-at-rest uses platform credential stores. TOTP secrets are encrypted. Argon2 parameters are explicit and portable.
- The FIDO2 slot is quarantined behind a feature flag until it can be properly redesigned, eliminating the credential_id-derived key vulnerability.
- Domain crates are fully independent again. `cargo test -p koi-health` works without building `koi-proxy`, `koi-dns`, `koi-certmesh`, or `koi-mdns`.
- Zero `unwrap()`/`expect()` in production paths eliminates an entire class of panics.
- The binary crate's daemon initialization is defined once, making shutdown ordering auditable.

### Negative

- The dual-port model adds operational complexity. Operators must allow both ports 5641 and 5642 through firewalls. The mTLS port is only functional after certmesh initialization; before that, only the HTTP port serves traffic.
- The `x25519-dalek` dependency adds ~40KB to the binary for the promotion protocol.
- The trait-based cross-domain injection adds ~150 lines of trait definitions in koi-common and ~200 lines of bridge implementations in the binary crate. Domain constructors become slightly more verbose.
- Breaking changes to the breadcrumb format, `EncryptedKey` serde shape, `UnlockSlot::Totp` serde shape, and `PromoteRequest`/`PromoteResponse` wire protocol. No migration path — this is a clean break.
- The FIDO2 unlock slot is unavailable until the feature is redesigned and the `fido2-unlock` feature flag is stabilized.

### Risk Mitigation

- The DAT is a bearer token with the same security properties as a session cookie. It is protected by filesystem permissions on the breadcrumb file. An attacker with local filesystem read access to the breadcrumb can impersonate the CLI — this is acceptable because such an attacker already has the same privileges as the daemon user.
- The mTLS listener does not start until `CertmeshCore` has a CA and server certificate. Pre-certmesh, only the HTTP+DAT port is available, and certmesh inter-node endpoints return 503.
- Existing `ca-key.enc` and `unlock-slots.json` files from pre-overhaul installations are incompatible. A migration ceremony (re-create CA or restore from backup) is required. This is acceptable given the experimental stage of the project.

## Implementation Plan

The overhaul is organized into 8 work streams with the following dependency graph:

```
WS-1 Foundation types ──────┬──→ WS-2 Auth infrastructure
WS-5 Panic elimination ─────┼──→ WS-3 Key material hardening
                             ├──→ WS-4 Cross-domain rebuild
WS-6 Async/blocking hygiene ┤
WS-7 Resource leaks ────────┼──→ WS-8 Binary crate cleanup
```

WS-1 and WS-5 have no dependencies and execute first. WS-6 and WS-7 are independent. WS-2, WS-3, and WS-4 depend on WS-1 (foundation types). WS-8 runs last.

Detailed implementation specifications for each work stream are in `docs/plans/security-architecture-overhaul.md`.

Verification after completion: `cargo check && cargo test && cargo clippy -- -D warnings && cargo fmt --check`, followed by a repeat of the 6-agent codebase review to confirm all 87 findings are resolved.
