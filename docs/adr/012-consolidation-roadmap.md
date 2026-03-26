# ADR-012: Post-v0.2 Consolidation Roadmap

**Status:** Proposed
**Date:** 2026-03-25
**Depends on:** ADR-011 (Security & Architecture Overhaul)

## Context

All eight implementation phases (0–8) are code-complete. The project has 14 crates, ~70 HTTP endpoints, ~50 CLI commands, and 807+ passing unit tests. A full inventory audit on 2026-03-25 identified gaps in three categories:

1. **Immediate defects** — 1 failing test, 1 crate with zero test coverage
2. **Documentation drift** — validation suite not reflecting completion, stale phase references, minor gaps
3. **Architectural debt** — the 87 findings catalogued in ADR-011, plus several smaller items

This ADR defines an incremental, ordered plan to address every identified gap. Each block is designed to be mergeable independently. The plan is ordered by risk (fix what's broken first), then by value (security before convenience), and grouped to respect domain boundaries.

## Decision

Execute the roadmap in 7 blocks. Each block is a coherent unit of work that can be reviewed and merged independently. Blocks are ordered so that earlier blocks never depend on later ones.

---

## Block 1: Stabilize (Green Build + Test Gaps)

**Goal:** Get to green, fill obvious test coverage holes.
**Risk:** Zero — pure bugfix and test additions.
**Estimated scope:** Small.

### 1.1 Fix failing test: `open_enrollment_with_deadline`

The test at `crates/koi-certmesh/src/http.rs:1557` sends a deadline body to the `open_enrollment_handler`. The handler attempts `save_roster()` to disk via `crate::ca::roster_path()`, which resolves to a machine-scoped directory that doesn't exist in the test environment. The no-body variant passes because test ordering creates the directory as a side-effect, or the save path is skipped — needs investigation.

**Approach:** The HTTP handler tests should not hit real filesystem paths. Either:
- (a) Inject the roster path via `CertmeshState` so tests can use `tempdir`, or
- (b) Make the test fixture create the expected directory structure.

Option (a) is cleaner (aligns with DDD — domain state owns its storage context), but has wider blast radius. Option (b) is a tactical fix. Recommend (b) now, (a) during Block 5.

### 1.2 Add unit tests for koi-embedded

The only crate with zero `#[cfg(test)]` modules. The builder pattern, configuration validation, and handle lifecycle are completely untested.

**Approach:** Add tests for:
- `Builder` defaults and configuration overrides
- Capability enable/disable flags
- `KoiHandle` construction (no runtime — just struct wiring)
- Event subscription registration
- Error paths (invalid config combinations)

### 1.3 Harden test isolation across all crates

Audit all tests that call `ca::roster_path()`, `ca::ca_dir()`, `paths::data_dir()` or similar filesystem-dependent functions. These are fragile in CI and on machines where `%ProgramData%\koi\` doesn't exist.

**Approach:** Grep for `data_dir()`, `ca_dir()`, `certmesh_dir()` in `#[cfg(test)]` contexts. Each should use `tempdir` or be wrapped in a helper that overrides `KOI_DATA_DIR`.

---

## Block 2: Documentation Hygiene

**Goal:** Docs match reality. No stale phase references, no missing content.
**Risk:** Zero — documentation only.
**Estimated scope:** Small.

### 2.1 Update validation-suite.md

- Remove the "Phases 5–8 in progress" implication. All phases are code-complete.
- Note that checkboxes are for **manual acceptance testing**, not implementation status.
- Fix P0-31 (`cargo build --no-default-features --features mdns`) — feature flags were replaced by runtime tunables. Either remove this test or update it.

### 2.2 Add mTLS port explanation to certmesh guide

`--mtls-port 5642` is documented in [cli.md](../reference/cli.md) but not explained in [certmesh.md](../guides/certmesh.md). Add a "Network Architecture" section explaining:
- Port 5641: local HTTP (loopback by default)
- Port 5642: inter-node mTLS (bound 0.0.0.0, requires certmesh enrollment)
- Which endpoints live on which port

### 2.3 Add koi-embedded testing note

Document in [embedded.md](../guides/embedded.md) that the embedded crate is integration-tested via the builder pattern but currently lacks unit tests (addressed in Block 1.2).

### 2.4 Archive or update koi-spec.md references

`docs/archive/koi-spec.md` references the old single-crate architecture. Add a header noting it's superseded by the reference docs.

---

## Block 3: Panic Elimination + Async Hygiene (ADR-011 WS-8)

**Goal:** Remove all production-path panics; fix blocking-in-async.
**Risk:** Low — behavioral changes are minimal, each fix is local.
**Estimated scope:** Medium (touches many files, but each change is small).

This is ADR-011 Work Stream 8, extracted as the first security work because it has no breaking changes and immediately improves reliability.

### 3.1 Replace `unwrap()` / `expect()` in production paths

Audit and fix every `unwrap()`/`expect()` in non-test code:

| Pattern | Replacement |
|---------|-------------|
| `mutex.lock().unwrap()` | `.unwrap_or_else(\|e\| e.into_inner())` + `tracing::warn!` |
| `serde_json::to_string().unwrap()` | Match on Result, use fallback JSON |
| `string[..N]` byte slicing | `chars().take(N).collect()` |
| Key generation `unwrap()` | Propagate `Result` |

### 3.2 Fix blocking-in-async patterns

| Location | Issue | Fix |
|----------|-------|-----|
| `detect_mode()` | Blocking `KoiClient` call on async thread | Wrap in `spawn_blocking` |
| `execute_reload_hook()` | Holds roster lock across `spawn_blocking` | Release lock before spawn |
| DNS upstream lookup | `std::net::lookup_host` (blocking) | `tokio::net::lookup_host` |
| Health file reads | `std::fs` in async context | `tokio::fs` |
| koi-embedded `set_var` | `std::env::set_var` is unsound in multi-threaded | Propagate via `RuntimeConfig` struct |

### 3.3 Bounded channels in mDNS worker

Replace unbounded `mpsc` in the mDNS daemon worker with bounded `sync_channel(256)`. Add backpressure logging when channel is full.

---

## Block 4: Cross-Domain Trait Boundaries (ADR-011 WS-7)

**Status:** SKIP — verified 2026-03-25 that zero cross-domain imports exist.
The domain boundary model was implemented correctly from the start.
ADR-011's description of cross-domain imports was prospective (proposed
architecture), not a finding about current code.

~~**Goal:** Domain crates depend only on `koi-common`, never on each other.~~
~~**Risk:** Medium — architectural refactor, but no behavior change.~~
~~**Estimated scope:** Medium-large.~~

~~Currently `koi-health` imports `koi-proxy`, `koi-dns`, `koi-certmesh`, `koi-mdns` for read-only data. This violates the domain boundary model stated in CONTEXT.md.~~

### 4.1 Define integration traits in `koi-common`

```rust
// koi-common/src/integration.rs

/// Summary types (no domain internals leak)
pub struct CertSummary { pub hostname: String, pub expires: DateTime<Utc>, pub fingerprint: String }
pub struct DnsEntrySummary { pub name: String, pub ips: Vec<IpAddr> }
pub struct ProxySummary { pub name: String, pub listen_port: u16, pub running: bool }
pub struct MdnsServiceSummary { pub name: String, pub service_type: String, pub port: u16 }

/// Traits that domain crates can depend on
pub trait CertProvider: Send + Sync { fn enrolled_members(&self) -> Vec<CertSummary>; }
pub trait DnsProvider: Send + Sync { fn entries(&self) -> Vec<DnsEntrySummary>; }
pub trait ProxyProvider: Send + Sync { fn active_proxies(&self) -> Vec<ProxySummary>; }
pub trait MdnsProvider: Send + Sync { fn discovered_services(&self) -> Vec<MdnsServiceSummary>; }
```

### 4.2 Implement bridges in binary crate

The binary crate already has `DaemonCores` with `Option<Arc<DomainCore>>` for each domain. Add bridge structs:

```rust
// crates/koi/src/bridges.rs
struct CertBridge(Arc<CertmeshCore>);
impl CertProvider for CertBridge { ... }
```

### 4.3 Inject providers via domain constructors

`HealthCore::new()` accepts `Option<Box<dyn CertProvider>>` etc. instead of importing domain crates directly.

### 4.4 Remove cross-domain Cargo dependencies

After wiring bridges, remove `koi-certmesh`, `koi-mdns`, `koi-dns`, `koi-proxy` from `koi-health/Cargo.toml` (and any other cross-domain deps).

---

## Block 5: Key Material Hardening (ADR-011 WS-2 + WS-4)

**Goal:** Consistent secret lifecycle — typed wrappers, zeroize-on-drop, encrypted at rest.
**Risk:** Medium — serde breaking changes for `EncryptedKey` and `UnlockSlot::Totp`.
**Estimated scope:** Medium.

### 5.1 `SecretBytes` and `SecretString` newtypes in koi-crypto

- `ZeroizeOnDrop`, no `Clone`, no `Debug` (or redacted Debug)
- Replace all `Vec<u8>` / `String` / `[u8; 32]` secret material
- Audit: grep for raw key bytes in `koi-crypto`, `koi-certmesh`
- **Includes vault master key**: `Vault.master_key: [u8; 32]` currently uses
  manual `Drop` zeroize (`iter_mut().for_each(|b| *b = 0)`) which the compiler
  may optimize away. Migrate to `SecretBytes` for guaranteed clearing.

### 5.2 Store Argon2id parameters with ciphertext

Current `EncryptedKey` doesn't store KDF params. Add:
```rust
pub struct EncryptedKey {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
    kdf: KdfParams,  // NEW: { algorithm: "argon2id", m_cost, t_cost, p_cost }
}
```
**Breaking change:** serde shape changes. No migration — old keys re-encrypted on first unlock.

### 5.3 Encrypt TOTP shared secret at rest

Currently stored as plaintext hex in `unlock-slots.json`. Encrypt with a key derived from the passphrase. Decryption requires passphrase + TOTP code + secret-derived key.

### 5.4 Inject storage paths via CertmeshState (from Block 1.1)

**Status:** DONE (commit dc843b6). `CertmeshPaths` struct added to
`CertmeshState`, all internal callsites migrated.

---

## Block 6: Authentication & Network Security (ADR-011 WS-1 + WS-6)

**Status:** SKIP — verified 2026-03-25 that all items are already implemented:
- 6.1 DAT: `dat_auth_middleware`, `X-Koi-Token` header, breadcrumb write ✓
- 6.2 Loopback: HTTP binds `127.0.0.1`, mTLS on `0.0.0.0` ✓
- 6.3 X25519: `EphemeralKeyPair`, DH key agreement in failover.rs ✓
- 6.4 CORS: origin predicate restricts to localhost/127.0.0.1 ✓
- 6.5 Hooks: `HOOK_FORBIDDEN` chars, absolute path check, CN auth ✓

~~**Goal:** No unauthenticated mutations; secure inter-node communication.~~
~~**Risk:** High — breaking changes to breadcrumb format and wire protocol.~~
~~**Estimated scope:** Large.~~

### 6.1 Daemon Access Token (DAT)

- Generate 256-bit random token at startup
- Write to breadcrumb file with restricted permissions (0600 Unix, restricted ACL Windows)
- Require `X-Koi-Token` header on all mutation endpoints (POST/PUT/DELETE)
- SSE connections pass token as `?token=` query parameter
- Dashboard receives token via HTML `<meta>` tag
- `KoiClient` reads token from breadcrumb automatically

### 6.2 Bind HTTP to loopback only

Change default bind from `0.0.0.0:5641` to `127.0.0.1:5641`. Inter-node traffic goes through mTLS port.

### 6.3 Ephemeral X25519 key agreement for promotion

Replace current promotion protocol (empty-passphrase encryption) with:
1. Standby sends ephemeral X25519 pubkey + TOTP code
2. Primary generates ephemeral key, computes shared secret via DH
3. Derives encryption key via HKDF-SHA256
4. Encrypts CA key material, sends back
5. Standby decrypts, re-encrypts locally with own passphrase

**Breaking change:** `PromoteRequest` / `PromoteResponse` wire protocol changes.

### 6.4 CORS lockdown

Replace `CorsLayer::permissive()` with:
- Loopback port: allow only same-origin (dashboard)
- mTLS port: no CORS needed (not browser-accessible)

### 6.5 Reload hook input validation

- Strict allowlist: absolute paths only, no shell metacharacters
- Direct execution via `Command::new()` without `sh -c`
- mTLS port enforces CN matches target hostname

---

## Block 7: Remaining Items (Lower Priority)

**Goal:** Feature completions and quality-of-life improvements.
**Risk:** Low — independent, non-breaking additions.
**Estimated scope:** Small per item.

### 7.1 Factory reset command

`koi factory-reset` — destroys entire data directory and recreates from scratch. Equivalent to `koi certmesh destroy` + clearing mDNS registrations + removing state files.

### 7.2 FIDO2 CLI input support

Wire FIDO2 hardware key input in `ceremony_cli.rs`. Currently hard-coded `bail!()`. Requires platform-specific authenticator library integration.

### 7.3 SelectMany ceremony input

Implement multi-select input in the ceremony CLI render loop. Currently falls back to text.

### 7.4 SSE event replay (ring buffer)

Phase 2 of the SSE Event IDs proposal: bounded ring buffer for event replay on `Last-Event-ID` reconnection.

### 7.5 FIDO2 unlock redesign (ADR-011 WS-3)

Gate behind `#[cfg(feature = "fido2-unlock")]` (already done). Full redesign: platform credential store sealing + strict sign_count enforcement.

### 7.6 Auto-unlock via platform credential store (ADR-011 WS-5)

Seal passphrase in DPAPI (Win), Keychain (Mac), Secret Service (Linux). Fallback to 0600-permission file with warning.

**Update (e94ffbd):** The new `koi-crypto::vault` module already implements
this pattern generically (keyring-first, Argon2id-from-machine-ID fallback).
`CertmeshCore::save_auto_unlock_key` / `try_auto_unlock` should migrate to
store the passphrase via `Vault::store("certmesh-auto-unlock", passphrase)`
instead of reimplementing the same dual-backend logic. This collapses WS-5
into a thin wrapper around the vault.

### 7.7 Dashboard enhancements (KOI-0002 phases 7.2–7.4)

- Browser actions (register/unregister from UI)
- Additional browser pages
- WebSocket upgrade for lower-latency updates

---

## Consequences

### Positive

- **Green build** before any architectural changes (Block 1)
- **No big-bang** — each block is independently mergeable
- **Security-first ordering** — panic elimination (Block 3) and auth (Block 6) before feature work (Block 7)
- **Domain boundaries enforced** (Block 4) before key material changes (Block 5), preventing further cross-crate coupling
- **Breaking changes concentrated** in Blocks 5–6, not scattered

### Negative

- Blocks 5–6 introduce serde breaking changes with no migration path (acceptable for pre-1.0 project)
- Block 4 (trait boundaries) is a large refactor with no visible user impact — motivation must be architectural clarity, not feature delivery
- FIDO2 (7.2, 7.5) remains gated/broken until platform authenticator integration is solved — this is an unsolved problem across the Rust ecosystem

### Risks

- Block 3 (panic elimination) touches many files — risk of introducing subtle behavior changes. Mitigate with comprehensive test runs after each sub-block.
- Block 6 (DAT + loopback binding) changes the default network posture — existing deployments that rely on LAN access to port 5641 will break. Document upgrade path clearly.

---

## Appendix A: New Capabilities Added During Consolidation

| Capability | Commit | Location | Impact on Roadmap |
|------------|--------|----------|-------------------|
| `koi-crypto::vault` | e94ffbd | `crates/koi-crypto/src/vault.rs` | Block 5.1 (master key → SecretBytes), Block 7.6 (certmesh auto-unlock → vault) |

## Appendix B: Dead Code Inventory

All `#[allow(dead_code)]` items and their disposition:

| Item | Location | Disposition |
|------|----------|-------------|
| `push_renewal()` | koi-client/src/lib.rs:458 | Keep — used when roster tracks member endpoints (Block 4+) |
| `renewal_result()` | koi/src/format.rs:238 | Keep — paired with `push_renewal()` |
| `KoiScope` enum | koi/src/surface.rs:387 | Keep — future command-surface scope filtering |
| `CaKeyPair` field | koi-certmesh/src/ca.rs:34 | Keep — zeroize on drop + future re-encryption |
| `ongoing()`/`finished()`/`with_warning()` | koi-common/src/pipeline.rs:40 | Keep — SSE streaming helpers |
| `CertmeshBridgeEmbedded` | koi-embedded/src/lib.rs:939 | Keep — used via trait impls in embedding scenarios |
| `ProxyBridgeEmbedded` | koi-embedded/src/lib.rs:1058 | Keep — used via trait impls in embedding scenarios |

## Appendix C: Documentation Gaps

| Gap | Block | Action |
|-----|-------|--------|
| validation-suite.md implies phases 5–8 incomplete | 2.1 | Clarify checkboxes are acceptance testing |
| P0-31 references removed feature flags | 2.1 | Update or remove test spec |
| mTLS port not explained in certmesh guide | 2.2 | Add "Network Architecture" section |
| No koi-config guide | — | Low priority — config is internal |
| No command-surface guide | — | Low priority — internal crate |
| `factory-reset` referenced in system.md as planned | 7.1 | Implement the command |
