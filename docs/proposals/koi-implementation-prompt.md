# Koi Implementation Prompt

**For:** Claude (coding agent)
**Project:** Koi — Local Network Toolkit
**Spec:** See `koi-spec.md` (attached or in repository root)
**Date:** February 2026

---

## Who You Are

You are implementing Koi, a single-binary local network toolkit for LAN service discovery and certificate management. You are working from a detailed design specification (`koi-spec.md`) that has been through architecture review and ISO 27001 security evaluation. The spec is authoritative — follow it closely. If something in the spec is ambiguous, flag it and propose a resolution before proceeding.

The developer is Leon, an Enterprise Architect who designed this system. He will review your work. He values clean architecture, clear separation of concerns, and code that reads like its intent. He does not value cleverness for its own sake.

---

## Technical Decisions

**Language:** Rust

**Rationale:** Koi is already a Rust project. Rust gives us single binary compilation, excellent cross-platform support (Linux, Windows, macOS, ARM via cross-compilation), memory safety without garbage collection (important for long-running network daemons), strong async ecosystem for mDNS listeners and health heartbeats, and a mature cryptography ecosystem. The target audience runs this on everything from Raspberry Pis to Windows workstations.

**Crate path:** `github.com/sylin-org/koi`

**Minimum Rust edition:** 2021

**Async runtime:** `tokio` (multi-threaded)

---

## Repository Structure

```
koi/
├── Cargo.toml                        # Workspace root
├── crates/
│   ├── koi-cli/                      # Binary crate — CLI entry point
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs               # Entry point, CLI root
│   │       ├── commands/
│   │       │   ├── mod.rs
│   │       │   ├── root.rs           # koi status, version, help
│   │       │   ├── mdns.rs           # koi mdns <subcommands>
│   │       │   ├── certmesh.rs       # koi certmesh <subcommands>
│   │       │   ├── dns.rs            # koi dns <subcommands>
│   │       │   ├── health.rs         # koi health <subcommands>
│   │       │   └── proxy.rs          # koi proxy <subcommands>
│   │       └── output.rs             # Formatting, color, --json support
│   ├── koi-mdns/                     # Library crate — mDNS capability
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── discovery.rs          # Service discovery
│   │       ├── announcer.rs          # Service advertising
│   │       └── registry.rs           # Discovered service cache
│   ├── koi-certmesh/                 # Library crate — certificate mesh capability
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ca.rs                 # CA creation, key management, cert signing
│   │       ├── enrollment.rs         # Join flow, TOTP verification, approval
│   │       ├── failover.rs           # Primary/standby detection, promotion, demotion
│   │       ├── lifecycle.rs          # Cert renewal, push distribution, reload hooks
│   │       ├── roster.rs             # Roster data model, sync, revocation list
│   │       ├── certfiles.rs          # Cert file writing to standard path, fullchain assembly
│   │       ├── health.rs             # Heartbeat, cert chain validation
│   │       ├── audit.rs              # Append-only signed audit log
│   │       ├── entropy.rs            # Active entropy collection (keyboard mashing, passphrase, manual)
│   │       ├── profiles.rs           # Trust profile definitions and defaults
│   │       ├── scope.rs              # Domain/subnet constraints for cert issuance
│   │       └── backup.rs             # Export/restore encrypted backup
│   ├── koi-dns/                      # Library crate — local DNS resolver
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── resolver.rs           # DNS listener, query handling, upstream forwarding
│   │       ├── zone.rs               # Local zone management, name generation rules
│   │       ├── records.rs            # Record sources: static, certmesh SANs, mDNS registry
│   │       ├── aliases.rs            # Service alias generation (grafana.lan from _grafana._tcp)
│   │       └── safety.rs             # RFC 1918 enforcement, rate limiting, LAN-only binding
│   ├── koi-health/                   # Library crate — network health
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── machine.rs            # Machine health from mDNS/certmesh signals (automatic)
│   │       ├── service.rs            # Service health checks: HTTP, TCP (opt-in)
│   │       ├── checker.rs            # Async check runner, interval management
│   │       ├── state.rs              # State tracking, transition detection
│   │       └── log.rs                # State transition log (append-only)
│   ├── koi-proxy/                    # Library crate — TLS-terminating reverse proxy
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── listener.rs           # HTTPS listener with rustls, cert hot-reload
│   │       ├── forwarder.rs          # HTTP forwarding to backend
│   │       ├── config.rs             # Proxy entry management (add/remove/list)
│   │       └── safety.rs             # Localhost-only default, remote backend guard
│   ├── koi-truststore/               # Library crate — platform-specific trust store
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                # Trait definition
│   │       ├── linux.rs              # update-ca-certificates
│   │       ├── windows.rs            # certutil
│   │       ├── darwin.rs             # Keychain
│   │       └── nss.rs                # Firefox NSS (cross-platform)
│   ├── koi-api/                      # Library crate — inter-node REST API
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs             # HTTP(S) server setup
│   │       ├── certmesh_handlers.rs  # /v1/certmesh/join, /renew, /roster, /health
│   │       └── middleware.rs          # Cert chain validation, rate limiting
│   ├── koi-crypto/                   # Library crate — cryptographic utilities
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── keys.rs               # ECDSA key generation, encryption at rest
│   │       ├── totp.rs               # TOTP generation, verification, QR code
│   │       ├── pinning.rs            # Certificate fingerprint pinning
│   │       └── tpm.rs                # TPM detection and sealing (best-effort)
│   └── koi-config/                   # Library crate — config and state persistence
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── state.rs              # Local state file management
│           └── paths.rs              # Platform-specific paths (including cert path)
├── scripts/
│   └── build.sh                      # Cross-compilation targets
├── docs/
│   ├── koi-spec.md                   # The full specification
│   └── security-model.md             # User-facing security documentation (from spec §10)
├── LICENSE
└── README.md
```

The workspace structure with separate crates enables feature-gated compilation. `koi-certmesh` and its crypto dependencies can be excluded for a lighter mDNS-only build.

---

## Key Dependencies

Use established, well-maintained crates. Do not reinvent what exists.

| Purpose | Crate | Notes |
|---------|-------|-------|
| Async runtime | `tokio` | Multi-threaded runtime for all async operations |
| CLI framework | `clap` (derive) | Subcommand structure matches moniker model perfectly |
| mDNS | `mdns-sd` | Pure Rust mDNS/DNS-SD. Alternatively `zeroconf` for platform-native backends |
| X.509 / CA | `rcgen` + `rustls` | `rcgen` for cert generation, `rustls` for TLS. Avoid OpenSSL dependency. |
| ECDSA | `p256` (from RustCrypto) | ECDSA P-256 key generation and signing |
| TOTP | `totp-rs` | Standard TOTP/HOTP implementation |
| QR code | `qrcode` + `image` | Generate QR code, render to terminal via Unicode blocks |
| Encryption at rest | `aes-gcm` + `argon2` (RustCrypto) | Argon2id for key derivation from passphrase, AES-256-GCM for encryption |
| HTTP server | `axum` | Tokio-native, composable middleware, TLS via `axum-server` + `rustls` |
| HTTP client | `reqwest` (rustls) | Roster sync, cert renewal push, health HTTP checks |
| Serialization | `serde` + `serde_json` | Roster, config, API payloads |
| Terminal UI | `indicatif` | Progress bars for entropy collection |
| Terminal input | `crossterm` | Raw keyboard input for entropy collection (cross-platform) |
| TPM | `tss-esapi` | Best-effort TPM 2.0 support. Feature-gated. Fail gracefully if unavailable. |
| Logging | `tracing` + `tracing-subscriber` | Structured logging. Audit log is separate (custom implementation). |
| Color output | `owo-colors` or `colored` | Respect `NO_COLOR` env var |
| IP/subnet | `ipnet` | CIDR parsing and containment checks for scope constraints |
| Constant-time comparison | `subtle` (RustCrypto) | For TOTP verification — prevent timing attacks |
| Memory zeroing | `zeroize` | Derive `Zeroize` + `ZeroizeOnDrop` on all key material structs |
| Platform paths | `dirs` | Platform-appropriate config/data directories |
| Error handling (lib) | `thiserror` | Typed error enums in library crates |
| Error handling (bin) | `anyhow` | Contextual errors in CLI binary |
| Async channels | `tokio::sync` | `mpsc` for enrollment approval flow, `watch` for state changes |
| DNS server | `hickory-server` (formerly trust-dns-server) | Authoritative DNS for local zone |
| DNS resolver | `hickory-resolver` (formerly trust-dns-resolver) | Upstream forwarding for non-local queries |
| HTTP reverse proxy | `hyper` | Low-level HTTP client/server for proxy forwarding (axum is built on hyper) |
| File watching | `notify` | Watch cert files for changes (hot-reload in proxy) |

**Feature flags in workspace `Cargo.toml`:**
```toml
[features]
default = ["mdns", "certmesh", "dns", "health", "proxy"]
mdns = ["koi-mdns"]
certmesh = ["koi-certmesh", "koi-crypto", "koi-truststore"]
dns = ["koi-dns"]
health = ["koi-health"]
proxy = ["koi-proxy"]
tpm = ["tss-esapi"]                # Opt-in, requires system TPM libraries
```

---

## Implementation Phases

Build in this order. Each phase produces a working, testable binary. Do not start a phase until the previous one is complete and tested.

### Phase 0: Restructure Existing Codebase

**Goal:** Migrate the existing Koi mDNS codebase from its current flat structure into the capability moniker architecture. Zero behavioral changes. Every test that passed before must pass after.

**Critical discipline:** Don't rewrite — relocate. Move first, refactor later. Inventory every CLI command, REST endpoint, and config path before moving anything. Nothing left behind.

**Steps:**

1. **Inventory.** List every existing CLI command, REST endpoint, config key, and test. This inventory is the migration checklist.

2. **Workspace setup.** Convert the single crate into a Cargo workspace:
   - Create `crates/koi-cli/` (binary crate)
   - Create `crates/koi-mdns/` (library crate, receives existing mDNS logic)
   - Create `crates/koi-config/` (library crate, receives config/paths)
   - Create placeholder crates for future capabilities (empty `lib.rs`, feature-flagged)

3. **CLI migration.** Existing commands move under `koi mdns <command>`:
   - `koi discover` → `koi mdns discover`
   - `koi announce` → `koi mdns announce`
   - Add backward-compatible aliases at the root level that print deprecation notices:
     ```
     Warning: `koi discover` is deprecated. Use `koi mdns discover`.
     This alias will be removed in the next release.
     ```
   - Add `koi status` (unified dashboard — shows mDNS status for now)
   - Add `koi version` (build info, git hash, feature flags)
   - Wire up `--json` flag on all commands (outputs JSON instead of human-readable)

4. **REST API migration.** Namespace existing endpoints:
   - `/discover` → `/v1/mdns/discover`
   - `/status` → `/v1/mdns/status`
   - Old endpoints return 301 redirects with `Location` header for one release cycle.
   - Add `/v1/status` (unified status endpoint)

5. **Verify.** Run the complete existing test suite. Every test must pass with no modifications to test logic (path updates in test setup are fine).

**Deliverable:** A working binary with `koi mdns discover`, `koi mdns status`, backward-compatible aliases, `--json` flag, and the workspace structure ready for new crates.

---

### Phase 1: Moniker Infrastructure + mDNS Enhancements

**Goal:** Solidify the capability moniker framework and enhance mDNS with features needed by later capabilities.

**Steps:**

1. **Moniker framework.** Each capability registers with a trait:
   ```rust
   trait Capability {
       fn name(&self) -> &str;
       fn status(&self) -> CapabilityStatus;
   }
   ```
   `koi status` calls `.status()` on each registered capability and renders the unified dashboard.

2. **`--json` everywhere.** Every command supports `--json` for machine-readable output. Human-readable is the default. JSON output is stable — breaking changes require version bumps.

3. **mDNS enhancements.** Add features the later capabilities need:
   - Richer service metadata in TXT records (for certmesh to advertise CA info)
   - Custom service type advertising (`_certmesh._tcp`, `_dns._udp`)
   - Last-seen timestamp tracking per discovered service (for health)
   - Event system: notify when a service appears, disappears, or changes

4. **Config infrastructure.** Establish the `~/.koi/` directory structure:
   ```
   ~/.koi/
     config.toml        # Global config
     certs/             # Certificate files (created by certmesh)
     state/             # Runtime state
     logs/              # Audit and health logs
   ```
   Platform-specific paths via `dirs` crate. Config is TOML.

**Deliverable:** Enhanced mDNS with event system, `~/.koi/` directory structure, `koi status` showing mDNS health, `--json` on all commands.

---

### Phase 2: Certmesh Core (Local CA Mode)

**Goal:** Implement the core certificate mesh — CA creation, TOTP enrollment, and cert file management.

**Steps:**

1. **Entropy collection.** (koi-crypto/entropy.rs)
   - Keyboard mashing mode: raw keystrokes via crossterm, measure timing and character entropy
   - Progress bar via indicatif
   - Mix with system RNG, and TPM hardware RNG when available
   - Produce 256+ bits of entropy for CA key seeding

2. **CA creation.** (koi-certmesh/ca.rs)
   - ECDSA P-256 keypair generation via `p256` crate
   - Root CA certificate via `rcgen`
   - Encrypt private key at rest with Argon2id + AES-256-GCM
   - Write CA files to `~/.koi/certmesh/ca/`

3. **TOTP enrollment.** (koi-certmesh/enrollment.rs, koi-crypto/totp.rs)
   - Generate TOTP secret, encrypt alongside CA key
   - QR code display via `qrcode` crate (Unicode block rendering to terminal)
   - Six-digit code verification with `totp-rs`
   - Rate limiting: 3 failures → 5-minute lockout (constant-time comparison via `subtle`)

4. **Trust profiles.** (koi-certmesh/profiles.rs)
   - Profile selection prompt on `certmesh create`
   - Store profile in roster metadata
   - Profile-driven defaults for approval, enrollment state, operator prompting

5. **Certificate issuance.** (koi-certmesh/ca.rs, koi-certmesh/certfiles.rs)
   - SAN auto-population from mDNS knowledge: hostname, FQDN, mDNS name, all LAN IPs
   - Sign service cert with root CA
   - Write cert files to standard path (`~/.koi/certs/<hostname>/`):
     - `cert.pem` — service certificate
     - `key.pem` — service private key
     - `ca.pem` — root CA public certificate
     - `fullchain.pem` — cert + CA concatenated

6. **Trust store installation.** (koi-truststore/)
   - Platform detection
   - Install root CA public cert into system trust store
   - Firefox NSS detection and installation

7. **Roster management.** (koi-certmesh/roster.rs)
   - Roster data model per spec §9.1
   - All design-time fields present from day one
   - Serialize/deserialize with serde

8. **REST API for enrollment.** (koi-api/)
   - `/v1/certmesh/join` — TOTP-authenticated enrollment endpoint
   - mDNS advertisement of `_certmesh._tcp`
   - CA discovery on join via mDNS

9. **Audit log.** (koi-certmesh/audit.rs)
   - Append-only, timestamped, signed entries
   - First entry: `pond_initialized`
   - Entry on each enrollment

**Deliverable:** `koi certmesh create`, `koi certmesh join`, working TLS between two machines, cert files at standard path, trust store installation, audit log.

**Test:** Machine A creates mesh, Machine B joins via TOTP. Both machines can `curl https://stone-01.lan` without cert errors. Cert files exist at `~/.koi/certs/`.

---

### Phase 3: Failover + Lifecycle

**Goal:** Implement standby promotion, failover detection, and automatic cert renewal with reload hooks.

**Steps:**

1. **Promotion.** (koi-certmesh/failover.rs)
   - `koi certmesh promote` — TOTP-verified CA key transfer
   - Encrypted transfer over the certmesh API
   - Standby receives full roster
   - Periodic roster sync (pull model with signed manifest)

2. **Failover detection.**
   - Monitor `_certmesh._tcp` mDNS presence
   - 60-second grace period before promotion
   - Deterministic tiebreaker (lowest hostname alphabetically)
   - Old primary returns → defers to new primary

3. **Cert renewal.** (koi-certmesh/lifecycle.rs)
   - At day 20 of 30-day lifetime, CA mints fresh certs
   - Push to members via `/v1/certmesh/renew` (validated by existing cert chain)
   - Overwrite cert files at standard path
   - Execute reload hook if configured

4. **Reload hooks.** (koi-certmesh/lifecycle.rs)
   - `koi certmesh set-hook --reload "<command>"` — stored in roster
   - Execute after cert files are written
   - Log success/failure
   - Hook is per-machine

5. **Certmesh heartbeat.** (koi-certmesh/health.rs)
   - Every 5 minutes: connect to CA, validate cert chain, verify pinned fingerprint
   - Log failures as warnings

6. **Unlock after reboot.**
   - `koi certmesh unlock` — decrypt CA key with passphrase
   - CA cannot sign until unlocked
   - Clear UX: "CA is locked. Run `koi certmesh unlock` to resume signing."

**Deliverable:** Two-CA setup (primary + standby), automatic failover on primary failure, cert renewal with file overwrite + reload hooks.

**Test:** Primary goes offline → standby takes over within 60s → members still get renewals. Primary returns → becomes standby without conflict. Cert files update in place. Reload hook fires.

---

### Phase 4: Institutional Controls

**Goal:** Implement approval workflows, enrollment windows, operator attribution, scope constraints, and compliance reporting.

**Steps:**

1. **Approval workflow.** Interactive prompt on CA terminal during enrollment. Uses `tokio::sync::mpsc` channel between API handler and terminal.

2. **Enrollment windows.** `open-enrollment --duration`, `close-enrollment`. Auto-close timer. TOTP codes rejected outside windows.

3. **Operator attribution.** `--operator` flag on create/join, logged to audit trail.

4. **Scope constraints.** Domain and subnet validation on cert issuance. Refuse and log requests outside scope.

5. **Compliance summary.** `koi certmesh compliance` — adapts to trust profile. Simple health check for personal, full audit summary for organization.

6. **TOTP rotation.** `koi certmesh rotate-secret` — new QR code, old codes invalidated, existing members unaffected.

**Deliverable:** Full institutional workflow. Organization profile requires approval + operator + scope.

---

### Phase 5: Backup, Restore, Hardening

**Goal:** Encrypted backup/restore, revocation, and security hardening.

**Steps:**

1. **Backup.** `koi certmesh backup` — export CA key + TOTP secret + roster + audit log. Encrypted with user-provided passphrase. Scary confirmation prompt.

2. **Restore.** `koi certmesh restore` — rebuild from backup. Prompt for backup passphrase, then new unlock passphrase.

3. **Revocation.** `koi certmesh revoke <host>` — add to revocation list, push with roster sync. Members check list on certmesh connections.

4. **TPM integration.** (koi-crypto/tpm.rs) Feature-gated. Detect TPM 2.0, seal CA key in hardware. Fail gracefully to software encryption if unavailable.

5. **Security hardening.** `zeroize` on all key material structs. Constant-time TOTP comparison. Cert pinning enforcement.

**Deliverable:** Complete backup/restore cycle. Revocation works across mesh. TPM sealing on supported hardware.

---

### Phase 6: Local DNS Resolver

**Goal:** Implement the lightweight DNS resolver that puts a DNS face on Koi's service registry.

**Steps:**

1. **DNS server.** (koi-dns/resolver.rs) Using `hickory-server`:
   - Custom `Authority` implementation that queries Koi's three record sources
   - Listen on port 53 (configurable). Handle port 53 permissions:
     - Linux: `CAP_NET_BIND_SERVICE` capability, or run on high port with firewall redirect
     - macOS/Windows: may require elevated privileges
   - UDP and TCP listeners

2. **Record sources.** (koi-dns/records.rs) In priority order:
   - Static entries (from `koi dns add`)
   - Certmesh SANs (from enrolled member certificates)
   - mDNS registry (from discovered services)
   - Priority resolution: first source with a match wins

3. **Service alias generation.** (koi-dns/aliases.rs)
   - `_grafana._tcp` on stone-05 → `grafana.lan` → stone-05's IP
   - Multi-instance: return all IPs (round-robin) + disambiguated names
   - Conflict logging when aliases overlap

4. **SAN feedback loop.** When DNS generates a new alias, notify certmesh. Certmesh includes the alias in the next cert renewal (within the 10-day window before the 30-day expiry). Wire this through the capability event system.

5. **Upstream forwarding.** (koi-dns/resolver.rs) Using `hickory-resolver`:
   - Queries outside the local zone forwarded to upstream
   - No caching (leave that to upstream)
   - No open recursion

6. **Safety.** (koi-dns/safety.rs)
   - RFC 1918 enforcement: local zone names must resolve to private IPs only
   - LAN interface binding by default
   - Rate limiting on queries
   - Query logging only at debug level

**Deliverable:** `koi dns serve`, `koi dns lookup`, `koi dns add/remove/list`. Devices using Koi as DNS server can resolve `grafana.lan`.

**Test:** Start DNS, add static entry, verify resolution. Start Grafana on a mesh member, verify `grafana.lan` resolves via mDNS alias. Verify non-local queries forward upstream.

---

### Phase 7: Network Health

**Goal:** Implement present-tense health synthesis from existing signals, plus opt-in service checks.

**Steps:**

1. **Machine health.** (koi-health/machine.rs)
   - Synthesize from: mDNS last-seen, certmesh heartbeat, cert expiry, DNS resolution
   - No new network traffic — purely consuming data other capabilities already produce
   - Up/down threshold: configurable, default 60s since last seen

2. **Service health.** (koi-health/service.rs)
   - HTTP check: GET URL, expect 2xx (uses `reqwest` with certmesh trust)
   - TCP check: connect to port, expect open
   - Configurable interval per service (default 30s)
   - Async check runner (koi-health/checker.rs) using tokio intervals

3. **State transitions.** (koi-health/state.rs)
   - Track previous state per machine and service
   - Detect transitions (up→down, 200→502, etc.)
   - Only log on transitions, not every check

4. **State transition log.** (koi-health/log.rs)
   - Append-only flat file
   - Format: `timestamp | name | old_state → new_state | reason`
   - Not a database — designed for human reading

5. **Live watch.** `koi health watch` — terminal UI that refreshes in place. Use `crossterm` for raw terminal control. Ctrl+C to exit cleanly.

**Deliverable:** `koi health status`, `koi health watch`, `koi health add/remove`, `koi health log`.

**Test:** Take a mesh member offline → health shows "down" within 60s → state transition logged. Add HTTP service check → verify 200 OK appears in status.

---

### Phase 8: TLS-Terminating Proxy

**Goal:** Implement the last-mile TLS terminator for services that don't speak HTTPS natively.

**Steps:**

1. **HTTPS listener.** (koi-proxy/listener.rs)
   - `axum` + `rustls` using cert files from standard cert path
   - Cert hot-reload: watch `~/.koi/certs/<hostname>/` with `notify` crate, reload `rustls` config when files change
   - Listen on configured port

2. **HTTP forwarding.** (koi-proxy/forwarder.rs)
   - Forward incoming requests to backend URL via `hyper` client
   - Preserve headers (add `X-Forwarded-For`, `X-Forwarded-Proto: https`)
   - Stream response back to client

3. **Backend safety.** (koi-proxy/safety.rs)
   - Default: backend must resolve to localhost/127.0.0.1/::1
   - `--backend-remote` flag to allow non-local backends
   - Log warning when remote backend is configured: "Backend traffic to {host} is unencrypted"

4. **Proxy config.** (koi-proxy/config.rs)
   - `koi proxy add/remove/list/status`
   - Persist proxy entries in `~/.koi/config.toml` and roster
   - Multiple proxies per machine, each with different listen port

5. **Integration with health.** Proxy's backend connectivity check is a natural health signal. Wire proxy status into health's data sources.

**Deliverable:** `koi proxy add grafana --listen 443 --backend http://localhost:3000` results in `https://grafana.lan` working in any browser on the network.

**Test:** Start a plain HTTP server. Add proxy entry. Verify HTTPS access from another machine. Renew cert → verify proxy hot-reloads without dropping connections.

---

## Implementation Guidelines

### Code Style

- `rustfmt` default configuration. No exceptions.
- `clippy` at `warn` level in CI, `deny` for `clippy::correctness`.
- Meaningful error messages. Not "failed to connect" but "Failed to connect to certmesh CA at 192.168.1.10:8443: connection refused. Is the CA running? Try `koi certmesh status`."
- No `unwrap()` in library crates. `expect()` with messages only in CLI where the invariant is truly documented.

### Security

- All key material structs derive `Zeroize` + `ZeroizeOnDrop`.
- TOTP comparison uses `subtle::ConstantTimeEq`.
- No logging of TOTP codes, private keys, or passphrases — even at trace level.
- Cert files written with restrictive permissions (0600 on Unix).
- CA private key encrypted at rest, always. No "skip encryption for development" mode.

### Testing

- Each phase must have integration tests that exercise the full flow.
- mDNS tests may need to be marked `#[ignore]` for CI (multicast doesn't work in containers).
- Certmesh tests: use temp directories for cert storage, mock the trust store.
- DNS tests: use high ports (>1024) to avoid needing root.
- Proxy tests: spin up test HTTP server, add proxy, verify HTTPS works.

### Error Handling

- Library crates: `thiserror` with typed enums. Every error variant should suggest an action.
- CLI binary: `anyhow` for contextual wrapping. Top-level handler prints user-friendly message.
- Never panic on network errors. Networks are unreliable. Handle it.

### Cross-Platform

- Test on Linux (primary), macOS, and Windows.
- Trust store installation is the most platform-specific code. Isolate it in `koi-truststore`.
- Use `dirs` crate for all platform paths. Never hardcode `/home/` or `C:\Users\`.
- Port 53 permissions are platform-specific. Handle gracefully with clear error messages.

---

## What Not to Build

Preserved from architecture review for future reference:

**Container port forwarding.** Rejected. Docker bridge NAT, WSL2, Podman rootless, Kubernetes CNI — each different, each changing. The real pain is solved by DNS naming + proxy TLS termination.

**General-purpose monitoring.** Health is present tense only. No time-series, no graphs, no alerting. Use Prometheus/Grafana for that.

**DNSSEC.** Disproportionate for local networks. Certmesh provides trust at the TLS layer instead.

**General-purpose reverse proxy.** No URL rewriting, no load balancing, no WAF. Koi Proxy is a cert-aware TLS pipe, nothing more.

**Let's Encrypt Bridge Mode.** Specified in the design doc but intentionally deferred. Build Local CA Mode first, validate the architecture, then add ACME integration as a separate phase. The enrollment, failover, and lifecycle infrastructure is the same — only the cert source differs.

---

## Quick Reference: CLI Surface

```
# Cross-cutting
koi status                                    # Unified dashboard
koi version                                   # Build info
koi help                                      # Usage

# mDNS (Phase 0-1)
koi mdns discover                             # Find services
koi mdns announce                             # Advertise a service
koi mdns status                               # Discovered services, cache state

# Certmesh (Phase 2-5)
koi certmesh create                           # Initialize CA
koi certmesh join                             # Enroll with TOTP
koi certmesh promote                          # Become standby CA
koi certmesh status                           # Roster, cert expiry
koi certmesh revoke <host>                    # Remove from mesh
koi certmesh backup                           # Encrypted export
koi certmesh restore                          # Rebuild from backup
koi certmesh rotate-secret                    # New TOTP secret
koi certmesh open-enrollment                  # Open enrollment window
koi certmesh close-enrollment                 # Close enrollment window
koi certmesh compliance                       # Security summary
koi certmesh log                              # Audit log
koi certmesh unlock                           # Decrypt CA key
koi certmesh set-hook --reload "<cmd>"        # Post-renewal command

# DNS (Phase 6)
koi dns serve                                 # Start resolver
koi dns stop                                  # Stop resolver
koi dns status                                # Names, upstream, stats
koi dns lookup <name>                         # Manual query
koi dns add <name> <ip>                       # Static entry
koi dns remove <name>                         # Remove static entry
koi dns list                                  # All resolvable names

# Health (Phase 7)
koi health status                             # Full health view
koi health watch                              # Live terminal view
koi health add <name> --http <url>            # HTTP check
koi health add <name> --tcp <host:port>       # TCP check
koi health remove <name>                      # Remove check
koi health log                                # State transitions

# Proxy (Phase 8)
koi proxy add <name> --listen <port> --backend <url>
koi proxy remove <name>
koi proxy status
koi proxy list
```
