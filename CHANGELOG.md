# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-06-22

A consolidation-and-hardening release: a unified serving layer, security hardening (with a
few deliberate behavior changes), one-line install + a signed multi-arch container image,
and a documentation overhaul. Pre-1.0, so a minor bump — but it carries behavior changes
(see **Changed** / **Security**); review the [upgrade guide](docs/guides/upgrading.md)
before upgrading a non-loopback or scripted deployment.

### Added
- **One-line install scripts** — `install.sh` (Linux/macOS) and `install.ps1` (Windows)
  detect your OS/arch, download the matching release archive, verify its SHA-256, and
  install `koi` onto your `PATH`. No root for the default per-user location;
  `KOI_VERSION` / `KOI_INSTALL_DIR` override the tag and path.
- **Published container image** — `ghcr.io/sylin-org/koi`, multi-arch (linux/amd64 +
  linux/arm64), assembled on each release from the exact musl binaries.
  `docker run -d ghcr.io/sylin-org/koi:latest`.
- **Signed build provenance** — every release archive and the container image carry a
  GitHub Artifact Attestation (Sigstore, keyless); the image also ships an SBOM. Verify:
  `gh attestation verify <file|oci://…> --repo sylin-org/koi`.
- **`koi-serve` crate** — the serving layer (the one HTTP/OpenAPI router, IPC, MCP HTTP,
  inter-node mTLS + ACME, Prometheus SD, dashboard wiring, and the posture-reactive trust
  plane) extracted from the binary; one `koi_serve::serve()` is shared by the daemon, the
  Windows service, and `koi-embedded`. New crate on crates.io.
- **`--dns-qps` / `KOI_DNS_QPS`** — configure the DNS query-rate limit (default 200).
- **Embedded:** `http_port(0)` ephemeral binding read back via `KoiHandle::bound_http_port()`,
  and the `koi_embedded::testkit` module for in-process integration tests.
- Lenient boolean parsing for the `--no-*` / `KOI_NO_*` env family (`1`/`true`/`yes`/`on`).

### Changed
- **The install scripts finish with a live result** — they run `koi status` and hand off to
  `koi mdns discover` / `koi install`, so onboarding lands on something visible.
- **Embedded HTTP is secure-by-default** — it binds loopback; `announce_http()` now
  **requires** `http_token(..)` or `start()` fails closed with `KoiError::InsecureConfig`
  (was a warning). *Breaking for embedders that exposed HTTP without a token.*
- **Rate-limited DNS queries return `REFUSED`** (was `SERVFAIL`, which invites retries).
- **`GET /v1/certmesh/log` requires the token on every method** — the CA audit log is no
  longer a token-free read. *Breaking for scripts that read it unauthenticated.*

### Security
- **DNS rate limiting is now per source IP** — each client gets its own budget
  (`--dns-qps`) with a whole-resolver backstop and a hard-bounded client map, so one noisy
  or hostile LAN peer can no longer starve resolution for everyone (the old single global
  bucket's failure mode; spoofable UDP sources can't grow the map without limit).
- **Trust/zone reads are peer-gated on a non-loopback bind** — `GET /v1/certmesh/diagnose`
  and `/v1/dns/{list,zone,entries}` require the `x-koi-token` from a non-loopback peer
  (loopback callers stay token-free; an unknown peer fails closed). `/v1/certmesh/status`
  and `/v1/certmesh/trust-bundle` stay open by design — they are load-bearing in the
  unauthenticated cross-host enrollment / trust-sync protocol (the trust-bundle is
  ES256-signed and self-verifying). *Breaking for remote scripts that read these tokenless.*
- **The whole `/v1/udp/*` surface is token-gated on every method** — `GET /v1/udp/status`
  and `/v1/udp/recv/{id}` expose other token-holders' bindings and datagrams.
- **UDP binds loopback by default** — a non-loopback bind or destination now requires
  `--allow-remote` (an SSRF / egress-relay guard). *Breaking for `koi udp bind` to `0.0.0.0`.*
- Certmesh `/promote` + `/set-hook` reject revoked members; the mDNS→DNS alias bridge drops
  non-private IPs; CORS is restricted to exact loopback origins; the data directory is created
  `0700` (Unix) / ACL-restricted (Windows); CA-vault secrets are written owner-only; ACME
  refuses new accounts while enrollment is closed.

### Fixed
- The Windows-service uptime clock now starts before core build (it had been undercounting by
  the CA auto-unlock time).

### Internal
- `impl CertmeshCore` split into eight cohesive submodules; dropped unused dependencies; shed
  the production-dead pipeline streaming-status machinery; de-flaked the embedded-UDP and proxy
  data-plane tests under parallel load.

### Documentation
- A full capability-coverage audit drove a three-wave doc pass: a reference truth-pass (auth
  model, cert policy, DNS rate limit, embedded API), **11 new capability cards** + a cards
  index, an [overview / "is it for you?"](docs/overview.md), and a
  [ports & firewall reference](docs/reference/ports.md).

## [0.4.2] - 2026-06-21

A large lean-and-reach release: the certificate mesh is roughly halved, the CLI surface
is unified on clap, and Koi gains four ways to feed the tools you already run — an MCP
server for AI agents, an ACME server, Prometheus discovery, and label/DNS/trust doors.
It also lands the **ADR-020 mode-transparent trust plane** (every node carries a
*posture*, with signed/sealed messages, posture-reactive listeners, and a trust-doctor),
**hardens enrollment** (pinned-fingerprint invites, a sequenced signed roster, machine
binding), spins the OS trust-store installer out to the external `os-truststore` crate,
and fixes a long-standing mDNS browse bug on long-lived daemons.
It carries **breaking changes** despite the patch version (pre-1.0, 0.x): see *Removed*
and *Changed* below — existing certmesh `roster.json` files may need a
`koi certmesh create` re-run.

### Added
- **`koi mcp serve`** — an MCP server over stdio so AI agents get a first-class door into
  the LAN (discover/announce/resolve/inventory/health/runtime tools, heartbeat-leased
  announcements that clean up on agent crash). One-line config in any MCP client. New
  `koi-mcp` crate; `docs/guides/mcp.md`.
- **`koi certmesh acme enable`** — an RFC 8555 ACME server (dns-01, self-served in-process
  through Koi's own DNS zone — wildcards + offline issuance, no propagation wait). Caddy,
  Traefik, lego, acme.sh get certs from Koi's CA with one config line; `docs/guides/acme.md`.
- **`GET /v1/sd/prometheus`** — Prometheus HTTP service discovery, including the unique
  `__meta_koi_cert_expiry_days` per-service certificate-expiry label.
- **Traefik / caddy-docker-proxy label ingestion** — a container labelled only for Traefik
  or Caddy gets a Koi DNS name with zero relabeling.
- **`GET /v1/dns/zone?format=hosts|dnsmasq|json`** + `docs/guides/dns-coexistence.md`
  (conditional-forwarding recipes for AdGuard Home, Pi-hole, dnsmasq, Unbound, Technitium).
- **`koi trust install|list|remove|export`** — install/track/remove any CA root (not just
  certmesh's) in the OS trust store.
- `koi-common::runtime_state::DomainRuntime` + `events` + an async `Capability` trait, and
  `docs/reference/domain-template.md` — the documented contract for adding a domain.
- **Mode-transparent trust plane (ADR-020).** Every node carries a *posture* (Open ↔
  Authenticated) derived from its local identity, with one API that behaves the same in
  both modes: a `Posture`/`PostureLevel` oracle; `ensure_identity()`, an idempotent
  identity maintainer; signed `Envelope`s (carry-cert ES256 — verify offline against the
  mesh root); `Sealed` confidentiality; a typed `Peer` + `discover()` + a posture-keyed
  `client_for`; and a **same-port posture dial** — one listener serves plaintext while
  Open and mTLS once Authenticated, flipping live with no dropped connections — that
  drives the mTLS (5642) and ACME (5643) listeners reactively. `participate()` is the
  three-line trusted service. Exposed across `koi-common`, `koi-certmesh`, and
  `koi-embedded`; the language-neutral wire contract is in `docs/reference/trust-protocol.md`.
- **`koi trust diagnose [--fix]`** (`GET /v1/certmesh/diagnose`) — a trust-doctor that
  reports posture, identity integrity, self-revocation, renewal health, CA-trust-install,
  and clock skew, each with a distinct remedy, and exits non-zero on RED.
- **Hardened enrollment (ADR-015 F1/F2 + ADR-017).** Pinned-fingerprint invites
  (`<secret>.<ca_fp>` → preflight + install hard-fail on mismatch; TOTP stays TOFU);
  least-privilege certificate profiles; member-pull rotate-key renewal over mTLS; a signed
  monotonic trust bundle with a sequenced single-writer roster + boundary revocation;
  `_certmesh._tcp` fingerprint advertisement + trust-anchor self-heal; machine-binding
  clone-refusal at boot.

### Changed
- **certmesh slimmed 18.7k → 9.4k source lines** with zero loss of the create / TOTP-join /
  renew / unlock / backup / restore / revoke / manual-promote loop.
- **CLI is now driven by clap as the single source of truth** — catalog drift is a build
  failure; the generic `command-surface` crate is gone (folded into `koi/src/help/`).
- Trust profiles collapse to two booleans (`enrollment_open`, `requires_approval`); the
  named presets survive as ceremony/CLI UX labels only. `CertmeshStatus` drops `profile`
  and gains the two booleans.
- The CA boots auto-unlocked from the vault on auto-unlock profiles (the write path, latent
  in 0.4.1, now functions).
- **The OS trust-store installer spun out to the external `os-truststore` crate (ADR-019)**
  — published separately on crates.io with a cert-as-identity API; the in-tree
  `koi-truststore` crate is removed. No user-facing change.
- **The `_certmesh._tcp` CA-discovery announcement is now posture-reactive** — a node that
  boots Open then runs `certmesh create` advertises immediately, with no daemon restart
  (folded into the same posture-watch supervisor that drives the mTLS/ACME listeners).

### Removed (breaking)
- **FIDO2** (all three layers — the `AuthAdapter` trait stays as the re-entry path).
- **Automatic CA failover** (the mDNS absence-watcher / tiebreaker / roster-sync); manual
  `koi certmesh promote` remains.
- The **certmesh compliance** endpoint + CLI (use `/status` + `/log`).
- Enrollment **deadline** + **CIDR/domain scope** (`set-policy`).
- `RuntimeBackendKind` **Systemd/Incus/Kubernetes** stubs — `koi --runtime k8s` is now a
  clear parse error instead of a silent fallback.

### Fixed
- **Destructive commands no longer bypass confirmation in `--json` mode** — `koi --json
  certmesh destroy` / `factory-reset` previously wiped data silently; they now refuse
  without `--yes` (one shared confirmation gate).
- **The `--endpoint` token leak**: an explicit remote endpoint no longer receives the local
  daemon's breadcrumb token. New `--token` / `KOI_TOKEN`; a 401 prints an actionable hint.
- Catalog/manifest drift (rotate-totp, phantom flags, wrong dns record types) — fixed by
  construction via the clap conformance tests.
- **Certmesh enrollment was blocked by the DAT token.** `POST /v1/certmesh/join` is
  TOTP-authorized (a joining node can't know the CA host's local token), but the DAT
  auth middleware required the token on every mutation, so a tokenless `koi certmesh
  join` was rejected with 401 by the daemon. `/v1/certmesh/join` is now exempt from the
  token requirement (the handler still enforces the TOTP code + enrollment policy);
  every other certmesh write remains token-gated.
- **The ACME server-auth TLS listener would panic on start.** `adapters::acme::build_tls_config`
  used a bare `rustls::ServerConfig::builder()`; with both aws-lc-rs (rustls) and ring
  (koi-crypto) linked there is no process-level default crypto provider, so the listener's
  spawned task panicked and the ACME port silently failed to come up. It now resolves the
  provider explicitly (aws-lc-rs via `builder_with_provider`), matching `koi_certmesh::mtls`
  and koi-proxy. Guarded by a new unit test.
- **`koi certmesh join <endpoint>` misrouted the joiner's key custody to the CA.** The
  global `--endpoint` and the `join` / `promote` positional CA endpoint collided on clap's
  arg id, so passing a CA positionally silently populated `--endpoint`; `join` then resolved
  its LOCAL key-custody daemon (the `member-csr` / `member-cert` calls that generate and
  keep the member private key) from that and sent them to the remote CA, which rejected
  them with 401. The positional is now `ca_endpoint` (no id collision) and `join` / `promote`
  always resolve the local daemon from the breadcrumb. Found by the new ADR-018 cross-host
  integration test.
- **A long-lived daemon's `discover` (and the dashboard LAN browser) surfaced nothing**,
  while a cold standalone `koi mdns discover` resolved fine and `koi mdns resolve` worked
  on the *same* daemon. The browse hub multiplexes one mdns-sd browse per type across N
  subscribers via a future-only channel; mdns-sd replays its cache only to the first
  listener, so any discover that joined an already-cached type (e.g. once the lazy LAN-wide
  meta-browse held it) received future events only and never saw the already-resolved
  service. `subscribe_type` now replays the per-type warm record cache to the joining
  subscriber (that subscriber only). Stock mdns-sd, no fork; root-caused and validated on
  the two-box hardware gate.
- **`koi status` now surfaces mDNS receive-health** — a browse that has been active on a
  live LAN with zero inbound is reported as such instead of a silent "healthy", per
  ADR-020's anti-silence ethos.

## [0.4.1] - 2026-06-15

### Added
- New `koi-compose` composition crate — the single place the daemon, the Windows service, and `koi-embedded` construct a running daemon (domain cores, cross-domain bridges, the container orchestrator, the certmesh role loops, capability status, and ordered shutdown). It is a composition crate consumed only by the binary and `koi-embedded`, so the kernel and domain crates keep clean dependency closures.
- A workspace dependency-graph architecture guard (`koi-common/tests/architecture.rs`) that fails the build if any domain crate depends on another domain crate.
- `koi-embedded` builder opt-ins (default-off): `.orchestrator(true)` (translate container lifecycle events into mDNS/DNS/health/proxy entries) and `.certmesh_background(true)` (run the certmesh renewal / roster-sync / heartbeat / failover loops).

### Fixed
- **Windows `koi install` parity:** the Windows service now spawns the runtime orchestrator and the certmesh background loops (renewal, roster sync, member heartbeat, failover) that the foreground daemon runs. Previously `koi install` produced a structurally weaker daemon that silently let certificates expire and never wired discovered containers into the domains. The three daemon entry points now share one construction path, so this cannot drift again.
- **Embedded remote `MdnsHandle::subscribe`** no longer returns a silently dead receiver in client (remote) mode — see the breaking note below.

### Changed
- The certificate-authority data paths now have a single source of truth, and on auto-unlock profiles (`JustMe` / `MyTeam`) the CA boots **already unlocked from the vault** at daemon/service startup instead of requiring `koi certmesh unlock`. `MyOrganization` still boots locked.
- Under the Windows service, an mDNS initialization failure is now non-fatal (the service starts degraded with mDNS disabled), matching the foreground daemon, instead of aborting startup.
- `koi-client` no longer depends on `mdns-sd`: the shared wire types moved to the `koi-common` kernel.
- `main.rs` slimmed from ~1300 to ~156 lines (CLI dispatch, daemon wiring, and infrastructure helpers split into focused modules). No behavior change.

### Breaking
- `koi-embedded`: `MdnsHandle::subscribe()` now returns `Result<broadcast::Receiver<MdnsEvent>, KoiError>`. In embedded mode it returns `Ok(..)` as before; in client (remote) mode it returns `Err(KoiError::RemoteUnsupported)` — there is no all-types lifecycle stream to forward remotely (the daemon's `/v1/mdns/subscribe` requires a service type), so use `MdnsHandle::browse(service_type)` for a remote event stream. Previously it returned a receiver that silently yielded nothing.

## [0.4.0] - 2026-06-13

### Added
- New `koi-dashboard` crate holding the dashboard + mDNS-browser presentation layer (HTML, SSE, snapshot, the single unified event forwarder, the mDNS browse adapter, and a lazy LAN-wide meta-browse). It is a composition crate consumed only by the binary and `koi-embedded`.
- Optional, default-on cargo features for `koi-embedded`'s heavy backends so lean consumers can drop them: `docker` (bollard Docker/Podman client), `keyring` (OS credential store / Secret Service / D-Bus), and `qr` (qrcode + image PNG codec), plus a `full` umbrella. A default dependency is unchanged; `default-features = false` sheds all three (and the bollard-stubs `=` version pin), and any subset is re-armed à la carte. See the embedded guide and ADR-014.
- Lazy mDNS meta-browse: the LAN-wide browse worker now starts on the first browser request and idles out after 5 minutes; `koi status` reports `Browse: active|idle`. Default daemon startup performs no LAN-wide multicast browsing.

### Changed
- Restored `koi-common` to a types-only kernel: the dashboard/browser presentation code and its presentation-only dependencies (`tokio`, `tokio-stream`, `tokio-util`, `async-stream`, `hostname`) moved out to `koi-dashboard`. Domain crates no longer pull them transitively via the kernel.
- The Docker/Podman runtime backend is now gated behind the default-on `docker` feature in `koi-runtime` (the runtime *capability* stays unconditional). With it off, the Docker/Podman/Auto backends resolve to `BackendUnavailable`, like the not-yet-implemented systemd/incus/kubernetes backends. The `koi` binary always ships every backend.

### Fixed
- **Security:** closed verified LAN-attacker XSS vectors in the mDNS browser page. Service names and TXT records are now rendered via DOM construction (`createElement` + `textContent`/`dataset`) instead of HTML-string concatenation, so hostile values can no longer break out of attributes; launch links pass through an explicit `http`/`https` scheme allowlist (dropping `javascript:`/`data:`). The dashboard page's `esc()` is quote-safe and its activity log uses DOM construction, and both pages now send a `Content-Security-Policy` header.

## [0.3.0] - 2026-06-13

### Added
- `--http-bind` flag (and `KOI_HTTP_BIND` env var) to control the daemon's HTTP listen address: `loopback` (default), `bridge` (auto-resolves the Docker/Podman bridge IP at startup), an explicit `<ip>`, or `0.0.0.0`. This makes the headline container use case real — containers reach the daemon over plain HTTP on the bridge address while the daemon stays private by default. Non-loopback binds log a startup warning naming the flag and surface the active address in `koi status` (`Bind:` line / `http_bind` field), the breadcrumb file, and the startup log. Invalid values fail with a clear message.
- `koi token show` and `koi token write <path>` commands for container access. `show` prints the daemon access token, is tty-guarded (refuses to write to a non-tty pipe without `--force`), and supports `--json`; `write` creates a `0600` file (ACL-restricted on Windows) suitable for mounting as a container/Compose secret. Both read the token from the daemon breadcrumb.
- Self-signed certificate fallback in `koi-proxy`: a proxy entry now always starts even when no certmesh-issued certificate is present, giving true zero-config TLS termination.

### Changed
- Rebuilt the `koi-proxy` data plane as a TLS-terminating **TCP passthrough** (`tokio-rustls` + `copy_bidirectional`) replacing the HTTP reverse-forwarder. WebSockets and any bidirectional/upgraded protocol now pass through transparently. Certificate resolution now tries `certs/<entry.name>/`, then `certs/<hostname>/`, then a generated self-signed certificate, and hot-reloads on change. **Breaking:** the `/v1/proxy/status` shape replaces the hardcoded `running: true` with a real `state` (`running`/`error`/…), inline `error` detail, and `cert_source` (`certmesh`/`self-signed`); the dashboard, embedded API, and `koi proxy status` table were updated to match. Listen port and `/v1/proxy/*` paths are unchanged.
- **Breaking:** the daemon's HTTP listener now binds **loopback only by default**. Previously the listener was reachable on the network and the Windows firewall port was opened unconditionally; exposure is now opt-in via `--http-bind`, and on Windows the firewall rule is created only when the port is actually exposed. Exposure never relaxes authentication — token-protected mutations are still required regardless of bind address.
- Reset project versioning to plain pre-1.0 SemVer (`0.3.0`) consistently across the workspace and all internal dependency definitions, replacing the previous timestamp-patched version scheme.
- Consolidated binary and library deployment into explicit SemVer GitHub Releases (tag-triggered), replacing the automated timestamp-patched version pipeline. Installation now uses prebuilt release archives.
- Suspended crates.io automated publishing; isolated it to a manual `workflow_dispatch` workflow with strict dependency ordering and post-publish index-propagation verification.
- Updated installation instructions in the README to point directly to prebuilt GitHub Releases archives.
- Migrated `koi-dns` to the hickory 0.26 family (server/resolver/proto), tracking the upstream `authority` → `zone_handler`, `ServerFuture` → `Server`, and `Header` → `Metadata`/`HeaderCounts` API changes. DNS behavior (response codes, record filtering, control flow) is preserved 1:1; the `/v1/dns/*` surface is unchanged.
- Upgraded `mdns-sd` 0.17 → 0.20 and `bollard` (Docker/Podman client) 0.20 → 0.21, plus in-range refreshes of `chrono`, `hyper`, `serde_json`, `terminal_size`, `tower-http`, `utoipa`, and `zeroize`.
- Replaced the `netdev` dependency with stdlib-based default-route detection for the `/v1/host` interface list (a "connected" UDP socket reports the default-route source IP, matched to an interface via the already-present `if_addrs` crate). This removes 8 transitive crates (`netdev`, `netlink-*`, `dlopen2`, `paste`, `system-configuration`); the `/v1/host` response shape is unchanged.

### Fixed
- Fixed the broken `koi-proxy` data plane: the old listener registered an axum 0.8 `/*path` wildcard route that panicked at startup inside a `tokio::spawn` (silently, while `status()` reported `running: true`), and the cert watcher called `tokio::spawn` from notify's non-tokio thread (panicking on the first cert event). TLS termination — the crate's headline feature — could not have worked since the axum 0.8 upgrade. The rebuild fixes all three structurally and adds a self-signed certificate fallback so a proxy always starts.
- Fixed certmesh-issued proxy certificates never being found unless the proxy entry name happened to equal the hostname (the proxy read `certs/<entry.name>/` while certmesh writes to `certs/<hostname>/`); certificate resolution now falls back through both paths.
- Fixed weekly scheduled QA workflow failures by cleaning up references to deleted `.sh` integration test scripts and replacing them with cross-platform `.ps1` invocations running on PowerShell Core (`pwsh`).
- Repaired `tests/integration.ps1` and `tests/concurrency.ps1` to dynamically resolve operating-system differences (handling `koi` vs `koi.exe` and resolving dynamic breadcrumb endpoint paths).
- Injected Daemon Access Token (DAT) headers (`x-koi-token`) into integration test requests to authenticate mutations against HTTP endpoints.
- Resolved token isolation during client-mode CLI operations by allowing auto-discovery via local environment variables.
- Enabled the crates.io verification script to use explicit pipefail (`shell: bash`) on GitHub Actions so failures are no longer silently ignored.

### Security
- Patched 6 RUSTSEC advisories in the transitive TLS/crypto stack via a targeted lockfile bump (`aws-lc-sys` 0.38.0 → 0.41.0, `aws-lc-rs` 1.16.1 → 1.17.0, `rustls-webpki` 0.103.9 → 0.103.13):
  - RUSTSEC-2026-0048 — `aws-lc-sys` CRL distribution-point scope logic error (CVSS 7.4)
  - RUSTSEC-2026-0044 — `aws-lc-sys` X.509 name-constraints bypass
  - RUSTSEC-2026-0104 — `rustls-webpki` reachable panic in CRL parsing
  - RUSTSEC-2026-0049, RUSTSEC-2026-0099, RUSTSEC-2026-0098 — `rustls-webpki` name-constraint / CRL matching flaws
- Cleared all actionable `cargo audit` informational advisories: dropped `rustls-pemfile` (RUSTSEC-2025-0134, unmaintained) by migrating both direct uses to `rustls-pki-types` `PemObject`; bumped `indicatif` 0.17 → 0.18 to remove `number_prefix` (RUSTSEC-2025-0119, unmaintained); bumped `rand` 0.9.2 → 0.9.4 (RUSTSEC-2026-0097, unsound). Removing `netdev` additionally eliminated the build-time `paste` advisory (RUSTSEC-2024-0436), so `cargo audit` now passes with no ignores. CI gained MSRV, `cargo audit`, and Dependabot enforcement.
