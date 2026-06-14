# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
