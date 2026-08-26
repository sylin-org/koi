# ADR-034: Multi-Channel Distribution & Free Signing

**Status:** Accepted (operator-ratified 2026-08-25)
**Date:** 2026-08-25
**Builds on:** ADR-025 (artifact-first release channel; the manifest stays the publication chokepoint), ADR-032 P4 (installer groundwork), ADR-033 (koi-desktop workbench, tray MVP)
**Research input:** [`docs/distribution-prior-art.md`](../distribution-prior-art.md) — per-channel prior art and signing-cost matrix, sources checked 2026-08-25

---

## Context

Koi ships today as GitHub Release archives + checksums + canonical manifest (rc.2), a GHCR image,
crates.io crates with binstall metadata, an inert `@sylin-org/koi` npm dispatcher, and the product's own
`koi install` (SCM service / systemd unit). The operator wants: several installation formats including
npx; one-click install on any OS; the service starting headless; and the workbench GUI coming up
minimized/tray where the OS supports it — using **free** signing wherever a genuinely free path exists.

## Decision

### D1 — Publication spine unchanged

Every format is generated from the same release manifest chokepoint (ADR-025). No format may introduce a
second artifact source of truth. The release dry-run gate (RL-1/RL-10) is extended to validate each new
format's outputs (carrier packages, `latest.json`, attestations) **before** tagging.

### D2 — Landing page lives on sylin.org's Koi page (operator-hosted)

The OS-detecting install page is served from the operator's existing site rather than a new domain.
Canonical script paths: `<koi-page>/install.sh` and `<koi-page>/install.ps1` (exact host path is
operator-owned). Scripts download the pinned archive from GitHub Releases, verify its sha256 against the
release checksums, then invoke the product's own installer (`koi install`) plus optional tray
registration. Terminal installs never set a quarantine attribute → no Gatekeeper/SmartScreen surface on
this path. Precedent: deno.land/install.{sh,ps1}, bun.sh, rustup.rs.

### D3 — Windows Authenticode via SignPath Foundation (free) — application submitted 2026-08-25

The Foundation application was submitted 2026-08-25 (project "Koi", repository
`sylin-org/koi`, maintainer type "Independent community project", build system "GitHub Actions");
Foundation review is pending. Eligibility holds: OSI dual license
(MIT/Apache-2.0), public repos, actively maintained, released artifacts, documented download page.
Strings attached and accepted: publisher identity reads "SignPath Foundation"; README carries
"Free code signing provided by SignPath.io, certificate by SignPath Foundation" (added to README and
release notes when signing goes live); their origin-verification
step joins the release pipeline. `SIGNPATH_ENABLED` remains false before approval, so releases stay
possible with an explicit unsigned status. Once enabled, missing credentials or a failed signing request
stops publication. SmartScreen reputation accrues under
the Foundation's identity across consecutive signed releases; EV certificates are explicitly rejected
(no SmartScreen bypass since 2024); Azure Artifact Signing ($9.99/mo, geo-limited) is the fallback only
if SignPath declines.

### D4 — macOS is terminal-first for 1.0 (free)

Distribution flows through `install.sh`, Homebrew, or direct `curl` of archives — none set quarantine,
so unsigned-but-hash-pinned binaries run without Apple paperwork. Notarized DMG ($99/yr Developer ID)
is deferred until browser-download macOS UX is actually demanded; revisit as its own decision.
DMG/App bundles still get ad-hoc signatures (required to run at all on Apple Silicon).

### D5 — npm becomes the esbuild-pattern carrier set (amends ADR-025)

`@sylin-org/koi` remains the entry package but stops being an install-time downloader. It declares
`optionalDependencies` on platform carriers (`@sylin-org/koi-win32-x64`, `-linux-x64`, `-linux-arm64`,
`-darwin-x64`, `-darwin-arm64`, …) whose `os`/`cpu` fields make npm fetch exactly one binary; a thin
launcher resolves and execs it (env override for CI). Carriers are pure binary carriers: no scripts, no
runtime deps, binaries sha256-verified against the release checksum file at packaging time. All carrier
versions equal the exact release version (registry immutability respected — carriers debut at the next
version; rc.2 is never repointed, RL-2). Publishing uses npm trusted publishing (OIDC, cloud runners)
so provenance attests automatically. This supersedes ADR-025's download-dispatcher mechanics and its
"one binary package per target" rejection; ADR-025's placement rule is restated as unchanged law:
**a service is never registered from an npm-managed path** — `koi install` (landing-page scripts,
NSIS installer, or the npm-installed `koi` shim) still places the binary in Koi's stable per-user
location and registers from there; npx trials may run from cache, installs never do.
Operator actions required once: trusted-publisher config per package + `NPM_PUBLISH_ENABLED`.

### D6 — Package-manager channels authorized (top free set)

In implementation order:

1. **Homebrew tap** `sylin/homebrew-tap` (self-hosted, zero review): formula for the CLI/service;
   cask for the .app later.
2. **winget** (winget-pkgs PR): NSIS installer `/S` silent, direct GitHub Release URLs,
   `InstallerSha256` pinned, `ElevationRequirement: elevationRequired` (service install).
3. **AUR** `-bin` PKGBUILD pulling release artifacts.
4. **Scoop bucket** (self-hosted), mirroring the tap shape.
5. **Nix flake** in-repo.

Deferred, with reasons recorded: Flathub/Snap (sandboxing conflicts with a systemd/SCM service model —
a sandboxed GUI would not see the host daemon), Microsoft Store/MSIX (external action + packaging
identity work; free re-signing noted for later), Chocolatey (redundant with winget+Scoop for this
audience). Each submission above remains an individually operator-approved external touch.

### D7 — Tray-minimized autostart is product behavior, split by session

The daemon never spawns the GUI (Windows Session 0 isolation makes that structurally wrong; daemons
outlive user sessions). Instead: `tauri-plugin-autostart` v2 registers koi-desktop per-user at login
with a `--minimized` flag (start hidden, lamp-only). Installers and first-run enable it by default; a
workbench settings toggle calls enable/disable. Headless Linux servers install no GUI component at all.

### D8 — Free integrity layers ship alongside

Tauri updater minisign keypair (mandatory for the updater plugin; public key compiled in; `latest.json`
+ `.sig` hosted on GitHub Releases); GitHub build provenance attestations on all release archives;
npm provenance via trusted publishing; cosign keyless on GHCR optional.

## Consequences

- One NSIS installer (service + workbench + autostart registration) becomes the Windows double-click
  story; the ps1 one-liner remains the no-GUI path. Both consume identical signed payloads.
- The release workflow grows: carrier-package assembly + hash verification, `latest.json` generation,
  SignPath step (secret-gated), attestations. All validated by the pre-tag dry run.
- SignPath application is an external operator action; everything else in P-A/P-B is local work.
- Registry inventory grows from 17 crates + 1 npm package to ~1 entry + N carriers per release; the
  publish-inventory check must cover them.

## Alternatives considered

- Keep ADR-025's downloading dispatcher unchanged — rejected: install-time network fetch breaks behind
  proxies/custom registries and has a weaker supply-chain story than hash-pinned carriers with provenance.
- Buy EV/Authenticode retail — rejected: EV no longer bypasses SmartScreen (2024); $150–400/yr buys
  nothing SignPath doesn't give free.
- Electron-style auto-update without OS signing — rejected: updater signatures prove integrity, not
  publisher identity; first-install UX still needs the OS-level trust path (D3/D4 handle it).
