# Distribution formats & free signing — prior-art research

**Status:** superseded as a decision record — its recommendations were **ratified 2026-08-25** and now
live in [`adr/034-multi-channel-distribution.md`](adr/034-multi-channel-distribution.md). This page
remains as the research/evidence appendix.
**Date:** 2026-08-25. Facts checked against live sources the same day (links at bottom).
**Goal (operator):** Koi available in several installation formats (npx, …); one-click
download+install regardless of OS; service starts; GUI fires minimized/tray where the OS supports it;
free signing wherever a genuinely free path exists.

---

## 0. What rc.2 already ships (assets to build on)

| Asset | State |
|---|---|
| GitHub Releases: 6 archives + sha256 sidecars + canonical manifest | live since rc.2 |
| GHCR container image | live, exact-version tags |
| crates.io `koi-*` | live (rc.2); cargo-binstall metadata wired |
| `@sylin-org/koi` npm dispatcher | **built, inert** — version-pinned downloader of official archives; publishes only when `NPM_PUBLISH_ENABLED` is set (ADR-025) |
| `koi install` real installer | Windows SCM service + Linux systemd unit, W1 lane physically green |
| `koi-desktop` workbench (Tauri 2) | tray MVP landed (status line/Open/Quit), Ghostlight-pinned tauri versions (ADR-033) |
| Release workflow | dry-run gate validates checkout/manifests before tagging (RL-1/RL-10); registries immutable (RL-2) |

## 1. Signing reality matrix (2026)

### Windows (Authenticode / SmartScreen)

| Path | Cost | Notes |
|---|---|---|
| **SignPath Foundation** | **Free for OSS** | OV-level cert issued *to the Foundation*, key on their HSM, CI-integrated (GitHub Actions). They verify each signed binary was built from our public repo ("origin verification"). Conditions: OSI license ✓ (MIT/Apache dual), public repo ✓, actively maintained ✓, already-released artifacts ✓, documented download page ✓, attribution line in README ("Free code signing provided by SignPath.io, certificate by SignPath Foundation"). Publisher shown on SmartScreen = "SignPath Foundation"; reputation accrues per signing identity. **This is the load-bearing free path.** |
| Azure Artifact Signing (ex-Trusted Signing) | $9.99/mo | Microsoft's recommended non-Store path; geo-limited (orgs US/CA/EU/UK; individuals US/CA only); reputation still builds from zero. Only worth it if SignPath doesn't fit. |
| Microsoft Store (MSIX) | Free signing | Microsoft re-signs → zero SmartScreen warnings. But Store submission is an external action and MSIX identity/packaging is real work. Defer; revisit post-1.0. |
| EV certificate ($400+/yr) | — | **No longer bypasses SmartScreen** (behavior removed 2024). Do not buy for this reason. |
| Unsigned | Free | "Windows protected your PC" every version, forever; Win11 Smart App Control may hard-block unsigned binaries entirely. |

Key mechanic: SmartScreen reputation attaches to the **signing identity**, so consecutive signed releases
inherit accumulated trust; unsigned files restart at zero every release.

### macOS

| Path | Cost | Notes |
|---|---|---|
| Developer ID + notarization | **$99/yr** (Apple Developer Program) | The only path that makes browser-downloaded DMGs open warning-free. macOS 15 removed the right-click→Open bypass; unsigned/quarantined apps need System Settings approval. Apple Silicon requires at least ad-hoc signing to run at all. |
| Terminal / package-manager installs | Free | Gatekeeper triggers on the **quarantine attribute**, which browsers set but `curl`/brew/scoop-style tools do **not**. Binaries installed via `curl … \| sh`, Homebrew, or MacPorts run fine with zero Apple paperwork. |

So macOS has a fully free path as long as first install flows through a terminal or brew — which is also
how deno/bun/uv/rustup ship to macOS today.

### Linux

No Authenticode-analog needed. GPG-signed apt/yum repos are free when we add them; AUR/Nix/Flathub have
their own review/verification but no fees. Our tarball+`koi install` systemd path is already the product's
own installer (RL-12: test machines run the real installer — same principle for users).

### Free integrity layers that complement OS trust (all free, all recommended)

- **Tauri updater signatures**: minisign-format Ed25519 keypair via `tauri signer generate`; public key
  compiled into the app; `latest.json` manifest + `.sig` files hosted on GitHub Releases. Mandatory for
  the updater plugin anyway; gives update-channel integrity independent of Authenticode/notarization.
- **GitHub artifact attestations** (`actions/attest-build-provenance`): free build-provenance for release
  archives; `gh attestation verify` for users.
- **npm provenance**: automatic when publishing via trusted publishing (OIDC) from GitHub Actions.
- **cosign keyless** on the GHCR image: free Sigstore signing if we want it.

## 2. Install-format prior art, per channel

### The one-liner landing page (deno/bun/rustup/uv pattern)
A static page detects OS and prints the right command:

```text
macOS/Linux:  curl -fsSL https://get.koi.dev/sh | sh
Windows:      irm  https://get.koi.dev/ps1 | iex
```

Prior art: deno.land/install.sh+ps1, bun.sh, rustup.rs, astral.sh (uv/ruff), pnpm. Hosting = static files
(GitHub Pages or any static host, free). The script downloads the right archive from GitHub Releases,
verifies its sha256 against the release's checksums, installs to a user dir, and invokes `koi install`
(the product's own installer) plus optional tray registration. This satisfies "one command, any OS" and
costs zero signing: nothing is quarantined (no browser MOTW), and Windows' `iex` path runs without
writing a flagged file (the downloaded archive does get MOTW → SmartScreen applies to it; see §4).

### npm (`npx` / global install)
Two proven shapes:

1. **Dispatcher (current @sylin-org/koi design)**: thin package that downloads the official archive pinned to
   the exact version at install time. Pro: single artifact source of truth, no binary inside npm. Con:
   network fetch during install; supply-chain story rests on the dispatcher's hash check.
2. **Platform-carrier packages (esbuild pattern)**: `@sylin-org/koi` carries `optionalDependencies` like
   `@sylin-org/koi-win32-x64`, `@sylin-org/koi-linux-arm64`, … each with `os`/`cpu` fields so npm downloads only
   the matching binary; launcher resolves + execs it. Prior art: esbuild (`@esbuild/*`), Biome,
   rollup, tailwindcss/oxide, bun, microsoft/apm. No postinstall download; works offline after install;
   npm provenance covers each package. Con: N packages per release, all must be version-synced, and it
   amends ADR-025's "never cache-hosted runtime" stance (registry now hosts binaries).

Either way: flip live requires operator actions — configure npm **trusted publishing** (OIDC, no
long-lived token; npm ≥ 11.5.1; per-package trusted-publisher setting) and set `NPM_PUBLISH_ENABLED`.
`npx @sylin-org/koi@rc …` then works with no install at all.

### Package managers

| Channel | Cost/review | Fit |
|---|---|---|
| **Homebrew tap** (self-hosted repo) | none | First-class macOS + Linux CLI distribution we control; formula pins URL+sha256 of our release archives. homebrew-core submission later once notable. Cask for the .app. |
| **Scoop bucket** (self-hosted) | none | Windows CLI/portable, same shape as tap. |
| **winget** (winget-pkgs PR) | community review; external action (ADR-032 P4 anticipated this) | Requires: silent install support (NSIS `/S` ✓), direct ISV URLs (our GitHub Releases ✓), InstallerSha256 pinned, elevation declared (service install = `elevationRequired`). Signing not mandated, but SmartScreen reputation checks run against installer URLs during validation. |
| **AUR** | account + PKGBUILD, free | Arch users expect it; can be `-bin` pulling release artifacts. Community-maintained allowed. |
| **Nix flake** | self-hosted in repo | Cheap to maintain, strong adoption among the target audience. |
| **Flathub** | free, verification required | Later; GUI-first channel. |
| **cargo install** | already live | `cargo install koi-net` (+ binstall fast-path already wired). |

## 3. One-click-per-OS UX ladder (recommended target state)

| OS | Best free one-click story | Upgrade path |
|---|---|---|
| Windows | Landing page → `irm get.koi.dev/ps1 \| iex` installs service + tray app; **or** winget; **or** signed NSIS installer double-click | SignPath-signed NSIS (service + workbench in one installer, registers SCM service + autostart-to-tray). Reputation accrues under the Foundation identity; warnings fade over releases. Store/MSIX much later. |
| macOS | Landing page → `curl … \| sh` (or `brew install sylin/tap/koi`) — no quarantine, no warnings, free | Notarized DMG only if/when browser-download UX matters ($99/yr, operator call). |
| Linux | Landing page → `curl … \| sh` invoking the product's own `koi install` (systemd unit, default data root) | deb/rpm (Tauri bundler emits them for the GUI), AUR, Nix flake, signed apt repo later. |

"Single click regardless of OS" therefore decomposes into: one landing page + three native flows, all
fed by the existing release manifest chokepoint (ADR-025 stays the publication spine).

## 4. Service-fires-GUI-minimized: the correct mechanism

The daemon never spawns the GUI (Session 0 isolation makes that wrong on Windows, and daemons outlive
sessions). Prior art instead binds **user-session autostart of the tray app** to the installed service:

- `tauri-plugin-autostart` v2 (2.x): Windows (Run-key), macOS (LaunchAgent or AppleScript launcher),
  Linux (XDG autostart) — supports launch args, e.g. `--minimized`.
- koi-desktop already has the tray MVP; add a `--minimized` flag (start hidden, lamp-only) + a settings
  toggle that calls enable/disable. First-run of the installer/workbench enables autostart by default;
  tray connects to the local service over the frozen loopback API (existing transport rules).
- On headless/server Linux, no GUI component is installed at all — the split is already natural:
  `koi` (service) vs `koi-desktop` (session UI).

## 5. Phased proposal (each phase independently landable; external touches stay operator-gated)

- **P-A — no new authority needed:** landing page + install scripts (sh/ps1) driving existing archives +
  `koi install`; Tauri updater keys + `latest.json` feed for koi-desktop; `--minimized` flag +
  autostart wiring in the workbench; GitHub build attestations in the release workflow.
- **P-B — operator console actions:** npm trusted publisher (OIDC) config + `NPM_PUBLISH_ENABLED`; decide
  dispatcher vs esbuild-style carriers (amends ADR-025 if carriers).
- **P-C — free Windows signing:** apply to SignPath Foundation (operator submits; free; attribution line
  goes in README); wire their GitHub Actions step into the release pipeline for NSIS + exe.
- **P-D — taps & submissions (each its own operator approval):** Homebrew tap, Scoop bucket, winget PR,
  AUR pkgbuild, Nix flake.
- **P-E — optional spend:** Apple Developer Program $99/yr for notarized DMG (only if browser-download
  macOS UX becomes a requirement).

## 6. Decision points for the operator

1. npm shape: keep ADR-025's downloading dispatcher, or amend to esbuild-style platform carriers?
2. Apply to SignPath Foundation? (attribution line in README is the string attached)
3. Is terminal-first macOS acceptable for 1.0 (free), deferring notarization ($99/yr)?
4. Landing page domain/host (static, e.g. GitHub Pages behind a `get.` subdomain)?
5. Which package-manager submissions to authorize, in what order?

## Sources (checked 2026-08-25)

- Microsoft, "Code signing options for Windows app developers" — pricing table, EV-bypass removal,
  SignPath Foundation mention: learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- Microsoft, "SmartScreen reputation for Windows app developers": learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
- SignPath Foundation program + conditions: signpath.org, signpath.org/terms.html
- Azure Artifact Signing pricing (ex-Trusted Signing): azure.microsoft.com/en-us/products/artifact-signing
- Tauri v2 Updater (minisign keys, latest.json): v2.tauri.app/plugin/updater/
- Tauri v2 Autostart plugin (Win/macOS/Linux, launch args): v2.tauri.app/plugin/autostart/
- npm trusted publishing + provenance: docs.npmjs.com/trusted-publishers, docs.npmjs.com/generating-provenance-statements
- esbuild platform-package pattern + trusted-publishing runbook: esbuild.github.io/getting-started/, github.com/evanw/esbuild/blob/main/RUNBOOK.md
- winget repository policies/validation: learn.microsoft.com/en-us/windows/package-manager/package/repository
- macOS Sequoia unsigned-app behavior / notarization requirements: ytyng.com/en/blog/tauri-github-actions-macos-sign-notarize (Developer ID $99/yr, right-click bypass gone)
