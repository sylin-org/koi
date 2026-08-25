# ADR-031: Desktop Control Plane — Tray, Dashboard-as-Pane, Config Substrate

**Status:** Accepted (operator-approved 2026-08-24). Amended 2026-08-24 by
[ADR-033](033-koi-desktop-workbench.md): L1's tray-icon MVP and the L2
non-decision are superseded — the desktop surface is the Tauri workbench in
`sylin-org/koi-desktop`. Config substrate (below) stands unchanged.
**Date:** 2026-08-24
**Builds on:** ADR-020 (truthful capability ladder), ADR-026 (posture vocabulary), ADR-029 (host classes), the D3 deferral (no config subsystem) which this ADR partially reverses
**Constrained by:** zero-telemetry / no-background-services-beyond-the-daemon doctrine; binary-size discipline

---

## Context

Koi is headless-delightful and desktop-invisible. Servers are fine — defaults boot into
a working system and status tells the truth. But on the machines people actually touch
daily (Windows, CachyOS/desktop Linux), "install-and-you're-done" currently ends at a
health endpoint. There is no tray presence, no at-a-glance posture, no place to see or
change anything without the CLI.

The operator decision: low-cognitive-load delight is now a product goal, Windows and
desktop Linux are first-class targets, and the pane work begins from basics rather than
a grand UI plan.

## Decision

### Layered delivery — cheapest delight first

**L0 — First-run truthfulness (all OSes, ships first).**

- `koi welcome`: on first boot the daemon prints exactly three things — the machine's
  LAN name (`<host>.<zone>`), the dashboard URL, and the single suggested next command.
  Nothing else. Pinned by a unit test on the output contract.
- Adaptive-capability messages become plain sentences stating behavior and reason
  ("discovery is off because avahi is using mDNS — everything else works"), consistent
  across log, `/v1/status`, and welcome output. One wording source in code.

**L1 — Tray control plane (Windows + desktop Linux).**

- Tray icon whose color encodes **posture** (Open / Authenticated / Confidential — the
  existing ADR-020 vocabulary; no new states invented).
- Menu: hostname + level line; Open Dashboard; Renew Now; Copy LAN name; Pause/Resume;
  Quit. Every action maps to an existing daemon surface (loopback HTTP + DAT from the
  breadcrumb, named-pipe IPC once proven) — **the tray introduces zero new daemon API**
  beyond what L0 exposes.
- Implementation: `tray-icon`-family crates (Windows + appindicator on Linux); the
  dashboard remains browser-served by the daemon.
- MVP validation is physical-manual on Windows and one Linux DE, then automated where
  the platform allows.

**Pane strategy: the dashboard *is* the pane.**

The web dashboard grows editable sections in value order — DNS records first (API
exists), webhook sinks, roster view, health checks. No native GUI toolkit is adopted
for L1.

**L2 — Embedded pane shell (deferred, explicit non-decision).**

If/when the pane outgrows the browser, **Tauri** is the leading candidate (Rust core
reuse, small shell, per-OS webviews); egui is the fallback if webview weight is
unacceptable. Deliberately undecided until L1 usage says what the pane must do —
recorded here so the question is not re-litigated silently.

### Config substrate (basics now, refined with the pane)

D3's deferral is reversed in minimal form:

- Versioned TOML at the platform config dir (`%PROGRAMDATA%\koi\config.toml` /
  `~/.config/koi/config.toml`); `koi config init` writes a fully commented default;
  `--config <path>` overrides discovery.
- Precedence: **CLI flag > env var > config file > built-in default.** The file may
  express only what flags already express — no new semantics ride in with it.
- Unknown keys are a loud startup error (typo protection), matching the manifest
  precedent from ADR-028.
- The pane later edits exactly this file through the daemon (write via DAT-gated
  endpoint, atomic replace), keeping one source of truth.

## Consequences

- The tray/pane never widens the attack surface beyond loopback + existing auth.
- Config file becomes a support artifact users can paste in issues — improving
  diagnosability for free.
- Tauri/non-decision is contained: nothing in L0–L1 depends on it.

## Validation

- Unit: welcome-output contract; config parse/precedence/unknown-key errors.
- Physical: L1 tray MVP exercised on Windows and one Linux DE; `config init` +
  flag-over-file behavior verified on both.
