# ADR-045: Shared Rust renderer — comparison in progress

Status: **Proposed; no renderer selected**. Date: 2026-09-05.
R06/renderer-decision owns this comparison. ADR-033's production Tauri workbench
remains unchanged; ADR-040 local authentication and ADR-042 Pond authority remain
binding. The product destination remains `crates/koi-ui/` under ADR-044.

## Alternatives and current evidence

1. Retain the existing pinned Tauri shell and use Maud 0.27.0 for Rust-authored
   shared HTML. Application meaning remains in Rust. A future small DOM adapter
   would transport rendered fragments/user intent, not reconstruct catalog state.
2. Replace the shell with Dioxus 0.7.10 desktop and reuse Rust components for
   server-rendered web. This adds porting work for the existing tray, single-instance,
   autostart, notification and authenticated control integrations. The experiment
   does not assume that work is free or already implemented.

Both implement one row, Home/Devices/Settings/About anchors and the original card
in `tools/koi-ui-spike/`, an isolated locked workspace. The reader calls the same
existing authenticated local client and consumes the existing schema; neither
renderer introduces a domain model, listener or JavaScript-owned catalog.

Official sources consulted:

- [Tauri process model](https://v2.tauri.app/concept/process-model/): the core and
  system webview are distinct; Windows uses WebView2, Linux WebKitGTK and macOS
  WKWebView. Retaining Tauri retains these dependencies, not a bundled browser.
- [Tauri IPC](https://v2.tauri.app/concept/inter-process-communication/): commands
  provide request/response across that boundary; a rendered fragment can use the
  existing channel without making a browser the privileged client.
- [Maud escaping](https://maud.lambda.xyz/text-escaping.html): dynamic content is
  escaped by default; raw insertion is confined here to source-owned card/assets.
- [Dioxus setup](https://dioxuslabs.com/learn/0.7/getting_started/) and
  [platform features](https://dioxuslabs.com/learn/0.7/guides/platforms/): desktop
  also needs WebView2/WebKitGTK (plus Linux native packages); browser WebAssembly
  is a separate target. A renderer swap alone is not evidence of musl portability.

The docs expose the 0.7 series; Cargo resolution identified 0.7.10 as the current
stable patch while search advertised a 0.8 alpha. The experiment pins 0.7.10 and
its complete lockfile, rather than choosing the alpha or mixing an older top-level
patch with newer internals.

## Measurements and limits

Host: CachyOS test-01, Rust 1.97.0, glibc, WebKitGTK 4.1 version 2.52.6;
Chromium 152.0.7977.75. Exact commands and final results are in the R06 report.

- Both renderers' behavioral tests pass for the same typed input, including all
  seven conditions, hostile HTML/attribute input, empty/unavailable/loading and
  absence of privileged/placeholder actions.
- Dioxus desktop dependency compilation passed on glibc, resolving Wry 0.53.5 and
  Tao 0.34.8. Existing Tauri uses its recorded upstream Tao decoration patch.
  Different dependency provenance warrants real decoration/lifecycle checks;
  it is not proof that Dioxus is broken.
- Both offline Chromium pages passed 320 px layout, four 44 px navigation targets,
  visible keyboard skip-link/focus, source image loading, no network assets and
  zero active animations under reduced motion. The first visual capture showed
  clipped text; removed the nested-scroll risk, added per-text-line bounds checks
  and fixed Chromium's full-page screenshot gutter cropping. Final captures pin
  the full 320 px width rather than cropping at the narrower document content size.
- The initial old installed daemon returned catalog HTTP 404, so the first
  screenshots proved only unavailable/component behavior. The later guarded
  R05 daemon upgrade and packaged `c497b3b` run below supersede that live-data gap.

SSR reader sizes and normal dependency closures are measured in the report.
They include the same HTTP client/assets but exclude a desktop shell; do not
compare those numbers as full application size or user-observed performance.

Native peer compiler requests are now complete at exact spike source `d2f6645`:
Windows/MSVC (`51ea071`) and Alpine/musl (`b8f3062`) both passed the seven renderer
tests, strict Clippy/format and Dioxus desktop dependency compilation. Neither peer
launched a window. All three native compiler targets therefore have positive
evidence; installed native behavior remains a separate gate.

| Native SSR reader | Maud bytes | Dioxus bytes |
|---|---:|---:|
| CachyOS/glibc | 3,176,424 | 3,513,064 |
| Windows/MSVC | 2,963,968 | 3,325,952 |
| Alpine/musl | 3,277,728 | 3,618,112 |

Desktop `c497b3b` adds an explicitly invoked candidate-A evaluation through
[Tauri's asynchronous custom protocol](https://docs.rs/tauri/2.11.5/tauri/struct.Builder.html#method.register_asynchronous_uri_scheme_protocol),
not a default UI replacement or extra server. Git-pinned shared components render
the complete document after an authenticated Rust catalog read; only the existing
main window's exact evaluation root is admitted. Locked source gates and release
build pass. Its native Arch package and physical acceptance were exercised
under the report's exact-baseline restoration guard. This remains an experiment,
not a selection inferred from the SSR-reader size advantage.

CachyOS packaged proof now passes at `c497b3b`: the installed workbench renders
a real catalog row and original card with kernel-enforced external IP denial,
320 px native client width, visible native keyboard focus, close-to-tray/reveal,
singleton rejection and a safe missing-service page. The native Arch executable
is 13,455,424 bytes with 15 direct ELF runtime imports (the existing GTK/WebKit
family); package SHA and screenshots are in the report. One healthy upgraded
daemon and one normal-mode packaged workbench remain; identity, settings and
firewall are unchanged. Reduced-motion behavior is proven in offline Chromium,
not yet a native OS-preference journey. Windows and Alpine packaged requests now
name this exact source; their earlier compiler passes do not replace them.

## Production component map (proposal, not implemented)

These destinations are proposed within R01's `crates/koi-ui/` boundary. R06 must
confirm them in CONTRACT.md only with the selected, measured route.

| Responsibility | Proposed exact owner |
|---|---|
| Public rendering entry, typed presentation input | `crates/koi-ui/src/lib.rs` |
| Four navigation destinations | `crates/koi-ui/src/components/navigation.rs` |
| Catalog row and declared condition copy | `crates/koi-ui/src/components/service_row.rs`, `condition.rs` |
| Original source card | `crates/koi-ui/src/components/mascot_card.rs` |
| Family tokens/card CSS and original sprite | `crates/koi-ui/assets/family-v1.css`, `koi.png` |
| Home launchpad / device detail | `crates/koi-ui/src/screens/home.rs`, `devices.rs` |
| Settings / About | `crates/koi-ui/src/screens/settings.rs`, `about.rs` |
| Native intake/render invocation | `koi-desktop/src/ui.rs`, using existing `local_daemon.rs` |
| Authenticated headless HTML adapter | `crates/koi-serve/src/ui.rs`, not a second server |

No service action is enabled by a view heuristic. Domain facades/compose retain
truth; `koi-client` retains snapshot recovery; `koi-serve` retains authorization.
Pond cannot receive the operator catalog until R09 supplies its public projector.
No parallel serving path or permanent experiment mode is authorized by this ADR.

## Decision gate / next work

Before selecting: reconcile the requested exact-source musl and Windows packaged
proof and the remaining native reduced-motion journey. CachyOS's build, guarded
serial upgrade, live row and installed/offline integration are now proven.
Headless/browser output alone cannot claim WebKit or desktop lifecycle parity.
Windows-only physical gaps may later use the ledger's narrow readiness exception;
missing Linux proof cannot. No readiness is granted by this proposed ADR.

After the decision, move only the selected components/assets into `koi-ui`,
provide locked cross-repository packaging commands, retire both experiment variants
and preserve preferences, identity, local authentication and advanced access.
