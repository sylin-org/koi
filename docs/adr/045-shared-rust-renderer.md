# ADR-045: Shared Rust HTML with Maud and the Tauri shell

Status: **Accepted for R06/renderer-decision**. Decision: 2026-09-06 UTC.
The production shared crate and authenticated web adapter are implemented at
`b4c32fa`; desktop migration and affected native acceptance are tracked separately
in [R06/shared-shell](../prompts/delight/reports/R06-shared-shell.md).
ADR-033's Tauri lifecycle boundary is retained; its JS-authored presentation direction
is superseded by the Rust boundary below. ADR-040 local authentication and ADR-042
Pond authority remain binding. The destination is `crates/koi-ui/` under ADR-044.

## Decision

Use **Maud 0.27.0** for the shared Rust-authored HTML/components and retain the
existing **Tauri 2.11.5** native shell, its pinned Tao correction, native integrations
and system webviews. The same pure Rust renderer serves desktop and authenticated
headless HTML through their existing intake/transport owners. Do not introduce a
JS-owned catalog, Dioxus desktop runtime or additional daemon/listener.

The choice follows the measured experiment, not Tauri's previous incumbency alone:

- The Maud/Tauri route has packaged live/authenticated/offline, native motion,
  keyboard, tray/singleton and unavailable/recovery evidence across Windows,
  CachyOS/glibc and Alpine/musl. The final missing cases closed at Windows `0233b43`
  and Alpine `16effd8`, on unchanged desktop ccee0fc/shared 72cb286 artifacts.
- Both alternatives passed the same typed-renderer and hostile-input tests and
  compiled on all three native targets. Maud's stripped SSR reader was smaller
  on each; this is supporting size evidence, not a desktop speed/memory benchmark.
- Dioxus's desktop dependency closure compiled, but no equivalent replacement
  tray, authentication, packaging or window lifecycle was exercised. Choosing it
  would require implementing and validating that additional migration. No evidence
  establishes a portability or runtime benefit that warrants it for this work order.
- The original family assets and shared GTK motion correction work through the
  retained native boundary. Their implementation does not need a second framework,
  new domain state or runtime access to a sibling checkout/CDN.

Application meaning, typed state and platform behavior stay in Rust. Minimal browser
interactivity may carry user intent and apply rendered output, but cannot reconstruct
catalog truth, receive desktop credentials, infer authorization or bypass native
focus/motion behavior. Dynamic content remains escaped; raw markup is limited to
source-owned assets. The headless renderer must not depend on GTK/Tauri.

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

## Measurements and limits (experiment chronology)

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
under the report's exact-baseline restoration guard. This was experiment
integration, not selection inferred from SSR-reader size alone.

CachyOS's initial packaged proof passed at `c497b3b`: the installed workbench rendered
a real catalog row and original card with kernel-enforced external IP denial,
320 px native client width, visible native keyboard focus, close-to-tray/reveal,
singleton rejection and a safe missing-service page. The native Arch executable
is 13,455,424 bytes with 15 direct ELF runtime imports (the existing GTK/WebKit
family); package SHA and screenshots are in the report. One healthy upgraded
daemon and one normal-mode packaged workbench remain; identity, settings and
firewall were unchanged. At that checkpoint reduced motion was proven only in
offline Chromium. The later native correction and peer results below close that
gap; the earlier compiler passes did not replace packaged physical evidence.

## Native motion follow-up

Alpine's first packaged c497b3b run failed the native motion lane and restored its
exact prior deployment; issue 001 was later resolved by its ccee0fc retry. CachyOS reproduced a
real gap with the actual in-process GTK preference, not only an XSettings file:
GTK Wayland received animations 1→0→1 while the visible halo continued moving.
The [R06 correction](../prompts/delight/reports/R06-renderer-decision.md#native-motion-correction--2026-09-05-17131716-edt)
publishes shared `72cb286` and desktop `ccee0fc`: a Linux-only evaluation binding
applies the shared reduction stylesheet through native WebKit at startup and on
GTK notification, removing only its own sheet when re-enabled. No JS preference
imitation, normal-mode change or new native library family is required.

Installed CachyOS ccee0fc now passes two physical runs without instrumentation:
motion on/off/on in the same PID, startup with reduction already active, intact
original card, real row and native narrow keyboard focus. Reduced capture pairs
are byte-identical; enabled/resumed pairs differ. The exact normal deployment and
native preferences are restored with the daemon unchanged. Both renderer browser
regression checks pass even when media says no-preference. Fresh Windows and
Alpine packaged requests name ccee0fc. Their later physical results are reconciled
below; the original diagnostic failure is preserved as history.

## Peer reconciliation

Alpine `1c3d1c9` proves the installed ccee0fc native motion correction, including
startup-reduced, real row/card, offline assets, tray/singleton and service-loss/
recovery. Issue 001 is resolved. Its later [keyboard tail](../../fleet/alpine-linux/journal.md#2026-09-06-0131-utc--r06-alpine-keyboard-tail-accepted)
at `16effd8` proves an ordinary operator Tab and visible native navigation focus at
320 logical px on the same package. No permission change or input emulation occurred.

Windows `11ed53f` proves WebView2 motion, narrow focus, offline and window/tray
behavior. Its [recovery tail](../../fleet/windows/journal.md#2026-09-05-36--r06-windows-recovery-tail-accepted)
at `0233b43` then used a verified elevated independent guard to stop the unchanged
service, capture the real unavailable view, restart it and capture a recovered row.
Normal deployment and identity/configuration were restored. No native case is
being waived via linux-ready; both former prerequisite failures remain historical.

The [final reconciliation](../prompts/delight/reports/R06-renderer-decision.md#final-decision-and-acceptance)
preserves artifact continuity and the cleanup qualifications: Windows removed an
uninventoried ignored `.tmp/` parent, so absence of unrelated untracked loss cannot
be proved; Alpine restored one unrelated library from its historical source recipe,
not the unavailable original binary. Neither event is evidence of renderer failure
or permission to repeat that cleanup. This decision accepts the rendering route,
not a clean whole-candidate/restoration verdict, full product UI or public release.

## Production component map

These destinations are fixed in CONTRACT.md within R01's `crates/koi-ui/` boundary.
R06/shared-shell implements them; the renderer-decision's historical native proof
does not by itself accept the replacement package.

| Responsibility | Selected exact owner |
|---|---|
| Public rendering entry, typed presentation input | `crates/koi-ui/src/lib.rs` |
| Four navigation destinations | `crates/koi-ui/src/components/navigation.rs` |
| Catalog row and declared condition copy | `crates/koi-ui/src/components/service_row.rs`, `condition.rs` |
| Original source card | `crates/koi-ui/src/components/mascot_card.rs` |
| Family tokens/card CSS and original sprite | `crates/koi-ui/assets/family-v1.css`, `koi.png` |
| Source card markup and shared layout/focus/motion rules | `crates/koi-ui/assets/card.html`, `shell.css`, `reduced-motion.css` |
| Home launchpad / device detail | `crates/koi-ui/src/screens/home.rs`, `devices.rs` |
| Settings / About | `crates/koi-ui/src/screens/settings.rs`, `about.rs` |
| Native intake/render invocation | `koi-desktop/src/ui.rs`, using existing `local_daemon.rs` |
| Linux-native motion binding | Existing `koi-desktop/src/native_motion.rs`, consuming shared reduction rules |
| Authenticated headless HTML adapter | `crates/koi-serve/src/ui.rs`, not a second server |

No service action is enabled by a view heuristic. Domain facades/compose retain
truth; `koi-client` retains snapshot recovery; `koi-serve` retains authorization.
Pond cannot receive the operator catalog until R09 supplies its public projector.
No parallel serving path or permanent experiment mode is authorized by this ADR.

## Consequences and next work

R06/renderer-decision is accepted/ready. R06/shared-shell is now implemented:
shared/client b4c32fa, normal desktop e010086, retired variants/new guards d20c3d4.
The Alpine recipe at bd8121c pins the same e010086 product. Local workspace,
desktop and installed CachyOS checks pass; exact peer/hosted validation remains
pending. R06 as a whole and downstream R07/R11 are not yet ready.

The production crate was published before updating the desktop pins. Both spike
variants and the probe flag/protocol/dependency are retired; immutable commits
retain historical reproducibility. New hostile-input/state/auth/asset/browser and
native lifecycle guards replace those tests. No experimental product mode remains.
Advanced uses the existing asset origin so storage and watched import survive;
native navigation releases its prior event registrations. The authenticated web
adapter remains separate from Pond. Exact source, commands, artifact hashes and
remaining acceptance cases are in the shared-shell report.

Platform evidence is limited to the named Windows/WebView2 and Linux/WebKitGTK
environments. macOS remains physically unverified; immutable/GNOME and full product
journeys need their later native checks. System webview dependencies remain required
for desktop, never for headless rendering. Fresh production integration must earn
its own affected source/hosted/native checks; experiment acceptance is not R29 proof.
