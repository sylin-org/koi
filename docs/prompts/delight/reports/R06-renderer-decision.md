# R06 / renderer-decision

Status: in_progress / pending. This is the published claim and experiment plan,
not a renderer selection or native acceptance.

## Starting revisions and dependencies

Koi product `a892808` (R05 implementation `e673af6`); dispatch `731e72c`;
desktop `ba39faff62ea758baaac5cffe2a8ac4ac206bfb3`. R01 and R05 are accepted;
R05's Windows installed evidence and all 13 jobs of CI `33974240044` passed.
Ghostlight's source is actually in `../ghostlight` at
`2255a0ec2ac5bf709a8dcfdd333df82c55697b11`, not `../browser-mcp`.

## Exploration / bounded plan

**Task:** Compare a Rust-authored HTML view inside the existing Tauri shell with
one Rust desktop/web alternative, using one catalog row, navigation and the
original card; keep domain truth and authentication outside presentation.

**Files read:**

- Desktop `Cargo.toml`: pinned Tauri 2.11.5 and upstream Tao decoration patch;
  preserving that platform boundary is an explicit comparison cost.
- Desktop `src/local_daemon.rs`: authenticated local discovery, no assumed port
  or browser-visible token; existing `main.rs` catalog commands use that boundary.
- `crates/koi-client/src/lib.rs`: `from_local` and `catalog_snapshot` already own
  typed authenticated reads and schema refusal; the experiment reuses them.
- `crates/koi-common/src/service.rs`: authoritative catalog IDs, conditions,
  actions and schema; no duplicate wire model is needed.
- `crates/koi-dashboard/src/lib.rs` and `koi-serve/src/pond_ui.rs`: existing
  presentation and immutable five-file Pond bundle; no route changes in this claim.
- Desktop `ui/index.html` / `styles.css`, visual dictionary and ADR-033:
  original card, blue accent, ink/motion tokens and existing native shell contract.

**Reusing:** Already exists: catalog/schema/condition types, authenticated client,
native tray/window/session control, original card/sprite and source family tokens.
Explicit searches covered binary constants, common types, mDNS `protocol.rs`
(the former `protocol/` directory is now a file), client and DNS/Health/Proxy/
CertMesh types. None requires a new domain or persistence model. Needs to be
created: bounded renderer probes and behavioral rendering tests.

**Creating new:**

| New code | Exact location | Justification |
|---|---|---|
| Isolated experiment manifest and lock | `tools/koi-ui-spike/Cargo.toml`, `Cargo.lock` | Separate workspace; neither alternative enters product dependencies before selection |
| Shared presentation-only input and condition copy | `tools/koi-ui-spike/src/lib.rs` | Both renderers consume identical typed input; never infer reachability |
| Maud and Dioxus renderers | `tools/koi-ui-spike/src/maud_view.rs`, `dioxus_view.rs` | Same row/card/nav experiment, explicit alternative feature flags |
| Read-only local catalog executable | `tools/koi-ui-spike/src/main.rs` | Existing local client; HTML to stdout; no daemon or listener |
| Versioned source assets | `tools/koi-ui-spike/assets/family-v1.css`, `spike.css`, `card.html`, `koi.png` | Exact source extraction/copy plus documented accessibility overrides; no runtime sibling/CDN |
| Reproduction/asset provenance | `tools/koi-ui-spike/README.md` | Locked commands and limits; fixtures never masquerade as native proof |
| Offline browser behavior | `tools/koi-ui-spike/browser-smoke.mjs` | Chromium pipe-based test of narrow layout, keyboard, images and reduced motion; no network listener |
| Generated evidence exclusion | `tools/koi-ui-spike/.gitignore` | Keep builds, screenshots and local catalog output out of Git |
| Comparison/next production component map | `docs/adr/045-shared-rust-renderer.md` | Proposed until measured platform and live packaged cases pass |

**Pattern:** Following `koi-client::KoiClient::from_local` / `catalog_snapshot`
for live data; desktop's source card/CSS for appearance; pure rendering above
`koi-common` for downward dependencies. Maud 0.27.0 versus stable Dioxus 0.7.10
(Cargo resolution corrected the initial 0.7.3 probe to the current stable patch),
not the 0.8 alpha. No `mdns-sd` import, duplicate shared type, global constants,
new wire schema or business rule. Existing serde schema tests remain authoritative;
new tests cover hostile names, schema refusal, states, empty versus unavailable,
and absence of unimplemented privileged actions.

**Risks:** Full catalog is forbidden on Pond until R09's public projector. Do not
publish this experiment as Pond or replace a production screen prematurely.
The installed old daemon currently returns 404 for catalog; live proof requires
an exact tested candidate and serial own-host upgrade with restoration first.
Browser/SSR measurements do not prove tray, package, WebKit, musl or Windows.
Native route/packaging writes require a claim expansion before implementation.

## Write reservation and tests

This claim reserves only the experiment subtree, this report, ADR-045 and owned
CachyOS journal updates (plus this selected ledger row). **It does not reserve
root Cargo.toml/Cargo.lock, CONTRACT.md, common/client/serve code or desktop source.**
R20 can claim its independent paths. No product files or peers are mutated by
this initial experiment. After publication, fetch and recheck active claims.

Timebox initial comparison to 30 minutes of build/render exploration, checkpoint
actual results before any longer native migration. Run both feature variants'
locked tests, Clippy, formatting, release builds, artifact/dependency measurements
and original-asset provenance checks. Fixture rendering is test-only; executable
default always reads the installed daemon and fails closed when it cannot.

## Evidence and next action

Read-only baseline: systemd active, sole recorded MainPID `1249009`, NRestarts 0;
operator `/v1/catalog` returns HTTP 404; WebKitGTK 4.1 version 2.52.6; Rust 1.97.0.
No installation, provider, firewall, state or peer mutation. Native acceptance,
Windows, musl, live packaged/offline route and renderer selection remain pending.

## First experiment checkpoint — 2026-09-05

Before -> after: no experiment -> two working Rust render functions and one
authenticated local snapshot reader, source-vendored card/assets, locked isolated
builds, seven behavioral tests and a reusable offline browser smoke. Neither
candidate is installed, selected, exposed on Pond or included in product dependencies.

| Measured item | Maud 0.27.0 | Dioxus 0.7.10 |
|---|---:|---:|
| Stripped glibc SSR reader, bytes | 3,176,424 | 3,513,064 |
| Normal dependency package/version lines, deduped, including probe | 147 | 191 |
| Initial release build elapsed (Cargo reported) | 1m 24s | 1m 19s |
| Unavailable-page offline Chromium smoke | pass | pass |
| Windows GNU typed reader/render cross-check | pass | pass |

These are **SSR reader** sizes, not whole desktop sizes. Both readers include the
same existing Koi client and original embedded assets; `ldd` reports libc,
libgcc_s and the ELF loader (plus virtual vdso). Builds shared cached dependencies
and ran alongside other compilation; elapsed times are observations, not a speed
comparison. Both final single-feature artifacts have the byte sizes above after
the narrow-screen correction. Dioxus desktop-feature compilation separately passed
on CachyOS in 41.99s, with 374 normal dependency lines; no desktop runtime was
launched or measured. Windows GNU cross-check passed in 2m 06s; it is not Windows
physical proof and did not compile the desktop shell there.

Commands/results:

- `cargo test --manifest-path tools/koi-ui-spike/Cargo.toml --locked --features
  dioxus-renderer`: **7 passed**, each applicable behavior runs against both renderers.
- Matching strict `cargo clippy --all-targets ... -- -D warnings` and `cargo fmt
  --manifest-path ... --check`: pass.
- Locked single-feature release builds and glibc `dioxus-desktop-check`: pass.
- `cargo check --manifest-path tools/koi-ui-spike/Cargo.toml --locked --target
  x86_64-pc-windows-gnu --features dioxus-renderer`: pass.
- Existing desktop `node --test ../koi-desktop/ui/app.test.mjs`: **40 passed**;
  no desktop source changed.
- Both live readers against this installed daemon emit unavailable HTML and
  **exit 1**, correctly preserving the HTTP 404/schema gap. No fixture fallback.
- `node tools/koi-ui-spike/browser-smoke.mjs <target/renderer.html>`: pass for
  both. Chromium 152 at 320 px, 305 px document content, zero clipped critical text
  lines, four 44 px navigation targets with real destinations, both original
  100 px images decoded offline, zero network assets/active reduced-motion
  animations, keyboard Tab exposes the skip link and solid focus outline.
  Both pages have **zero rows and unavailable=true**; this is negative-path
  component evidence, not the live-row acceptance case.
- Source PNG hashes match exactly. Family prefix SHA-256
  `dec71fe77c3c1a6447a10af1e6c514375873cdff20d94987a3863701a1c67372`;
  original card markup `82e2216befff4f2b9289c4fc235338d661a9b9284ca1ab9d6204da0291fe8c8c`.
- Documentation leak/surface guards, script syntax and diff checks pass. Generated
  HTML/screenshots/builds are ignored, not committed.

The first escaping test assumed identical entity spelling; both renderers escaped
the input safely. Replaced that assertion with parsed-DOM text/attribute equality
and absence of injected elements/event handlers. Added hostile raw-name fallback
coverage. A visual capture also exposed narrow-screen clipping risk: removed the
inherited nested body overflow and added per-line bounds assertions. Full-page
capture now pins the 320 px width to avoid Chromium gutter/capture relayout cropping.

The full existing workspace test/check/Clippy/release chain is running separately
as preparation for a later own-host serial upgrade; it is **not yet a passing gate**
in this checkpoint. Its product tree equals R05 `e673af6`; the probe is not a
workspace member. No native upgrade begins on a pending or failing gate.

Current state: in_progress/pending. ADR-045 is proposed, not accepted; CONTRACT.md
and all production paths remain unchanged. The installed `/usr/local/bin/koi`
still hashes `b2079cd3bb2e35a46f0344b8181b92e302b33681c12104124dadf4026d54cdc3`.
No peer or system mutation, second daemon, workbench or remaining temporary browser
profile is part of this checkpoint. The test browser uses a pipe, not a listener.

Next concrete action: finish/reconcile the preparation gates; publish exact-source
Windows/musl compile requests; expand the native claim with precise restoration
before upgrading the one local daemon and integrating a packaged renderer. Live
catalog, installed/offline WebKit route, tray/session behavior, musl and Windows
native cases remain pending. Do not consume this row as linux-ready.

## Bounded peer compile requests

Published experiment source: **`d2f6645ad699fa511348dd0e9f4ec312fe65e6f7`**.
This source is sufficient; the sibling desktop is not needed to build the probes.
R01/R05 dependencies are accepted. These requests test compiler/platform viability
only; no full native UI or task acceptance can be inferred from their results.

| Run ID | Requester | Executor | Scope |
|---|---|---|---|
| `r06-probe-d2f6645-windows-20260905` | cachyos-linux | windows | Native Windows build/test and desktop dependency compilation |
| `r06-probe-d2f6645-alpine-20260905` | cachyos-linux | alpine-linux | Native musl build/test and desktop dependency compilation |

Procedure, on the executor's next operator invocation:

1. Preserve any active claim/worktree. Build this exact commit from a clean export
   or detached source worktree, following the existing fleet source rules. Record
   `rustc -vV`, target/libc and any already-required native compiler options. Do not
   substitute a later `dev` source or classify a cross-build as native execution.
2. Run `cargo test --manifest-path tools/koi-ui-spike/Cargo.toml --locked --features
   dioxus-renderer` and the matching strict all-target Clippy check. Use existing
   CI test isolation (`KOI_NO_CREDENTIAL_STORE=1`); do not invoke credential stores.
3. Run `cargo check --manifest-path tools/koi-ui-spike/Cargo.toml --locked
   --no-default-features --features dioxus-desktop-check`. Use the host's supported
   native shared-WebKit musl recipe where applicable and record exact flags.
   Missing SDK/native prerequisites are an explicit unavailable case, not PASS.
4. Build the two stripped release readers independently using the README commands;
   record target, source, artifact sizes/hashes, build duration and required native
   libraries. Do not launch the readers or another desktop/daemon for this request.
5. Append evidence in the executor's owned journal and update its peer row. Restore
   nothing on the installed host because no system surface is mutated. Remove only
   run-owned temporary source/build directories when safe; preserve user work.

Allowed effects: isolated source/build outputs and owned evidence publication.
Forbidden effects: installed Koi/workbench changes, service restart, listening port,
provider/firewall/trust/configuration/credential changes, remote session launch.
No peer artifact or service is reserved. Expected result is truthful native
compile/test evidence (or exact failing prerequisite), not a renderer selection.
Do not install new system packages under this compile-only request; report the
missing prerequisite for a separately scoped native step. Debian has no work here.

## Preparation gates reconciled — 2026-09-05 13:35 EDT

The separate gate chain completed with exit 0:

- `KOI_NO_CREDENTIAL_STORE=1 cargo test --workspace --locked`: **1,939 passed,
  0 failed, 15 ignored** across 58 reported suites/doctest groups. Ignored cases
  are not accepted native evidence. Initial compilation/linking took 13m 32s.
- `cargo check --workspace --all-targets --locked`: pass (39.73s).
- `KOI_NO_CREDENTIAL_STORE=1 cargo clippy --workspace --all-targets --locked --
  -D warnings`: pass (38.11s).
- `cargo fmt --all --check`: pass.
- `cargo build --locked --release -p koi-net`: pass (2m 18s). Prepared, **not
  installed**, `target/release/koi`: 64,844,120 bytes, SHA-256
  `dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975`.

These check the unchanged R05 product tree: `git diff e673af6 HEAD -- crates
Cargo.toml Cargo.lock` is empty. Gate preparation began at `2593c7e`; only the
isolated probe and documentation were published while those gates ran. The release
phase completed with source head `78955474f6083d2048e1de1cced3413de6f6cd2c`.
No changed product source, lock or installer was introduced during compilation.

Source conformance also passed: the extracted CSS prefix and original card match
the desktop source exactly (terminal whitespace normalized); all 37 root tokens
match the discovered Ghostlight source except the three intentional Koi accent
tokens. The original PNG is byte-identical. Both temporary browser profiles were
removed; generated evidence remains ignored under the experiment's `target/`.

Final installed-state check: systemd active/running, MainPID `1249009`, NRestarts
0; `pgrep -x koi` returns that one PID and `pgrep -x koi-desktop` returns the
unchanged package-owned PID `1150`; loopback health is OK. Installed daemon hash
remains the recorded old candidate. Both repositories are clean and published.

The initial 30-minute comparison is checkpointed with real source/build/component
evidence, **not** a selected renderer. R06/renderer-decision remains in_progress
and pending; shared-shell/R07/R11 are not unblocked. Next session resumes this
claim: reconcile peer compiler results, specify/claim the native packaged integration
and interruption-safe restoration, then serially upgrade the one installed daemon
and workbench for the live-row/offline/native acceptance cases. Do not deploy the
prepared binary or mark linux-ready merely because the source gates pass.

## Packaged integration claim expansion — 2026-09-05

The owner instructed CachyOS to proceed with packaged integration and native proof.
Starting revisions: Koi `a1c1ff8`, desktop `ba39faf`. Resume only
R06/renderer-decision; shared-shell and final renderer selection remain pending.

**Task:** Exercise the Maud candidate through the one installed Tauri workbench
using the same shared Rust document and authenticated client as the headless probe.
This is a native evaluation of candidate A, not a default-product renderer switch.

**Files read:** Desktop Cargo manifest/build/config and capability files define
the existing package/security boundaries; `main.rs` owns singleton/tray/window
construction; `local_daemon.rs` and `koi-client` own authenticated local access;
the spike library/CLI own the already-tested document and schema consumption;
the native Arch PKGBUILD owns the durable installed artifact. Tauri 2.11.5's
local source and official Builder docs confirm an asynchronous custom URI scheme
can return owned HTML without binding another HTTP listener.

**Reusing:** Seven passing shared renderer tests, original assets, existing
`KoiClient::from_local`, typed catalog/schema, existing singleton and tray lifecycle,
native Arch package recipe and ownership-aware daemon installer. Explicit constant/
type searches found 80 binary constant lines, 157 common type lines, 2 mDNS
`protocol.rs` enums, 9 client type lines and 394 domain type lines. No new catalog,
credential, protocol/domain DTO or persistence owner is required.

**Creating new:**

| Exact write path | Change and placement |
|---|---|
| `koi-desktop/Cargo.toml`, `Cargo.lock` | Pin `koi-ui-spike` and `koi-client` to published Koi source `d2f6645`; only Maud feature compiled; no build/runtime sibling checkout dependency |
| `koi-desktop/src/renderer_probe.rs` | Explicit `--renderer-probe` selection, restricted asynchronous internal protocol, Rust-only catalog read/render, safe unavailable response and focused route tests |
| `koi-desktop/src/main.rs` | Register protocol; select evaluation URL in existing main window only when requested; preserve normal startup/singleton/tray/control paths |
| `koi-desktop/README.md` | Reproducible locked native evaluation, provenance, normal-mode restoration and non-acceptance limits |
| `tools/koi-ui-spike/native/` | Own-host baseline/rollback and verification helpers if needed; exact guarded targets, no peer mutation |
| This report, ADR-045, CachyOS journal and selected ledger/peer rows | Claims and exact source/artifact/native evidence; no premature renderer selection |

**Pattern:** Reuse `build_workbench` and its existing singleton; return the shared
`maud_view::render` document through Tauri's asynchronous custom protocol. Use
the already-typed Koi client to read inside Rust. Only GET of the evaluation root
from the active main evaluation window may read the daemon. No arbitrary URL,
filesystem path, JS-owned catalog, token output, extra listener or mutation route.
The document's script-free CSP and embedded original assets stay self-contained;
normal workbench CSP/capabilities remain unchanged.

**Risks:** Custom-protocol origins differ on Windows; retain its native compile/
physical obligations. Packaged WebKit may expose rendering or scheme issues that
Chromium cannot prove. Git dependency resolution must work from published source,
not an implicit local path. Evaluation mode must not bypass singleton, alter
autostart intent, enter the published Pond bundle or become a permanent second UI.
No `mdns-sd` imports, duplicate common types, centralized new constants or upward
domain dependencies. New helper state is presentation/transport only; no wire
schema additions. The existing protocol tests and seven rendering behavior tests
remain authoritative and native routing gets its own negative tests.

### Own-host mutation envelope (only after package/source checks pass)

1. Recheck host `test-01`, the one service/workbench, installed binary/package hashes,
   unit/enablement, real data root, operator socket ownership, autostart, provider,
   firewall and disabled-Pond baseline. Prepare exact private backup/rollback
   material and an interruption-safe restoration mechanism before any stop/upgrade.
2. Use the prior fully-tested daemon product tree and verify prepared binary hash
   `dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975`.
   Serially upgrade the existing system service through `koi install`; preserve
   identity, state, configured ports and operator policy. Never start a test daemon.
3. Build/test the published desktop revision with its locked dependencies; use the
   existing Arch recipe and pacman to upgrade its one durable package. Preserve
   the old package or an equivalent supported exact-byte recovery artifact first.
4. Stop the old workbench, install, launch the package-owned executable with
   `--renderer-probe` in the existing Plasma login. Verify live row/original card,
   offline assets, visible narrow/focus behavior, tray close/reveal and singleton
   rejection. Use existing poke/tray routes; no debug server or new network port.
5. End with exactly one healthy daemon and one normal-mode packaged workbench;
   evaluation mode must not persist into autostart. Restore every temporary native
   change and remove run-owned helpers/credentials. If any required validation
   fails, restore the exact prior deployment before reporting that failure.

This reserves only the named desktop paths, optional native helper subtree and
owned evidence, not root manifests/lockfiles, shared service types or CONTRACT.md.
Existing peer requests still compile their immutable `d2f6645` probe; packaged
desktop requests will name the later exact desktop revision separately.

### Native compiler requests reconciled

Windows published `51ea071`: exact `d2f6645`, native MSVC, both renderer tests
7/7, strict Clippy/format and Dioxus desktop dependency check passed. Independent
Maud/Dioxus stripped SSR readers are 2,963,968 / 3,325,952 bytes; normal dependency
closures are 145 / 190 lines (desktop alternative 326). See its
[owned journal](../../../../fleet/windows/journal.md#2026-09-05-29--r06-native-windows-renderer-compiler-probe)
for hashes, native runtime prerequisites and unchanged deployment attestation.

Alpine published `b8f3062`: exact `d2f6645`, native musl 1.2.6, Rust 1.98.0,
both renderer tests 7/7, strict Clippy/format and desktop dependency check passed
with its established shared-musl CRT flag. Independent SSR readers are 3,277,728 /
3,618,112 bytes, both static PIE without DT_NEEDED. See its
[owned journal](../../../../fleet/alpine-linux/journal.md#2026-09-05-1806-utc--r06-native-musl-renderer-compiler-probe)
for hashes and unchanged OpenRC/package/provider deployment attestation.

Both requests are completed compiler evidence only. No peer launched a reader or
window; these results do not close packaged/native/live-row acceptance.

### Packaged candidate source

Desktop `c497b3bc6ca2f99799b2f5e268a841f5c4d36d77` is published on `main`.
Only explicit `--renderer-probe` registers the asynchronous `koi-renderer` scheme
and selects it in the existing singleton main window. Normal UI, tray, autostart,
capabilities and original default CSP are unchanged. The shared renderer/client
are Git-pinned to `d2f6645`; Cargo resolves the nested spike workspace from the
published repository without a sibling checkout. Non-root routes, foreign
authorities, queries, bodies, methods and window labels fail before catalog I/O.
Errors use the shared safe unavailable page and no-store/script-free headers.

`cargo check --all-targets`, locked Rust tests (25 pass, 1 existing ignored),
strict locked all-target Clippy, format and all 40 existing JavaScript tests pass.
One initial new assertion incorrectly expected the word "unavailable" instead of
the actual safe copy "Cannot read the local catalog."; corrected before these
passing gates. Locked release build passed in 1m57s: checkout executable 19,793,672
bytes, SHA-256 `b426735f4a3622afba6b7fa0dd1f4b4700c566c93a828ff7afab83dcaa442ec3`.
This is not the final package hash: Arch applies its native build/strip flags.

Native packaging uses the unchanged Arch PKGBUILD in a fresh directory with
detached published source `c497b3b`, `makepkg --noextract --holdver --noconfirm`,
and ordinary locked build/test recipe. Source HEAD is checked before and after.
The old package's embedded executable matches the installed workbench exactly:
package SHA-256 `23cc3e04bec520421738b2d7f55673cf0b29899647fe34bfc50737310179b45c`,
embedded/installed executable `cf6f256aef2254cc3ef8f19fcf8892c60d8b32463748ed6de6149f0fbac70f74`.
The prepared root-private checkpoint is `/var/tmp/koi-r06-native.5AgVQlFu`, mode
0700. Its archive contains identity material and is deliberately not published.
No installed transition has happened at this source/preparation checkpoint.

## CachyOS packaged native proof — 2026-09-05 14:27–14:34 EDT

Run `r06-native-c497b3b-cachyos-20260905` **passes its measured CachyOS lane**.
R06/renderer-decision is still pending; this does not select a renderer, complete
the shared-shell slice, or claim untested physical targets.

### Exact artifact and serial deployment

- Desktop source: `c497b3bc6ca2f99799b2f5e268a841f5c4d36d77`, checked before and
  after the unchanged Arch recipe. Native `build()` passed in 4m44s; `check()` in
  4m58s, with 25 passing Rust tests, zero failures and one existing ignored case.
- Native package `koi-desktop-git-0.1.3.r61.gc497b3b-1-x86_64.pkg.tar.zst`:
  4,341,968 bytes, SHA-256
  `c95ae640911e5624ac1fdee99ec35b056352f023252fd4c7c1c118553155bf20`.
  Embedded and installed executable: 13,455,424 bytes, SHA-256
  `316fc8fa06a2474fe4de75c445cd5f3ee77d1a2fe91ccb23a9b188033065843e`.
  `readelf -d` lists 15 direct ELF runtime imports in the existing GTK/WebKit family.
  The recipe warns about an embedded `$srcdir` reference; strings inspection
  confirms a compiled source-location string. Assets are `include_str!/include_bytes!`
  data, not files loaded from that path; launch uses neutral working directory `/`.
- Root-private checkpoint `/var/tmp/koi-r06-native.5AgVQlFu`, mode 0700,
  baseline archive SHA-256
  `b462145b6d5e33d3b596e007a2127baa5900584c1fd1a07a9d1e97d78915a0d7`.
  Archive/old package/helper integrity passed before arming a root 25-minute
  `koi-r06-native-rollback.timer`; it was active before the first install.
- Supported `target/release/koi install --operator test` serially upgraded the
  existing service, PID `1249009 → 1364590`, preserving standard ports. Installed
  daemon matches the earlier fully gated unchanged R05 product tree (`e673af6`):
  SHA-256 `dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975`.
  This replaces the old rejected Epic 002 deployment without rewriting its failure.
- Retired only verified package-owned workbench PID `1150`, upgraded through
  `pacman -U`, and launched `/usr/bin/koi-desktop --renderer-probe` as test from `/`.
  Pacman's existing snapshot hooks created ordinary root snapshots 57/58.
  There was no second daemon, alternate data root, port remap or peer mutation.

### Visible and behavioral results

1. Evaluation PID `1365330` ran in a transient unit with `IPAddressDeny=any`,
   `IPAddressAllow=localhost`. `bpftool cgroup show` confirmed both real ingress
   and egress programs (487/486) attached to its cgroup. This blocks external IP
   traffic for the workbench and its children while leaving the machine network,
   local-control Unix socket and existing loopback endpoints intact. No UFW rule
   or provider changed. The native view displayed one real service, its declared
   "Found on the network" condition and snapshot revision 108, not fixture data.
2. The original card and image render fully offline. KWin's settled observation
   records frame `{x:80,y:80,width:320,height:900}`, native client
   `{x:80,y:108,width:320,height:872}`. Top navigation and critical text fit; a
   native PageDown exposed the complete original card. The first KWin print was
   made before asynchronous resizing settled; the helper now observes the settled
   geometry instead of treating the old size as final evidence.
3. A real Tab event through existing user-authorized libevdev/uinput produced
   the visible skip-link and blue focus outline in WebKit. The two-second helper
   creates only a navigation-key device and removes it on exit; no new permission,
   package, input daemon, text, Enter or pointer action was required.
4. A second `--renderer-probe` invocation exited with "already running; revealed
   it", preserving PID `1365330`. KWin delivered the actual close request; the
   process and sole Koi SNI remained. Invoking the real SNI menu's **Open Workbench**
   item (DBusMenu ID 3) revealed that same process and 320 px client again.
   `--poke` only refreshes and is not reveal evidence; this Ayatana SNI has no
   Activate handler, so the actual menu route was used. No product defect was
   inferred from those harness route corrections.
5. Stopped the evaluation and the existing service, then launched the same
   installed evaluation package as PID `1366029`. With service MainPID 0/inactive,
   WebKit displayed "Cannot read the local catalog" plus its embedded original
   assets; no live row or success state was fabricated. Stopped that evaluation,
   restarted the service and launched the normal installed workbench without flags.
6. Rebuilt the locked Maud headless reader using its existing feature, read the
   real local catalog (33 services), and passed the offline Chromium smoke again:
   one rendered row, unavailable=false, zero clipped text, four 44 px destinations,
   both images decoded, zero network assets, visible keyboard focus and zero active
   animations under reduced motion. The first reader command hit the previously
   Dioxus-only executable and refused Maud with exit 2; no false live result was
   taken from it. Native GTK reduced-motion preference was **not** changed/tested.

The offline evaluation cgroup reported 259.9 MiB peak memory and 55.270 CPU seconds
over 3m44.956s while these interactions ran. This is a single observed run, not a
comparative performance benchmark. No corresponding Dioxus desktop runtime metric
has been measured. Existing Ayatana deprecation warnings appeared in both modes;
no Koi warning/error appeared in the installed daemon during this lane.

Visible captures remain under ignored `tools/koi-ui-spike/target/`:

| Capture | SHA-256 |
|---|---|
| `native-live-320.png` | `961452dfef56d254c0899a11af23681748754525453b8755d050489430481235` |
| `native-focus-320.png` | `2ab922167067c5ddcfbfd85c9e525a1b3f060a42ac339797f8f06e30bd402629` |
| `native-card-320.png` | `0e4c1c83596eb592d045e56c56cf406063868dced9514702faa9869bec747fda` |
| `native-tray-reveal.png` | `418a0ccbb00d43e1fc938145c6fd55434606705471b8bf635ecf5eb209492344` |
| `native-unavailable-320.png` | `fd228078025ebfe33c2b12169cc6368576b6a2b3d161e858168c98144d3aa678` |
| `native-normal-restored.png` | `54cbf886516ebcfb5fd1354ec7333cc85527d2e6bc1d11ff9556732b94570685` |

### Final restoration and handoff

Exactly one enabled/active/running `/usr/local/bin/koi --daemon`, PID `1366166`,
NRestarts 0, and one package-owned normal `/usr/bin/koi-desktop`, PID `1366184`,
remain. Normal UI visibly reports authenticated posture, UI health and daemon
health pass, and exactly one Koi SNI remains. Only normal 5640/5641 loopback
listeners are present; Pond 5644 is closed. The default workbench retains its
normal 1100 px client width; `--renderer-probe` is absent from its arguments and
autostart. The originally absent XDG autostart entry remains absent.

Unit, member identity, local-access policy, data-root config, DNS, health, Pond
intent and trust files match the pre-run hashes exactly. Avahi, resolved and UFW
remain active/enabled. Both UFW files match the prior hashes and metadata exactly;
GTK settings and kdeglobals are unchanged. `/etc/koi` remains absent; local-control
socket is 0600 test:root. No installer backup/transaction debris remains.

After these checks, disarmed the timer under the restore lock, marked the checkpoint
accepted and removed its executable helper. Both offline evaluation units/cgroups,
the timer, KWin scripts and temporary input device are gone. No credential helper
was created. Keep the root-private archive and old package for recovery; never
publish their contents. The generated input executable was removed. The fresh
package/build-source directory was moved into ignored `target/native/` after the
system mount refused desktop trash; nothing from the build was irrecoverably
deleted and the shared Cargo target was preserved. Native package and build logs
remain available locally. No change to CONTRACT.md or root product source/lock was
made, so those files remain available for R20.

## Bounded packaged peer requests

Requests: `R06/windows-packaged-renderer` and `R06/alpine-packaged-renderer`.
Each hat must acknowledge in its own journal before its own native mutation.
No remote agent launch or peer mutation is authorized; Debian receives no build.
The next owner invocation may service this ready evidence request before R20;
an already claimed disjoint task need not be abandoned or duplicated.

Exact desktop source: `c497b3bc6ca2f99799b2f5e268a841f5c4d36d77`. Shared renderer/
client source is pinned inside that manifest to `d2f6645`. Required catalog daemon
product source: accepted R05 `e673af61b624a7603946b02af57d12cf20bc6aba` (or explicitly
reconciled already accepted successor). Reuse an already accepted installed R05
artifact; do not rebuild/reinstall it ceremonially. Alpine's last journal still
records the older deployment, so first claim its exact own-platform package paths,
run required native daemon gates and use its ordinary signed APK/OpenRC upgrade
with captured identity/config/ports and interruption-safe recovery. Do not migrate
its owned 5651 port or revive Avahi merely for this request.

1. Verify clean/reserved source and native provenance; run locked desktop tests,
   strict all-target Clippy, formatting, existing 40 JS tests and release build.
   Build/install through the existing native package recipe. Claim only any required
   OS-specific recipe pin update; do not change shared renderer, root types, desktop
   Cargo version/lock or security policy without returning the issue to CachyOS.
2. Capture prior exact service/package, durable recovery artifacts and restored
   startup/identity/provider/firewall state. Arm interruption-safe rollback before
   the serial stop/install/start. Keep one daemon and one installed workbench.
3. Quit the old workbench; launch the package-owned executable with explicit
   `--renderer-probe` from a neutral directory. Capture the real row/original card,
   320 px navigation/readability, native keyboard focus and native reduced-motion
   preference where safely controllable. Prove embedded assets without external
   network access using a scoped mechanism; do not change another host/network.
4. Check singleton, actual tray close/reveal and safe missing-service behavior with
   recovery. Finish with one healthy daemon and one **normal-mode** packaged
   workbench, exact restored temporary state and no credential/helper residue.
5. Publish exact sources, installed/package hashes, package/runtime dependencies,
   screenshots, commands/results, limitations and final process/port/identity
   attestations in the owning journal. Mark only this request completed/failed.
   Missing physical infrastructure is pending evidence, never an invented pass.

After peer reconciliation, finish the remaining native reduced-motion journey,
make the measured ADR selection, reserve the selected production `koi-ui`/adapter
paths and retire both spike variants in the required follow-on slice. Until then,
R06, shared-shell, R07 and R11 remain pending; this successful CachyOS lane is not
permission to install an experimental default UI or publish Pond's operator view.

## Motion-boundary follow-up claim — 2026-09-05

Starting Koi `f1315c9`, desktop `2f91002` (only Alpine packaging changed after
`c497b3b`). R20 is accepted at `3eb1147`; its changes do not alter the pinned
renderer or this host's installed R05 daemon. Resume only R06/renderer-decision.
Alpine's `5f422ba` records a failed physical motion/focus lane and exact rollback;
do not erase that failure or change its owning journal/issue.

**Task:** Determine which native animation preference the actual GTK3 Wayland
workbench consumes, reproduce the reported halo failure at that boundary, and
correct the shared implementation or validation procedure according to evidence.

**Files read:** Shared `lib.rs` owns script-free embedded documents and seven
behavioral tests; `family-v1.css`/`spike.css` own the original animation and existing
reduced-motion overrides; desktop `renderer_probe.rs`/`main.rs` own the authenticated
route and singleton; native helpers own compositor/input evidence; Alpine issue
001 and its journal identify the observed XSettings failure and exact restoration.
GTK 3.24.52 Wayland source and WebKitGTK 2.48.7 settings source establish the
toolkit/native preference boundary independently of our CSS.

**Reusing:** Existing original assets/media rules, installed `c497b3b` package,
authenticated R05 daemon, GTK/GDK APIs and native screenshot/keyboard helpers.
Explicit searches found 80 binary constant lines, 157 common type lines, 2 mDNS
protocol enum lines, 9 client type lines and 399 domain type lines. No new domain,
wire, catalog or credential type is needed. Existing GTK settings already expose
the boolean consumed by WebKit; a read-only backend-aware observer is missing.

**Creating new:**

| Exact path | Ownership/reason |
|---|---|
| `tools/koi-ui-spike/native/gtk-motion-observer.c` | Read-only actual GTK/GDK motion values and backend, not a second UI/backend |
| `tools/koi-ui-spike/native/motion-cachyos.sh`, native README/helpers as needed | Bounded own-host preference/window verification with interruption-safe restoration |
| `tools/koi-ui-spike/browser-smoke.mjs` | Behavioral animation on/off transition checks rather than a CSS-string assertion |
| R06 report, ADR-045, owned journal, selected ledger rows | Exact findings, native evidence and corrected peer procedure |

**Pattern:** Follow the existing native C helper's bounded lifetime and existing
installed-workbench/compositor evidence; read GTK's actual property before blaming
the shared stylesheet. Production Rust/CSS or desktop manifest changes need a
follow-up exact-path claim after reproduction; none is assumed here.

**Risks:** XSettings describes X11 and may not be the GTK3 Wayland source. GTK's
backend can instead use GSettings or the settings portal; WebKit observes
`GtkSettings:gtk-enable-animations`. A file value or XSettings dump alone cannot
prove what this process consumed. Native preference changes must be restored exactly
and must not restart the daemon or alter authentication. No new mdns-sd import,
duplicate shared type, upward dependency or wire protocol is proposed. The original
failed Alpine request remains failed until its own corrected physical run passes.

### Reproduction and production claim expansion

The read-only observer confirms X11/Wayland use different sources: changing
GSettings to false produced GTK/GDK Wayland=0 while XSettings and GTK X11 stayed 1.
More importantly, a read-only GTK module inside installed evaluation PID `1370357`
logged actual `gtk-enable-animations` transitions 1→0→1, while captures still
changed in the reduced phase. Runs `motion-cachyos-20260905` and
`motion-cachyos-observed-20260905` failed and restored the preference and normal
workbench automatically; the daemon/package/GTK files were unchanged. This is a
real native mapping/repaint failure, not merely an XSettings harness mistake.

Extend the claim only to `tools/koi-ui-spike/src/lib.rs`,
`assets/spike.css`, new `assets/reduced-motion.css`, and sibling desktop
`Cargo.toml`, `Cargo.lock`, `src/main.rs`, new `src/native_motion.rs`, `README.md`.
Extract the existing motion-safe declarations once and expose them as a Rust
constant; keep browser media-query behavior. On Linux only, the existing evaluation
webview gets an owned WebKit user stylesheet when its actual GtkSettings disables
animations. Apply at attachment and on notification, remove only that stylesheet
on re-enable, and disconnect on widget destruction. No JS, config imitation,
polling, domain state, new library family, or normal-mode behavior change. Reuse
the GTK 0.18/WebKitGTK 2.0 bindings already in Tauri's native dependency closure.

Behavioral browser tests must show ordinary halo motion, reduced-media suppression,
native-fallback suppression even when media says no-preference, then restored motion
after removal. Native proof must show nonzero/zero/nonzero image differences across
1→0→1 without changing the evaluation PID. Re-run locked desktop gates and native
package; preserve the current package for guarded rollback. Keep the installed R05
daemon untouched (R20 source is not an implicit deployment). Reissue exact peer
requests only after the corrected artifact is published/proven on CachyOS.

### Shared fallback checkpoint

Extracted the existing reduction rules into `assets/reduced-motion.css` and
exported `REDUCED_MOTION_CSS`; both renderers still wrap those exact rules in the
browser media query. Seven shared tests, formatting and strict all-target Clippy
with both renderer features pass. Offline Chromium checks pass for Maud and
Dioxus: 320 px navigation, no clipped text, original images, keyboard focus,
zero external assets, media reduction, and `card-halo → none → card-halo` when
the native fallback is inserted/removed while media remains no-preference.
This proves the shared declarations, not native GTK integration. Publishing this
source first allows the desktop's two Git dependencies to pin the same immutable
revision; installed native proof and peer retries are still pending.

## Native motion correction — 2026-09-05 17:13–17:16 EDT

The correction is published and **passes CachyOS installed motion/focus proof**.
Shared source `72cb286f7c4b4c285893693a58fdebcf896a1538`, desktop
`ccee0fce1bb579e032a0aad2a8603f869b22a2b2`. Both desktop Git dependencies pin
`72cb286`; common/client/config are byte-unchanged from the prior pin `d2f6645`.
R20's accepted source is not an implicit daemon upgrade. No root workspace
manifest, lock, domain source or CONTRACT change was needed.

### Boundary, implementation and gates

The GTK3 Wayland backend maps GSettings/portal preferences to the actual
`GtkSettings:gtk-enable-animations`; XSettings is not a sufficient proxy. See
[GTK 3.24.52 Wayland settings source](https://github.com/GNOME/gtk/blob/3.24.52/gdk/wayland/gdkscreen-wayland.c)
and [WebKitGTK 2.52.6 settings observer](https://github.com/WebKit/WebKit/blob/webkitgtk-2.52.6/Source/WebKit/UIProcess/gtk/SystemSettingsManagerProxyGtk.cpp).
[WebKit issue 255097](https://bugs.webkit.org/show_bug.cgi?id=255097) documents
GTK motion support and a related GTK3 Wayland caveat; it is context, not proof
of the exact upstream cause here. The in-process read-only observer established
that the old installed application received 1→0→1 while its halo still animated.

The Linux-only evaluation binding now reads that property at attachment and on
notification, adds the shared motion rules as a WebKit user stylesheet when
disabled, and removes only its own stylesheet on re-enable. Destruction disconnects
the session-lived settings handler; a weak manager reference prevents retaining
the webview. No polling, JS, replacement card, desktop-specific preference file,
new dependency family, normal-mode change or domain behavior was introduced.

Shared seven tests, strict all-target Clippy, formatting and both offline renderer
browser checks pass (including fallback insertion/removal with media=no-preference).
Desktop all-target check, locked tests (25 pass, 1 existing ignored), strict locked
all-target Clippy, formatting and all 40 JS tests pass. The unchanged Arch recipe
then passed locked release build in 53.58s, locked tests in 14.56s and packaging
from a clean detached exact source; recipe test result is again 25/0/1.
An initial build-directory placement beneath the isolated spike workspace was
rejected by Cargo's workspace ancestry check before compilation. Moving the
detached build to `/var/tmp` resolved it without a manifest/recipe workaround.

### Artifact and measured native behavior

Installed package `koi-desktop-git 0.1.3.r63.gccee0fc-1`:
4,340,458 bytes, SHA-256
`0b7ac83875b9193dfd7c01baf158ea47424a42620d03b9d900edd312dc5ae7ff`.
Embedded/installed `/usr/bin/koi-desktop`: 13,456,704 bytes, SHA-256
`29de5306d31362a766498678803edc769595116bc19b08f52ed69fbb2317438e`.
Its 15 direct ELF imports remain the existing GTK/WebKit library family.
The package is 1,510 bytes smaller and executable 1,280 bytes larger than c497b3b;
these are artifact measurements, not a performance benchmark.

Before stopping the sole workbench, preserved the accepted c497b3b package in a
fresh root-private `0700` checkpoint `/var/tmp/koi-r06-motion.Njz4EvIu`, checked
its hash, and armed a root 25-minute desktop-only rollback timer. The historical
daemon/data restore helper was **not** reused. Ordinary `pacman -U` performed the
serial upgrade (normal snapshot hooks 59/60). The daemon was never stopped.

Both following runs used the **installed** executable from `/`, without the
diagnostic GTK module. Each user three-minute preference/workbench restore guard
was active before mutation; each run preserved its evaluation PID across phases.
ImageMagick AE is reported as an absolute-error metric, not an integer pixel count.

| Run / evaluation PID | Initial reduced | Enabled AE | Reduced AE | Resumed AE |
|---|---:|---:|---:|---:|
| `motion-cachyos-fixed-20260905` / 1379477 | not requested | 144.685 | **0** | 238.986 |
| `motion-cachyos-startup-fixed-20260905` / 1379883 | **0** | 229.971 | **0** | 238.198 |

GTK/GDK Wayland values were 1→0→1 (second run also started at 0), while XSettings
remained 1 throughout. The complete original card was visibly intact and the
reduced pairs were byte-identical. The second run also visibly showed a real
catalog row at snapshot revision 19716, four narrow navigation destinations and
the native Tab skip-link/focus outline at 320 px. No fixture or JS probe was used.
Historical c497b3b offline/tray/singleton/unavailable evidence remains historical;
those unrelated cases were not rerun or relabeled as ccee0fc proof in this delta.

Captures remain in ignored `tools/koi-ui-spike/target/native/<run>/`:

| Capture | SHA-256 |
|---|---|
| First run `reduced-a.png` and `reduced-b.png` | `d30e3de0071fed9894541bb1ef3b43bb5e336600400ca576b0f8b2b5bdaed631` |
| Startup run `initial-reduced-a.png` and `initial-reduced-b.png` | `ae31157142495cb47bdf2b093a7a8caad6baff28306d19bb04a6eecdac4187b5` |
| Startup run `reduced-a.png` and `reduced-b.png` | `b1aca98a110692d5f4cb04ffd13ace149f4ae906e0ca7c5d21868eda3b033ba7` |
| Startup run `focus.png` | `39eae7f05d6e6ab8a30cf8dca1d8c51e1f1ae96f9750accaaa680af383e0f8e9` |
| Startup run `normal-restored.png` | `64894d9f6c163ca384968063a35125f8822f2eead387ec3241b86f98aeda9e96` |

### Restoration

Exactly one unchanged R05 daemon, PID **1366166**, NRestarts 0, and one upgraded
normal-mode workbench, PID **1380276**, remain healthy on loopback 5641/5640.
One Koi tray item remains; Pond 5644 is closed. The normal 1100 px workbench visibly
reports authenticated posture; no evaluation flag/module is in its ExecStart or
unit environment. Explicit GSettings=true was restored, not reset to a guessed
default. Unit, daemon binary, member, config, health, DNS, trust, Pond, installation,
local policy, both UFW files, GTK settings, xsettingsd config and kdeglobals all
match the fresh baseline hashes. Providers/firewall are active/enabled, `/etc/koi`
and autostart entries remain absent. No daemon warnings since the diagnostic start.

Verified restoration before accepting under the root restore lock, disarmed the
timer and removed its copied privileged executable helper (tracked source remains).
Prior package and baseline hashes remain private for recovery. Both user timers,
evaluation units and KWin scripts are gone; the input device exited and generated
input/observer executables were relocated into ignored evidence storage. No new
input permission, credential file or remote mutation occurred. Package/build
material remains at `/var/tmp/koi-r06-motion-build.uDJ7tas1/package`.

## Corrected packaged peer requests

Fresh requests: `R06/windows-packaged-motion-v2` and
`R06/alpine-packaged-motion-v2`; fresh run IDs
`r06-native-ccee0fc-windows-<date>` / `r06-native-ccee0fc-alpine-<date>`.
Exact desktop **ccee0fce1bb579e032a0aad2a8603f869b22a2b2** pins shared
**72cb286f7c4b4c285893693a58fdebcf896a1538**. Required daemon remains accepted
R05 **e673af61b624a7603946b02af57d12cf20bc6aba** or an explicitly reconciled
already accepted successor. Reuse an accepted installed daemon when available.
Alpine's failed request and issue 001 remain historical/open until its own retry;
cancel the unacknowledged old Windows request rather than ask it to test stale code.

Follow all five steps in **Bounded packaged peer requests** above, substituting
these exact sources, plus the following correction:

1. Acknowledge in the owning journal before any mutation. Build/test/install using
   the native package path with fresh exact-baseline recovery and bounded timer.
   Only the owning OS recipe's source pin may be updated after claiming it; shared
   manifests/renderer/security policy changes return to CachyOS. Windows does not
   build Linux-only GTK bindings. Keep one real service and workbench per host.
2. On Linux, first observe the **actual GTK/GDK backend preference** using the
   provided read-only observer. If needed, use its read-only module for diagnosis,
   then repeat final proof without it. XSettings remaining 1 while GTK Wayland=0
   is expected on CachyOS, not a failed preference update. Capture exact prior
   GSettings/portal/file values and restore them, including unset versus explicit.
   Use only a safely controllable actual native source. Do not imitate an OS
   preference with an injected product config, force media emulation or weaken
   input permissions. Alpine should reconcile issue 001's XSettings-only wording
   in its own evidence against these actual backend observations.
3. In the same evaluation PID show animated→static→animated with the complete
   original card intact; also launch once with reduction already enabled. On
   Windows use the real OS animation setting and WebView2, not GTK instructions.
   Native focus, offline assets, tray/singleton and unavailable/recovery remain
   required per the existing procedure. Missing physical keyboard infrastructure
   stays an explicit unverified case; no permission relaxation is requested.
4. Finish normal-mode, restore all temporary state and publish exact artifacts,
   captures, commands, native limitations and final process/identity/port evidence.
   Mark only the fresh request completed/failed. Do not erase the failed first run.

No cross-host service is consumed/reserved by these requests. Each own-host artifact
reservation starts at acknowledgement and ends on completion/restoration; the
acknowledgement expires at session end or 24 hours, whichever comes first. A later
session re-acknowledges its exact baseline before mutation. No remote agent launch
is authorized; Debian receives no build. Renderer selection remains pending the
required peer reconciliation; shared-shell, R07 and R11 are not released yet.
