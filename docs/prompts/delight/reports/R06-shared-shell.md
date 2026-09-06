# R06/shared-shell

## Task and selected slice

**Task:** Promote the selected Maud presentation into production `koi-ui`, native
Tauri and authenticated headless adapters, preserving advanced access and storage.

Starting revisions: Koi `2c8a9a9`, desktop `ee5333f`; both clean and synchronized.
R01/R05 and R06/renderer-decision are accepted; this claim is not acceptance.

## Exploration / exact write claim

**Files read:**

- `tools/koi-ui-spike/src/{lib,maud_view}.rs`: proven escaped components and assets.
- `crates/koi-common/src/service.rs`: reuse exact catalog/device/service vocabulary.
- `crates/koi-serve/src/{http,catalog,lib}.rs`: existing authenticated router and snapshot intake.
- `koi-desktop/src/{main,local_daemon,renderer_probe,native_motion}.rs`: preserve discovery, native lifecycle and GTK motion.
- `koi-desktop/ui/{index.html,app.js}` and manifests: retain advanced tools and their existing stored-state migration.
- ADR-040/042/043/044/045, architecture, epic, charter and contract: authoritative boundaries. The suggested utilities reference does not exist; searched existing modules instead.

**Reusing:** `CatalogSnapshot`, `Device`, `Service`, declared conditions and schema
decoder already exist in `koi-common::service`; authenticated client operations
already exist in `koi-client`; native discovery remains `local_daemon`. Explicit
constant/type searches covered the binary, common/client and mDNS/DNS/Health/Proxy/
Certmesh modules (mDNS protocol is `protocol.rs`, not a directory). No domain type,
wire schema, state repository, listener or credential handoff needs creating.

**Creating new:**

| New code | Exact location | Justification |
|---|---|---|
| Pure renderer/input/document | `crates/koi-ui/src/lib.rs` | Shared Rust presentation, only common types/Maud/assets |
| Navigation, rows, conditions, original card | `crates/koi-ui/src/components/{mod,navigation,service_row,condition,mascot_card}.rs` | Selected component map |
| Four section renderers | `crates/koi-ui/src/screens/{mod,home,devices,settings,about}.rs` | Selected screen owners; full journeys remain R07–R09 |
| Embedded family assets | `crates/koi-ui/assets/{family-v1.css,koi.png,card.html,shell.css,reduced-motion.css}` | Promote original assets with provenance intact |
| Crate metadata/docs and examples/tests | `crates/koi-ui/{Cargo.toml,README.md,examples/components.rs,tests/render.rs}` | Reproducible component and hostile-input coverage |
| Authenticated headless adapter/bootstrap | `crates/koi-serve/src/ui.rs`, `crates/koi-serve/assets/{ui-login.html,ui-transport.js}` | Existing operator router; `/v1/ui/shell` avoids Pond's `/v1/ui` publication contract |
| Normal native renderer | `koi-desktop/src/ui.rs` | Replaces probe using existing asynchronous custom protocol and authenticated local intake |
| Browser regression | `crates/koi-ui/tests/browser-smoke.mjs` | Replacement for experiment browser tests |

Also claimed: root `Cargo.toml`/`Cargo.lock`, `crates/koi-serve/{Cargo.toml,src/lib.rs,src/http.rs}`,
`.github/workflows/publish.yml`; desktop `Cargo.toml`/`Cargo.lock`, `src/main.rs`,
`src/native_motion.rs`, `src/renderer_probe.rs`, `ui/{index.html,app.js,app.test.mjs}`,
`tauri.conf.json`, `README.md`; retire tracked experiment manifest/lock/renderer/assets/
browser script in `tools/koi-ui-spike/` after replacement (preserve ignored artifacts
and native recovery helpers as historical evidence). Documentation claims:
`docs/prompts/delight/{CONTRACT.md,LEDGER.md,reports/R06-shared-shell.md}`,
`docs/adr/045-shared-rust-ui-renderer.md` (resolve actual filename before edit),
`docs/reference/{architecture.md,http-api.md}`, `docs/SURFACES.md`, owned
`fleet/cachyos-linux/journal.md`, and `fleet/delight-dispatch.md` for final status.

Claim refinement before test edits: the actual ADR path is
`docs/adr/045-shared-rust-renderer.md`. Add
`crates/koi-serve/assets/ui-transport.test.mjs` for behavioral token/cancellation/
logout transport tests. This is adapter-only coverage, not a browser catalog model.
Also claim `crates/koi-common/tests/architecture.rs`: every new workspace crate
requires classification. Add a kernel-only presentation class for `koi-ui`, not
permission for domains to import presentation or for UI to import domain state.

**Pattern:** Follow `koi-serve::catalog` for in-process snapshot intake and the
selected native asynchronous protocol for Rust-only authenticated HTML. Native
HTML is script-free; explicit refresh rereads the complete snapshot. The browser
bootstrap only transports a manually supplied token in a header and applies
Rust-rendered markup; token remains in memory, never URL/storage/logs. No new
catalog or action logic in JavaScript. The public bootstrap contains no operator
data; rendered reads require DAT even on loopback and are unavailable when an
embedded host has not configured authentication. Pond is unchanged.

**Risks:** Native-to-advanced navigation must preserve the existing asset origin
and local storage; native motion must attach to the normal window; unavailable
must not look empty or healthy. No `mdns-sd` import or upward/domain dependency is
introduced. Constants remain with consumers. No new protocol type needs a serde
round-trip test; existing catalog decoder guards remain.

## Planned verification (not results)

Focused pure-renderer/hostile-input/all-condition, HTTP authentication/negative
route, native adapter tests; locked workspace check/test/strict Clippy/format;
desktop Rust/strict Clippy and existing Node suite; offline 320px keyboard/motion
browser checks; publish/lean/surface/doc guards. Publish Koi replacement before
pinning desktop client/UI to the same exact Git revision. Packaged own-host proof
uses a fresh exact-baseline guard; Windows/musl affected native proof remains
pending until exact new artifacts are exercised by their own hosts. No remote
agent launch or peer host mutation.

## Current status

Implemented: shared crate/HTTP adapter, desktop migration and experiment retirement.
Local source and installed CachyOS checks pass; external acceptance remains pending.
The progress notes below retain the chronology, not outstanding implementation work.

## Implementation progress

Pure components and headless adapter implemented. Initial focused run found a
test error: it compared the runtime's seeded snapshot with an invented default
epoch/time. The corrected test captures the real runtime status before rendering;
no product fallback was added. Focused rerun: 159 serving and 7 renderer tests pass.
Five browser-transport tests pass (header-only credentials, remote-HTTP refusal,
failed-read clearing, logout/pagehide late-response fencing, latest-read ownership).
Offline Chromium loading/unavailable checks cover 320px, focus, original images,
no external assets and native-fallback motion on/off/on. These are component tests,
not installed native acceptance. Initial locked workspace check passes; full test
and strict Clippy gates are running. Desktop source integration is in progress;
41 retained/extended JavaScript tests pass, before its dependency pin/build.

Native Advanced retains its exact existing Tauri asset origin. The shared shell
reads durable daemon preferences but does not inspect browser storage. Existing
watched-item import runs when Advanced is opened, and Settings explicitly says so;
unmatched legacy values and backups stay in that original origin. No stored-state
schema or persistence write has been introduced by the shell.

## Native validation claim

Desktop `e010086` / shared `b4c32fa` is published. Native locked tests (25 pass,
one pre-existing cross-host ignored test), strict Clippy, format and 42 Node tests
pass. Advanced now releases its native event registrations before returning Home,
including pending registrations; a new behavioral test pins that lifecycle.

Claim `tools/koi-ui-native/{README.md,restore-cachyos.sh,key-once.c,kwin-narrow.js}`
for the new production artifact's bounded CachyOS check. Follow the existing
root-private checkpoint and libevdev/KWin patterns, but use a fresh checkpoint
and the current ccee0fc prior package/hash, never an old recovery archive. The
guard is desktop-only, also restoring the already-running service and true motion
preference after an interrupted negative check; it does not restore old daemon
data. Only Tab/Enter/Home/End navigation keys are admitted, after activating the
one Koi window. No permission changes, remote host mutations or diagnostic webview
instrumentation. Build uses the unchanged Arch recipe outside the workspace.
Claim `.github/workflows/ci.yml` to run the new browser-transport Node tests in the
existing contract job; renderer Rust tests already run with the workspace suite.
Final packaging audit claims `koi-desktop/packaging/alpine/APKBUILD`: unlike the
Arch Git recipe, it pins the old ccee0fc archive. Update only its version/release,
immutable product commit and verified source checksum to e010086, so the peer's
unchanged musl build procedure tests the production shell rather than the probe.

The first full-workspace run used an architecture test executable compiled before
the new class was added and reported `koi-ui` unclassified. The current architecture
suite passes all 16 tests. A complete rerun against the finished source is running;
the original run is not recorded as a pass. Final focused tests: 160 serving and
7 renderer tests pass; initial full strict Clippy passes. Hosted/new native targets
remain separately pending.

## Implementation and verification

Status: **implemented / pending external acceptance**, not R06 parent acceptance.

Published source: shared crate/operator adapter `b4c32fa9b524549509b34b01bb24cc06455407ad`;
desktop product `e010086ef1ede16c4ab5dc3c6431fcbf82a9c715`; experiment retirement,
CI tripwire and current native helpers `d20c3d4934e0790e1866a8fb5f0367648243d476`.
Desktop `bd8121ccab51650c0d237f307b9e80450e674c1d` changes only the Alpine recipe:
`0.1.3_git20260906-r0`, pinned to the same e010086 product. All 38 archive files
match that Git tree; its SHA-512 is recorded in APKBUILD. No peer recipe edit is
needed. The retired variants/lockfile/assets are recoverable from immutable Git;
ignored captures, binaries and historical recovery material were preserved.

Before → after: the experiment is no longer selectable or a dependency. Normal
native launch uses the pure Rust shell, all catalog rows, typed conditions, dated
manual refresh, four real section destinations and original embedded card. Native
Advanced remains at its original asset origin, with a Home return and owned event
listener cleanup. No storage migration, credential-in-JavaScript or second daemon
was introduced. Existing watched import remains explicitly reachable in Advanced.
Headless `/ui` is a data-free login/bootstrap; `/v1/ui/shell` is a complete shared
HTML document protected by DAT on every peer, including loopback. Browser intent
transport has no DTO/domain logic and forgets token/display on failure or page exit.
Pond publication and public projection are unchanged.

### Completed source checks

- `KOI_NO_CREDENTIAL_STORE=1 cargo test --workspace --locked`: pass against final
  production Rust source, 1,962 passed / 15 existing ignored cases across 61 result
  groups (including doctests). Ignored cases are not physical acceptance.
- `cargo check --workspace --all-targets --locked`, full strict all-target Clippy
  and `cargo fmt --all --check`: pass. Final check/Clippy took 13.33s/2.46s after
  the full build; initial compilation was substantially longer.
- Focused serving/UI: 160 + 7 tests pass, including all declared conditions,
  hostile IDs/names/aliases, no inferred actions, exact device-ID grouping,
  loading/unavailable/empty separation, DAT GET/HEAD across loopback/remote/unknown
  peers, noncanonical paths and public-bootstrap isolation. Architecture: 16 pass.
- `node --test crates/koi-serve/assets/ui-transport.test.mjs`: 5 pass; included in
  the existing hosted contract job. Desktop `node --test ui/app.test.mjs`: 42 pass.
- Desktop locked tests: 25 pass / one existing live cross-host ignored case;
  strict all-target Clippy, formatting and real Arch recipe build/check pass.
- Offline Chromium smoke passes for loading, unavailable and an actual catalog
  read through authenticated `/run/koi.sock` access. 320px, no clipped critical
  text, four >=44px navigation targets, visible keyboard skip focus, two decoded
  original images, zero external assets and motion stop/resume. Live DOM contains
  66 row renderings across Home/device details; this is not 66 distinct services.
- Publish-list (20 crates), lean embedding, surface ledger, documentation leak and
  whitespace guards pass. The shared headless closure has no GTK/Tauri dependency.

Local logs: `/var/tmp/koi-r06-shared-{workspace-final,focused-final,architecture,
check-final,clippy-final,desktop-test-locked,desktop-clippy,desktop-node,web-node,
package,lean}.log`. Exact replacement component commands are in
`crates/koi-ui/README.md`; native helpers in `tools/koi-ui-native/README.md`.

### CachyOS installed-artifact evidence — 2026-09-06 UTC

Real unchanged Arch recipe in `/var/tmp/koi-r06-shell-build.V0NgeEhw`, exact e010086
checkout, ordinary package install. No runtime repository-relative asset path.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `koi-desktop-git-0.1.3.r65.ge010086-1-x86_64.pkg.tar.zst` | 4,334,790 | `38c41423c25709efb4488e432102e0e257528ecab0672d0290fd62e991cb6501` |
| Installed `/usr/bin/koi-desktop` | 13,442,112 | `c874a638d31b48dfba0ec45c6a110799dbf6fdd31f604aad66605fc59a2d407a` |
| Unchanged accepted R05 `/usr/local/bin/koi` | 64,844,120 | `dc1ebd15b8d1bf2d725c212912d78a5dd9581aa897c505596e8b0a268d9b3975` |

Fresh root-private `/var/tmp/koi-r06-shell.aYAtcutn` held the exact ccee0fc prior
package, reviewed helper/checksums and baseline hashes. A verified independent
25-minute root timer was armed before stopping/upgrading anything. It never fired.
Acceptance was recorded under its lock after restoration; the timer, executable
helper and privileged shell are removed. The private prior package remains.

Installed native checks (no diagnostic webview module or preference simulation):

1. Ordinary-user PID 1433577 rendered real catalog rows/card with external IP
   denied. `bpftool cgroup show` proved ingress 887/egress 886 attached to its
   transient system unit; loopback remained allowed. No extra daemon/listener.
2. Actual KWin client geometry was 320×872. Visible native Tab focus passed.
   Keyboard-selected Advanced loaded the genuine existing controls, and its Home
   button returned to a fresh Rust snapshot in the same process.
3. Native animation preference on/off/on in PID 1433577 gave pixel AE
   `423.293 / 0 / 364.608`. Startup already reduced in new PID 1436098 also gave
   AE 0, with the original card visibly intact. GSettings was restored to true.
4. Guarded real service stop gave SCM-independent systemd inactive/PID 0 and a
   refreshed explicit unavailable page without stale rows. Restart of the same
   unchanged daemon gave PID 1435976, health OK and refreshed real rows.
5. Closing removed the window from KWin while the same process/SNI remained.
   The actual SNI menu's `Open Workbench` item (ID 3, bus peer proven to be PID
   1436098) reopened it. Direct SNI `Activate` has no handler on this existing
   Ayatana backend, as in the prior experiment; the real menu route was used.
   Another installed executable invocation revealed the existing singleton.
6. Final normal launch: one package-owned workbench PID **1436590**, no flags or
   IP-denial test unit; one enabled/active daemon PID **1435976**, NRestarts 0.
   The normal user unit resolves its working directory to `/home/test`, outside
   the checkout. 5640/5641 are loopback-only; Pond 5644 is closed. All **19**
   captured daemon-state files remain byte-identical, as do the GTK/Xsettings/KDE
   config files. Avahi, resolved and UFW remain active/enabled; no firewall policy
   edit occurred. No temporary input device, KWin script or offline cgroup remains.

Captures are in ignored `target/shared-shell-native/01-live.png` through
`16-normal.png` (motion pairs include startup-reduced). One failed direct-Activate
attempt produced an untargeted screenshot `14-tray-revealed.png`; that newly
generated capture was discarded, not used as evidence. Historical/unknown ignored
files were not cleaned. Package-manager Snapper pre/post snapshots 61/62 are the
ordinary installation hooks, not an agent cleanup or unrelated package upgrade.

The daemon was deliberately **not upgraded** in this desktop-only native run.
The new authenticated headless adapter has source/router and locked-build evidence,
not a claim that the currently installed R05 daemon serves the new `/ui` routes.

### Remaining acceptance / next action

Hosted Koi CI `34006973717` on d20c3d4 has passed Ubuntu/Windows/macOS tests,
format, contract tests (including new JS), MSRV, surface, lean, strict Clippy,
audit, architecture and Windows GNU cross-check jobs. The final cross-host job
is still running at the publication checkpoint; the whole run is not yet a pass.
No desktop branch CI run exists; native desktop checks are explicit.
MacOS desktop remains physically unverified, as in the accepted renderer decision.

R06/shared-shell and its parent are implemented/pending, not accepted/linux-ready.
Reconcile the hosted run and the two exact native requests below; R07/R11 remain
gated. The remaining work is verification, not an unfinished renderer variant,
missing adapter, placeholder action or distributed source assignment.

## Bounded production native requests

`R06/windows-shared-shell` and `R06/alpine-shared-shell`: verification only on the
addressed host after its own operator invokes `fleet/task.md`. No remote launch,
source fix, dependency update or package-recipe rewrite. Acknowledge in the ledger
before own-host mutation, with fresh run ID and exact baseline/recovery artifact.
Requests expire 2026-09-08 03:00 UTC or immediately on a changed product source;
after expiry revalidate before mutation. Release the request on result/restoration;
no other host is reserved while waiting for an operator.

Exact product: desktop **e010086ef1ede16c4ab5dc3c6431fcbf82a9c715**, shared/client
**b4c32fa9b524549509b34b01bb24cc06455407ad**. For Alpine use APKBUILD from desktop
**bd8121ccab51650c0d237f307b9e80450e674c1d**, which fetches that exact product.
Use Koi d20c3d4 for replacement renderer tests (not a nonexistent spike workspace).

1. Preserve/inspect worktrees and installed identity/configuration. Run locked
   desktop tests/strict all-target Clippy/format and `node --test ui/app.test.mjs`;
   `cargo test -p koi-ui --locked` from Koi for shared components. Use
   `KOI_NO_CREDENTIAL_STORE=1` for tests. Do not assign a heavy build to Debian.
2. Windows: `cargo tauri build --bundles nsis --ci -- --locked`, then the supported
   normal-user NSIS install, with the exact old package retained. Alpine: detached
   native `abuild` through the published APKBUILD, verify archive/package and
   install through APK. Record source/package/executable hashes and runtime versions.
3. Normal launch, never `--renderer-probe`: real local catalog/card, 320px navigation,
   visible physical keyboard focus, Advanced → Home and explicit refresh. Prove
   original embedded assets offline without broad host-policy changes. Check actual
   native motion on/off/on and startup-reduced, not only a preference-file dump.
4. Close-to-tray/menu reveal and second invocation must retain a single instance.
   Service-loss/recovery needs a separately verified independent guard capable of
   restarting the existing service; on Windows prove actual elevation before stop.
   Refresh must remove old rows on failure and show a real new snapshot on recovery.
   Do not replace the accepted daemon or its data root for this UI request.
5. Restore motion, host policy, test utilities and startup shape; retain the new
   package only if accepted locally, otherwise restore the exact previous package.
   Leave one healthy original daemon and one normal package-owned workbench. Preserve
   settings, watched backups, identities/keys, package world/dependencies and all
   unowned/unknown ignored data. Never `git clean` a scratch parent.
6. Publish evidence/defects only in the peer's own namespace and complete/fail the
   request honestly. Return source defects to CachyOS. Compiler proof is not a
   substitute for physical input, recovery or restoration.
