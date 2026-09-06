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

In progress: shared crate/HTTP implementation and desktop migration. Source gates
and new installed-artifact acceptance remain distinct; no R06 parent acceptance.

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
