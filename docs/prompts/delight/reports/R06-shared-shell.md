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

In progress: exploration/claim only. Next: implement pure shared components and
HTTP adapter, verify/publish replacement, then migrate desktop and retire experiments.
