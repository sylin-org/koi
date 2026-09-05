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
