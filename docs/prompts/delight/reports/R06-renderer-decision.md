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
| Comparison/next production component map | `docs/adr/045-shared-rust-renderer.md` | Proposed until measured platform and live packaged cases pass |

**Pattern:** Following `koi-client::KoiClient::from_local` / `catalog_snapshot`
for live data; desktop's source card/CSS for appearance; pure rendering above
`koi-common` for downward dependencies. Maud 0.27.0 versus stable Dioxus 0.7.3,
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

Next: publish/recheck this claim, implement both bounded views and measure their
locked source builds. No acceptance case has been marked passed by this plan.
