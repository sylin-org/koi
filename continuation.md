# Continue Koi's interface refinement

You are continuing the Koi product and UX realignment in
`E:\repo\github\sylin-org\koi`, with the native host in the sibling checkout
`E:\repo\github\sylin-org\koi-desktop`. The owner considers the current result
materially better but still lacking. Continue from the real installed product,
refine it against Ghostlight's visual signature, implement the changes, rebuild
and deploy the actual Windows artifacts, and inspect the delivered result. Do not
stop at a plan, mockup, or source-only implementation.

## Current priority: preserve the inspector's task

The owner's subsequent review identified functional drift: the single UI lost
the full mDNS browsing/query workflow promised by the consolidation plan.
Restore and evaluate top-level **mDNS** beside **Services** before another visual-only
refinement pass. The technical user who installs Koi to inspect what mDNS
reports is a complete first-use scenario. Preserve the single renderer and all
existing user data. Keep active network queries distinct from catalog filters.

Read [the retained-task audit](docs/ux/retained-task-audit.md) and the current
ledger for the bounded implementation, red-team and evaluation work. The audit
also records other source-level retention gaps; restoring mDNS does not accept
those tasks or independent U06 usability. Report observed source, isolated
browser, installed API and installed native evidence separately.

The mDNS restoration is now implemented and locally deployed. Read
[the restoration receipt](docs/ux/mdns-inspector-proof.md) for exact artifacts,
red-team corrections, passing source/browser checks and live installed API
results. The installed native walkthrough remains uncompleted: the owner stopped
Computer Use with Escape. Preserve the restored task and address remaining
retention gaps explicitly before claiming complete retained-capability coverage.

## Read these first

1. `AGENTS.md` and `.codex/skills/explore/SKILL.md`.
2. `docs/adr/047-one-interface-built-in-presenter.md` — the accepted and
   implemented single-interface decision.
3. `docs/ux/single-ui-proof.md` — exact consolidation and installed-artifact
   receipt.
4. `docs/ux/README.md`, `docs/ux/visual-signature-plan.md`, and
   `docs/ux/single-ui-plan.md` — the current experience contract and refinement
   direction.
5. `fleet/epics/004-container-lan-adoption.md` and
   `fleet/launch/LEDGER.md` — U07 is accepted; U02–U06 still contain the relevant
   refinement and acceptance work.
6. The live source in `crates/koi-ui`, `crates/koi-serve`, and the sibling
   desktop adapter. Treat source and current runtime behavior as authoritative
   when an older prose receipt conflicts with them.
7. The actual Ghostlight implementation in
   `E:\repo\github\sylin-org\ghostlight`. Compare its current source and rendered
   product directly. Do not rely only on remembered screenshots or approximate
   the family styling from descriptions.

The Koi and koi-desktop worktrees contain extensive authorized, uncommitted work
on top of these source bases:

- Koi: `791f87ebe0a8ba93246f60ce0b283c13fb86595b`
- koi-desktop: `d432b9ed207307f1825f0706473eaef4dbeb227b`

Preserve every existing change. Do not reset, clean, checkout over, or broadly
rewrite either worktree. Inspect diffs narrowly before editing and keep the two
repositories coordinated.

## Product outcome

Koi is the local substrate for finding applications on a private network,
understanding what they are doing, and reaching the right one. Certmesh is its
private-space identity and trust capability: enrolled machines and participating
applications can share identity under an authority the operator controls. It is
a visible differentiator, but it must remain an optional, honest capability and
must not obscure Koi's immediate service-discovery value.

The interface should feel like it belongs beside Ghostlight on sylin.org: quiet,
precise, dense, characterful, and deliberate. It must support a healthy service
inventory without becoming sterile or visually flat. Evidence and recovery
belong close to the decision they support. Delight should come from hierarchy,
motion, detail, useful color, and clear feedback rather than ornamental bulk.

## Non-negotiable architecture

Koi has **one single UI**. `crates/koi-ui` is the sole product presentation owner
for all five top-level destinations:

**Services → mDNS → Certmesh → Settings → About**

About is always last. Refresh and any browser-session controls precede the
destination group. The authenticated daemon browser, native Tauri application,
and explicitly enabled Pond listener render the same shared interface. An
adapter may supply permitted state and bounded effects, but it may not introduce
another navigation tree, visual system, dashboard, or product state model.

Do not restore or recreate any of the following:

- the old dashboard or mDNS browser HTML;
- the previous eight-screen Tauri application or its CSS/JavaScript assets;
- a Legacy, Advanced, Home, Open system tools, or Open advanced tools escape;
- a separate Certmesh experience;
- hidden functionality reachable through an older screen;
- Pond-published UI bundles, `/v1/ui` upload/clear, UI generations, or the old
  durable bundle repository.

Valuable behavior belongs inside the appropriate shared destination. Remove
obsolete material rather than preserving compatibility paths in this pre-1.0
product. Access differences may redact facts or disable controls; they must not
create a second experience.

Current canonical routing is:

- `/` redirects to `/ui`;
- `/mdns-browser` redirects to `/ui?tab=services`;
- retired `/v1/ui` returns 404;
- `/v1/ui/shell` remains the authenticated shared-fragment endpoint and is not
  the retired publication API.

Pond is a deliberately restricted view. It receives only an mDNS-derived service
projection and coarse allowlisted capability health, has no mutation bridge, and
uses the same screens. Preserve its durable enabled/disabled intent. Do not
expose preferences, checks, active operations, local candidates, or Certmesh
identity through the public document.

## Visual direction to preserve and improve

Use Ghostlight as the source-level family reference while retaining Koi's own
identity.

- Preserve Ghostlight's navigation button geometry, type, and rhythm: roughly
  30px painted height, 13px horizontal padding, 7px radius, 2px visible gap, and
  12.5px regular system sans, with a full 44px interaction target. Keep the exact
  Koi order above and About at the far right. Do not copy Ghostlight's teal
  palette.
- Keep Koi's blue signature, centered around `#60a5fa` and `#93c5fd`, on a
  charcoal ground. Use semantic green, amber, violet, gray, and red selectively
  for state, action, attention, and row rails. The current interface still needs
  more intelligent color and stronger focal points, but it should not become
  noisy.
- Secondary and faded text must be at least as quiet as Ghostlight's. The earlier
  Koi treatment was too light. The current family direction uses a secondary
  role near `#7a7a83`, with Ghostlight around `#71717a`; verify actual contrast
  and rendered appearance instead of treating these values as immutable.
- Services is a dense, single-row column layout on desktop, with expandable
  details in a proper pane. Preserve scanability, stable columns, keyboard
  access, and eligibility cues. The verified baseline used 49px rows and showed
  11 complete rows at 1280×800. Keep at least 10 complete rows at that viewport.
  At 390px and 320px, reflow cleanly without page-wide horizontal overflow;
  compact rows may grow to about 102px.
- About is its own final destination. It contains one standalone Sylin product
  card beside the product story, observed statistics, accurate version/license
  facts, and grouped documentation links. Do not put the card inside a grid of
  Settings cards.
- Clone Ghostlight's card structure and foil behavior faithfully from its current
  implementation: the same layered composition, pointer geometry, mascot echo,
  halo/foil movement, hover lift, reduced-motion behavior, and polished resting
  state. Adapt its hue and artwork to Koi. The foil must be visibly present and
  convincing, not merely detectable by a test or only visible at an ideal hover
  point.
- Certmesh is the visible product name. Do not label it Private Space. Explain
  current role, authority, identity condition, renewal, membership, audit, and
  recovery using current typed domain state. Keep authority-only actions distinct
  from member actions and never turn unavailable/redacted state into reassurance.
- Settings should read as a coherent set of operator tasks, not a collection of
  generic dashboard cards. Native service/autostart, DNS, Pond, preferences, and
  connection facts should use the same hierarchy and control language as the
  rest of the product.
- Preserve Koi's pixel mascot and warm, direct copy. Errors and destructive
  controls remain precise and restrained.

The owner's latest judgment is “Better, but still lacking.” Treat the present UI
as a strong structural baseline rather than final visual acceptance. Inspect it
for the remaining weak hierarchy, overly empty or generic surfaces, drab state
treatment, inconsistent spacing/type, insufficient foil presence, and places
where controls or explanations do not yet form one coherent narrative.

## Current implementation ownership

The main presentation files are:

- `crates/koi-ui/src/lib.rs`
- `crates/koi-ui/src/operator.rs`
- `crates/koi-ui/src/state.rs`
- `crates/koi-ui/src/screens/services.rs`
- `crates/koi-ui/src/screens/private_space.rs` — an internal filename; visible
  language is Certmesh
- `crates/koi-ui/src/screens/settings.rs`
- `crates/koi-ui/src/screens/about.rs`
- `crates/koi-ui/src/components/navigation.rs`
- `crates/koi-ui/src/components/service_details.rs`
- `crates/koi-ui/assets/family-v1.css`
- `crates/koi-ui/assets/shell.css`
- `crates/koi-ui/assets/card-effect.js`
- `crates/koi-ui/assets/interaction.js`

The authenticated browser adapter is in:

- `crates/koi-serve/src/ui.rs`
- `crates/koi-serve/assets/ui-transport.js`

The Pond projection is in `crates/koi-serve/src/pond.rs`. The native adapter is
in `E:\repo\github\sylin-org\koi-desktop\src\ui.rs` and `src\main.rs`; its
`ui\index.html` is only a packaging stub. Keep presentation logic out of the
adapters.

The previous consolidation deleted dashboard/mDNS HTML, the old Tauri assets,
the Home/Advanced bridge, Pond UI publishing, `pond_ui.rs`, and generated
`C:\ProgramData\Koi\ui` content. Confirm these stay absent whenever an entry point
or adapter changes.

## How to continue

1. Start with a visual and interaction audit of the actual installed Koi and the
   current authenticated browser renderer. Compare matched Services, open service
   details, Certmesh, Settings, and About states with the real Ghostlight product
   and source. Use populated data at 1280×800 plus 390px and 320px reflow. In
   commentary, state the few concrete gaps you are correcting, then keep working.
2. Trace each issue to the shared renderer or shared assets. Make changes in
   `koi-ui` first. Touch adapters only for real data or bounded effects that the
   shared screen requires.
3. Favor a small number of decisive refinements over another cosmetic layer.
   Check typography, density, column alignment, selected/hover/focus states,
   pane composition, semantic color, empty/unavailable/error states, control
   grouping, and the About card at rest and in motion.
4. Exercise real flows. A command existing in source is not proof that its UI is
   understandable or that the current response contract works. Verify retained
   Services, mDNS, Certmesh, Settings, and documentation actions through their actual
   adapter where safely possible.
5. Iterate from screenshots or direct observation until the change is materially
   visible in the installed product. Do not declare success from DOM assertions
   alone.
6. Update the relevant UX proof and `fleet/launch/LEDGER.md` with exact new
   evidence. Keep U07 accepted as the architectural constraint. Do not create a
   replacement epic. Visual refinement belongs mainly to U02; task-level
   Certmesh work belongs to U05; independent usability and delivered-product
   acceptance belong to U06.

Avoid asking the owner to repeat settled preferences. Make reasonable design
decisions from the current product, Ghostlight, and this brief. Ask only when a
truly product-defining choice cannot be inferred.

## Safety and live data

The owner has already authorized implementation, real Windows deployment, and
PowerShell elevation. That authorization persists for the work necessary to
make refinements concrete and reviewable. Use elevated PowerShell through
`Start-Process -Verb RunAs -WindowStyle Hidden` where daemon installation needs
it. Keep filesystem operations in PowerShell end to end and resolve/check exact
roots before any recursive removal.

Preserve configuration, preferences, Certmesh identity, roster, audit history,
and Pond intent. Do not destroy, recreate, unlock, re-enroll, revoke, or otherwise
mutate the owner's live Certmesh merely for visual QA. Destructive Certmesh trials
belong on a disposable identity. Do not expose the daemon access token in command
output, screenshots, HTML, or logs.

Pond was temporarily enabled for the preceding installed inspection and restored
to disabled afterward. Keep it disabled unless a bounded check requires it, and
restore the prior state immediately after that check.

If using computer control, read the applicable computer-use skill and use the
provided UI tools. Do not improvise PowerShell mouse/keyboard automation. The
previous environment exposed browser surfaces but not native app control, so
recheck current capabilities instead of assuming either availability or absence.

## Focused verification

Run checks appropriate to the files changed, then rebuild and deploy the real
artifacts. The preceding consolidated baseline passed:

- `cargo test -p koi-ui`: 7 unit and 14 render tests;
- `node --test crates/koi-ui/tests/card-effect.test.mjs crates/koi-serve/assets/ui-transport.test.mjs`:
  27 tests;
- Chrome-backed `crates/koi-ui/tests/browser-smoke.mjs` with a 36-row fixture;
- `cargo test -p koi-serve`: 144 passed, 1 explicit live firewall check ignored;
- `cargo test -p koi-dashboard`: 33 unit plus 1 hostile-JSON test;
- koi-desktop `cargo test`: 22 passed, 1 explicit live cross-host check ignored;
- `cargo check --workspace` and `cargo fmt --all --check` in both repositories.

For the browser layout check, the known working invocation is:

```powershell
cargo run -q -p koi-ui --example components -- fixture > target/debug/koi-ui-components.html
$env:CHROMIUM_PATH='C:\Program Files\Google\Chrome\Application\chrome.exe'
node crates/koi-ui/tests/browser-smoke.mjs target/debug/koi-ui-components.html
```

For a CSS- or markup-only refinement, use focused renderer, foil, interaction,
and browser checks instead of repeatedly running every broad suite. Expand the
test scope when a Rust contract, adapter, route, or native effect changes.

Build and install the daemon from the real release source:

```powershell
cd E:\repo\github\sylin-org\koi
cargo build -p koi-net --release
$installer=(Resolve-Path '.\target\release\koi.exe').Path
Start-Process -FilePath $installer -ArgumentList @('install') -Verb RunAs -Wait -PassThru -WindowStyle Hidden
```

Verify the installed `C:\Program Files\Koi\koi.exe` hash matches the built release
binary, the Windows service is running, and `/healthz` returns 200.

Build and install the desktop through the established Tauri/NSIS path:

```powershell
cd E:\repo\github\sylin-org\koi-desktop
npx --yes @tauri-apps/cli@2.11.4 build --bundles nsis
```

Stop the preceding `koi-desktop` process, install the resulting NSIS package
silently with `/S`, launch `C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe`, and
verify its version/process/artifact identity. An NSIS-installed executable may
have a different hash from the uninstalled target binary; record both the
installer and installed executable identities rather than assuming equality.

The preceding deployment receipt recorded these identities, which are historical
comparison points and must be rechecked after any build:

- installed daemon/source SHA-256:
  `C8350D0403659DF94E48B96992E5DA79760F6286FB17C59DF3135DE3F2D12A0D`;
- desktop installer:
  `E:\repo\github\sylin-org\koi-desktop\target\release\bundle\nsis\Koi_0.1.3_x64-setup.exe`,
  SHA-256 `0203975B4DBBA5D326A341C5C0A87A4B0EBFC6B4A1DBF8249F3EB99C694E2F49`;
- installed desktop `C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe`, version
  `0.1.3`, SHA-256
  `FEB218366F3F769EF589A43E6C62E4B10E656AB1EB9DE44E9900B20BF0BF37CA`.

PIDs from the prior receipt are intentionally omitted because they are transient.

## Definition of done for this refinement pass

The pass is complete when the installed Windows application shows a visibly more
resolved Sylin-family interface across Services, an expanded detail pane,
Certmesh, Settings, and About; Ghostlight-derived choices are traceable to its
actual implementation; density and narrow reflow remain sound; the foil reads
clearly at rest and in motion; useful semantic color improves attention without
clutter; every retained action stays inside the one shared UI; focused checks
pass; and the exact rebuilt/deployed artifact evidence is recorded.

Report the final result in terms of what changed, why it improves the product,
how the real installed UI was inspected, which checks passed, and any specific
remaining acceptance risk. Do not present source completion as delivered UX if
the installed product was not observed.
