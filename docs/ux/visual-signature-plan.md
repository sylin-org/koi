# Align Koi with the Sylin visual signature

Date: 2026-09-13. Status: implemented as part of the single shared interface.
The [single-UI plan](single-ui-plan.md) owns the completed consolidation and retirement.
This document retains the approved visual rules; earlier migration shortcuts
are superseded. See [the scoped deployment receipt](visual-signature-proof.md).
This direction is grounded in the supplied installed-product screenshots and
the inspected Koi and Ghostlight sources.

Koi should feel like Ghostlight's sibling: a quiet local instrument, with clear
evidence, restrained light and a little character. Preserve the approved dense
service rows and on-demand details pane. Keep the operational destinations in
order and add About as the final navigation item.

The owner's refinement fixes two reference elements: Ghostlight's navigation
button dimensions and typography (with Koi's own colors), and its standalone
About card with adjacent statistics and documentation links. The navigation
order for Koi is **Services → mDNS → Certmesh → Settings → About**. About is a
dedicated destination, not a section beneath Settings.

This refines [the experience contract](README.md) within
[Epic 004](../../fleet/epics/004-container-lan-adoption.md), primarily U02, with
private-space presentation in U05 and delivered visual acceptance in U06.
The receipt records this slice; the ledger retains the broader packages' status.

## What the comparison shows

| Aspect | Current Koi | Ghostlight reference | Koi direction |
| --- | --- | --- | --- |
| Header | Large wordmark, left-aligned navigation, strong blue selected tab | Quiet status band, small facts, navigation to the right, neutral selected tab | Preserve the reference buttons' geometry and typography; keep Services, mDNS, Certmesh, Settings in order, then About last. Place Refresh before the destination group so About remains the rightmost item |
| Hierarchy | Bright body text and bold 20px card headings make most regions equally prominent | Light operational headings, smaller section labels, deliberate ink hierarchy | Let service names and useful actions lead; lighten page headings and reduce supporting section emphasis |
| Surfaces | Solid raised panels and comparatively bright borders | Near-black canvas, translucent washes and hairline separators | Use family surface tokens; reserve a containing panel for a distinct task or selected detail |
| Inventory | Approved aligned rows and expandable pane | Dense activity rows, mono metadata, small icons and restrained semantic rails | Keep Koi's structure and readable density; adopt the quieter separators, metadata and state treatments |
| Settings | A grid of explanatory cards, including unavailable-preference copy | Status uses compact groups and horizontal action strips | Organize by real tasks, with inline explanations and available actions |
| About | Trading card nested inside a fourth settings card | Standalone trading card beside an editorial product story, facts and grouped links | Dedicated final navigation destination with one standalone card, statistics and documentation links |
| Personality | The mascot carries most of the family resemblance | Light, typography, spacing, motion and copy reinforce the mascot | Make the signature pervasive while keeping decoration out of routine inventory scanning |

The website's account of calm, useful tools that expose their evidence supports
this direction; it is a product principle, not just a palette.
[Sylin](https://sylin.org/). Ghostlight's desktop implementation is the visual
reference for this plan; its browser action overlays are a separate vocabulary.

## The implementation already has the foundation

[The renderer](../../crates/koi-ui/src/lib.rs) concatenates
[family-v1.css](../../crates/koi-ui/assets/family-v1.css) and then
[shell.css](../../crates/koi-ui/assets/shell.css). The family asset already carries
the charcoal canvas, ink ramp, translucent surfaces, font stacks and motion
curves found in Ghostlight. Koi's blue accent is already the intended family
variation. The later shell adds a competing surface palette, stronger global
button treatment and heavier typography.

Use the existing Rust/Maud renderer and shared assets. Reconcile the shell with
the family foundation instead of adding another override stylesheet or a new
frontend. Keep layout, responsive behavior and Koi-specific components in the
shell; give shared visual roles one canonical token definition. Avoid importing
Ghostlight's fixed viewport/minimum-width rules or action-specific animation
machinery. A cross-repository design-system package is unnecessary for this slice.

Source reference: sibling repository `ghostlight`, HEAD
`140728e430a73b2a1b238451dd3bf68b68f91c73`, inspected on 2026-09-13:

- `crates/orchestrator/ui/styles.css`: tokens, `.band`, tabs, rows, cards,
  `.about` and `.tcg`.
- `crates/orchestrator/ui/index.html`: header, status and About composition.
- `docs/design/visual-language.md`: shared principles and the deliberate
  distinction between the teal workbench and sky-blue browser effects.

The Ghostlight checkout has unrelated uncommitted work; it was inspected only.
The earlier [visual dictionary](../assessment/2026-09-sylin-visual-dictionary.md)
remains a research record. The owner's current refinement keeps the three
operational destinations and promotes About to the final navigation item.

## Target visual rules

| Role | Target |
| --- | --- |
| Canvas | Existing `--bg: #0f0e12`; surfaces use the family white washes at roughly 1.2–2.2% |
| Separators | Family `--line` / `--line-2`, white at 6% / 10%, for decorative divisions; interactive boundaries and focus retain sufficient contrast |
| Ink | `#f4f4f5` for strongest emphasis; `#c9c9d1` for normal content; `#a1a1aa` for readable supporting text, with actual contrast checked on each surface |
| Brand | Koi blue `#60a5fa`, lighter `#93c5fd`; keep Ghostlight's teal exclusive to its identity |
| Typography | Existing Segoe UI/system sans and mono stacks. Operational page headings about 24–25px at weight 300–400; section headings 14–16px at 400–500; inventory remains 14–15px |
| Metadata | Small mono facts, addresses and identifiers; uppercase tracking only for short group labels. Do not copy Ghostlight's faint 9px operational labels literally |
| Header | Approximately 58–60px at desktop widths, small product mark/name and concise snapshot context, neutral selected-tab wash |
| Navigation buttons | Ghostlight geometry: 30px visible height, 13px horizontal padding, 7px radius and 2px visible gap; 12.5px regular system sans. Preserve this visual footprint, adapting color to Koi. Keep Services → mDNS → Certmesh → Settings → About in both visual and keyboard order |
| Controls | Quiet secondary chrome, about 30–32px visibly painted where appropriate, within non-overlapping interaction targets of at least 44px; retain larger visible inputs where helpful |
| Inventory | Existing 48–52px ordinary rows, one separator, aligned columns, subtle selected wash/blue edge and explicit selected semantics |
| Details | One containing pane; grouped facts separated by spacing/rules, with clear endpoint and action placement instead of repeated nested boxes |
| Motion | Existing Koi contract: 120–180ms feedback and up to 240ms meaningful reveal, using family curves; reduced motion remains effective |

The installed refinement clones Ghostlight's pointer-driven card foil variables
and restores the hover lift and halo. Koi uses condition-backed blue, green,
amber, violet and red rails in the inventory, and a `#7a7a83` quiet-text role:
visually close to Ghostlight's `#71717a` while retaining the existing normal-text
contrast baseline on Koi's canvas.

Color distinguishes brand/selection from observed condition. A status rail, when
useful, accompanies text rather than replacing it. Do not put glow on every
responding service. Reserve a restrained halo for the mascot and a bounded cue
for actual work; no continuously breathing health indicator.

## Ordered implementation slices

### 1. Reconcile tokens and shared chrome — U02

Edit `assets/family-v1.css`, `assets/shell.css` and
`src/components/navigation.rs` under `crates/koi-ui`. Replace competing shell
colors with explicit family roles, scope button variants, lighten headings and
restore neutral navigation selection. Preserve the specified reference button
geometry and typography, with larger non-overlapping hit areas outside the
painted chrome. Retain the responsive and accessibility overrides needed by Koi.
Keep Refresh before the destination group; About remains its last item.

Pass a small typed presentation summary from `src/lib.rs` into navigation using
the actual `View` and catalog. Header facts may report a received snapshot and
its service count. Loading and unavailable views need their own words. Do not
derive an overall "Ready" or secure-network claim from discovered services.
Use existing freshness evidence where available; adding a live-connection label
requires real adapter state and belongs to U03. Keep native snapshot language
honest when updates require Refresh.

Done when every destination shares the same compact band, type hierarchy and
control vocabulary, with Services, mDNS, Certmesh, Settings and About in that
order at desktop and narrow widths.

### 2. Apply the signature to the inventory and pane — U02

Edit `src/screens/services.rs`, `src/components/service_details.rs` and their
shell rules. Preserve the existing columns, ordering, filtering and action
eligibility. Quiet repeated Open buttons and secondary metadata. Use spacing
and fine rules within the details pane; give its title, condition, endpoint and
next action a clear reading order.

Done when a populated inventory still shows at least ten complete ordinary rows
at 1280×800, the selected row is unmistakable, and opening/closing details retains
the existing focus and list context. Do not add Ghostlight's latest-activity hero
above Koi's inventory: service finding is the primary task here.

### 3. Recompose Settings and About — U02

Edit `src/screens/settings.rs`, `src/screens/about.rs`, `src/state.rs`,
`src/lib.rs`, navigation and shell rules. Add the typed About destination and
render it through the existing shared view-query path in both adapters. Use compact
settings groups and horizontal action strips for available configuration and
diagnostics. Remove standalone cards whose only purpose is to promise future
controls. Consolidate the existing installation, DNS and diagnostic tasks into
Settings and remove the advanced-tool detour as part of the same delivered change.

Move About out of Settings into its own final navigation destination. At desktop
widths, put the existing
300×478 trading card at left and a bounded text column at right, using roughly
32–42px separation. Stack at narrow widths and fit the card within the viewport.
Remove its outer `.content-card` wrapper.

The text column contains a short account of finding and opening local services,
the optional private-space identity capability, compact statistics from the
actual snapshot (such as service and host counts), accurately labeled available
version facts, and grouped documentation links for getting started, understanding
trust and inspecting the project. Unavailable statistics remain unavailable;
do not substitute zero or invent uptime. Identify the renderer version as the interface version; do not
present it as the daemon or installer version. Include only verified facts and
working links. Reuse the existing sprite and trading-card asset; retain crisp
pixel rendering, blue accent, version disc and flavor line. A decorative card
does not acquire a fake button interaction.

Done when About reads as a deliberate Sylin composition and Settings offers
useful destinations without a dashboard of explanatory boxes.

### 4. Carry the same hierarchy into Certmesh — U05

Edit `src/screens/private_space.rs` and reuse the same groups, fact lists and
action strips. Replace the current catalog-only explanatory page with current
Certmesh status and retained operations in this destination. Remove its route
to another application; an unavailable read stays in the same UI with recovery.

As U05 brings in authoritative status, place this machine's role, authority and
required attention above dense membership rows. Keep identity membership,
application reachability and browser trust distinct. These data/action bindings
remain U05 work and are required by U07 before the consolidated UI is delivered.

Done when Certmesh belongs visibly to the same product and every displayed
state/action has evidence behind it.

### 5. Review and deliver the actual shared interface — U06

Review the shared rendered UI in the browser and installed desktop, then package
through the existing release process. The concept remains an illustration;
production screenshots establish this alignment. The linked receipt records
the local build/deployment and the scope of the completed visual review.

Use matched captures of populated Services, an open detail pane, Settings/About
and Certmesh. Check a 30-entry mixed-state layout at 1280×800 and reflow at
390px and 320px. Include keyboard focus, complete endpoint access, 44px targets,
contrast and reduced motion in that focused review. Run existing relevant
renderer/interaction checks when their code changes; avoid an unrelated backend
test campaign for a visual pass.

Done when browser and desktop show the same signature, density and navigation,
and the review records the actual build and remaining capability gaps. Preserve
the separate launch gates in the ledger; visual acceptance does not complete
native endpoint actions or physical-client lifecycle evidence.

## Review standard

At first glance, Koi and Ghostlight should share their canvas, quiet chrome,
typographic rhythm, delicate boundaries and editorial About composition. At
working distance, Koi should still prioritize finding a particular service,
understanding its evidence and opening its application. The result keeps Koi's
blue identity and practical density while making the family resemblance clear
even when the mascot is off screen.
