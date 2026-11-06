# One Koi UI: consolidation and removal plan

Date: 2026-09-13. Status: implemented; installed development acceptance in progress.
Owner: coordinating agent. Requirement: the owner's explicit correction to
consolidate the product, eliminate obsolete content, and ship one interface.
Execution authority: [Epic 004, U07](../../fleet/epics/004-container-lan-adoption.md#u07--consolidate-and-retire-the-separate-interfaces)
and [the launch ledger](../../fleet/launch/LEDGER.md).

Implementation follows [ADR-047](../adr/047-one-interface-built-in-presenter.md).
The source result removes the duplicate desktop/dashboard assets, bridge commands,
Pond bundle publication and repository, then renders native, authenticated browser
and restricted LAN views through `koi-ui`. Exact build, route and deployment
evidence belongs in [the implementation receipt](single-ui-proof.md).

This plan supersedes the migration exceptions in earlier UX plans that allowed
an advanced workbench, a return-to-Home bridge, or a placeholder Certmesh page
to count as a coherent experience. The approved appearance remains the target.
The installed visual slice is useful work, but it did not complete realignment.

## Completion means one product

Koi has one navigation model, one set of screens and components, one visual
system, and one authoritative interpretation of each capability. Native desktop,
authenticated browser and optional LAN viewing use that same presentation.
Transport and permissions can differ; they do not introduce another interface.

Every retained capability has a named, discoverable home. There is no Advanced
destination, hidden workbench, old dashboard, iframe, alternate theme, or link
that switches to a second application. Existing row expansion, details panes
and task dialogs stay: they reveal detail within the same product. They do not
conceal another navigation tree. Normal role and authorization checks still apply.

Keep **Services → mDNS → Certmesh → Settings → About**, with About last. Preserve the
approved dense rows, optional details pane, Ghostlight navigation dimensions and
fonts, Koi colors, quieter supporting text, semantic condition cues, and the
single About card with its foil, real statistics and documentation links.

## What the source audit found

Audit baseline: Koi `791f87e` and sibling `koi-desktop` `d432b9e`, both with the
preserved development working trees inspected on 2026-09-13. Findings below are
source evidence, not fresh verification of every operational flow.

| Current implementation | Finding and implication |
| --- | --- |
| [`koi-ui`](../../crates/koi-ui/src/lib.rs), its screens and assets | Shared Rust/Maud rendering already provides the approved navigation, service list, details and About. Its main input is only a catalog. Certmesh is explanatory text; Settings delegates operational work elsewhere. Expand this renderer to cover retained tasks. |
| [`Links::advanced`](../../crates/koi-ui/src/lib.rs), [Certmesh](../../crates/koi-ui/src/screens/private_space.rs), [Settings](../../crates/koi-ui/src/screens/settings.rs) | The buttons explicitly leave the shared interface. Browser targets `/`; native targets the old Tauri asset root. Delete this navigation contract when the tasks are integrated. |
| Sibling `koi-desktop/ui/index.html`, `app.js`, `styles.css` | A second full application with Glance, Discover, Browser, Diff, Trust, DNS, Status, a capability page and another About. `src/ui.rs` adds the newer custom-protocol app; `show_shared_shell` and the Home button bridge the two. Retain useful operations, remove both-shell plumbing and duplicate screens. |
| Sibling `ui/app.js::trustGateOf`, `trustRoleOf`, `renderTrustMembers`, and their tests | They expect top-level `ca_initialized`, `ca_locked` and `members`. Current [Certmesh status](../../crates/koi-certmesh/src/status.rs) uses explicit `role`, `identity`, nested `authority`, and `renewal`. The old fixtures repeat obsolete fields. Porting the markup is insufficient; repair the contracts and action gates. |
| [`koi-dashboard` HTML](../../crates/koi-dashboard/assets/dashboard.html) and [mDNS browser HTML](../../crates/koi-dashboard/assets/mdns-browser.html) | More independently authored pages, mounted by [HTTP routing](../../crates/koi-serve/src/http.rs) at `/` and `/mdns-browser`. Preserve needed data APIs and browser workers; retire the HTML renderers. |
| Sibling `pond_publish_ui`; [Pond](../../crates/koi-serve/src/pond.rs) and [bundle repository](../../crates/koi-serve/src/pond_ui.rs) | Phone sharing publishes the old desktop HTML/JS/CSS, and versioned URLs can keep old generations accessible. Fixing only the current root leaves another old interface reachable. Consolidation must include the publisher, active selection and versioned routes. |
| [`KoiStatus`](../../crates/koi-compose/src/status.rs) | Composition already captures the catalog, capability reports and exact domain projections together. Reuse this source of state; do not reconstruct product truth in browser JavaScript. |
| Sibling native commands and service manager | Useful service control, startup, DNS, Certmesh, event, preference and URL-opening adapters already exist. Command presence proves implementation exists, not that every current UI flow works. Verify retained flows against current responses. |

## Retain, consolidate, repair, remove

The old screen names are not the new information architecture. Keep task value
and tested behavior; do not preserve a feature merely to keep a tab occupied.

| Existing content or behavior | Decision | Single home and required treatment |
| --- | --- | --- |
| Shared service catalog, filtering, sorting, selected details, endpoint evidence | Retain | **Services**. One list and durable identity model. Maintain state and focus through updates. |
| Browser Open/Copy, native validated opener, favorites and aliases | Consolidate | **Services**, using the same visible controls and eligibility contract. Complete native bindings; stop redirecting native users to another surface for preferences. |
| Desktop Discover and Browser; separate web mDNS browser | Remove duplicate screens; retain useful evidence | **Services → mDNS**, beside Catalog in the shared screen (the earlier Network evidence label). Raw announcements, TXT, type descriptions, withdrawals and observed query results remain inspectable. Clearly label raw evidence; it is not another authoritative service inventory. See the [retained-task audit](retained-task-audit.md). |
| Cross-host Diff | Retain the diagnostic task; repair its boundaries | **Services → Compare observations**. Reuse the comparison semantics, retain observer/time and explicit peer failure. Validate peer URL parsing and the current remote-read/auth contract; the old unauthenticated generic GET and colon-split address handling are not the new transport design. |
| Glance, duplicated Status hero, happenings, watched pins | Consolidate useful events; remove duplicate landing pages | Per-service changes in the details pane and **Settings → Diagnostics → Recent activity**. Preserve bounded events, repetition grouping and useful attention cues. Remove a second home feed and duplicate favorite storage. |
| Certmesh status, members, authority, identity expiry, renewal and audit | Repair and integrate | **Certmesh** opens directly on current role, identity condition, authority and required attention, then dense members and audit. Read current typed fields; degraded identity never turns an enrolled node into an open node. |
| Create/join/unlock, invites, renewal, enrollment controls, revoke, destroy | Preserve the operational intent; rebind and verify | **Certmesh** role-appropriate actions and task dialogs. Reuse domain commands and native validation where correct. Show actual outcomes, current fingerprints and pending/failed recovery. Remove old success copy that assumes request completion proves identity health. |
| Recovery help and existing CLI operations lacking a GUI | Consolidate documentation; do not invent a wizard | **Certmesh → Recovery** has concise, accurate guidance and direct documentation for supported commands. Keep CLI/API capability. Do not retain an old screen or add fake controls to imply an unimplemented GUI flow. |
| DNS static records and ephemeral TXT controls | Retain and integrate | **Settings → Names & DNS**. Separate persisted names from temporary TXT; show actual outcome and error state. Service naming evidence links here within the same app. |
| Service installed/running state, Start/Stop/Run once, login startup, data root | Retain native capability | **Settings → This installation**, available even when the daemon is down. Use existing native service ownership. Browser sessions explain device-local control limits in place; they do not switch UIs or expose process control remotely. |
| Capability ladder, health/DNS/proxy/UDP status, daemon events | Consolidate operational facts; remove duplicate dashboards | **Settings → Diagnostics**, with status and reasons from composition/domain snapshots. Remove architectural slogans such as “ADR-035 made visible,” redundant tiles and repeated overall health judgments. |
| Phone/QR, read-only LAN sharing, Stop sharing | Retain useful sharing; replace its presentation delivery | **Settings → LAN access**. The shared renderer uses a deliberately public projection and visible read-only context. No desktop-supplied old application bundle; no copied operator token, roster, audit, private filesystem path or mutation authority. |
| Duplicate About, competing CSS, separate cards and foil drivers | Remove duplicates | **About** and the existing `koi-ui` assets are canonical. Version facts identify daemon, desktop and interface accurately when available. |
| Dashboard API grid and developer reference pages | Remove from everyday product screens; retain real reference | Documentation links in **About** and task-specific help. `/docs` remains an explicit API reference, not another Koi dashboard or operational home. |
| Demo-only success forms, placeholder promises, “Open system/advanced tools,” Home bridges | Remove from shipped product | No substitute page explaining that the useful UI lives elsewhere. The earlier concept is design evidence only and must not remain a competing current specification. |

## The final navigation

| Destination | Visible task groups |
| --- | --- |
| **Services** | Services list; Network evidence; Compare observations. Service selection opens the approved pane with endpoints, checks, identity and relevant changes. |
| **Certmesh** | Overview and identity; Members and enrollment; Activity and recovery. Available operations follow the actual role and authority state. |
| **Settings** | This installation; Names & DNS; Diagnostics; LAN access. Each group is visible and uses ordinary sections or secondary navigation, never an unlabeled advanced mode. |
| **About** | One foil card, product description, observed statistics, version facts, documentation and project links. |

The initial view should answer the destination's primary question. Avoid a wall
of equally weighted tools. Keep the five top-level buttons stable; task groups
use consistent secondary navigation, and details return to their originating
row or control. Read-only or platform-limited sessions explain those limits in
the same location. Unavailable domain state is a visible state, not hidden content
or an excuse to offer another application.

## Implementation architecture

Use the retained Rust/Maud approach; a framework replacement is unnecessary.

- **One presentation owner:** `crates/koi-ui` owns all screen markup, navigation,
  styles, icons, card interaction, view state and action presentation. Extend
  typed inputs beyond `CatalogSnapshot` with the facts these screens need.
- **One domain interpretation:** `koi-compose` assembles existing authoritative
  snapshots; `koi-serve` maps approved read projections into shared presentation
  inputs. Existing domain types/commands own role, enrollment, names and outcomes.
  Add a shared wire type only where the two adapters actually need it; do not
  copy domain state into a second UI database or import domain code into the
  common kernel.
- **One interaction implementation:** extract navigation, forms, focus recovery,
  dialogs and feedback into shared assets in `koi-ui`. Browser and native adapters
  supply transport and permitted platform effects. Neither owns screen templates,
  independent status logic, nor another inventory.
- **Native bootstrap:** keep the existing Tauri asset origin for the one native
  bootstrap, so old local storage can be read during migration. Replace its old
  application with the shared Rust-rendered content through a typed native
  render/interaction adapter. Remove the separate `koi-ui` origin navigation and
  Home/Advanced bridge. A small bootstrap and transport are not another renderer.
  Native credentials stay in Rust; command access remains main-window/local-origin
  scoped. Render the same Settings offline state with local service controls
  when the daemon cannot answer.
- **Browser bootstrap:** reuse authenticated `/ui` and its token-in-memory
  transport, serving the same shared components and interaction assets. Define
  narrow, authenticated operations, with revision/conflict handling. Do not
  expose a generic arbitrary-command or arbitrary-URL proxy to the browser.
- **LAN viewing:** keep Pond's explicit enable/disable, listener lifecycle and
  public-data boundary. Serve the built-in shared presentation from the daemon
  against that restricted projection. A missing public catalog projection is
  real implementation work; full operator snapshots must not be reused as-is.
  Retire the desktop bundle publication dependency and prevent retained old
  generations from selecting another application.

Shared CSP and native capabilities must be reviewed with the changed bootstrap.
Do not loosen operator authentication, execute scripts from raw service data or
add a remote native window merely to make the adapters look consistent.

## Ordered delivery under U07

These are implementation steps inside one consolidation task, not independent
UI releases. Do not deploy another partially migrated two-interface build.
The next deployment must include the retained scope and removal work together.

| Step | Ownership and concrete work | Exit evidence |
| --- | --- | --- |
| **1. Lock the retained contract** | `koi-ui`, `koi-compose`, `koi-serve`, sibling native adapter. Turn the table above into named view/action cases; map current DTOs, roles, read-only modes and platform effects. Record each old control's replacement or explicit removal. | Every shipped old screen/control has a disposition. Current Certmesh fixtures come from current domain types. An implementation that merely exists is not marked verified. |
| **2. Build the single runtime path** | Shared `koi-ui` render inputs/interaction assets, `koi-serve/src/ui.rs`, sibling `src/ui.rs`, `src/main.rs`, bootstrap/capabilities/build configuration. Replace native double-origin navigation, integrate authoritative status and common action transport, and keep offline Settings usable. | Same renderer and five destinations in native/browser; navigation never loads the old app; no duplicate subscriptions after revisits. |
| **3. Finish Services integration** | Shared service screens/details, native catalog/preferences/opener, discovery and comparison adapters. Move useful raw evidence and comparison into the named Services groups. Use the authoritative catalog for preference/action eligibility. | Native/browser retained actions work, list context survives updates, ambiguous saved identities are not merged, and failed peer reads remain explicit. |
| **4. Integrate Certmesh** | Shared Certmesh components; current Certmesh read/command contracts through serving/client/native adapters. Replace obsolete status inference and old forms; bring existing role-appropriate operations and recovery guidance into the same destination. | Open/member/authority, locked, revoked/expired/invalid and unavailable states are correct. Supported retained operations are verified against the daemon; actual trust material is unchanged by installation. |
| **5. Integrate Settings and sharing** | Shared installation/DNS/diagnostic/LAN sections; native service manager/startup; DNS APIs; composition status/events; Pond serving. Replace Phone's old-bundle publisher with the canonical built-in UI. | Local controls work with stopped daemon; DNS changes reread state; sharing serves the same presentation with public fields only and no mutation routes. |
| **6. Remove superseded surfaces and migrate data** | Koi HTTP/CLI/welcome paths, dashboard HTML owners, Pond old-generation handling, sibling assets/bridge commands, installer/bootstrap configuration and current docs. Delete obsolete entry points/assets and migrate stored preferences/peer entries. | No shipped route, tray item, deep link, packaged file or cache-selection path can reopen the old UI. Compatibility routes lead to the canonical equivalent; stale bundle publication cannot restore it. |
| **7. Verify and deploy the whole result** | Focused shared/adapter/domain-boundary checks and installed Windows/browser review, then the existing release build/install route. Update receipts for both repositories and affected launch gates. | Retention/removal checklist, installed task walkthroughs, single-entry route audit, density/accessibility checks and exact artifact identities. U07 closes only on the integrated delivered result. |

Steps 3–5 depend on step 2. Step 6 requires their retained replacements and data
migration. Step 7 requires step 6. U03–U05 retain ownership of their domain/task
behavior; U07 owns consolidation, source deletion and entry coverage. U06 still
owns independent operator evidence. This avoids a second competing task ledger.

## Entry-point and deletion checklist

| Surface to retire | Replacement / compatibility behavior |
| --- | --- |
| `Links::advanced`, Open system tools, Open advanced tools | Remove the field and all callers. Certmesh and Settings render their own retained tasks. |
| Sibling old eight-tab `ui/index.html`, screen-rendering parts of `app.js`, competing `styles.css`, duplicate card assets | Replace with generated/shared bootstrap and transport. Extract valuable event grouping and action logic into the correct shared/native owners before deleting old screen code. Remove stale fixture tests; keep behavioral checks against new contracts. |
| Native `ADVANCED_URL`, `show_shared_shell`, extra custom-origin app, Home navigation cleanup | One native bootstrap at its existing storage origin; one navigation lifecycle. Keep cancellation/listener cleanup as normal lifecycle behavior, not as a bridge between apps. |
| `koi-dashboard/assets/dashboard.html`, `mdns-browser.html`, their HTML handlers | Retire HTML. Keep snapshot/SSE/raw-discovery APIs and workers that are still consumed. Audit references before deleting or renaming the crate; its name alone is not a reason to discard useful backend code. |
| HTTP `/`, `/mdns-browser`; CLI `koi launch`; daemon/service welcome URLs; native launch/autostart/tray | Route to the canonical shared UI and the corresponding Services view where applicable. Add compatibility for previously advertised `/v1/dashboard` if needed; do not redirect JSON snapshot/event routes. Preserve login and intended destination. |
| Embedded/headless host with no operator authentication | Do not silently mount operator controls. If it offers HTML, use the same renderer with its approved read-only projection; otherwise offer no UI. No anonymous legacy dashboard fallback. |
| Pond selected and versioned old UI, desktop `pond_publish_ui` bundle push | Serve canonical shared assets. Old HTML bookmarks redirect to the same read-only destination; obsolete asset versions expire or return a clear unsupported response. Stop accepting old application bundles as executable UI. Preserve enablement and listener intent; document the publication API compatibility change. |
| Duplicate product copy, alternate mock as current spec, docs advertising alternate tools | Update current product/agent/epic instructions and packaged help. Keep historical ADR/research records; any architectural change to Pond delivery receives a superseding ADR during implementation. Existing evidence is labeled by its actual scope, not rewritten into consolidation proof. |

Migration preserves data, not obsolete screens. Read old `koi-watched` and
`koi-diff-nodes` at the existing native origin. Reuse the exact-match favorite
import behavior, byte-for-byte backup and revision-conflict handling. Preserve
aliases, unresolved names and ambiguous matches for a visible review in Settings;
never assign a favorite to a same-named stranger. Keep import idempotent across
interruption. Old feed cursors need no second feed to survive; obsolete cursors
can be retired after recording the disposition. Do not erase Certmesh keys,
rosters, audit, configuration, startup preferences or enabled LAN-sharing intent.

## Verification that closes the real task

1. **One reachable interface:** inspect packaged assets and every route above.
   Follow all internal controls from all five destinations. No alternate header,
   old theme, old About, Home bridge, or legacy app can load. Include bookmarked
   URLs and a retained Pond generation, not only a fresh installation.
2. **Retained operations:** exercise service Open/Copy/preferences; raw discovery
   and peer failure; current Certmesh role/action flows; DNS; local service/startup;
   and LAN sharing. Role/destructive operation proof uses disposable identities
   and isolated fixtures. Do not destroy or re-enroll the operator's live mesh
   as a UI check. Record unsupported platform effects visibly and accurately.
3. **Boundaries and failure:** cover token loss, public projection redaction,
   no LAN mutations, unknown/stopped daemon, stale state, interrupted commands,
   reconnect and revision conflicts. Membership is not browser HTTPS success.
4. **Upgrade:** verify original preferences and identity material survive, import
   is retryable, and an older desktop publisher cannot reactivate the old UI.
5. **Usability:** verify the installed app and browser, all five destinations,
   at least 30 mixed service entries, ten complete ordinary rows at 1280×800,
   390/320px reflow, keyboard focus/return, contrast, reduced motion, the actual
   foil effect, and About last. Evaluate task discovery, not just screenshots.

Run affected renderer, interaction, routing/auth and native tests; reuse existing
domain tests where bindings change. Old mock tests that encode obsolete DTOs
must be replaced. No broad unrelated backend test campaign is needed for copy
or layout edits. Source checks, a successful build and a running process alone
cannot close the installed one-UI requirement.

## Scope and plan status

This work consolidates existing valuable capability. It does not add a new
frontend framework, another inventory, a remote-control plane, or the unfinished
service-name HTTPS workflow. Those are separate product decisions. Broken old
bindings must be repaired to preserve a retained capability; they are not a
reason to retain its obsolete UI or disguise it as an advanced tool.

The consolidation is implemented in source and locally deployed on Windows.
Independent usability acceptance, destructive Certmesh action trials and the
cross-machine launch evidence remain governed by U06 and the launch ledger; they
do not restore any removed interface.
