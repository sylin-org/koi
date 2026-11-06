# Koi experience direction

The [single-UI consolidation plan](single-ui-plan.md) and
[ADR-047](../adr/047-one-interface-built-in-presenter.md) define the implemented
presentation. One shared renderer contains the retained product tasks; obsolete
screens, bundle delivery and alternate entry paths are removed. The
[U07 receipt](single-ui-proof.md) records the local development deployment.

The subsequent [retained-task audit](retained-task-audit.md) found capability
gaps behind that consolidation claim. The network inspector is an explicit
user task: mDNS is a first-class destination beside Services, with local filtering distinct
from active discovery queries. The ledger and task receipts own implementation
and evaluation; the architectural decision does not prove every retained task.
The [mDNS restoration receipt](mdns-inspector-proof.md) records the implemented
inspector, independent red-team corrections and installed development evaluation.

Koi makes local services understandable and useful: find a service, open the
application, understand its state, and recover when something fails. When a
deployment needs shared identity, a private space brings its machines and
participating applications under an authority the operator controls.

The interface should feel calm, capable and warm. Delight comes from a service
keeping its identity through change, a useful explanation arriving at the right
moment, and an actual application opening successfully. The existing pixel koi,
charcoal surfaces and blue accent provide the visual identity.

The [Sylin visual-signature plan](visual-signature-plan.md) compares the installed
Koi interface with Ghostlight's implementation and defines the next presentation
refinement: quiet shared chrome, restrained surfaces and an editorial About
composition, preserving the dense inventory and placing About last in navigation.
The owner's refinement preserves Ghostlight's navigation button dimensions and
typography while retaining Koi's colors, plus its standalone About card with
statistics and documentation links.

The [visual implementation receipt](visual-signature-proof.md) records this
alignment in the shared renderer and installed Windows development packages.

[Explore the interactive concept](concept.html). It uses invented local sample
data and performs no Koi operations. It establishes a design direction, not a
working renderer or an accepted user trial. [Epic 004](../../fleet/epics/004-container-lan-adoption.md)
defines implementation packages U01–U07; [the ledger](../../fleet/launch/LEDGER.md)
owns their status. The concept is illustrative; this document owns behavior and
acceptance when a mock interaction simplifies the actual protocol.

The [first implementation receipt](implementation-proof.md) records the shared
Rust shell and authenticated browser integration now in source, its checks and
remaining native/release gates. Source implementation and design acceptance are
separate from a delivered candidate.

The [endpoint-action receipt](action-proof.md) records the first U03 slice:
catalog-gated Open and Copy address in the authenticated browser view. It also
records why native actions, preferences and live lifecycle remain open.

The concept's manual client-observation form explores how evidence might be
explained. It is a scenario demonstration, not a requirement to build a new
observation database or to treat self-report as an automatic network check.

## One product, consistent navigation

| Destination | Operator question | Content and progression |
| --- | --- | --- |
| **Services**, the default | What can I use, and what is mDNS reporting? | **Catalog**: dense aligned rows, search, host/state filtering, sorting, favorites, hosting device, actual endpoint and on-demand evidence/recovery. **mDNS**: reported types and instances, full TXT and source observations, bounded active browse/requery/resolve, and explicit observation limits. |
| **Certmesh** | Which identities belong here, and what needs my attention? | This machine's role, authority, enrollment, identity renewal, membership changes and recovery. Keep authority controls distinct from member controls. |
| **Settings** | How is Koi configured, and where can I inspect it? | Local preferences, installation/startup, DNS configuration and diagnostics. Raw mDNS discovery belongs in Services; recent operational activity remains a retained task with separate acceptance. |
| **About**, always last | What am I running, and where can I learn more? | One standalone mascot card beside the product story, actual snapshot statistics, accurately labeled version facts and grouped documentation links. |

Device details are reachable from a service or member. Device filtering belongs
with Services; membership belongs with Certmesh. Do not introduce a second
top-level inventory with different names or health judgments. On narrow windows,
keep the same order and labels in a compact navigation row:
Services → mDNS → Certmesh → Settings → About. Refresh precedes the destination
group, leaving About last. About has its own shared destination with the
standalone card, snapshot statistics and documentation links.

Useful capabilities live in these destinations. The separate eight-tab desktop
workbench, dashboard HTML and raw-browser HTML have been deleted. The HTTP root
and native launch enter the canonical UI. Authentication and read-only LAN limits
remain explicit within that presentation.

## The first useful journey

1. **Arrive.** Show the connected machine and whether observations are current.
   An empty catalog says what Koi can find and offers the documented container
   fixture. It does not invite the user to create a CA before discovering anything.
2. **Find.** A compact row leads with the service's friendly name, hosting device,
   eligible address and plain-language condition in aligned columns. Keep layout
   and ordering stable as observations arrive. Search/filtering and an explicit
   sort help with a populated network. Counts support the inventory; revisions
   belong in details.
3. **Open.** Use the catalog's actual browser-usable endpoint. Show the target
   before dispatch. If several endpoints are eligible, offer an explicit choice.
   Copy address is a secondary action with a brief confirmation. Dispatching a
   URL establishes an attempt; Koi cannot infer that the new browser loaded it.
4. **Understand.** Details distinguish discovery, client naming, connection and
   application response. Say where and when each check ran. A response observed
   by the daemon does not prove that a second computer can reach the application.
5. **Recover.** Put the specific failed step beside one useful next action. A
   failed lookup might lead to resolver setup; a connection timeout alone cannot
   establish a firewall cause. Unknown evidence stays unknown. Let the operator
   retry, preserve the earlier result, and report what changed.
6. **Return.** Restart/recreation preserves authoritative service identity and
   saved personal intent. A stopped service loses its current Open action; a
   retained favorite explains its absence. A same-named stranger cannot inherit
   the old service's favorite or alias.

The release proof still includes the real application on a second physical
computer and the lifecycle matrix in L03. A successful click or attractive mock
cannot replace that evidence.

## A language of evidence

Treat condition, freshness, reachability, identity and TLS as separate facts.
Never collapse them into one green “secure” or “healthy” badge. Use text and a
small icon with color as a supporting cue.

| State or observation | What the interface says and does |
| --- | --- |
| Loading | “Connecting to Koi…” with a stable layout; expose a bounded unavailable state if connection fails. |
| Empty, current snapshot | “No services found yet.” Explain the supported first container task and offer its setup instructions. Distinguish a search with no matches. |
| Starting | “Starting.” State what is still being observed; do not fabricate readiness. |
| Found | “Found.” Discovery exists; an application response has not been established. Open may be offered only when an endpoint is independently eligible. |
| Responding | “Responding · checked from [observer] [age].” Details identify the actual check; a TCP connection is not an HTTP application response. |
| Not responding | Name the observed failure and observer. Offer explanation/retry supported by a real operation. Do not promise that retry will fix the network. |
| Stale or disconnected | “Last seen [time]” and a visible stale marker. Retain useful evidence, invalidate current-success claims and let authoritative eligibility govern actions. |
| Absent | “Not currently found.” Retain a saved favorite if applicable; remove stale usable endpoints and explain how to remove the favorite. |
| Ambiguous | “More than one possible match.” Show the conflicting candidates without selecting an identity by name alone. |
| Recovered | Briefly describe the successful check, then settle into the normal row. Do not reset selection, duplicate the service or steal focus. |
| Operation failed | Preserve user input where safe, show the actual result and a next action. A timeout or lost response is not evidence that a mutation never happened. |

Use concrete verbs: **Open**, **Copy address**, **View details**, **Check connection**,
**Join private space**, **Review recovery**. A `Diagnose` action in an internal enum
does not establish an available service-diagnosis API. Until that path exists,
provide current observations and relevant instructions without an inert button.
Successful mutation feedback follows an authoritative result or refreshed state.

## Certmesh: identity with understandable boundaries

Introduce Certmesh as “Machines and participating applications sharing identities
issued by an authority you control.” Explain the value before displaying
certificate mechanics. The first screen makes this machine's state explicit:
outside a private space, a member, or an authority. Show authority identity and
fingerprint, identity expiry/renewal, and any required operator action. A locked
CA is a specific issuance condition, not a claim that every running service failed.

Offer role-appropriate flows using implemented operations: create or join a
space, verify the authority fingerprint, enroll a named machine, inspect members
and known revocations, renew identity, and review recovery. Enrollment passphrases
and recovery secrets must not enter URLs, logs, screenshots or example receipts.
Authority changes explain their effect and require deliberate confirmation in
the product; inspect fresh state after an uncertain response. Preserve existing
recovery capability while migrating its presentation.

Membership is distinct from application permission, network isolation and browser
certificate trust. Signed membership information helps Koi-aware applications
apply their own decisions; revocation is not universal instantaneous TLS rejection.
Describe only the actual message-signing/encryption behavior. A device with a
valid identity can still host a service whose URL a browser does not trust.

Service-name HTTPS stays a service-level progression: intended name, DNS path,
authorized certificate issuance, listener, client trust, then validation and
renewal. L07 owns the missing public grant/listener workflow. The concept may
explain this relationship, but production must not present an unfinished setup
control as available. Existing member-name TLS retains its documented scope.

## Density is the default

A returning operator should see a useful inventory immediately. Use a short
**Services** heading, a compact toolbar and full-width aligned rows. Reserve
welcome copy and illustrations for the empty state. Repeated rounded cards,
large glyph blocks and an always-open details panel consume too much space as
the catalog grows.

At a 1280×800 CSS-pixel viewport and default zoom, target at least ten complete
ordinary service rows with navigation and controls visible. Desktop rows should
normally be 48–52px high, with 14–15px readable type and 44px action targets.
Each cell uses one line: **Name | Host | Endpoint | State | Action**. Move the
operating system, check age and explanatory evidence into details. Keep the
observed state meaningful on its own, such as “Responding on host” or “Client DNS
failed”; density cannot turn it into an unexplained colored dot. A single subtle
separator between rows is enough. Keep the table header available while scrolling.

The service name and an expansion cue open a details pane for that selected
service. At a wide viewport, place the pane beside the inventory so another row
can be inspected without closing a modal. Highlight the selected row and expose
its expanded state to assistive technology. Only one service pane is open at a
time; selecting another row updates that pane without launching the application.
The pane contains the complete endpoint, host, current condition, freshness,
host/client evidence and the relevant Open or recovery action. These details
explain the row; they are not another inventory.

The pane is closed by default and does not permanently take inventory width.
Closing it or pressing Escape returns focus to the originating control and
retains filters, sort and scroll position. If that row no longer exists, return
focus to the list's search control
and announce that the service is no longer in the results. The service name and
actions remain explicit keyboard targets; do not make a clickable row the only
way to reach them. Selection never implies opening an address. Long addresses
may abbreviate within a column, with an explicit
keyboard/touch-accessible Details action revealing the complete target and its
Open action. Include the complete target in the list Open control's accessible
description; a hover tooltip is insufficient. Unambiguous Open does not need an
extra confirmation dialog. Similarly named entries must remain distinguishable.

Search names, hosts and addresses; combine host and observed-state filters. Always
show matching and total counts and an obvious reset when no entries match. Sorting
is a deliberate operator choice with a stable identity tie-break; background
health changes must not unexpectedly move the focused row. Update observed state
and action eligibility immediately. If re-sorting or filter removal would move
an active row, defer that structural change while it is being used and show a
results-changed notice with an explicit update action. Details retain the selected
identity and explain absence; they cannot retain a falsely usable endpoint.
Avoid dozens of equally bright primary buttons: action styling should support
scanning the whole list.

At narrow widths, the details pane becomes a focused drawer/dialog with visible
close, appropriate focus containment and return. A task dialog opened from the
pane returns to it when dismissed; Escape closes the foremost surface first.
Reflow each entry into a compact name/host line, address, state
and accessible actions. Aim for roughly 88–112px ordinary rows; allow extra height
for long names, addresses, zoom or larger text. Density must not hide failure text
or shrink controls below their target size. Apply the same row discipline to
private-space membership; authority summary facts should not dominate the list.

Validate with at least 30 varied entries across several hosts, including names
with shared prefixes, long addresses and mixed current/unknown/failure states.
Check finding a late-list entry, combining filters, sorting, opening the intended
service and returning from details. This fixture is layout/interaction evidence,
not a performance benchmark or a claim of live discovery. Larger-catalog rendering
strategies belong to measured implementation work, not an assumed new subsystem.

## Visual and interaction rules

| Element | Rule |
| --- | --- |
| Surfaces | Preserve the existing charcoal family: background `#0f0e12`, raised panels near `#18171d`. Use a small number of elevations and borders; avoid a dashboard of equally prominent metric cards. |
| Type | System font, normally Segoe UI on Windows; 14–15px inventory text, 15–16px explanatory body, comfortable line height and short headings. Names use proportional type; addresses and identifiers use monospace. |
| Color | Primary ink `#f4f4f5`, supporting ink `#c9c9d1`, quiet readable ink `#a1a1aa`, blue accent `#60a5fa`. Validate actual foreground/background pairs; old muted gray is not automatically suitable for small text. |
| Shape and spacing | A 4px spacing base, mostly 4/8/12/16px around inventory controls and 24/32px for separate task regions. Use aligned rows with separators; gentle corners belong to containing panels, not every entry. |
| Actions | One visually primary action per task region. Minimum 44px interaction targets are a product choice. Secondary details, preferences and copy controls remain discoverable without hover. |
| Motion | Short 120–180ms feedback; up to 240ms for a meaningful reveal. Honor reduced motion. No looping health animation, confetti, auto-dismissed errors or waiting for animation before an action works. |
| Koi identity | Use the existing pixel koi most prominently in welcome/empty states and About, with a quiet presence in navigation. Warm, direct copy supplies personality; failures remain precise and respectful. |
| Feedback | Brief copy/favorite confirmation, progress for actual pending work, persistent failure until addressed, and quiet recovery. Announce important asynchronous status without reading the whole catalog on every update. |

Preserve visible keyboard focus, logical heading/landmark order, a skip link,
native control semantics and focus return after dialogs. Escape closes transient
details where appropriate without discarding an in-flight destructive operation.
Live refresh preserves focused controls, selection and scroll context. Long names,
IPv6 addresses, localization and zoom must wrap or scroll within their own region.
No page-wide horizontal scrolling at a 390px viewport; verify reflow at 320 CSS px.

Use WCAG 2.2 AA contrast, keyboard and focus requirements as the baseline: 4.5:1
for normal text, 3:1 for large text and applicable non-text controls. Focus must
remain visible and unobscured. The 44px product target is stricter than the AA
24px target-size minimum, which also has exceptions.
[WCAG 2.2](https://www.w3.org/TR/WCAG22/),
[focus guidance](https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum.html).

Visibility of status, consistent language, recognition over recall, error
recovery and restrained presentation guide these choices. These are design
principles, not evidence that Koi is usable; observation supplies that evidence.
[Nielsen Norman Group usability heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/).

## Implementation placement and known gaps

This source audit describes the development tree at baseline `791f87e` plus the
current documentation work on 2026-09-12. It did not run or certify a desktop
package. Follow [ADR-045](../adr/045-shared-rust-renderer.md) and the existing
domain/presentation ownership; a new frontend framework is unnecessary.

| Concern | Existing owner and bounded change |
| --- | --- |
| Shared presentation | [koi-ui](../../crates/koi-ui/src/lib.rs), its screens/components and family/shell assets render Services, mDNS, Certmesh, Settings and About, dense service columns and details. `UiState` carries bounded view intent; Rust owns filtering, ordering and catalog meaning. The concept's sample JavaScript is not production architecture. |
| Service truth/actions | [common service contracts](../../crates/koi-common/src/service.rs) and [composition catalog](../../crates/koi-compose/src/catalog.rs). Reuse endpoints, checks and observations. Correct current-service favorite/alias eligibility and the advertised diagnosis action before binding controls. |
| Transport/preferences | [authenticated UI adapter](../../crates/koi-serve/src/ui.rs), [transport JavaScript](../../crates/koi-serve/assets/ui-transport.js), [preferences](../../crates/koi-serve/src/preferences.rs) and [typed client](../../crates/koi-client/src/lib.rs). Bind typed actions deliberately; recover snapshot/epoch gaps and revision conflicts. |
| Native adapter | Sibling repository `koi-desktop`, especially `src/ui.rs`, `src/main.rs` and `ui/app.js`. The [view-query integration](../../tools/koi-ui-native/README.md) and validated Windows opener are applied in the installed development checkout. About's source-owned documentation URLs use that opener. The shared native service pane still withholds endpoint actions pending its deliberate typed bridge. |
| Certmesh | [authoritative status](../../crates/koi-certmesh/src/status.rs) and [HTTP operations](../../crates/koi-certmesh/src/http.rs). The legacy desktop Trust view expects obsolete top-level `ca_initialized`, `ca_locked` and `members`; migrate to current `role` and nested `authority` through typed inputs before relying on it. |
| Entry consistency | [HTTP routing](../../crates/koi-serve/src/http.rs), native launch and [Pond](../../crates/koi-serve/src/pond.rs) use the shared renderer. Root compatibility routes lead to canonical destinations; Pond retains explicit enablement and an mDNS-only public projection. See [the U07 receipt](single-ui-proof.md). |

Composed service diagnosis, local application sharing, secure-service orchestration
and a public catalog projection are not established merely by their architecture
names or action enums. Scope real backend work explicitly. Avoid new browser-side
inventories, endpoint guesses, secret-bearing transport shortcuts and “success”
based solely on a request being dispatched.

## How this becomes accepted experience

U01 establishes this narrative and a reviewable concept. U02–U05 implement its
task behavior; U07 consolidates and removes the separate interfaces; U06 verifies
the delivered surfaces and operator experience. Before L06, name the
advertised interface and entry URL/application in the candidate receipt. The
preview's operator UI must complete the service-opening and recovery journey,
provide working retained Certmesh tasks, complete U07, and pass the core U06 checks. A CLI
only formative trial can start earlier; it does not close the UI workstream.

Use the same [L05 participants and observation protocol](../launch/cohort.md),
with the actual candidate after implementation. Record whether operators can
find the service, choose the right address, interpret evidence, recover, and tell
private-space membership apart from browser HTTPS. Record wrong turns, questions
and assistance. Ask what felt reassuring or frustrating after the attempt.
Visual preference is informative; it cannot substitute for completion.

U06 receipts name both repo revisions when a desktop artifact is involved and
cover the real delivered entry, offline assets, keyboard/focus, screen-reader
status, reduced motion, narrow/zoomed layout, unavailable daemon, reconnect and
the L03 lifecycle. Mock screenshots establish layout only. Release and traction
claims remain governed by [launch readiness](../launch/README.md).
