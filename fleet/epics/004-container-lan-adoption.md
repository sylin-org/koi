# Epic 004: Put Koi's container-to-LAN workflow in operators' hands

Status: active.
Decision: [ADR-046](../../docs/adr/046-container-lan-adoption.md).
Task authority: [launch ledger](../launch/LEDGER.md).
Execution entry: [fleet/task.md](../task.md).
Release facts: [launch readiness](../../docs/launch/README.md).
Experience contract: [UX direction and interactive concept](../../docs/ux/README.md).
Consolidation contract: [one Koi UI](../../docs/ux/single-ui-plan.md).

## Outcome

An operator labels a container, opens its actual application from a second
computer on the LAN, and sees correct names and state after restart, recreation
and removal. A bounded operator preview makes this useful before the optional
trusted-service workflow is complete.

The trusted-service extension adds an exact service URL that the intended client
resolves and validates normally, including renewal and recovery. One existing
proxy/resolver integration is supported by a complete reproducible recipe.

Ten independent qualified operators supply initial activation and retention
evidence. Download counts do not close this epic.

Public orientation presents Certmesh as Koi's private-space identity and trust
pillar alongside container discovery: locally governed member enrollment, renewal
and signed membership information for participating applications. Existing
Certmesh capability and the trusted-service extension have distinct setup and
acceptance boundaries. The first container trial does not require a CA.

## Scope

The first scenario matrix is Windows x64/Docker Desktop and Linux glibc
x64/Docker Engine, with both directions of independent client access. Use a
single ordinary LAN with multicast permitted and published application ports.
Make DNS delegation and firewall requirements explicit.

Do not infer Linux Podman, macOS, musl, routed VLAN, guest Wi-Fi or arbitrary
application compatibility from those results. Maintain existing platform builds,
security checks and API regression obligations; add scenario rows when demonstrated.

Use existing CLI/HTTP interfaces for early formative trials. A coherent operator
experience is a first-class workstream: Services, Certmesh and Settings,
with useful actions, truthful state and recovery on the selected preview surface.
U01–U07 define that bounded work using the existing shared Rust renderer and
authenticated adapters. No framework migration is required.

The owner requires one shipped UI. U07 consolidates valuable existing functions
and removes superseded desktop/browser screens, duplicate assets and navigation
bridges. Keeping them behind an advanced-tools button does not satisfy the UX
gate. New local-application sharing and unfinished service-name HTTPS remain
separate scope. A CLI-only formative trial does not complete the UI workstream.

## Work packages

### L01 — One current product and contributor story

Rewrite orientation, guides, references, distribution material and agent/fleet
entry points around ADR-046. Remove obsolete execution plans and unsupported
claims; retain ADR/research evidence. Provide one readiness page and one ledger.

Acceptance: current docs link the same epic; examples match implemented commands;
all local links resolve or are explicitly external to this repo; the surface
ledger parses; no prepared registry channel is called available. The document
rewrite does not claim new product acceptance.

### L02 — Select and verify an operator-preview artifact

Inspect registry versions and candidate source. Choose a fresh unoccupied version
only when ready to publish; do not reuse or repoint an existing tag. Fix
installation and packaging blockers for the supported scenario matrix.
Run the hosted release dry run from a clean checkout of the exact source.

Acceptance: a candidate receipt identifies source/lock/archives/checksums,
installer revisions and test results. A clean Windows and Linux install reaches
the intended daemon through documented commands; an upgrade preserves existing
configuration/identity; uninstall and interrupted-install recovery leave a
documented state. Any optional npm or OS package channel is verified at its
public endpoint before being advertised.

### L03 — Complete the real container-to-second-device task

Use one pinned Compose fixture and a published application port. Label it using
implemented metadata. Verify runtime discovery, mDNS publication, stable naming
through the client's normal resolver, and the actual HTTP application from an
independent physical client. Record any explicit DNS delegation setup.

Exercise already-running containers at Koi startup, container restart/recreation,
changed published ports, Docker restart, host reboot and stop/removal. No stale
endpoint may be presented as currently usable. Name collisions must be explicit.

Acceptance: repeatable receipts cover Windows host → Linux client and Linux host
→ Windows client, with actual host/runtime/client versions, source/hash/PID and
observed results. A runtime test double or Koi's own DNS lookup is insufficient.
Publish a copyable fixture and a bounded, measured recovery expectation.

### L04 — Explain and recover from the failures in that task

Exercise blocked multicast, missing DNS delegation, wrong published binding,
closed firewall port, unavailable daemon and stale runtime observations. Separate
discovery, naming, reachability and application readiness in existing CLI/HTTP
output and documentation.

Acceptance: each failure has a reproducible symptom, accurate classification,
one useful next action and a verified recovery. Neither silent success nor a
generic “network error” closes a case. Preserve application authentication and
network isolation during recovery.

### L05 — Run formative independent trials early

Use the [cohort protocol](../../docs/launch/cohort.md). Begin problem interviews
and observation as soon as a bounded artifact/task can be honestly tried; do not
wait for L07/L08 or whole-desktop completion. Expand to ten qualified independent
operators once L02/L03 identify the preview.

Acceptance: consented, anonymized records capture prior approach, task, artifact,
network shape, elapsed time, interventions, failure stage and outcome. Report
observed counts, not selected success stories. Product and docs fixes from these
trials feed L02–L04 and L06 before wider reach.

### L06 — Publish the bounded operator preview

Requires accepted L02/L03/L04 proof, the core U06 experience receipt for the
explicitly selected preview UI surface, and at least five observed L05 attempts,
including failures. There must be no unresolved security, data-loss, install
recovery or advertised-task blocker. A failed trial is a learning result, not
automatic permission to misstate readiness.

Prepare versioned release notes, exact install path, compatibility table,
known limits, verification and rollback information, and a short reproducible
demo. Release only the tested scope, with incomplete service-specific HTTPS
explicitly outside it.

Acceptance: the release artifact and selected registries are fetched independently
after publication and complete the quickstart. Public front-door links point to
that version's docs. Record the actual URLs and identities. Community messages
are separate reviewed communications; never mark them sent from a draft.

### L07 — Complete trusted service-name HTTPS

Wire exact service-name grants to a public operator action and to host proxy or
the chosen ACME consumer. Issue a service certificate with the right SAN, start
the actual listener, and provide explicit client DNS/root setup and diagnosis.

Acceptance: a second Windows and Linux client resolves the exact URL through its
normal resolver and validates the certificate without bypasses. Exercise renewal,
daemon/runtime restart, CA locked/unavailable, wrong name, wrong account,
revocation semantics and service removal. Verify key permissions and cleanup;
certificate issuance must not silently enroll a workload as an administrator.

### L08 — Prove one existing proxy/resolver integration

Select Caddy or Traefik and one resolver configuration using observed operator
needs. Supply exact versions, account/grant setup, DNS hooks, root distribution,
issuance, renewal and cleanup. Keep the established proxy responsible for its
listeners and advanced routing.

Acceptance: an independent operator can run the full recipe without modifying
an application image or inventing a missing adapter. Failure and recovery are
verified. Record which steps remain manual. Additional integrations remain
unclaimed until they meet the same standard.

### L09 — Publish the trusted-service extension and decide stable readiness

Requires L07/L08, refreshed affected L02–L04 proofs and a new clean-checkout dry
run. Treat a source, dependency, installer or shipped-asset change as a new
artifact identity with affected revalidation.

Acceptance: publish a distinct immutable version with tested client/runtime
matrix, upgrade/backup/recovery instructions and known security limits. The
maintainer explicitly records whether the supported contract merits stable
status; a version number, architecture milestone or old soak cannot decide it.

### L10 — Decide the next investment from retained use

Follow each qualified operator at 30 days after their first observed attempt.
Separate preview and trusted-extension users. Record continued task use, support
minutes, problems, reasons for stopping and concrete alternatives. Keep all ten
qualified operators in the primary denominator, including people who never
activated; also report retained use among those who activated. Missing replies
remain unknown and do not count as retained.

Acceptance: publish an anonymized internal evidence summary using the cohort
thresholds, a missing-data count and a continue/narrow/reconsider decision.
Seek a reusable downstream integration when users support that direction.
Do not add features solely to make the progress table look complete.

## Experience work packages

The [UX contract](../../docs/ux/README.md) owns narrative, navigation, state copy,
visual rules and source placement. Each package ships through existing domain
owners and adapters. Sample HTML establishes a concept only.

The [Sylin visual-signature plan](../../docs/ux/visual-signature-plan.md) supplies
the source-grounded Ghostlight alignment sequence for U02, U05 and U06. It refines
presentation while retaining the approved service density, details pane and
operational destination order. The owner's refinement preserves the reference
navigation button dimensions and typography, and adds About as the final
destination with a standalone card, statistics and documentation links. It is
defined in the plan, with the completed local visual slice recorded in
[its delivery receipt](../../docs/ux/visual-signature-proof.md).

The owner's subsequent correction is captured by the [single-UI plan](../../docs/ux/single-ui-plan.md).
U07 is the integration and retirement requirement across these packages. It
supersedes permission to ship a shared shell that delegates useful tasks to
another interface; visual acceptance is not functional consolidation.

### U01 — Establish the experience contract

Map the actual entry surfaces and broken transitions. Define Services as the
default, Certmesh as the private-identity home, and Settings as supporting
configuration/diagnostics. Establish the state/action language, visual family,
accessibility rules and an interactive sample-data concept.

Acceptance: source-grounded audit and task/state specification link the exact
implementation owners; the concept works at desktop and narrow widths with
keyboard navigation. Its simulated operations and unimplemented production
capabilities are explicit. Acceptance covers design artifacts, not shipped UX.

### U02 — Build the shared shell and consistent entry

Depends on U01. Extend `koi-ui` screens/components and existing family/shell assets.
Implement Services, Certmesh, Settings and About in that order, with About
last, plus readable service hierarchy, empty/loading/
unavailable states and the retained operational tasks within these destinations.
Coordinate HTTP entry routing and the sibling native adapter when in scope.
Use the UX contract's dense inventory as the default: single-line desktop columns,
compact chrome and a details pane that opens from the selected row. Reserve
expanded welcome content for empty states.

Acceptance: every shipped product entry leads to this experience; `/` and
authenticated `/ui` resolve to the canonical UI without weakening auth. Keyboard,
focus, wrapping and reduced motion work. Retained operational/recovery functions
are integrated before superseded screens are deleted in the same delivered
change. No second catalog, alternative workbench or new frontend framework.
With a 30-or-more-entry fixture at 1280×800 and default zoom, show at least ten
complete ordinary rows with controls visible; preserve readable type and 44px
action targets. Narrow layouts reflow without hiding conditions or actions.

### U03 — Open services and preserve identity through change

Depends on U02 and L03's fixture. Render authoritative addresses, host, evidence
and available actions; implement details, safe Open/Copy, favorites and aliases
with typed transport. Correct action eligibility, including current services'
preference actions. Handle snapshot gaps, reconnect and preference conflicts.
Support combined search/host/state filters, truthful counts and deliberate stable
sorting. An expandable details pane preserves selection/list context and does not
permanently take inventory width. On wide views the list remains operable beside
it; narrow views use a focused drawer/dialog. Closing nested task dialogs returns
to the pane; closing the pane returns to its row or a predictable list fallback.

Acceptance: users can find and attempt the actual application from the chosen UI;
multiple endpoints and scoped IPv6 are explicit. Restart/recreation/removal and
missed events preserve identity, focus and personal intent without stale usable
actions. Test hostile endpoint/name inputs and revision conflicts. Before native
Open is exposed, replace the existing shell-interpreted Windows opener with
validated typed URL dispatch and regression coverage. A dispatched URL is not
reported as proven second-device application success.

### U04 — Make failure and recovery understandable

Depends on U02/U03 and L04's real failure cases; backend preparation can begin
alongside L04. Use composition-owned evidence and implement any bounded missing
diagnosis operation before connecting its control. The existing advertised
`Diagnose` action is not proof of an implemented composed diagnosis route.

Acceptance: discovery, naming, connection and application checks identify their
observer, time, result and useful next action. Not-run and unknown stay explicit;
a timeout does not become a firewall diagnosis. Recovery preserves input/context
and updates from real state. Tests cover unavailable daemon, stale state,
cancellation/uncertain responses and the L04 failure matrix on the selected UI.

### U05 — Integrate Certmesh identity and operations

Depends on U02 and current Certmesh status/operations. Certmesh contains this
machine's role, authority, membership, renewal, audit and retained enrollment and
recovery tasks. Repair the desktop Trust view's obsolete status assumptions using
current typed role, identity and authority inputs. Retire its old screen and
bridge link under U07; explanatory text pointing at another UI is insufficient.

Acceptance: outside/member/authority and locked/degraded states render correctly.
Users can distinguish identity membership from application permissions and
browser TLS. Preserve verified create/join/renew/revoke/recovery capabilities;
any newly advertised guided flow needs role-appropriate end-to-end proof. Do not
gate the preview on new wizards. Service-name HTTPS controls depend on L07 and
remain unadvertised until their real workflow passes acceptance.

### U06 — Prove the delivered experience with operators

Depends on L02, the core U02–U05 slices and completed U07. Name the actual preview entry and
delivery surface in the receipt. Verify actual integration, not only the concept.
Reuse L05 observation rather than recruiting a separate design-only cohort.

Acceptance: the core service/open/details/recovery task and retained Certmesh
operations work on the delivered surface. All shipped entries use the same
screens and navigation, with no remaining old application. Cover keyboard and focus return,
screen-reader status, contrast, reduced motion, offline assets, 390px layout and
320 CSS px reflow, daemon loss/reconnect and L03 lifecycle. Use a controlled
30-or-more-entry fixture on the delivered renderer to verify finding a late-list
entry, filtering/sorting and returning from details; participants do not need
to deploy that many services. In real L05 tasks with participants' natural
inventories, record completion, wrong turns, assistance and confusion about
reachability/trust from at least five
L05 attempts on that surface. Recheck affected paths after changes. Desktop proof
names both repository identities when desktop is advertised. Wider UI expansion
remains separately bounded and cannot inherit this receipt.

### U07 — Consolidate and retire the separate interfaces

Current owner priority. Follow the [one-UI plan](../../docs/ux/single-ui-plan.md)
for the inspected retention/removal inventory, seven-step sequence, exact source
owners and all-entry-point checklist. U03–U05 own their task behavior; U07 owns
the single shared presentation, integration, saved-data migration, deletion of
superseded screens and delivery as one complete result.

Scope includes native desktop, authenticated browser, root/CLI/tray/autostart
entry and existing read-only LAN sharing. Reuse the
Rust renderer, domain contracts, service manager and validated adapters. Preserve
authorization and public projection boundaries within the same presentation.
Remove duplicate screens, competing assets, old status assumptions, Home/Advanced
bridges and placeholder content. Useful APIs/workers and user data are retained.

Acceptance: every retained task has one discoverable home and is verified against
current contracts. Every superseded control/screen has a replacement or documented
removal. No packaged route or stored old bundle can reopen a second UI.
Preferences, configuration and Certmesh material survive upgrade.
The next consolidated deployment includes retained functions and removals together;
a partial shell, alternate theme or old-tool link cannot close this package.
The installed/browser walkthrough and exact paired artifacts are recorded; U06
retains independent usability acceptance.

## Start here

1. Preserve accepted U07 as the interface constraint for every subsequent task;
   do not reintroduce alternate screens, bundle delivery or bridge navigation.
2. Continue L02 candidate preparation and L03 fixture/lifecycle work under their
   existing contracts. Coordinate catalog ownership with U03.
3. Prepare L04 failure cases and their U04 presentation together. Begin L05
   formative attempts as soon as the bounded artifact/task is honest to try.
4. Select the intended preview artifacts in L02, finish the required U02–U05
   behavior, and collect U06 proof and the required L05
   attempts before L06 publication.

These are ready work definitions, not automatic fleet dispatch or accepted
native results. Record a bounded claim in the ledger before editing.

## Dependencies and release gates

- L01 establishes the operating contract.
- L02 and L03 may prepare in parallel; accepted native proof uses the L02 identity.
- L04 uses L03's real fixture.
- L05 observation begins early and continues through both milestones.
- U02 starts after U01; U03 uses U02 and the L03 fixture; U04 joins L04 and U03;
  U05 uses U02 and existing Certmesh. U07 integrates retained behavior and removes
  separate interfaces; U06 verifies the consolidated delivery and operator tasks.
- L06 depends on L02/L03/L04, core U06 and the first five L05 attempts.
- L07 can begin alongside preview work when it does not delay the first usable task.
- L08 depends on L07's grant/issuance workflow.
- L09 depends on L07/L08 and refreshed release proof.
- L10 evaluates at least ten qualified operators with their 30-day follow-ups.

The preview gate excludes completion of L07–L10. Stable/trusted-release gates do
not waive security, upgrade safety or affected platform validation.

## Evidence and ownership

Use [proof receipts](../../docs/launch/proof.md). The source integrator owns
implementation and integration; platform hosts own only their native proof and
system mutations. Current routing/capacity live in [coordination](../coordination.md).
A documentation rewrite launches no remote fleet session.

The ledger owns status and claims. This epic owns the task definitions. Readiness
owns artifact/channel and supported-scenario facts. Do not duplicate status in
journals or independent prompt packs.

## Exit verdict

This epic closes when the operator preview has an actual published, verified
artifact with its core U06 experience receipt, the ten-operator evidence has
been reported honestly, and the
maintainer records the next-scope decision. The trusted-service extension must
either have its own verified published artifact or an explicit evidence-based
maintainer decision to defer/cancel L07–L09. A valid decision to concentrate on
discovery/lifecycle must not require unnecessary trust work to close the epic.
Missing retention targets can close as “reconsider/narrow” with evidence; they
cannot be reported as successful traction. Documentation completion alone closes L01.
