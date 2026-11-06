# Container-to-LAN launch ledger

This is the single task and claim authority for [Epic 004](../epics/004-container-lan-adoption.md).
The [readiness page](../../docs/launch/README.md) owns artifact and compatibility facts.

No operator-preview or trusted-extension candidate has been accepted under this
epic. The documentation realignment starts the campaign; it does not run a
deployment, create user observations or publish a release.

| Task | Outcome | State | Dependency | Claim / evidence |
| --- | --- | --- | --- | --- |
| L01 | Current docs, ADR and launch contract | accepted | Owner decision | [Documentation evidence](../../docs/launch/documentation-proof.md), including Certmesh positioning; source baseline `791f87e` plus this rewrite |
| L02 | Verified preview artifact and install | in progress | L01 contract | [Development deployment](../../docs/launch/lifecycle-fixture-proof.md#current-windows-development-deployment): current release-mode source installed transactionally as the Windows SCM service with matching source/staged hash and healthy runtime. Candidate identity, clean-checkout receipt, Linux, upgrade/uninstall and published artifact remain unclaimed. |
| L03 | Actual second-device container lifecycle | in progress | L02 identity for acceptance | [Fixture evidence](../../docs/launch/lifecycle-fixture-proof.md): pinned Compose fixture, run-identifiable application response, 60-second per-transition acceptance budget, local lifecycle dry run and real installed Windows daemon observation. The application answered through the host LAN address, but ordinary resolver and independent physical Windows/Linux peer proof remain unclaimed. |
| L04 | Task diagnosis and recovery | waiting | L03 fixture | Unclaimed |
| L05 | Early independent operator trials | ready for preparation | Honest bounded task/artifact for attempts | Unclaimed; 0 observations recorded |
| L06 | Published operator preview | waiting | L02/L03/L04, core U06 and five L05 attempts | No release receipt |
| L07 | Exact-name trusted HTTPS | ready for implementation | Existing grant foundation; source claim | Unclaimed |
| L08 | One complete existing-stack integration | waiting | L07 | Unclaimed |
| L09 | Trusted extension and stable verdict | waiting | L07/L08 and refreshed release proof | No candidate |
| L10 | Retention and next-scope decision | waiting | Ten operators and 30-day follow-ups | No retention evidence |
| U01 | UX narrative, state contract and interactive concept | accepted | Owner's requested single-line columns and expandable details; L01 | [Design evidence](../../docs/ux/design-proof.md), including 36-service inventory, 49px single-line desktop rows and responsive pane/focus checks; coordinating agent and bounded concept agent. Baseline `791f87e` plus preserved uncommitted work; design only |
| U02 | Shared shell and consistent entry | in progress | U01 | [Implementation evidence](../../docs/ux/implementation-proof.md): shared Rust renderer, typed view intent, dense rows/details and authenticated browser transport verified in source and browser. The paired native change was packaged through the npx Tauri NSIS route, installed and launched against the installed development daemon. The package is an unsigned local development artifact; candidate identity and physical UI acceptance remain required. |
| U03 | Safe service actions, live lifecycle and personal intent | in progress | U02 and L03 fixture | [Action evidence](../../docs/ux/action-proof.md) and [integrated U07 evidence](../../docs/ux/single-ui-proof.md): exact HTTP(S) Open and Copy are gated by authoritative catalog actions and shared URL validation; native/browser preference bridges preserve cross-field intent. Physical lifecycle and independent installed-native task observation remain U03/U06 acceptance work. |
| U04 | Connection explanation and recovery | waiting | U03 and L04 cases | Unclaimed; composed diagnosis is not established by action enum |
| U05 | Integrated Certmesh identity and operations | in progress | U02 and current Certmesh contracts | [Integrated U07 evidence](../../docs/ux/single-ui-proof.md): the shared destination now reads current role, identity, authority, renewal and diagnosis types and exposes bounded role-appropriate operations. Disposable-identity action trials and independent operator evidence remain. |
| U06 | Delivered UX acceptance and operator evidence | waiting | L02, core U02–U05, completed U07 and five L05 attempts | No product UX receipt; a partial shell is not consolidation proof. |
| U07 | One shipped UI; retained capability consolidated and superseded interfaces removed | accepted | Current owner priority; implementation coordinates U02–U05 | [Single-UI receipt](../../docs/ux/single-ui-proof.md): ADR-047, shared renderer/adapters, current Certmesh bindings, integrated Settings, retired source/routes/repository, public Pond projection, focused suites and exact installed Windows artifacts. Independent usability remains U06. |

## Claim and completion rules

2026-09-13 U07 accepted: the owner authorized implementation and local deployment
of one Koi interface. [ADR-047](../../docs/adr/047-one-interface-built-in-presenter.md)
and [the implementation receipt](../../docs/ux/single-ui-proof.md) record the
shared renderer, retained operations, source deletion, Pond redaction, route
behavior, tests and exact paired Windows artifacts. U06 remains the independent
usability and candidate acceptance gate; it is not a reason to retain a second UI.

2026-09-13: the coordinating agent claims the owner-authorized U02 visual-family
slice at Koi `791f87e` plus preserved working-tree work. Scope: `koi-ui` navigation,
typed About destination, screens, family/shell assets and focused renderer checks;
browser session-control placement; the paired `koi-desktop` documentation-link
handoff and local package update. The slice follows
[the visual-signature plan](../../docs/ux/visual-signature-plan.md) and does not
claim new Certmesh state bindings or native endpoint actions.

This bounded slice is implemented and locally installed. The
[visual alignment receipt](../../docs/ux/visual-signature-proof.md) records the
the original four-destination visual slice, standalone About card/facts/docs, shared styles,
focused checks and final daemon/desktop artifact hashes. U02 remains in progress
for its wider acceptance; U05 state bindings and U06 operator evidence remain open.

2026-09-13 refinement implemented and locally installed: Ghostlight's card foil
pointer behavior now runs through the shared presentation asset; the
private-identity destination is labeled Certmesh; secondary ink is darker without
dropping below the established contrast baseline; and condition-backed service
color rails carry catalog meaning into the dense table. The
[visual alignment receipt](../../docs/ux/visual-signature-proof.md) records the
focused checks and installed artifact hashes. Scope remains within the same visual
slice and adapters; no catalog meaning or Certmesh capability changed.

U02's earlier entry-continuity slice is superseded by U07's removal of the
dashboard HTML/handler and canonical root routing. The coordinating agent owns
the integrated replacement recorded in the U07 receipt.

Before editing, record a bounded task/subtask, owner, source baseline and affected
files. Preserve existing uncommitted work. Parallel work is allowed only with
disjoint ownership or an agreed integration boundary.

State values are ready, in progress, waiting, accepted, blocked with a concrete
cause, or deferred/cancelled by an explicit maintainer scope decision linked to
evidence. Preparation may proceed before a dependent proof exists; acceptance cannot.

An accepted row links an exact evidence receipt. Do not use elapsed time, a
published draft, a returned agent message or an installed binary alone as proof.
A failed proof remains failed until a new receipt demonstrates correction.

Native requests name source/artifacts, fixture, cases, restoration and requesting
owner. Only the invoked host performs its system mutations. Do not launch another
host's task from this ledger.

2026-09-13 owner-directed mDNS retention correction: the coordinating agent
claims implementation and integration under U02/U03, followed by an independent
red-team review and task-level evaluation. Source bases remain Koi `791f87e`
and koi-desktop `d432b9e`, plus all preserved working-tree changes. Disjoint
implementation owners cover (1) common discovery presentation contracts,
`koi-dashboard` and `koi-serve` adapters/tests; (2) `koi-ui` Services/mDNS
presentation, interactions and fixtures; and (3) the sibling native adapter.
The coordinator owns integration, deployment, documentation and evidence.

The source audit found that U07's promised Services → Network evidence was
not delivered: the shared catalog omits the full mDNS inspection/query workflow
and does not arm its lazy browse-all worker. U07's single-presentation architecture
remains accepted; complete retained-capability acceptance is not established by
the earlier deletion/deployment receipt. This slice restores the mDNS task and
does not silently accept other retained tasks or independent U06 usability.

This bounded mDNS slice is now implemented, independently red-teamed and locally
installed. The [restoration receipt](../../docs/ux/mdns-inspector-proof.md) records
526 Koi and 25 native Rust test passes, 34 JavaScript passes, workspace/format
checks, exact paired artifact identities, live installed browse/resolve/no-answer
and DAT checks, and responsive rendering of installed HTML. Pond remained
disabled. The installed native walkthrough is explicitly uncompleted after the
owner stopped Computer Use with Escape. U02/U03 remain in progress for broader
acceptance; other retention gaps and U06 are not closed by this slice.

2026-09-13 navigation refinement deployed: the owner promoted mDNS from a
Services subview to a first-class destination. The shared order is Services,
mDNS, Certmesh, Settings, About; legacy subview links canonicalize to `tab=mdns`.
The [restoration receipt](../../docs/ux/mdns-inspector-proof.md) records focused
transport/navigation tests, 320px target and overflow checks, current artifact
hashes and a passing installed live-query evaluation. This changes information
architecture only; discovery ownership and broader U02/U03/U06 status are unchanged.

## Counters

- Qualified independent operators: 0 recorded.
- Observed activation attempts: 0 recorded.
- Unassisted completions: 0 recorded.
- Thirty-day follow-ups: 0 recorded.
- Verified public preview artifacts: 0.
- Verified trusted-extension artifacts: 0.

These counters describe records in this campaign, not a claim that no private
users exist. Update only from actual receipts and consented observations.
