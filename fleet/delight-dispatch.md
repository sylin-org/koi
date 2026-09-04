# Epic 003 Linux dispatch

This is the Epic 003 branch of [task.md](task.md), not a second operator prompt.
The owner delegated execution to the Linux machines through `fleet/task.md` on
2026-09-04. That authorizes this dispatch, the bounded R work orders, and the
existing own-host test/deployment and direct-to-dev publication protocol. It does
not authorize a public release, remote agent launch, or another host's mutation.

## Read and route

Read [the epic](epics/003-delight-realignment.md), the
[charter](../docs/prompts/delight/CHARTER.md), the
[ledger](../docs/prompts/delight/LEDGER.md), and the
[contract](../docs/prompts/delight/CONTRACT.md). The ledger is the sole assignment
and status authority. Read only the selected prompt's source set after routing.

| Hat | Primary responsibility |
|---|---|
| cachyos-linux | R01 coordination and product contract, Rust UI/Sylin integration, usability, candidate reconciliation |
| debian-linux | Discovery/catalog, service naming/sharing, diagnostics, CertMesh and secure-service composition |
| bluefin-linux | Documentation, container journey, SDKs/integration, Windows source preparation, immutable native recipe |
| alpine-linux | Install contracts, Linux firewall integration, CI, CLI/MCP/embedding and musl/native portability |

Each executable ledger row has exactly one owner. A parent with subrows names its
integration owner; it is not an additional implementation assignment. Native rows
belong to their actual hats. The Windows hat is reserved for later native proof:
Linux agents prepare its source and record missing evidence, never impersonate it.
An explicit subsequent operator dispatch on Windows activates that hat's pending
proof; no Linux session may launch it. macOS remains unverified.

On that later Windows invocation, first execute the pending Windows cases linked
from implemented/linux-ready task reports, using their published source and
procedures. This supplies missing evidence; it does not waive a dependency or
transfer the Linux source assignment. Write only the Windows journal/evidence and
link a reconciliation request for each source owner. Owners then promote the
affected rows when their full cases pass. R29/windows waits for those predecessor
acceptances before its final candidate pass.

## First: finish the inherited native run

Epic 003 is authorized; product implementation is waiting for R01 and the old
campaign handover. Do not restart a dated soak or infer success from elapsed time.

1. Each hat checks its own installed state and newest journal against
   [Epic 002](epics/002-observable-domain-boundaries.md). If the existing OD-3 run is
   still active, finish that already assigned collector/peer/coordinator role and
   its restoration. Keep its frozen artifact stable. No new product deployment.
2. CachyOS may prepare R01's source contract while coordinating that run. Other hats
   may inspect their forthcoming source/build prerequisites without changing the
   product, active peer surface, provider, firewall, trust store or session.
3. CachyOS reconciles actual collector verdicts and all required cleanup evidence,
   including Windows. Record the exact old-campaign disposition in CONTRACT.md.
   Preserve its historical SHA, failures and journal ownership.
4. R01 may be accepted only with a complete source contract and either verified
   Epic 002 closure, or explicit operator supersession plus verified restoration.
   This delegation authorizes the new campaign; it does not cancel an active soak.
   Missing evidence leaves R01 implemented/pending, with an exact next dependency.
5. Once satisfied, record `Campaign: active` in the ledger and the handover result
   in the epic/contract. No additional routine activation approval is needed.

If the old run never started, failed, or missed its schedule, report that fact.
Do not silently reschedule six hours, erase the gate, or invent a completed run.
Complete authorized diagnosis/restoration; unresolved disposition stays visible.

## Select one bounded iteration

After handover, perform these steps in order:

1. Resume this hat's interrupted claimed slice before claiming another.
2. Service a ready peer-evidence request addressed to this hat, provided its task
   dependencies are ready and its exact source, operation and restoration scope
   are recorded. A read-only peer cannot be converted into a system mutation.
3. Reconcile completed subrows for parents this hat owns. CachyOS also updates
   whole-epic gates/candidate coordination when their evidence is complete.
4. Select this hat's lowest-numbered unfinished R task with ready dependencies.
   For subrows use table order among this hat's eligible rows. Accepted work and
   implemented rows waiting only for unavailable Windows evidence are not selected
   for redundant implementation. Follow the ledger's Linux dependency rule.
5. Read that prompt, plan its exact files, claim it as below, then implement,
   verify, document and publish. Do not ask for a plan already authorized here.

A fleet invocation may repeat this loop after a completed, published slice and a
fresh synchronization. Each iteration remains one bounded work order. A standalone
named-prompt invocation ends after its selected slice. At a context/session limit,
checkpoint the exact next action; `run fleet/task.md` resumes it without rediscovery.

If no owned work or addressed peer request is ready, report the precise dependency
and finish. Do not fall back to PH work, take someone else's task, repeatedly run
green checks, or mark the whole epic blocked. Another invocation rechecks the ledger.

Before reporting a dependency-only wait, fetch once and re-read changed ledger and
peer rows; another hat may have completed it during this session. A newly available
owned slice is work to execute, not a reason to request another operator prompt.

## Claim before editing shared implementation

Fixed owners prevent duplicate implementations; claims prevent overlapping changes.

1. Inspect/synchronize both relevant repositories. In the selected report record
   source revisions, exact intended write paths (including sibling repo names),
   tests, any shared contract change and required peers. This is a plan, not evidence
   that work passed. Set only your selected ledger row to `in_progress`.
2. Commit that claim/report, rebase and push to `origin/dev` before implementation.
   After the push, fetch/recheck other live claims. Overlapping write paths or a
   shared contract have one writer: the earlier published claim proceeds; the later
   claimant records the dependency and releases its conflicting claim. Nonoverlapping
   work may proceed concurrently. Scope expansion requires the same recheck.
3. Treat workspace manifests/lockfiles, shared CSS/components, CONTRACT.md, common
   API shapes and cross-repo build changes as shared writes. Disjoint ledger rows
   and owned report/journal files alone are not an implementation conflict.
4. Preserve all other rows during a rebase. If a predecessor contract changed,
   reconcile the code and repeat affected checks before publishing.
5. Checkpoint incomplete work honestly; do not release a claim with uncommitted
   changes that another executor could overwrite. Time alone never expires a claim.
   Reassignment requires a published handoff of code, tests and remaining work.

No per-agent forks, patch harvesting, force-pushes or global lock daemon. Continue
to use the existing dev branch protocol. Product code, documentation and its
evidence land together; a claim commit is explicitly not task completion.

## Peer evidence and native deployments

Use the ledger's peer-request table for bounded cross-host work; the owning task
report contains its exact procedure. A request names both hats, source/artifacts,
operation, allowed mutations, restoration, expected result and a fresh run ID.
The peer acknowledges readiness in its own journal; link its evidence from the row.
This file-based coordination does not authorize sending messages or launching agents.

A shared contract needs musl/GUI/immutable/headless evidence when its prompt says
so. Request that evidence before acceptance; do not replace it with a target list.
Keep the real one-Koi-per-host baseline, interruption-safe restoration, service
manager, package, firewall, provider, login and trust requirements from PROTOCOL.md.

For a peer run, reserve the exact peer artifact/surface from acknowledged readiness
through both sides' completion. An agent may work on source while reserved but
must not deploy/restart that peer or change its network/trust state. A missed
reservation is a failed prerequisite, not a reason to label an unobserved peer green.

Before R29, CachyOS publishes a candidate manifest and a newly acknowledged native
schedule in reports/R29.md. It may freeze a Linux development candidate under the
ledger's narrow Windows-evidence exception; this is not a release candidate verdict.
Record both repository SHAs, artifact identities, rows, peer roles, fault times,
thresholds and restoration. Never reuse Epic 002's SHA/run IDs/timestamps. Each
hat builds/installs the recorded source and owns only its native row. Windows
acceptance, reconciliation and R30 closure still wait for their full prerequisites.

## Publish and report

Use task IDs such as `R17/linux-firewall` in journals instead of old PH IDs.
Source-only work records native fields as not exercised; prose-only changes use
documentation checks and do not trigger a ceremonial install or workspace rebuild.

Publish selected code/docs, report, ledger row and owned journal through the existing
commit/rebase/push rules. For desktop changes publish the sibling repo too, recording
both SHAs and compatibility/order. Never leave the Koi dispatcher pointing at an
unpublished required desktop revision. Do not record acceptance before evidence lands.

Report what landed, checks, installed state if changed, remaining Windows/external
evidence, and the next exact dependency. Missing participant/hosted/native evidence
remains pending. No R task, gate or epic becomes accepted just because its source
implementation is done.
