# Epic 002 — Observable domain boundaries

- **Status:** active architecture rebuild; fleet execution paused
- **Opened:** 2026-09-03
- **Decision:** [ADR-043](../../docs/adr/043-observable-domain-boundaries.md)
- **Supersedes as active dispatch:** Epic 001 PH-5 release/soak work

## Objective

Make every Koi domain expose one cheap immutable status snapshot and a coalescing status
subscription, keep commands/state/events distinct, and make certmesh the first complete
authoritative boundary. Move every product presentation and cross-domain consumer to those
boundaries before naming another release candidate. Every observer, provider actor, listener,
connection set, and projector feeding those boundaries must have one explicit lifecycle owner;
partial startup and service installation must roll back as durable transactions rather than
leaving a second, unreported machine state.

The source workspace is `1.0.0-dev.0` for this work. The former frozen source
`e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef` is withdrawn as the active release candidate.
That does **not** erase or reverse Epic 001's accepted PH-4 results: its journals and physical
evidence remain true for the exact artifact tested. They are historical evidence, not proof
for the new development line.

## Dependency map

| Stage | State | Exit |
| --- | --- | --- |
| OD-0 — boundary implementation | **active in the shared development workspace** | ADR-043 types, feeds, mutation ordering, composition, protected certmesh status/public bootstrap, consumer migrations, lifecycle ownership, and transactional startup/install recovery are complete |
| OD-1 — repository validation | **waiting on OD-0** | formatting, workspace check/test/clippy, architecture guards, serde/status/revision/lag/security tests all pass |
| OD-2 — focused native validation | **paused; no fleet dispatch yet** | a later dated dispatch names the exact revision, hats, installed-product transitions, and status/auth assertions |
| OD-3 — candidate matrix and soak | **withdrawn until OD-2 closes** | a new explicit freeze and acceptance contract; old PH-4/PH-5 state is never inherited implicitly |

## Current fleet dispatch — wait without mutation

This section outranks retained PH-5 sections in every hat brief.

All fleet hats pause release, packaging, installed-entry, collector, canary, and soak work.
Do not build or install `dev` onto the standing deployment, start a collector, mutate a
provider/firewall/network/session, repeat a green physical gate, or label the former frozen
artifact as the current candidate. Preserve each machine's last journaled healthy Koi state
and the existing evidence.

When invoked through `fleet/task.md`, a hat performs only a read-only readiness check: confirm
the repository can synchronize normally, report that this epic is waiting on OD-0/OD-1, and
leave the deployed product unchanged. Apart from the dispatcher's required fast-forward
synchronization, do not create repository modifications. Do not create a journal entry or
commit for an unchanged wait report.

After OD-1, this epic will receive a dated OD-2 dispatch. It must state which old evidence is
still applicable and which behaviors require fresh physical proof. No hat infers that scope
from Epic 001.

## Validation contract for OD-0/OD-1

Repository validation must establish:

1. every domain returns its current immutable status without I/O/await/lock exposure and a
   new watcher sees that value immediately;
2. revisions advance on semantic changes, no-ops do not wake watchers, and coalesced/lagged
   consumers converge by rereading current state;
3. durable mutations publish in commit → status → event order and failure leaks neither a
   proposed success snapshot nor event;
4. certmesh distinguishes role, membership, authority, and identity health; a joined but
   damaged identity remains enforcement-closed;
5. full certmesh status is protected while the public bootstrap projection is minimal and
   sufficient for pinned enrollment;
6. `KoiStatusRuntime` owns the instance-scoped `KoiStatus` aggregate and explicit composition
   inputs without a global note registry; HTTP, dashboard, MCP, CLI, embedded, and Pond
   projections consume that aggregate; and
7. architecture guards preserve dependency direction, domain persistence ownership, and the
   `mdns-sd` boundary;
8. restartable stop and terminal shutdown remain distinct; after admission either transition
   converges through its owned cancel/abort/reap tail even when the requester disappears, with
   later calls sharing completion rather than being required for progress; Drop fences live
   work; and listener/provider/session children drain or abort within one bounded deadline
   without persistent Arc self-cycles, including on panic;
9. process-derived announcements are session-owned, provider transitions are
   break-before-make, and failed withdrawal/replacement converges without a duplicate or a
   permanent stale registration; and
10. systemd, OpenRC, and Windows installation serialize through one machine-global lock and
    recover only integrity-validated, durably checkpointed transactions; fault-injection and
    race tests prove no-clobber backup creation and cleanup-only recovery after the semantic
    commit;
11. cancellation before command admission has no effect, while cancellation after admission
    cannot split durable/native truth from the in-memory model, specialized projections, primary
    status, or success event; blocking platform work is queue-bounded, domain-owned, drained, and
    joined; and
12. Runtime-derived DNS, Health, and Proxy state is applied as complete transient scoped desired
    sets, never persisted as operator configuration or tracked in a composition-owned inventory;
    restart reconstructs it from current Runtime status and operator configuration wins explicit
    collisions;
13. one `CoreSpec.data_dir` becomes explicit `PersistencePaths` at composition and every domain
    receives only its owned path values; two-root tests prove no state, transition log, or
    certificate-directory crossover and no domain consults an ambient process root;
14. HTTP, IPC, mTLS, and ACME report ready only after exact listeners are acquired; breadcrumbs,
    Windows SCM-running state, and discovery presence follow those fences, while partial binds,
    half-open handshakes, cancellation, and late exits release or reconcile the whole owned
    generation;
15. command mode selection is client-only by default, standalone composition is explicit and
    refused beside a live local service, redirected stdin cannot create a responder, and every
    standalone native resource stays owned for its complete declared lifetime; and
16. custom Runtime producers enter through `RuntimeBackend` with the normal initial snapshot,
    observation, reconciliation, and teardown contract; malformed daemon responses, unavailable
    remote embedded operations, and host-observation failures remain typed errors rather than
    empty/default/no-op state.

## Coordination and publication

The fleet protocol remains one shared `dev` branch with direct authenticated pushes by the
agent that owns an explicitly dispatched change. There is no patch-harvesting or alternate
branch workflow. During the current wait dispatch, however, hats have no implementation or
evidence mutation assigned and therefore have nothing to commit or push.
