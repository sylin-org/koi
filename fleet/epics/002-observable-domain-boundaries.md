# Epic 002 — Observable domain boundaries

- **Status:** OD-2 focused native validation dispatched
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
| OD-0 — boundary implementation | **complete at `2f967e4`** | ADR-043 types, feeds, mutation ordering, composition, protected certmesh status/public bootstrap, consumer migrations, lifecycle ownership, and transactional startup/install recovery are complete |
| OD-1 — repository validation | **complete at `2f967e4`** | full locked workspace tests, strict clippy, formatting, architecture/status/security gates, Windows GNU checks, lean embedded builds, TypeScript tests, and documentation checks pass |
| OD-2 — focused native validation | **active; dispatched 2026-09-04** | every hat closes its row below using one installed Koi and at least one independent physical peer |
| OD-3 — candidate matrix and soak | **waiting on OD-2** | explicitly freeze the resulting source, run only the affected final matrix, then one coordinated installed-service soak through real native observers |

## Current fleet dispatch — 2026-09-04 OD-2

This section outranks retained PH-5 sections in every hat brief.

`2f967e4` is the shared OD-2 baseline, not a frozen release candidate. Pull the latest `dev`
before starting; documentation-only commits do not invalidate its product evidence. A product,
dependency, installer, package, or shipped-asset correction creates a new baseline: its owner
tests and pushes it directly, and any hat whose uncompleted row is affected synchronizes before
claiming a pass. Historical evidence remains true only for its recorded source and artifact.

Every hat may research locally, in repository history, and online; install the dependencies
needed by its own OS; and exercise its own provider, service manager, firewall, session, and
network state under the protocol's capture-and-restore rules. Use the real deployment and real
endpoints. There is exactly one installed Koi per host; no alternate-port twin, isolated data
root, fake production capability, or second helper daemon can satisfy a gate.

| Hat | Owned OD-2 delivery | Required physical proof |
| --- | --- | --- |
| `cachyos-linux` | Keep the accepted `2f967e4` install and Pond gate; close only the remaining systemd collector and Avahi/resolve1/native boundary slice. Fix a shared defect only at its owning domain boundary. | Use one real peer to observe cheap status/inventory revisions and provider generations across an actual provider loss/selection/recovery, then run the real systemd installed-service collector canary. Preserve one PID except where a planned installed-service restart is the behavior under test; restore Avahi, resolve1, UFW, Pond desire, and publications exactly. |
| `windows` | Inspect current `dev`, then implement any still-missing real Windows SCM observer behind the neutral installed-service boundary. Close SCM install/recovery/readiness, authenticated named-pipe ownership/lifecycle, HostIdentity, and Bonjour/native-provider behavior without compatibility fakes. | One installed SCM service and one independent Linux Koi peer must prove status/inventory revision convergence, named-pipe control, provider selection/loss/recovery, discovery removal, and a short SCM collector canary. Prove the pipe DACL and denial from a different unelevated account; restore provider and service state. |
| `alpine-linux` | Implement any still-missing real OpenRC observer behind the same neutral boundary. Close musl/OpenRC install and recovery, local IPC, HostIdentity, and Avahi/native-provider behavior. | One package-owned OpenRC service and one independent Koi peer must prove status/inventory revisions, provider selection/loss/recovery and removal, then a short OpenRC collector canary. Restore package, rc-service, Avahi, firewall, and publication state exactly. |
| `bluefin-linux` | Accept the architecture through the real immutable-Fedora/systemd deployment. Exercise system-service ownership, local IPC inode/HostIdentity, status/inventory/Pond projections, and Avahi/resolve1/native transitions; fix only reproducible shared or platform-owned defects. | Install the exact tested bytes serially, use one real peer for provider and Pond assertions, and run the real systemd collector canary. Prove reboot/restart reconstruction where needed and restore rpm-ostree/package, provider, firewall, and Pond state exactly. |
| `debian-linux` | Accept the architecture through the real headless systemd deployment, including shifted-port discovery only where the journaled non-Koi incumbent still requires it. Exercise CLI local control, status/inventory/Pond truth, HostIdentity, and the neutral systemd observer. | Use one real Koi peer for Pond and collector traffic, run the systemd collector canary, and prove service restart reconstruction plus exact config/identity/firewall restoration. Serve as a stable peer when its own state need not be mutated. |

Cross-host evidence is coordinated, not simulated: use a shared run ID and retain both machines'
source/artifact hash, service identity/PID, status revision/provider generation, traffic result,
and restoration verdict. A hat owns mutations on its own host. The peer may perform run-owned Koi
API publications and reads; provider, firewall, package, service, and session mutation requires
the peer hat. Prefer available stable pairs (`Windows↔Alpine`, `Bluefin↔CachyOS`, and
`Debian↔CachyOS/Bluefin`), but agents may choose another available fleet peer when that produces
the same real assertion without waiting.

Do not add a framework merely to coordinate the run. The cheap boundary snapshot, its coalescing
change feed, the real native adapter, and an evidence-producing client are the meaningful pieces.
If a native observer is absent, implement it; do not expose a guessed state. If a defect is found,
fix it at the responsible boundary, add the smallest regression coverage, push it, and continue
the physical gate on the corrected source. Add an ADR only when the architecture decision changes.

A row closes only with a journal entry and direct push containing exact provenance, the real
cross-host assertion, the short native collector result, and exact final restoration. Once all
five rows close, update this epic once to dispatch OD-3; do not start the long soak independently.

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

The fleet protocol remains one shared `dev` branch with direct authenticated pushes by every
agent that owns an explicitly dispatched change. There is no patch-harvesting, alternate branch,
or local-only completion workflow. Rebase ordinary races, never force-push, and leave a completed
session present on `origin/dev`.
