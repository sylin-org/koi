# ADR-043: Observable domain boundaries

- **Status:** Accepted
- **Date:** 2026-09-03
- **Builds on:** ADR-006, ADR-008, ADR-023, ADR-028, ADR-039, ADR-040, ADR-042
- **Supersedes:** presentation-owned reconstruction of domain state and the use of
  `CapabilityStatus` as a domain's authoritative status contract

## Context

Koi's domain facades already have two recognizable faces: commands mutate the model and
typed broadcast events report occurrences. Their state face is inconsistent. Some domains
return a structured snapshot, some expose only an asynchronous `CapabilityStatus`, and some
consumers reconstruct current truth from events, private persistence, or several unrelated
queries. Certmesh makes the cost visible: posture, CA ownership, roster membership, local
identity health, renewal health, and enrollment readiness are all real but no single domain
contract owns their relationship.

An event stream cannot be the source of current truth. Tokio broadcast receivers may lag,
start late, or disappear; replaying the events that happened to arrive creates a second,
consumer-owned model. Nor is `CapabilityStatus` sufficient: it is deliberately a small
human-facing summary and cannot safely drive enforcement, recovery, or cross-domain policy.

The opposite extreme would be a global internal state/event bus. That would hide ownership,
encourage stringly typed coupling, and turn the composition root into a service locator. Koi
instead needs the same small boundary on every domain while preserving explicit wiring.

## Decision

### 1. Every domain has three distinct faces

| Face | Meaning | Delivery and retention |
| --- | --- | --- |
| **Commands** | Requests to validate and change domain-owned state | Explicit facade methods; return only after the requested success boundary |
| **State** | The latest authoritative, immutable domain snapshot | Cheap `Arc` clone plus a coalescing `watch` subscription |
| **Events** | Semantic facts that occurred, such as joined, revoked, started, or failed | Typed `broadcast`; best effort and not replayable history |

These faces are related but not interchangeable. A command is not an event. An event does
not carry enough material to rebuild state. A status snapshot is not an audit trail and does
not promise to enumerate every intermediate transition.

Each domain exposes synchronous methods with the following shape (names may remain on the
domain's facade or runtime wrapper):

```rust
pub fn status(&self) -> Arc<DomainStatus>;
pub fn watch_status(&self) -> watch::Receiver<Arc<DomainStatus>>;
pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent>;
```

`status()` performs no file, network, async, or domain-lock work. A new status subscriber can
read the current value immediately. The status value is immutable and safe to retain. Large
collections may be shared behind `Arc` or exposed through a specialized query, rather than
making every status read clone an unbounded model.

`koi_common::status::StatusFeed<S>` supplies only the `Arc`/`watch` mechanics. A domain keeps
its feed private, owns snapshot construction and invariants, and decides which transitions
are meaningful. This is a shared primitive, not a registry, trait-object framework, or new
source of truth.

### 2. Status revisions are causal hints, not global sequence numbers

Every authoritative domain status carries an unsigned monotonic revision, normally the
`revision: u64` field. A narrower subsystem counter keeps its narrower meaning: for example,
mDNS control-plane `generation` identifies a provider-routing epoch while the enclosing mDNS
status revision covers registration and discovery changes as well. The snapshot is seeded during facade
construction from the domain's actual initial state. Within one running domain instance, a
semantically changed snapshot has a revision greater than the preceding snapshot; publishing
an equal/no-op projection does not advance it.

Revisions are process-local. They need not survive restart, are not comparable between
domains or nodes, and do not replace stable event IDs or durable audit sequence numbers. A
consumer uses a revision to reject a duplicate/stale projection and to tell that a refresh
changed something. It does not infer how many transitions occurred: `watch` deliberately
coalesces updates to the latest value.

Time is also an input owned by the affected domain. If certificate or lease health changes
merely because a deadline passes, a domain-owned timer republishes the status; consumers do
not poll files and independently calculate competing health states.

### 3. Successful mutations publish in one order

For a state-changing command, the required order is:

```text
validate / prepare
        │
        ▼
durably commit domain truth
        │
        ▼
publish the new immutable status
        │
        ▼
emit the semantic event
        │
        ▼
return success
```

"Durably commit" includes every persisted state or mandatory audit record that the command's
success contract requires. A failed commit publishes neither the proposed status nor its
success event. After an event is visible, a subscriber that rereads `status()` therefore sees
that event's state or a newer state. Failure to deliver a best-effort broadcast event never
rolls back a durable commit or its status publication.

Purely observed runtime transitions have no disk commit to invent. For those, the domain
first accepts the observation into its authoritative in-memory state, then publishes status,
then emits any corresponding semantic event. Native-resource commands retain their stronger
domain-specific acknowledgement rules; this ADR does not redefine a bound socket or provider
intent as success.

Caller cancellation does not move the commit point. Validation and preparation may be
cancellable while they have no accepted external effect. Once a command admits a durable or
native mutation, however, domain-owned execution retains the serialization right and completes
the coherent tail through durable settlement, in-memory acceptance, specialized projections,
primary status, and semantic event. The caller owns only its acknowledgement waiter and may
stop waiting without abandoning that work. A gate held only by the caller future is therefore
insufficient: dropping that future must not release serialization while detached filesystem or
platform work continues.

Restartable lifecycle commands preserve the same distinction at their boundary. A boolean
`false` acknowledgement means the domain accepted the command and authoritatively found the
resource already stopped. Closed terminal admission is a typed `shutting_down` error, and loss
of the retained execution owner before it can acknowledge is a typed worker error. HTTP,
clients, and embedded facades preserve those outcomes; neither owner loss nor transport failure
is allowed to look like an accepted no-op.

The smallest suitable mechanism remains local to the domain. A short bounded filesystem commit
and its in-memory publication tail may be one synchronous no-cancellation section. A blocking
platform adapter may instead use one domain-owned worker whose bounded queue is the admission
point and whose last owner drains accepted commands and joins the worker. Async native resources
may use a retained completion task. Koi does not introduce a global command executor or pretend
that cancellation can undo an effect already visible outside the process.

When an external platform cannot join the filesystem transaction, the domain first durably arms
an exact replayable intent, converges the platform, durably settles the intent, and only then
publishes success. Failure or process loss leaves pending/error truth that startup and later
reconciliation can finish; it never publishes a success event for an uncertain generation.
If final replacement is already visible but its crash durability is uncertain, the live model
accepts that visible generation and reattaches the exact, adapter-qualified transition as pending
before retrying durability. An ordinary pre-replacement failure retains the prior generation.
Neither outcome emits a success event or acknowledgement until reconciliation confirms settlement.

### 4. Lag recovery always rereads state

Events remain useful for audit notifications, UI activity, webhook fan-out, and targeted
reactions. A receiver that reports `Lagged`, starts after earlier events, or detects a revision
gap must reread the relevant authoritative status. It must not guess the missing transitions
or retain a possibly contradictory reconstruction.

Status watchers have simpler semantics: process every observed latest value and tolerate
coalescing. Consumers needing complete history use the domain's durable audit surface where
one exists. Neither `watch` nor `broadcast` is a durable queue.

### 5. Cross-domain wiring stays explicit

There is no global Koi-internal bus. Domain event enums and status types remain owned by their
domain. Cross-domain commands and queries use narrow typed integration ports, implemented and
wired in `koi-compose`; consumers never read another domain's persistence. Semantic event
fan-in remains a separate composition concern and does not become a command channel.

Closing or losing a source subscription is an observation failure, not a value supplied by
that source. A bridge retains the last accepted desired value and reports/retries the broken
observation path; only an explicit domain snapshot containing absence may drive destructive
convergence. In particular, losing Certmesh's CA-anchor watch may not be translated into a
request to remove the last accepted Certmesh trust root.

Pond is the one layering-shaped exception in placement, not ownership: its runtime and events
remain owned by the `koi-serve` bounded component, while its data-only status vocabulary lives
in `koi-common`. This lets the lower composition layer retain the exact typed snapshot without
creating a `koi-compose` ↔ `koi-serve` dependency cycle or inventing a duplicate projection type.

`koi-compose` owns the reactive system projection, `KoiStatus`, and its feed owner,
`KoiStatusRuntime`. The runtime subscribes to each enabled domain's status, accepts explicit
private composition inputs such as disabled/absent capabilities and serving state, and
publishes a new aggregate when an input meaningfully changes. `Cores` supplies composition
facts through typed methods; they do not pass through a process-global note registry. Pond
remains authoritative for its own desired/observed state, and `koi-serve` explicitly projects
its exact `PondStatus` into `KoiStatus.domains.pond`. The Pond capability card is derived from
that snapshot rather than supplied as a second, lossy status input. Pond also distinguishes
bound-listener liveness from LAN readiness: a firewall-blocked socket is running but waiting,
not falsely reported as stopped. UI publication and repository migration do not add a
`PondState`; the lifecycle vocabulary remains disabled, reconciling, running, waiting, and
error.

Pond serializes every lifecycle/UI status transition and corresponding event through one
instance-scoped publication gate. The durable replacement becomes visible before status,
status before event, and confirmed crash durability before command success; slow listener and
repository work remains outside the gate. If the replacement is visible but its directory
flush cannot be confirmed, status and the factual event still describe the visible state, but
the command returns typed durability uncertainty. An identical retry reflushes that state
instead of reporting a false no-op. Pond events are current-fact notifications, not durability
acknowledgements. Lifecycle publications preserve the UI projection, and UI publications
preserve listener truth, so independent writers cannot erase each other's accepted state.
`PondStatus.accepting_commands` is the monotonic terminal-admission fact: it becomes false before
the runtime can reject a lifecycle command, is preserved by draining listener observations, and
is returned as the same typed `PondStatus` body on terminal HTTP 503 responses.
Pond's fixed, request-size-bounded UI repository uses the ADR's short synchronous
no-cancellation form after command-lock admission: pointer commit, status publication, and
event emission contain no await point. A domain worker would add ownership machinery without
improving this rare local transaction; cancellation while waiting for the command lock remains
side-effect free and is tested explicitly.

The five-file UI uses durable content-addressed generations plus a separately committed
durable current pointer. Startup migrates valid preceding single-bundle and exact legacy-file
state into that model and fails closed on corrupt, incomplete, hash-incoherent, or dangling
state, including damage to a non-current retained generation. Loss of the migration marker
never permits destructive reinitialization of accepted or unknown repository content.
Accepted immutable generations remain addressable across later publishes and restarts. Once
loaded, `PondStatus.ui` is the single mutable current selection; the byte store only retains
immutable generations. The authenticated clear-selection command atomically commits the
pointer to `None`, then publishes `PondStatus.ui = unavailable`, then emits `UiCleared`;
clearing an already-empty selection is a status/event/persistence no-op. Clear never deletes
an immutable generation, so a previously accepted generation URL remains valid across clear
and restart. `GET /` captures the status selection and returns a no-store temporary redirect to
`/_koi/ui/<64-lowercase-hex>/`; the unchanged relative asset references then resolve inside
that one generation. There are no flat current-asset routes and no per-request reread of the
current pointer after selection. Root-absolute `/healthz` and allowlisted `/v1/...` reads stay
live rather than becoming generation assets. The HTML CSP explicitly admits its same-origin
external scripts with `script-src 'self'` and keeps `base-uri 'none'`.

Pond's unauthenticated `/v1/status` is an explicit coarse DTO projected from one `KoiStatus`
snapshot. It allowlists version, platform, uptime, aggregate revision, daemon/surface identity,
and known capability name/enabled/healthy triples. It is not serialization followed by
redaction, so internal summaries, endpoints, reasons, firewall details, and exact domain
snapshots cannot appear merely because an internal type grows.

When a domain deliberately exposes a specialized authoritative projection alongside its
bounded primary status, composition retains the exact projection needed by product surfaces in
the same `KoiStatus` value. For example, resolved mDNS records live in the domain-owned
`MdnsDiscoverySnapshot`, while Certmesh's `CertmeshRosterSnapshot` already decides and
normalizes active membership, and DNS exposes `DnsCatalogSnapshot` with sorted effective names
and operator-managed entries without leaking its resolver model or repository. A domain
publishes specialized projections before its primary status; the
primary status is the causal fence observed by composition. Prometheus discovery and MCP read
these retained projections from `KoiStatus` rather than receiving separate bridges or
recreating domain semantics at request time. Transport-backed MCP reads one peer-gated
`GET /v1/inventory` projection captured from the same aggregate, rather than joining separate
status, Health, and DNS requests. MCP resource invalidations likewise diff one coalescing
`KoiStatus` watch; they do not rebuild current state from broadcast events.

Cross-domain derived configuration is a complete transient desired-set projection, not a series
of durable operator commands. Runtime remains authoritative for the current opted-in instance
inventory. Composition translates its latest `RuntimeStatus` into complete scoped DNS, Health,
and Proxy desired sets and atomically replaces each target domain's process-local scope. The
target domain owns validation, deterministic merge, status/event publication, and conflict
precedence; explicit durable operator configuration wins a name collision. Scoped projections
are never written to operator repositories and start empty after a process restart, where the
current source status reconstructs them immediately. Composition keeps no parallel applied-state
ledger and does not infer missing removals from a best-effort event stream.

mDNS remains the deliberate native-resource variant: process-derived publications are owned by
a registration session because the provider may need acknowledged withdrawal and retry. Even
there, Runtime status is desired truth and the session is only the target resource owner, not a
second inventory. This pattern gives each producer one idempotent `replace scope` command while
keeping merge semantics and effective status inside the receiving bounded context.

A demanded mDNS browse that loses its provider route retains its last accepted records in the
discovery snapshot and reports that staleness through `unavailable_browse_count`; route loss is
not fabricated service removal. Stale records cannot satisfy point resolution or warm replay.
When a raw browse reopens, Koi retires the preceding observation's records in status and emits
their removal notifications before declaring the route current, after which real provider events
repopulate the snapshot. Operational status writers update only their own control/registration
facets, so they neither overwrite discovery nor invert its lock order.

HTTP, CLI, dashboard, MCP, embedded, and Pond presentations project from that same aggregate
rather than running their own status queries or trust inference. The existing
`CapabilityStatus` becomes a presentation projection derived from domain status, never
domain truth.

The embedded host-event adapter preserves this distinction. True domain broadcasts map to
host semantic events. A coalescing Certmesh status watch maps only to
`CertmeshStatusChanged { revision, posture }`, an explicit latest-value notification whose
revisions may skip; it never fabricates a `from → to` event history. Client-mode facades also
preserve boundary failures: an operation backed by a daemon endpoint returns its transport,
API, or decode error, while a local-only operation returns `RemoteUnsupported`. Empty state,
`false`, `None`, and success are never substitutes for remote failure.

This division is intentional:

- a domain decides what its state means;
- composition decides which domains are present and how their states form one product view;
- an adapter decides only how to serialize or render that view.

OS trust is its own domain rather than a Certmesh side effect. `koi-trust` owns the
Koi-managed-root aggregate, its cross-process transition lock, durable intent journal, the
real `os-truststore` adapter, and a revisioned `TrustStatus`/`TrustEvent` boundary. Certmesh
publishes a separate, non-serializable CA-anchor projection (including PEM) before its primary
status; composition observes that desired state and drives idempotent Trust commands. A
present anchor ensures the exactly named/source-owned managed root, replacing an older managed
generation by installing the new root before removing the old. An absent anchor removes only
the tracked `koi-certmesh-ca`/`certmesh` root, so destroy converges without ever taking ownership
of an operator root. Anchor observation failure is a third, explicit state: it retains the last
accepted Trust desire and surfaces/retries the error; unreadable or invalid material can never
masquerade as absence and authorize removal. Every platform effect is preceded by a durable intent and is recoverable
by startup, later commands, and periodic reconciliation. Public status and events expose only
coarse presence, fingerprints, ownership names, and errors—never replay PEM. `os-truststore`
imports are confined to this domain; Certmesh neither mutates nor diagnoses the OS store.

### 6. Certmesh is the first authoritative implementation

Certmesh's status explicitly separates at least four dimensions: local mesh role, local
identity condition, CA authority/readiness, and roster/enrollment state. Role is not identity
health, and local CA ownership is not membership.

A node with no persisted mesh membership is Open. A node that joined a mesh but whose leaf is
missing, corrupt, expired, or revoked remains a member with an unhealthy identity condition.
It must not silently become Open, because that would turn damaged authentication material into
a permissive downgrade. Enforcement remains closed until the identity is repaired or the
operator deliberately destroys/leaves the membership state. A pure member may correctly own
no local CA and have no authoritative local roster; consumers must not use either absence to
infer Open posture.

The full certmesh status includes operational and membership detail and is an operator
surface. `GET /v1/certmesh/status` therefore keeps the local-read exemption but requires the
daemon access token from a non-loopback or unknown peer. Unauthenticated enrollment gets a
separate `GET /v1/certmesh/bootstrap` projection
containing only the minimal public CA identity and enrollment facts needed before the caller
has credentials. That projection is derived from the authoritative certmesh status rather
than separately stored. The signed trust bundle keeps its existing public, self-verifying
protocol role; the audit log and full diagnosis remain protected according to their stricter
contracts.

Certmesh persists each command's artifact write-set through one transactional repository. A
pre-replacement failure leaves the preceding model intact. If a committed generation is visible
but its crash durability cannot be confirmed, the aggregate accepts that visible generation,
publishes the same status with a RED `repository_durability` diagnosis, and returns typed
uncertainty without emitting the command's semantic success event or acknowledgement. Startup
repository recovery accepts the visible committed generation and clears the process-local
diagnosis. Commands that update correlated models, such as ACME order and roster state, settle
only after every affected model is accepted, preserving the primary status as the causal fence.

### 7. Existing domains converge without a framework rewrite

mDNS keeps its structured control-plane generation and makes it part of the domain's cheap
status. DNS, Health, Proxy, UDP, Runtime, and Pond publish revisioned structured snapshots
from their existing owners. A runtime wrapper may own the status when it alone knows whether
the domain is started or bound. This is an incremental facade change, not a requirement that
every lifecycle share one generic controller or one status schema.

### 8. Observation and serving lifecycles have explicit owners

Reactive boundaries do not justify detached work. The facade or runtime that exposes a
status feed owns every observer, timer, provider actor, listener generation, connection set,
and projection worker that can publish into it. Cross-domain bridges own their narrowly wired
observers; presentation adapters own their cache projectors and event relays. A task must not
retain the owner that retains its `JoinHandle`.

Restartable `stop` operations and terminal `shutdown` operations are distinct where a domain
supports both. Shutdown signals cancellation first, retains every handle while awaiting it,
uses one bounded deadline for the whole owned set, aborts and reaps stragglers, and is safe to
retry if its caller is itself cancelled. `Drop` is the synchronous fail-closed fence: it
cancels and aborts still-owned work rather than detaching it. Accept loops own their child
connections through bounded drain, callback-backed providers keep callback context with its
native owner until terminal acknowledgement or quarantine, and blocking worker threads are
joined rather than detached. Retirement uses a deadline only when the native adapter supplies a
real cancellation/deadline mechanism; otherwise shutdown truthfully waits for the admitted call
to return instead of reporting a fictional timeout while an external effect continues.

Composition startup follows the same rule transactionally. Until the domain graph is
committed, a construction guard owns every admitted native resource and worker. Error or
cancelled construction rolls the partial graph back in reverse ownership order. A bare domain
model never exposes an alternate serving method that bypasses its runtime owner; standalone,
daemon, service, and embedded paths use the same lifecycle boundary.

Process-scoped derived mDNS announcements use session leases. Explicit withdrawal is the fast
path, while session drop moves an unsettled registration into the domain reaper so provider
churn or cancellation cannot leave permanent desired records. Replacements are
break-before-make and retry from latest status, preventing duplicate advertisements while
still converging after a native provider returns.

### 9. Composition inputs and readiness are explicit facts

The composition root resolves the machine data root once and constructs an immutable
`PersistencePaths` value from `CoreSpec.data_dir`. Domains receive only their exact path or a
small domain path value such as `HealthPaths`; they do not rediscover an ambient global root.
Two compositions with different roots must be independent in one process, including their
transition logs and certificate directories.

Preparing a root means creating and securing exactly that injected directory. It does not
manufacture child repositories or a default configuration, and failure is fatal to startup.
Destructive maintenance uses the same identity: factory reset obtains the active owner's
authoritative root, proves it is the selected root (including canonical path identity), asks
that owner to stop, and waits until ownership is positively absent before deleting anything.
Timeout, malformed credentials, permission failure, or an otherwise uncertain observation is
not absence and leaves the root untouched.

The application root likewise observes machine identity once, validates it, and injects one
immutable `HostIdentity` into serving and presentation adapters. Dashboard, `/v1/host`,
webhook provenance, ACME URLs, and the `_http`, `_mcp`, and `_certmesh` announcements therefore
cannot disagree because one of them reread the OS later or substituted `unknown`/`localhost`.
Certmesh receives the same hostname as required bootstrap input before its core can be shared
or retained reload reconciliation can start. Certificate creation, renewal, failover, local
identity lookup, and status projection use that injected value; the domain never reobserves
ambient OS identity. Standalone read-only Certmesh observation receives a hostname captured by
the CLI composition boundary and remains persistence-read-only.
This launch fact needs no event stream: a hostname change belongs to the next composition
generation. A provider usable outside that graph still performs its own strict prerequisite
assessment.

Platform engines enter through real provider ports. In particular, Runtime accepts a
`RuntimeBackend` through `start_with_backend`, then owns connection, initial inventory,
lossless snapshot-to-stream observation, reconciliation, and teardown exactly as it does for
built-in Docker/Podman selection. There is no public event-injection shortcut that lets a
producer bypass provider lifecycle or aggregate reconciliation. Direct event injection exists
only inside tests.

Serving readiness means that every advertised resource has been acquired and its adapter has
crossed an explicit readiness fence; spawning a task is not readiness. HTTP, local IPC,
Certmesh mTLS, and ACME listeners are bound before their generation is published. Exact
OS-assigned endpoints flow outward from those bound listeners. Breadcrumb publication,
Windows SCM `Running`, and `_certmesh._tcp` presence happen only after the corresponding
fence. A partial bind or registration failure rolls back the whole provisional generation;
late adapter exit withdraws presence and drives owned teardown/reconciliation.

The embedded adaptive-service boundary follows the same rule. Its sole public `serve` path
acquires the `TcpListener` and returns the exact bound address; the internal posture-reactive
worker receives that listener and cannot reinterpret readiness. `participate` adds an initial,
acknowledged session-scoped mDNS registration on the listener's actual port before success,
then retains listener and registration as one cancellable generation. Later posture restamps
are retryable desired state. Startup itself is composition-owned: dropping the readiness waiter
after a native publication command is admitted completes the provider acknowledgement and rolls
back the provisional registration and listener. Identity observation fails rather than publishing
`unknown`, while Certmesh identity acquisition deliberately remains best-effort so a legitimate
Open node can still serve plaintext.

The command host preserves the same one-owner invariant. Capability commands are clients of a
healthy authenticated local service or an explicit endpoint by default. Standalone composition
requires `--standalone`, is refused while the local service is alive, and retains its native
resources for the full command lifetime. Redirected stdin never selects a hidden execution
mode: the former implicit mDNS stdio adapter was removed because it silently created an
uncoordinated second responder. `koi mcp serve` remains an explicit stdio protocol adapter, but
it is a client of the authoritative service rather than another composition.

Local-owner discovery has three typed outcomes: `Present(owner access)`, positively `Absent`,
and `Uncertain(error)`. Only the first two authorize a mode decision. A malformed breadcrumb
may be superseded by a successful authenticated local-control observation, but transport
permissions, malformed responses, timeouts, and undecodable ownership state remain uncertain;
they never trigger standalone fallback or destructive repair.

Finally, adapter observation failures stay failures. Hostname/interface enumeration, daemon
response decoding, and remote embedded operations may not become an empty collection,
`false`, `0`, `None`, a no-op success, or a guessed label. Optional values remain optional only
when the domain contract says they are. This keeps cheap status useful: it contains observed
truth, not presentation fallbacks.

Provider adapters perform their own prerequisites as part of assessment and opening. For
example, the built-in mDNS provider is unavailable if it cannot observe a usable publication
hostname; it does not announce `localhost` or `service`. Presentation adapters likewise omit a
target when its domain snapshot has no concrete address instead of emitting a plausible
loopback endpoint.

## Consequences

- Current truth has one owner and one cheap read path per domain.
- Late or lagged consumers converge without replaying a lossy stream.
- Every product surface can agree while retaining presentation-specific redaction.
- Certmesh policy can distinguish an Open node from a joined but damaged member and remain
  fail closed.
- Full certmesh operational state is no longer exposed merely because it used GET; bootstrap
  discovery remains possible through a deliberately small projection.
- Status structs and revisions add some per-domain code, and every mutation path must be
  audited for publication ordering. That cost is preferable to consumer-owned state models.
- Explicit task ownership adds small lifecycle holders, but makes shutdown, cancellation,
  provider failover, and test isolation properties of the architecture rather than timing
  assumptions.
- `watch` coalescing means status subscriptions cannot answer "what happened?"; events and
  durable audit records keep that job.
- Persistent locations, providers, and serving endpoints are explicit composition values, so
  tests and embedded hosts can run independent instances without ambient-state coupling.
- Default CLI commands cannot accidentally become a second machine-resource owner, and
  readiness is not published before listeners and presence are usable.
- Boundary decode and host-observation failures are visible rather than being rendered as
  plausible but invented state.

## Rejected alternatives

- **Reconstruct state from events.** Late starts and lag make the result unknowable, and each
  consumer becomes a second state machine.
- **Make events durable and replayable.** This would add a log/offset subsystem to every
  domain while still not giving a constant-time current snapshot.
- **Use `CapabilityStatus` as the domain schema.** A human summary cannot safely carry
  enforcement or recovery semantics.
- **Expose locks or persistence to composition.** That breaks ownership and makes storage
  layout a cross-crate API.
- **Install one global state/event bus.** It hides dependency direction and weakens typed,
  domain-owned vocabulary.
- **Retain a process-global capability-note registry.** Hidden mutable composition input has
  the same ownership and test-isolation defects as a global bus; explicit runtime inputs keep
  assembly causal and instance-scoped.
- **Leave full certmesh status public for bootstrap.** Enrollment needs a fingerprint and
  readiness facts, not the roster, local identity condition, or authority diagnostics.
- **Treat task spawn as adapter readiness.** Scheduling says nothing about bind success and can
  publish dead endpoints or a false Windows service state.
- **Let each domain rediscover the process data directory.** Ambient path lookup couples
  independent compositions and lets one invocation read or mutate another root.
- **Fall back to standalone when daemon discovery fails.** Absence is not authority to create a
  second responder or open the same durable aggregate in another process.
- **Render malformed/failed observations with defaults.** Empty and zero are real domain values;
  using them for errors creates a second, fictional status model at the adapter.

## Validation

The implementation is accepted when all of the following are pinned by tests:

1. `StatusFeed` returns the current `Arc` immediately, wakes on change, suppresses equal
   updates, and coalesces safely to the latest value.
2. Every domain seeds a truthful initial snapshot; meaningful transitions increase its local
   revision and no-ops do not.
3. Mutation-path tests prove failed durability emits neither success status nor event, and an
   event subscriber rereads the committed revision or newer.
4. New wire status/bootstrap types round-trip through serde and tolerate additive fields as
   required by Koi's protocol rules.
5. Forced event lag and late subscription converge by rereading authoritative status.
6. Certmesh tests cover Open, CA authority, pure-member state, standby members in an
   authority roster, damaged and expired identity, and self-revocation; every
   joined-but-unusable case remains enforcement closed.
7. Router tests prove full certmesh status is token-protected from remote/unknown peers while
   retaining the local-read contract; bootstrap exposes only its allowlisted fields and is
   sufficient for enrollment pinning.
8. Composition tests prove one domain change advances `KoiStatus`, disabled domains remain
   explicit, and HTTP/dashboard/MCP/embedded projections derive from that aggregate. Embedded
   tests also pin coalescing status-notification semantics and prove remote transport/protocol
   failures cannot collapse into empty/default state, clean stream EOF, or no-op success.
9. Architecture guards continue to reject domain-to-domain dependencies, `mdns-sd` outside
   `koi-mdns`, and composition reads of domain-private persistence.
10. Pond tests force a publish between index and asset requests and prove that every response
    remains in the selected content generation; retained generations and the current pointer
    remain coherent across restart, and noncanonical or unknown generation paths never
    substitute current bytes.
11. Pond repository tests prove valid legacy migration and fail closed on incomplete,
    malformed, hash-incoherent, dangling, marker-lost, or retained-generation damage without
    discarding the preceding accepted or unknown repository content.
12. Pond boundary tests prove the public status DTO contains only its coarse allowlist, while
    lifecycle and UI transitions share status-before-event ordering and preserve each other's
    accepted projection without adding a lifecycle state; stop fencing derives from the
    latest gated status and cancellation deadlines cannot detach the listener or its process
    probes.
13. Lifecycle tests cancel startup, stop, and shutdown futures at adversarial points and prove
    that DNS, Health, Proxy, UDP, Runtime, mDNS providers, IPC, MCP sessions, browser workers,
    Certmesh/ACME servers, and Pond retain or synchronously fence every owned task and native
    resource; restartable stop remains restartable and terminal shutdown rejects re-arming.
14. Cross-target gates exercise native Linux plus Windows GNU ownership code, including
    callback-provider teardown, named-pipe connection draining, Windows process-tree cleanup,
    and service-install recovery. Composition startup failure proves an earlier bound domain
    is released before the error returns.
15. Persistence tests construct two compositions with distinct `PersistencePaths` and prove
    DNS, Health (including transition logs), Proxy, and Certmesh never cross roots or consult an
    ambient state directory.
16. Serving tests occupy HTTP, mTLS, ACME, and embedded adaptive-service ports, cancel half-open
    handshakes, exercise embedded port-0 publication/cancellation, and force initial-publication
    failures plus late adapter exits; no breadcrumb, SCM-running state, or mDNS presence may
    precede readiness, and provisional resources must be released before an error returns.
17. CLI tests prove automatic mode is client-only, standalone is explicit and rejected beside a
    live local service, redirected stdin creates no control plane, and standalone resources
    remain owned until their declared lifetime ends.
18. Runtime custom-provider tests enter through `RuntimeBackend`, reconcile an initial snapshot,
    consume lifecycle observations, and tear down through the same owner. Boundary tests prove
    malformed remote responses and failed host observation cannot collapse into default state.
19. Owner-selection tests distinguish present, absent, and uncertain local service observations;
    factory reset proves root identity, completed shutdown, and positively absent ownership before
    removal. Provider/presentation tests prove missing hostname or target address is reported or
    omitted rather than replaced by `localhost`, `service`, empty text, or zero.
