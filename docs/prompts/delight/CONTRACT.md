# Epic 003 product contract and campaign handoff

Contract version: **1**
Status: **accepted; R01/G0 ready and campaign active**

This is the source contract for Epic 003. It is usable without conversation history.
Names marked **existing** resolve in the tree at the R01 source revision. Names marked
**proposed** are authoritative destinations for the owning R task; their absence is
not evidence that a second alternative owner should be created.

## Activation record

- Current dispatcher: Epic 003 through `fleet/task.md` and
  `fleet/delight-dispatch.md`.
- Execution authority: the owner delegated the work to the Linux machines through
  `fleet/task.md` on 2026-09-04. Once R01 is accepted, no additional routine
  plan-approval question is required.
- Product implementation gate: R01 accepted after final restoration evidence at
  `b18302b200eba3049fec6b7e00c701ac9b4cff64`; fixed-owner dependency selection is active.
- Koi source when the R01 claim was published: `c5805859ad3976c2504d16cac8ff62b94755ad2d`.
  The claim's starting revision was `e2c4a8266ff07ffd85846b672e1be84b5fbc1e42`.
- koi-desktop source observed by the claim: `4c05ed22dfdc2c11fd220eb3a65a64abad05e299`.
- Acceptance source: Koi `b18302b200eba3049fec6b7e00c701ac9b4cff64` plus this
  documentation activation; koi-desktop remains clean at the recorded revision.
- Branch/publication mode: fixed Linux owners claim and publish coherent changes
  directly to `origin/dev` under the fleet protocol. No public release, tag, signing,
  package submission, or remote-agent launch is authorized.
- Windows physical evidence: reserved for a later operator-dispatched Windows hat.
  Linux implementation may become `linux_ready`; it cannot become Windows or full
  native acceptance.
- Epic 002 disposition: **closed unsuccessful; failed candidate rejected;
  restoration verified**. Frozen source
  `b3eb47e08817045f9371703d780ada9aab00995d`, run
  `v1-20260904-od3-b3eb47e`, sampled for the full six hours. Debian and Alpine
  passed 14/14 with 361/361 Bluefin reads and exact cleanup. Bluefin served all
  1,083 reads and restored Pond/firewall/service state exactly. Windows passed
  12/14 and all 361 reads but failed handle growth (`+1329`, limit 16) and thread
  growth (`+280`, limit 8); issue 004 assigns the diagnosed DNSAPI PTR-owner defect
  to R03 after activation. Windows removed run residue and preserved configuration,
  policy, artifact, service, workbench, provider, and disabled-Pond identity, but its
  live service process remained resource-elevated until the final cleanup. Windows
  journal entry 25 at `b18302b` proves one SCM restart to PID `24100` and two
  observations at 340/62 and 342/63 handles/threads, below the required 364/75
  envelope, with exact artifact/state and recovery-task removal. R01 is now
  `accepted/ready`. This restoration does not fix issue 004 or accept the failed
  candidate; R03 retains the correction and later Windows native evidence.

## Binding architecture

[ADR-044](../../adr/044-service-experience-ownership.md) is the durable decision.
[ADR-043](../../adr/043-observable-domain-boundaries.md) remains binding for command,
state, event, revision, cancellation, and lifecycle semantics. ADR-040 owns local
operator control, ADR-042 owns Pond, and STACK-0001 owns layering and frozen protocol
constraints.

The invariant is:

```text
domain facades own mutation and authoritative state
                  │
                  ▼
koi-compose owns explicit cross-domain projection/coordination
                  │
                  ▼
koi-serve owns transport and authorization adaptation
                  │
                  ▼
one Rust presentation boundary owns user language and components
```

No frontend reconstructs domain truth. No transport contains business rules. No
domain reads another domain's repository. No global service locator, workflow engine,
or event bus is introduced.

## Exact owner and path map

| Concern | Authoritative owner and path | State/transport consumers | State |
| --- | --- | --- | --- |
| Shared service vocabulary | `koi-common::service`, `crates/koi-common/src/service.rs` | compose, serve, client, UI, SDK/MCP | proposed, R04 |
| Raw DNS-SD record | `koi-common::types::ServiceRecord` | mDNS protocol and evidence | existing; not a catalog identity |
| Installation identity | `koi-config::installation`, `crates/koi-config/src/installation.rs`; `state/installation.json` | self-announcement and catalog | proposed, R04/R11 |
| Source-scoped mDNS evidence | `koi-common::integration::{MdnsDiscoverySnapshot, MdnsDiscoverySource, MdnsDiscoveryObservation}`, `crates/koi-common/src/integration.rs`; snapshot fields `sources` and `observations` | catalog, DNS, Health | existing; R03 complete, additive compatibility fields retained |
| Authoritative service catalog | `koi-compose::catalog::ServiceCatalogRuntime`, `crates/koi-compose/src/catalog.rs` | `KoiStatus.catalog`, serve, embedded | proposed, R04 |
| Durable personal preferences | `koi-preferences::PreferencesCore`, `crates/koi-preferences/src/lib.rs`; repository in `repository.rs`; `state/preferences.json` | catalog joins its status | proposed, R05 |
| Local service candidates | `koi-runtime::local_candidates`, `crates/koi-runtime/src/local_candidates.rs`; `LocalServiceSource` port | catalog and sharing | proposed, R16 |
| Linux candidate adapter | `crates/koi/src/platform/local_services/linux.rs` | injected into runtime | proposed, R16/linux |
| Windows candidate adapter | `crates/koi/src/platform/local_services/windows.rs` | injected into runtime | proposed, R16/windows |
| Sharing intent/receipts | `koi-compose::sharing::SharingRuntime`, `crates/koi-compose/src/sharing.rs`; `state/shares.json` | serve/client/UI | proposed, R17 |
| Plain/TLS forwarding | `koi-proxy` facade; proposed `ProxyTransport` and `ProxyEntryScope::Share` in `crates/koi-proxy/src/lib.rs` | sharing and secure setup | existing TLS owner, extended R17/R21 |
| Share firewall effect | proposed `ShareFirewall` port in `crates/koi-common/src/integration.rs`; native adapters under `crates/koi/src/platform/share_firewall/` | sharing coordinator | proposed, R17 native rows |
| DNS service name | `koi-dns` facade/scoped desired set | sharing and secure setup | existing owner, extended R17/R21 |
| mDNS advertisement | `koi-mdns::MdnsCore` registration session | runtime/sharing/secure setup | existing |
| URL diagnosis | `koi-compose::diagnosis::ServiceDiagnosis`, `crates/koi-compose/src/diagnosis.rs` | serve/client/CLI/UI | proposed, R19 |
| Service-name certificate grant | `koi-certmesh::service_names`, `crates/koi-certmesh/src/service_names.rs` | secure setup | proposed, R20 |
| Leaf issuance/renewal | `koi-certmesh` facade and repository | proxy TLS identity input | existing owner, extended R20 |
| Secure setup intent/receipts | `koi-compose::secure_service::SecureServiceRuntime`, `crates/koi-compose/src/secure_service.rs`; `state/secure-services.json` | serve/client/UI | proposed, R21 |
| OS trust roots | `koi-trust::TrustCore` | secure/client setup | existing |
| HTTP/SSE adapters | focused `catalog.rs`, `preferences.rs`, `sharing.rs`, `diagnosis.rs`, `secure_service.rs` under `crates/koi-serve/src/` | all HTTP callers | proposed, owning feature tasks |
| Typed client adapters | `crates/koi-client/src/lib.rs`, split by R25 if touched size requires | CLI, desktop, SDK/MCP | existing owner, extended R05/R17/R19/R21 |
| Local operator bootstrap | `crates/koi-serve/src/local_ipc/` and `koi-common::local_control` | local CLI/desktop | existing; not duplicated |
| Public Pond catalog | `koi-serve` allowlisted `PublicCatalogSnapshot` projector | Pond only | proposed, R09 |
| User language/components | `crates/koi-ui/`; exact renderer/component files fixed once by R06 | desktop/headless/Pond builds as permitted | proposed boundary; R06 decision pending |

`koi-compose::cores::PersistencePaths` adds exact paths for installation identity,
preferences, shares, and secure services and passes each owner only its own path.
Catalog observations and diagnosis reports are not durable repositories.

### Startup and shutdown order

`build_cores` owns the following deterministic order:

1. resolve `PersistencePaths`, open or create the installation identity, and recover
   Preferences, Sharing, and SecureService repositories before accepting commands;
2. construct domain facades and source adapters;
3. subscribe catalog/coordinator watchers before reading their initial snapshots, then
   reconcile the retained current values;
4. resume admitted share/secure intents and transfer every background task immediately
   to `RunningCores`' non-cloneable lifecycle owner;
5. acquire serving transports; only then publish ready/self-announcement state.

Terminal shutdown first closes coordinator admission, then drains or aborts bounded
diagnosis/probe work, stops source watchers, settles admitted share/secure commands,
reverses only non-durable run-owned leases, and finally follows the existing ordered
domain shutdown. Active durable share/secure desire is not interpreted as a request to
unshare during daemon shutdown; its owned resources converge again on restart. Explicit
Stop is the only operation that durably changes that desire and performs full reversal.
`ServiceDiagnosis` is request-scoped and owns no task after its bounded result returns.

## Shared service vocabulary

The following names and semantics are fixed. R04 may add fields needed by
implementation, but may not collapse the distinctions.

### IDs and schema

All IDs are opaque lowercase strings in JSON and Rust newtypes in
`koi-common::service`. New locally owned identities use complete UUIDv7 values;
derived observation keys use a versioned SHA-256 canonicalization defined beside the
catalog. Consumers never parse an ID for display or authority.

```rust
InstallationId(String) // durable, non-secret, one Koi installation
DeviceId(String)       // stable only when backed by explicit identity evidence
ServiceId(String)      // stable application/service identity
EndpointId(String)     // one normalized access target
ObservationId(String)  // one source-owned evidence identity
OperationId(String)    // durable share/secure operation identity
NetworkScopeId(String) // opaque scope within the catalog contract
```

Every top-level stored/wire value carries `schema: u32`. Schema 1 accepts unknown
additive fields but rejects a missing required field and an unknown newer schema when
that schema changes interpretation. Stored future schemas open read-only with
`unsupported_schema`; they are never treated as empty.

### Device

A Device is a catalog grouping supported by device-identity evidence. It is not
synonymous with hostname, IP address, CertMesh member, or permission.

- `id`: stable only when an installation ID, source-owned machine ID, or authenticated
  identity supports it; otherwise an epoch-scoped observed ID.
- `names`: observed display/host names with provenance, never a single overwritten
  truth.
- `addresses`: scoped observed addresses; IPv6 link-local values retain zone/interface.
- `koi_presence`: absent, observed, or identified by an `InstallationId`.
- `mesh_identity`: open, member, authenticated, unhealthy, or unknown, with evidence.
- `condition`: present, stale, absent, or ambiguous.

Mesh identity may strengthen correlation. It does not authorize an action and does not
prove application reachability or browser trust.

### Service

A Service is one application/API/resource a person may use, possibly supported by
several advertisements and endpoints.

- `id`, `device_id`, `display_name`, optional user `alias`, and `kind`;
- `condition`: `starting`, `found`, `responding`, `not_responding`, `absent`,
  `stale`, or `ambiguous`;
- `endpoints`, `observations`, latest `checks`, and `available_actions`;
- `favorite`, `local_only`, `managed`, and optional active operation summaries;
- `identity_confidence`: explicit, correlated, observed, or ambiguous.

`responding` requires unexpired `CheckEvidence`; an advertisement alone yields at
most `found`. Security is expressed in endpoint/check evidence, never a single
`trusted` boolean.

### Endpoint

An Endpoint is a normalized destination, not proof it works:

- scheme/protocol, host or scoped IP, port, optional path, network scope;
- source observation IDs and owner (`foreign`, domain, share operation, secure
  operation);
- `browser_usable`, transport encryption, expected service name, and authority needs;
- current reachability and client-TLS evidence by observer.

Unknown TCP listeners never receive `Open`. HTTP(S) endpoints with validated syntax may
offer Open; Ollama and other API-only services offer Copy API address or a typed client
action rather than a pretend browser UI.

### Observation

An Observation is a source claim with:

- stable observation ID and kind (`mdns`, `dns`, `runtime`, `local_listener`,
  `share`, `proxy`, `health`, `certmesh`, or `manual`);
- source/provider identity and source-local revision/generation;
- network scope, observer installation/device, `observed_at`, `valid_until`, and
  state (`current`, `withdrawn`, `stale`, `source_unavailable`);
- raw reference sufficient for advanced detail, without secret process environment or
  private-key material.

Explicit withdrawal is a fact. Loss of the source/watch is not withdrawal; it retains
the last observation as stale until bounded expiry.

### CheckEvidence

A CheckEvidence value states one performed check:

- `kind`: name resolution, TCP connect, HTTP response, backend health, proxy listener,
  firewall assessment, certificate SAN/expiry, OS root presence, or client TLS;
- observer and client identity, target endpoint, timestamp, deadline/timeout,
  `valid_until`, result (`passed`, `failed`, `unknown`, `not_run`), and stable reason
  code;
- optional safe technical detail and the source revision used.

`unknown` and `not_run` are values, not success. Daemon checks never become phone or
browser evidence. Recovery is reported only after the relevant check passes again.

### AvailableAction and authority

Available actions are derived from current facts and caller capability:

| Action | Minimum authority | Notes |
| --- | --- | --- |
| `open`, `copy_endpoint`, `view_details` | read projection | only when endpoint semantics permit |
| `favorite`, `set_friendly_alias`, `dismiss_candidate` | local operator + DAT | personal intent only |
| `diagnose` | local operator + DAT | read-only bounded probes |
| `share`, `stop_sharing` | local operator + DAT + applicable native authorization | durable operation |
| `set_up_secure_access`, `stop_secure_access` | local operator + DAT + applicable native authorization | durable operation |
| `install_root`, `join_device`, `repair_identity` | explicit domain/OS authorization | never implied by discovery |

Pond receives only the first row. A remote connection presenting the DAT may receive
permitted protected reads, but preference, share, secure-setup, and remedy mutations
fail with `local_operator_required`.

## Correlation, network scope, and conflicts

### Correlation precedence

The catalog evaluates evidence in this order:

1. equal explicit Koi `InstallationId`/`ServiceId`;
2. equal source-owned runtime or operation ID under the same installation;
3. equal proven Device plus identical normalized endpoint and compatible service kind;
4. otherwise keep separate.

High-confidence disagreement stops correlation and sets `ambiguous`; low-confidence
name/TXT similarity may be displayed as a suggestion but never changes identity.
Neither IP reuse, hostname reuse, display name, service type, nor port alone transfers a
favorite or operation.

### NetworkScope

`NetworkScope` contains family, interface identity, local address/prefix, route source,
and classification (`loopback`, `private`, `link_local`, `public`, `unknown`). Provider
scope is retained when available. An IPv6 link-local endpoint without a usable zone is
not openable. Scope IDs are opaque; only the structured value decides eligibility.

The first share supports one explicitly selected private IPv4 interface/CIDR. Public,
unknown, guest-isolated, or multi-interface scope returns a typed precondition instead
of broadening automatically. IPv6 share remains unsupported until R17 supplies an
equivalent scoped-firewall and client-verification path; observation/display still
retains IPv6 correctly.

### Name and port conflict

Preflight normalizes the requested `.internal` label, checks DNS ownership, probes the
selected bind address/port, and returns the exact proposed result before commitment.
A Koi receipt with the same operation/generation is idempotent. A foreign or different
Koi owner produces `name_conflict` or `port_conflict` plus safe alternatives. The
operation never silently takes over, deletes, or shifts a reviewed endpoint. A race
after preflight settles in retained error state and may be retried with a newly reviewed
target.

## Catalog revision, freshness, and retention

`CatalogSnapshot` has:

```json
{"schema":1,"epoch":"0199...","revision":42,"generated_at":"...","devices":[],"services":[],"local_candidates":[]}
```

- `epoch` is a new process-instance UUID. `revision` starts at zero and increases only
  on semantic change within that epoch.
- Clients accept coalescing. On a new epoch, gap, lost subscription, decode error, or
  stale revision, they refetch the whole snapshot.
- Domain revisions are causal input hints and remain incomparable across domains or
  restart.
- Explicit removal updates immediately. Source loss marks retained evidence stale for
  at most ten minutes. Stale evidence cannot enable Open or complete an operation.
- Bounds: 4,096 services; 16 observations and 32 current check records per service.
  Eviction is deterministic oldest-stale-first, then oldest-unpreferred inactive.
  Active operation targets and favorites retain one bounded summary, not raw history.
- Terminal share/secure receipts retain the latest 32 of each kind for 30 days. Active
  intent remains until safely stopped or explicitly abandoned after recovery.

The owning modules co-locate these constants. Domain/catalog timers perform expiry and
publish status; UI clocks do not mutate meaning.

## Durable preferences

`PreferencesStatus` carries its own epoch/revision and these schema-1 records:

```json
{
  "schema": 1,
  "expected_revision": 7,
  "service_key": {"kind":"koi_service","id":"svc_0199..."},
  "favorite": true,
  "friendly_alias": "Workshop dashboard"
}
```

Dismissal keys use a stable candidate recognizer/source key, not a port or display name
alone. Commands use optimistic `expected_revision`; a mismatch returns
`stale_revision` and the current revision. The owner atomically commits, publishes
status, emits its semantic event, then acknowledges. A no-op does none of those.

An absent favorite retains: stable key, friendly alias, last safe display name/device,
last condition, and last-seen time. It excludes raw TXT, private diagnostics, local
process details, DAT, invitations, keys, and receipts.

## Sharing operation

The supported schema-1 input is one candidate/service, one reviewed name/address/port,
one private network scope, and `mode: "plain_http"`. Authentication truth is explicit:
the first Ollama/API path is unauthenticated to permitted network clients unless the
application itself authenticates.

The durable lifecycle is:

```text
planned -> applying -> locally_ready -> peer_verification_pending
        -> verified
        -> stopping -> stopped
        -> recoverable_error
```

Before the first external effect, `SharingRuntime` commits intent with a unique
operation/generation. It then converges, in order, only the needed resources:

1. a Proxy-domain plain TCP forwarder for a loopback backend, or a foreign/direct
   reachability receipt when no Koi listener is needed;
2. a DNS-domain scoped `.internal` name;
3. an mDNS session advertisement appropriate to the actual endpoint;
4. a native firewall rule scoped to the selected private interface/CIDR and exact port;
5. local backend/listener/name checks;
6. an independent peer resolution and application request.

Each resource receipt identifies owner, external native ID, exact scope, prior
ownership, generation, and reversal command. `verified` requires step 6. Publication
without it remains `peer_verification_pending`; it is not renamed success.

Stop first commits desire=false, fences the generation, withdraws/reverses only owned
receipts in reverse dependency order, verifies the Koi path is gone, preserves the
original local application, then commits `stopped`. A known foreign path is reported as
possibly still reachable. Cancellation drops a waiter only. Process startup loads
active intent and resumes convergence before accepting a duplicate operation.

## Diagnosis

`ServiceDiagnosis::run` accepts either a `ServiceId` or an explicit `http`/`https` URL.
It rejects userinfo, fragments, unsupported schemes, unbounded redirects, oversized
responses, and remote generic-proxy use. It checks only applicable layers with bounded
time/concurrency:

1. catalog/source freshness and identity ambiguity;
2. Koi DNS result and, where the named observer supports it, OS/client resolution;
3. scoped TCP connection and firewall assessment when evidence exists;
4. TLS leaf validity, SAN, expiry, issuer/root evidence, and named-client verification;
5. proxy listener and backend health.

The result is a list of `CheckEvidence` plus at most two contextual
`AvailableAction`s. A timeout is `unknown` unless the firewall owner supplies direct
evidence. The read-only command never installs roots, changes DNS/resolvers/firewall,
opens a listener, or disables TLS verification. Mutating remedies are separate typed
commands with their own authority and receipts.

## Secure-service operation

The only first-class secure path selected by R01 is host TLS termination:

```text
existing backend
  -> authorized unique <service>.internal name
  -> CertMesh leaf whose SAN covers that exact name
  -> Koi Proxy TLS listener on reviewed private address/port
  -> scoped DNS/mDNS/firewall resources
  -> backend and local TLS checks
  -> named second-client resolution + ordinary TLS validation
```

`SecureServiceRuntime` persists its own operation ID, desired URL, prerequisite state,
and receipts. It reuses R17 receipt vocabulary but has a specific state machine rather
than a generic workflow. Private keys remain in CertMesh/Proxy host custody. Existing
valid names, roots, and listeners are referenced as foreign/pre-existing receipts and
never removed by Stop.

Progress separately reports name granted, consumer resolution unknown/passed, issuer
available, leaf issued/reloaded, listener running, backend responding, client root
pending/present, and client TLS unverified/verified. Setup may return one explicit user
step for resolver adoption or root installation, including intended URL, public root
fingerprint, and verification target. It never recommends `-k`, disables validation,
or calls root installation proof of HTTPS success.

Unauthorized SANs/wildcards are rejected. Name/port conflicts settle as retained typed
errors. Issuance/reload failure preserves the last accepted usable material. Stop
removes only operation-owned name/publication/listener/firewall resources and does not
destroy mesh membership, foreign roots, unrelated proxy entries, or the backend.

Per-workload private-key delivery, arbitrary browser support, public certificates,
identity-aware access enforcement, and automatic root rollout to phones/appliances are
not part of this path.

## Typed errors and HTTP mapping

Existing `ErrorCode` values remain in use where exact (`invalid_payload`, `not_found`,
`conflict`, `invalid_auth`, `scope_violation`, `provider_unavailable`,
`shutting_down`, `internal`). R04/R05 add these service-contract codes to
`koi-common::error::ErrorCode` and its exhaustive mapping tests:

| Code | HTTP | Meaning |
| --- | --- | --- |
| `local_operator_required` | 403 | authenticated caller is not on the local operator boundary |
| `stale_revision` | 409 | optimistic command revision lost; current revision returned |
| `unsupported_schema` | 409 | stored/client contract cannot be safely interpreted |
| `identity_ambiguous` | 409 | action requires one service/device but evidence conflicts |
| `name_conflict` | 409 | reviewed name belongs to another owner |
| `port_conflict` | 409 | reviewed bind is occupied by another owner |
| `network_scope_unavailable` | 422 | requested private scope cannot be enforced |
| `verification_pending` | 202 | local effect exists but required peer/client proof does not |
| `recovery_required` | 503 | durable intent exists and convergence/rollback needs retry |

Operation responses also carry `operation_id`, state, retryability, current snapshot
revision, and safe next action. Message text is descriptive; clients branch only on
the typed code/state.

## HTTP, SSE, IPC, and public routes

All full routes live on the existing operator HTTP adapter and use schema-1 DTOs.

| Method/path | Authority | Owner invoked |
| --- | --- | --- |
| `GET /v1/catalog` | loopback or remote DAT | catalog snapshot |
| `GET /v1/catalog/events` | DAT on every peer | best-effort SSE; refetch on gap |
| `GET /v1/preferences` | loopback + DAT | PreferencesCore status |
| `PUT /v1/preferences/services/{service_id}` | loopback + DAT | favorite/alias command |
| `PUT /v1/preferences/candidates/{candidate_id}` | loopback + DAT | dismissal command |
| `GET /v1/shares` | loopback + DAT | SharingRuntime status |
| `POST /v1/shares` | loopback + DAT | reviewed Share |
| `DELETE /v1/shares/{operation_id}` | loopback + DAT | Stop sharing |
| `POST /v1/diagnosis` | loopback + DAT | bounded read-only diagnosis |
| `GET /v1/secure-services` | loopback + DAT | SecureServiceRuntime status |
| `POST /v1/secure-services` | loopback + DAT | reviewed secure setup |
| `DELETE /v1/secure-services/{operation_id}` | loopback + DAT | owned cleanup |

Pond may mount `GET /v1/catalog` on its separate listener only after R09 supplies an
explicit `PublicCatalogSnapshot`. That route is not the operator DTO and has no SSE or
mutation siblings.

The local IPC protocol continues to authenticate the OS principal and return
`LocalDaemonAccess { endpoint, token, data_root }`. Desktop/CLI then use these HTTP
routes. No second IPC catalog protocol is added. Explicit remote endpoints never gain
local-only mutations even with a DAT.

## Serialized acceptance examples

These examples pin semantics; exact additive presentation fields may grow.

### Duplicate advertisements correlate by proven endpoint/device

Input observations:

```json
[
  {"schema":1,"id":"obs_a","kind":"mdns","device_id":"dev_koi_1","name":"Grafana","service_type":"_http._tcp.local.","endpoint":{"scheme":"http","host":"grafana.local","port":3000},"state":"current"},
  {"schema":1,"id":"obs_b","kind":"runtime","device_id":"dev_koi_1","source_id":"docker:4d2","endpoint":{"scheme":"http","host":"grafana.local","port":3000},"state":"current"}
]
```

Output excerpt:

```json
{"schema":1,"services":[{"id":"svc_0199...","device_id":"dev_koi_1","identity_confidence":"correlated","source_ids":["obs_a","obs_b"],"condition":"found","available_actions":["open","diagnose"]}]}
```

The same display name on `dev_koi_2` remains another service.

### Uncertain identity stays separate

```json
{"schema":1,"services":[{"id":"svc_epoch_a","display_name":"Printer","identity_confidence":"ambiguous","condition":"ambiguous","ambiguity":{"reason":"conflicting_hosts","candidates":["hall.local","office.local"]},"available_actions":["view_details"]}]}
```

No Open, favorite transfer, share, or secure action is enabled until one identity is
selected or stronger evidence arrives.

### Absent favorite survives restart

```json
{"schema":1,"epoch":"0199-new-process","revision":3,"services":[{"id":"svc_0198...","display_name":"Workshop dashboard","favorite":true,"condition":"absent","last_known":{"device_name":"bench","last_seen":"2026-09-03T21:10:00Z","kind":"web"},"endpoints":[],"available_actions":["view_details"]}]}
```

A new `Workshop dashboard` advertisement with another stable ID does not inherit it.

### Publication without peer verification

```json
{"schema":1,"operation_id":"op_0199...","kind":"share","state":"peer_verification_pending","desired_url":"http://ollama.internal:11434/","resources":{"forwarder":"owned","dns":"owned","mdns":"owned","firewall":"owned"},"checks":[{"kind":"backend_health","result":"passed","observer":"this_installation"},{"kind":"peer_http","result":"not_run","observer":"peer_required"}],"available_actions":["stop_sharing","check_again"]}
```

This is not `verified` and does not claim another device can call it.

### Remote operator mutation is forbidden

```json
{"request":{"method":"POST","path":"/v1/shares","peer":"192.168.1.44","dat":"valid"},"response":{"status":403,"body":{"error":"local_operator_required","message":"Sharing can only be changed from this machine."}}}
```

The same caller may use only separately authorized read projections.

### Process restart resets epoch, not identity

```json
{"before":{"epoch":"0199-a","revision":88,"service_id":"svc_0198..."},"after":{"epoch":"0199-b","revision":2,"service_id":"svc_0198..."},"client_action":"replace_from_full_snapshot"}
```

Revision 2 is not older than 88 because epochs differ. Active durable operations resume
under their original operation IDs.

### Old/future schema handling

```json
{"stored":{"schema":2,"favorites":[]},"running_contract":1,"result":{"error":"unsupported_schema","mode":"read_only","data_replaced":false}}
```

Legacy schema 0 is migrated only through the owning tested importer with backup and
atomic replacement; an unknown future schema is never reset.

## Migration and compatibility

- Task-oriented CLI/API organization may replace current domain-first primary flows.
  Advanced domain commands remain directly reachable until their replacement path is
  accepted; long-lived duplicate primary experiences are removed before R29.
- R05 migrates desktop `localStorage["koi-watched"]` only for unambiguous stable-key
  matches. It writes a backup before the schema-1 preference commit. Unmatched values
  remain available for manual review and do not bind by display name.
- Installation ID is created once for an existing data root and then retained across
  upgrade/reinstall. It is removed only by an explicit purge/factory reset whose scope
  is shown to the user.
- Preferences, active share/secure intent, CertMesh identity/keys/certificates,
  Koi-managed roots, DNS/proxy operator config, and unrelated native configuration are
  preserved or migrated transactionally. No interface rewrite authorizes their loss.
- Frozen HKDF/protocol labels in STACK-0001 remain byte-identical. New algorithms get a
  new versioned label.
- Mixed desktop/daemon versions use schema negotiation. Unsupported semantics produce
  `unsupported_schema` with minimum/maximum supported versions; they do not silently
  omit mutations or display empty success.
- Every intentional route/CLI removal is listed in R30 release changes. Compatibility
  adapters are bounded to the migration window and removed after their stored data and
  supported clients have moved.

## Journey and native/client matrix

The matrix separates evidence already held by the project from Epic 003 target
acceptance. It is not a claim that the new service experience exists.

| Surface | Current evidence entering R01 | Epic 003 requirement |
| --- | --- | --- |
| Windows SCM | OD-3 six-hour resource gate failed; candidate rejected; final SCM restoration passed at `b18302b` | R03 correction and native resource proof; install/catalog/share/secure source plus later Windows physical proof |
| glibc systemd (CachyOS/Debian) | exact installed lifecycle/local control/mDNS/Pond and short collectors accepted | fresh install, catalog, sharing, secure path, candidate rerun |
| immutable Fedora/Bluefin | exact frozen systemd candidate and packaged desktop ready | recommended immutable install + desktop/headless journey |
| musl OpenRC/Alpine | exact APK/OpenRC six-hour collector passed 14/14 with restoration | daemon/headless catalog, sharing where supported, package/candidate rerun |
| Plasma/GNOME desktop | installed workbench/tray/startup evidence on recorded artifacts | one R06-selected shared Rust UI and complete user journeys |
| headless web | daemon/Pond read-only evidence | full local operator web where authenticated plus bounded Pond projection |
| mDNS providers | Avahi, resolved/native, OpenRC native and Windows DNS-SD evidence on recorded artifacts | automatic second-machine browsing + publication + resolution on final candidate |
| macOS | no current physical acceptance | unverified; no release support claim without explicit evidence |

First-class journeys are: fresh install to useful catalog; automatic second-machine
presence; ready container to usable service; deliberate local HTTP/API Share and Stop;
host-terminated secure service to a named second-client HTTPS verification; URL
diagnosis and recovery; daily find/open/favorite; advanced raw access; and contributor
bounded change/test flow.

The secure client minimum for acceptance is one named ordinary browser on Windows and
one named system-TLS native client on Linux, each verified by R22 against then-current
official trust behavior. Other browsers/runtimes remain unverified until their own
evidence exists. R01 deliberately does not assume every browser uses the OS store.

## R06 presentation handoff

R06 owns exactly one pending architectural decision: the renderer, component/source
map, asset pipeline, and reproducible build/test commands rooted at `crates/koi-ui/`.
It must measure Windows, glibc, musl, desktop lifecycle, offline packaging, and headless
web behavior before choosing. R01 does not choose Dioxus, retain Tauri by default, or
authorize a JavaScript-owned product state model.

Whichever renderer wins, the presentation boundary owns everyday copy and the shared
Home/Devices/Settings/About components. It consumes typed catalog/actions/errors; it
does not infer status or embed domain mutations. The original Koi asset, source Sylin
tokens, keyboard/focus/reduced-motion behavior, and a usable 320px layout remain R06
acceptance requirements.

## Assessment finding disposition

| Finding | Contract disposition | Implementing owner/task |
| --- | --- | --- |
| D01 recovery policy/deadlines | R02 retired fixed 90/30/14 advice: new meshes default to 7/3/1, persisted policy and earliest actual `cert_expires` drive guidance, and grace authorizes renewal without extending TLS validity; CheckEvidence remains R23 | Bluefin R02 complete; Debian R23 later |
| D02 certificate names/client trust | R02 records current hostname plus configured-zone SANs, the v0.9.0 `.local` behavior, exact `cert_sans`, and per-client root/resolver verification; authorized service aliases and named second-client proof remain later work | Bluefin R02 complete; Debian R20-R22 later |
| D03 route/auth documentation | R02's tested route/auth matrix proves public bootstrap/trust, DAT-protected remote full status and mutations, the narrow invite/TOTP enrollment exception, and separate Pond/mTLS/ACME authorities | Bluefin R02 complete; R05/R09 later, R28 contract job |
| D04 discovery type pollution | R03 fixes the Windows DNSAPI linked-result owner mismatch at the provider boundary, preserves valid unknown/base/subtype types and escaped labels, and exposes query/provider/generation/availability separately from facts; UI filtering remains forbidden | Debian R03 complete; R04/R14 consume the corrected evidence |
| D05 candidate/hosted CI gap | R28 binds exact source, required hosted results and the six-target manifest in ADR-025's schema-1 report; source-only results keep native fields pending | Alpine R28 infrastructure, CachyOS/native hats R29 acceptance |
| D06 installer next-action mismatch | R02 labels bootstrap as binary-only and prints an executable full-path standalone discovery action; stable v0.9.0 and prerelease v1.0.0-rc.2 fixtures run it without a daemon, while durable service/catalog completion remains R11-R14 | Bluefin R02 complete; Alpine/Bluefin R11-R14 later |
| D07 no-match vs no-discovery | snapshot carries source availability, empty, absent favorite, and search state separately | CachyOS R07/R27 |
| D08 accessibility | shared UI contract reserves focus/keyboard/narrow/reduced-motion evidence | CachyOS R06-R09/R27 |
| D09 misleading workload certification | R02 states `koi.certmesh` is parsed request metadata only, not workload-certificate injection; secure host termination and client proof remain separate | Bluefin R02 complete; Alpine/Debian R15/R20-R22 later |
| D10 revocation scope | R02 distinguishes immediate Koi CA/principal and signed-bundle enforcement from ordinary TLS clients without CRL/OCSP, which may accept a leaf until its actual `NotAfter` | Bluefin R02 complete; Debian/Bluefin R20/R23/R26 later |

Other mandate mappings: catalog collapses overlapping Discover/Browser only when
evidence supports identity; Home replaces Glance noise; comparison has an explicit
not-run state; CA/member/Open remain typed dimensions; R06 owns Rust/source visual
language; R11-R14 own sane install and second-machine presence; R16-R18 own local
suggestion/share; R19/R23-R24 own diagnosis/recovery/integration completion; R25-R26
own CLI/SDK/MCP/embedding/contributor compatibility; R27/R29-R30 measure delight from
actual task outcomes.

## Change control and next action

Later tasks update only their relevant section and exact path as implementation lands.
A consumed contract change must include rationale, affected R rows, migration impact,
and repeated checks. R06 may fill only its presentation decision. No task silently
renames an owner or creates a parallel model because a proposed path is not yet present.

Implementation verification must add strict serde round trips for every new schema-1
type, exhaustive error-code/HTTP mappings, epoch/revision reset cases, deterministic
correlation and eviction fixtures, repository interruption/migration tests, local-versus-
remote authorization tests, and retained-owner cancellation/shutdown tests. Native and
second-client evidence remains separate from those repository tests.

Current next action: Bluefin claims R02, Debian claims R03 including issue 004,
and Alpine claims R28 through `fleet/task.md` and the ledger. CachyOS R06 waits for
R05. Windows's inherited cleanup is complete; future Windows physical proof awaits
its operator dispatch. No second six-hour soak is scheduled.
