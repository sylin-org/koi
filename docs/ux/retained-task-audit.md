# Retained tasks and the mDNS inspector

Owner correction: 2026-09-13. This audit records the task gap found after the
single-interface deployment. [The launch ledger](../../fleet/launch/LEDGER.md)
owns execution status. ADR-047 remains the presentation constraint.

## User tasks

These are product hypotheses and acceptance scenarios, not evidence of recruited
users or demand. One person may perform several of them.

| Profile | Task | Required outcome |
| --- | --- | --- |
| Network inspector | Understand what the local mDNS provider reports and investigate a missing service | Browse reported service types and instances, inspect TXT and endpoint facts, issue supported queries, and understand observation limits and failures without container or Certmesh setup. |
| Application operator | Find and reach an application | Use the catalog's actual eligible endpoints, retain personal intent, and distinguish discovery from reachability and recovery. |
| Application developer | Discover or publish services through Koi | Use predictable CLI/API/embedded contracts and inspect their results through restart, withdrawal and reconnection. |
| Identity administrator | Manage identities for participating machines and applications | Understand Certmesh role, authority, membership, renewal and recovery with honest permission and trust boundaries. |

The container-to-LAN scenario remains the release focus. Existing useful
inspection tasks remain regression obligations even when they are outside that
scenario's activation metric.

## Gap found in the preceding deployment

The [retention plan](single-ui-plan.md) promised Services → Network evidence.
The installed source baseline's shared renderer instead accepted a composed
service catalog and offered no complete mDNS browser, active query control or
full TXT inspection. Catalog search matched names, hosts and endpoints; it did
not issue an mDNS query. The catalog is not limited to HTTP services, but it
omits type-only observations and cannot replace the domain discovery projection.

The discovery behavior also changed: the browser adapter's lazy all-type worker
was retained, but the shared shell read composition status without touching its
browse demand. Opening or refreshing Services therefore did not initiate the
old browse-all behavior. Browser snapshot/event/query APIs and CLI discovery,
ping, resolution and subscription remained available.

The old HTML browser's local text filter must not be described as an arbitrary
DNS question interface. Supported query operations have separate semantics:
browse a service type, resolve a full service instance, or restart the all-type
browse. A restart acknowledgment is not evidence that a response was received.

## Acceptance for the restored task

The shared renderer contains visible **Services** and **mDNS** destinations.
Services presents the normalized catalog; mDNS presents network evidence and
queries as its own technical task.
The mDNS view consumes the existing authoritative discovery projection and
bounded browser read model. It does not establish a second service inventory.

1. Starting from idle discovery, enter mDNS and observe actual browse demand.
   Subsequent updates retain filters, expanded details, focus and pending input.
2. Inspect reported types even when they have no resolved instances; inspect
   non-HTTP and unresolved instances, full names, host/IP/port and every TXT
   entry supplied by the source. Display provider/query availability and
   provenance where supplied, without fabricating packet-level evidence.
3. Distinguish local filtering from an active query. Exercise all-type requery,
   a valid typed browse, full-instance resolution, malformed input, no answer,
   and provider/daemon failure. Preserve observed results and label their scope.
4. Show current observations and bounded withdrawal history honestly. Adapter
   first/last-seen timestamps do not prove packet arrival time or TTL freshness.
5. Stop view polling on exit and retain the existing owned idle/cancellation
   lifecycle. Reconnect from authoritative state after a lost update.
6. Verify hostile names and TXT remain text. Keep DAT private and operations
   bounded. Pond receives its existing allowlisted public projection and no
   query controls or new operator observations.
7. Exercise the actual browser/native adapters as well as fixture rendering.
   Check 1280×800 density and 390/320px reflow, keyboard operation and readable
   failure feedback. Distinguish isolated browser evidence, installed API
   evidence and a directly observed installed native walkthrough.

## Remaining retention checks

The following source gaps were also visible in the initial audit. This mDNS
slice does not silently close them or claim that it implements them:

| Promised retained task | Initial source finding |
| --- | --- |
| Services → Compare observations | No shared comparison view or bounded peer-comparison action was found. |
| Settings → Diagnostics → Recent activity | Capability summaries exist; the promised recent activity/event view was not found. |
| Settings → Names & DNS, temporary TXT | Static-name add/remove exists; the shared temporary TXT controls were not found. |
| Native installation controls with daemon unavailable | The native read failure rendered the unavailable shell without the host projection needed for service controls. |

These are source findings, not live acceptance failures from disposable
scenarios. Certmesh retained operations, upgrade data migration and the other
plan rows still need their own relevant task evidence. An agent review or a
passing renderer suite does not count as independent U06 operator observation.

Every future consolidation receipt should pair a removed task with its concrete
replacement and an exercised outcome, or with the owner's explicit removal
decision. Source deletion and successful installation alone cannot establish
retained-task completeness.
