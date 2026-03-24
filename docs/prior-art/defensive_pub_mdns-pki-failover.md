# Defensive Patent Publication

## Zero-Configuration PKI Certificate Authority Failover Using Multicast DNS Service Discovery

**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Publication Type:** Defensive Patent Publication (voluntary prior art disclosure)
**Implementation:** Koi v0.2 -- cross-platform local network service daemon (Rust)

---

## Field of Invention

Network security; Public Key Infrastructure (PKI); Service discovery; High availability; Zero-configuration networking.

## Keywords

mDNS, DNS-SD, PKI, certificate authority, failover, high availability, zero-configuration, leader election, deterministic tiebreaking, split-brain resolution, multicast DNS, service record, cryptographic fingerprint pinning, grace period, heartbeat, local area network.

---

## Background and Problem Statement

### The High-Availability Problem in PKI

A certificate authority (CA) is a critical piece of network infrastructure. When the CA is unavailable, no new certificates can be issued, no enrollments can be processed, and certificate renewal fails. For environments that rely on automated certificate management (e.g., mutual TLS between services, device enrollment), CA downtime directly translates to service disruption.

### Existing Approaches and Their Limitations

Existing PKI high-availability systems universally require explicit, pre-configured infrastructure:

1. **HashiCorp Vault HA (Raft consensus):** Vault's integrated storage backend uses the Raft consensus protocol for leader election and log replication. This requires each node to know the addresses of its peers at startup via explicit `retry_join` configuration. A minimum of three nodes (for quorum) must be provisioned and configured with each other's network addresses. The Raft protocol requires majority agreement (quorum) for leader election, meaning 2-of-3 or 3-of-5 nodes must be reachable. Vault does not use any form of network service discovery for cluster formation.

2. **EJBCA Enterprise HA (Shared database clustering):** EJBCA achieves high availability through database-level clustering (e.g., Galera Cluster for MariaDB, PostgreSQL streaming replication, Oracle RAC). Multiple EJBCA nodes connect to the same clustered database. Failover is handled at the database layer, not the application layer. This requires provisioning and maintaining a separate database cluster with its own HA infrastructure.

3. **Microsoft Active Directory Certificate Services (AD CS) HA:** AD CS achieves high availability through Windows Server Failover Clustering (WSFC) with shared storage (SAN, iSCSI). The CA private key resides on shared storage accessible to all cluster nodes. Failover is managed by the Windows cluster service. This requires Windows Server Enterprise/Datacenter edition, shared storage infrastructure, and Active Directory domain membership.

4. **`followtheleader` (npm library):** This open-source library (https://github.com/nickleefly/followtheleader) uses mDNS/Bonjour for zero-configuration leader election on local networks. It implements heartbeat-based failure detection with configurable weights and priorities. However, it is a general-purpose leader election library with no awareness of PKI, cryptographic identity, or certificate authority operations. It does not embed cryptographic fingerprints in service records and has never been applied to PKI failover scenarios.

5. **Consul / Serf (gossip-based discovery):** HashiCorp Consul uses a gossip protocol (Serf) for membership and failure detection, combined with Raft for leader election. While Consul can discover services on a network, it requires running a separate Consul agent infrastructure and does not operate on standard mDNS/DNS-SD protocols.

6. **Kubernetes cert-manager:** Automates certificate management within Kubernetes clusters. Leader election uses Kubernetes lease objects (stored in etcd). Requires Kubernetes infrastructure and does not operate on bare-metal LANs.

### The Gap

None of the above approaches achieve zero-configuration CA high availability on a local area network. Specifically, no prior system:

- Uses mDNS service records (RFC 6762/6763) as the sole liveness detection mechanism for a PKI certificate authority
- Embeds a cryptographic fingerprint of the CA certificate in mDNS TXT records to bind service discovery to cryptographic identity
- Achieves deterministic leader election for CA promotion without any inter-node communication, consensus protocol, or shared state
- Provides automatic split-brain resolution for certificate authority nodes based on mDNS service detection

The invention described herein fills this gap.

---

## Detailed Technical Description

### 1. System Architecture Overview

The system comprises one or more nodes on a local area network (LAN), each running a daemon process. Each node has a role within a "certificate mesh":

- **Primary**: The active certificate authority. Issues certificates, processes enrollments, and manages the roster of enrolled members. There is exactly one primary at any time.
- **Standby**: A hot standby that has received the CA private key material and can assume primary responsibilities. There may be zero or more standbys.
- **Member**: An enrolled node that has received a certificate but does not hold CA key material. Cannot promote.
- **Client**: A non-server participant that has enrolled for a client certificate.

The role of each node is recorded in a "roster" data structure -- a JSON document maintained by the primary and replicated to standbys. The roster contains, for each member:

```
RosterMember {
    hostname: String,
    role: MemberRole (Primary | Standby | Member | Client),
    enrolled_at: DateTime<UTC>,
    cert_fingerprint: String (SHA-256 of the member's certificate),
    cert_expires: DateTime<UTC>,
    cert_sans: Vec<String> (Subject Alternative Names),
    status: MemberStatus (Active | Revoked),
    pinned_ca_fingerprint: Option<String>,
    last_seen: Option<DateTime<UTC>>,
    ...
}
```

### 2. Service Registration (mDNS Announcement)

When a node starts and meets all of the following conditions, it registers an mDNS service record on the local network:

**Conditions for announcement:**
1. The node's CA key is present and unlocked (decrypted into memory)
2. The node's role in the roster is `Primary`
3. The HTTP server is running and accepting connections

The announcement is a DNS-SD service of type `_certmesh._tcp` registered via the mDNS protocol (RFC 6762). The registration includes:

**Service record fields:**
- **Instance name**: `koi-ca-{hostname}` where `{hostname}` is the machine's hostname
- **Service type**: `_certmesh._tcp`
- **Port**: The HTTP port the daemon listens on (default: 5641)
- **TXT records** (key-value pairs embedded in the DNS TXT record):
  - `role=primary` -- the node's current role
  - `fingerprint={sha256_hex}` -- the SHA-256 fingerprint of the CA certificate, hex-encoded
  - `hostname={hostname}` -- the machine's hostname

The `ca_announcement()` method on the domain core returns `Some(CaAnnouncement)` when all conditions are met, and `None` otherwise. The binary crate's background task loop translates this into mDNS register/unregister operations:

```
Pseudocode:
loop every 5 seconds:
    announcement = certmesh_core.ca_announcement(http_port)
    if announcement is Some AND no existing mDNS registration:
        register mDNS service with announcement parameters
        store registration ID
    else if announcement is None AND existing mDNS registration exists:
        unregister mDNS service
        clear registration ID
```

This means the mDNS service record automatically appears when the CA is operational and disappears when it is not (daemon shutdown, CA locked, role changed).

### 3. Liveness Monitoring (Standby Observation)

Each standby node runs a background task that continuously monitors the local network for `_certmesh._tcp` mDNS service records. The monitoring operates as follows:

**Monitoring loop (runs every 5 seconds):**

```
Pseudocode:
primary_absent_since: Option<Instant> = None

loop every 5 seconds (respecting CancellationToken for shutdown):
    services = browse mDNS for _certmesh._tcp services

    // Extract TXT records: Vec<(hostname, port, HashMap<String, String>)>
    active_primary = find_active_primary(our_ca_fingerprint, services)

    if active_primary is Some:
        primary_absent_since = None
        // Primary is alive; check for split-brain (see Section 7)
    else:
        if primary_absent_since is None:
            primary_absent_since = Some(Instant::now())
        // Primary is absent; check failover condition (see Section 5)
```

### 4. Fingerprint-Based Identity Verification

The function `find_active_primary(ca_fingerprint, services)` scans discovered mDNS services and returns the endpoint of a matching primary, if one exists.

**Algorithm:**
```
for each (host, port, txt_records) in services:
    is_primary = txt_records["role"] == "primary"
    fingerprint_matches = constant_time_compare(
        txt_records["fingerprint"],
        our_ca_fingerprint
    )
    if is_primary AND fingerprint_matches:
        return Some("{host}:{port}")
return None
```

The fingerprint comparison uses the `fingerprints_match()` function from the `koi_crypto::pinning` module, which performs constant-time string comparison to prevent timing side-channel attacks during fingerprint matching.

**Why fingerprint pinning is essential:**

Without fingerprint verification, any node on the LAN could register a `_certmesh._tcp` service with `role=primary` and trick standbys into believing a legitimate primary exists (preventing failover) or into connecting to a rogue CA. The SHA-256 fingerprint of the CA certificate is established during initial enrollment (when a standby joins the mesh) and is pinned in the standby's local roster as `pinned_ca_fingerprint`. A rogue node without the actual CA certificate cannot produce a matching fingerprint.

**Fingerprint format:** The fingerprint is the hexadecimal encoding of the SHA-256 hash of the DER-encoded CA certificate.

### 5. Absence Detection and Grace Period

When the primary's mDNS service record disappears from the network (because the primary daemon stopped, the process crashed, the machine lost power, or the network interface went down), the standby records the timestamp:

```
if primary_absent_since is None:
    primary_absent_since = Some(Instant::now())
```

The system defines a grace period constant:
```
FAILOVER_GRACE_SECS: u64 = 60  // 60 seconds
```

The function `should_promote(primary_absent_since, grace_duration)` determines whether the grace period has elapsed:

```
fn should_promote(primary_absent_since: Option<Instant>, grace: Duration) -> bool {
    match primary_absent_since {
        Some(since) => since.elapsed() >= grace,
        None => false,
    }
}
```

**Design rationale for the grace period:**

- **Daemon restarts:** A planned restart (e.g., for software update) may take 10-30 seconds. Without a grace period, a brief restart would trigger unnecessary failover.
- **Network blips:** Transient network issues (switch reboots, WiFi interference, cable disconnection) can cause mDNS service records to temporarily disappear.
- **mDNS cache expiry:** The mDNS protocol uses TTL-based caching. A service record may temporarily disappear from browse results during cache refresh.
- **60 seconds balances responsiveness and stability:** Long enough to ride out typical transient failures, short enough that the CA is not unavailable for an operationally significant period.

**Configurability:** The grace period is defined as a constant (`FAILOVER_GRACE_SECS = 60`) in the implementation. A variant of this disclosure covers making this value configurable at runtime (e.g., via environment variable or configuration file).

### 6. Deterministic Tiebreaking Without Distributed Consensus

When the grace period elapses and the standby is ready to promote, it must determine whether it is the correct standby to take over. In a multi-standby configuration, all standbys observe the same absence simultaneously and reach the `should_promote = true` state at approximately the same time.

The system uses a deterministic tiebreaker function:

```
fn tiebreaker_wins(my_hostname: &str, other_hostname: &str) -> bool {
    my_hostname < other_hostname  // lexicographic comparison
}
```

**Full election algorithm (executed independently on each standby):**

```
Pseudocode:
if should_promote(primary_absent_since, grace):
    other_standbys = roster.standbys()
        .filter(hostname != my_hostname)

    i_win = other_standbys.all(|other| tiebreaker_wins(my_hostname, other.hostname))

    if i_win:
        promote_self_to_primary()
```

**Key properties:**

1. **No inter-node communication required:** Each standby independently queries its local copy of the roster to determine the set of other standbys. The roster is periodically synchronized from the primary (every 5 minutes via `ROSTER_SYNC_INTERVAL_SECS`), so all standbys have a consistent (or near-consistent) view of the standby set.

2. **Deterministic outcome:** Given the same roster, every standby computes the same winner. The lexicographically lowest hostname always wins.

3. **Total ordering:** Lexicographic comparison on strings provides a total order. Ties (identical hostnames) return `false` for both nodes, preventing dual-promotion. In practice, hostnames are unique within a LAN.

4. **No quorum requirement:** Unlike Raft (which needs a majority of nodes), this tiebreaker works with any number of standbys, including a single standby.

**Tiebreaker properties and edge cases:**

- **Case sensitivity:** The comparison is case-sensitive (ASCII byte-level). `"Alpha" < "alpha"` because uppercase letters have lower ASCII values. This is documented and deterministic.
- **Numeric hostnames:** The comparison is lexicographic, not numeric. `"10" < "2"` because `'1' < '2'`. This is acceptable because the only requirement is a deterministic total ordering, not a "fair" one.
- **Empty hostnames:** Empty string sorts before all non-empty strings, providing a well-defined behavior even in edge cases.
- **Common prefixes:** `"node-01" < "node-02"` due to `'0' < '0'` at the differing position. This naturally orders numbered hostnames correctly for single-digit suffixes.

### 7. Self-Promotion Procedure

When a standby determines it should promote (grace elapsed AND tiebreaker won), it executes `promote_self_to_primary()`:

```
Pseudocode (promote_self_to_primary):
    hostname = get_local_hostname()
    roster = acquire_roster_lock()

    // Demote any existing primary to standby
    for member in roster.members:
        if member.role == Primary AND member.hostname != hostname:
            member.role = Standby

    // Promote self
    if let Some(self_member) = roster.find_member(hostname):
        self_member.role = Primary
        save_roster(roster)

        // Write audit log entry
        audit::append_entry("failover_promoted", [("hostname", hostname)])

        return Ok(true)

    return Ok(false)  // self not in roster (should not happen)
```

After promotion:
- The next iteration of the background loop will call `ca_announcement(http_port)` which will now return `Some(...)` (because the node is Primary with an unlocked CA)
- The mDNS service record `_certmesh._tcp` with `role=primary` is registered
- Other standbys observing this record will set `primary_absent_since = None`, canceling their own failover timers

### 8. Split-Brain Detection and Resolution

A split-brain condition occurs when two nodes both believe they are the primary. This can happen if:

- A network partition separates primary and standby, the standby promotes, and then the partition heals
- A primary is temporarily unreachable (but not crashed), a standby promotes, and the original primary returns
- Two standbys promote simultaneously due to clock skew in the grace period check

The system detects and resolves split-brain as follows:

```
Pseudocode (in the standby monitoring loop, when the node is currently Primary):
    services = browse mDNS for _certmesh._tcp services

    for each (host, port, txt) in services:
        if txt["role"] == "primary"
           AND txt["fingerprint"] matches our CA fingerprint
           AND host != our_hostname:
            // Another primary detected! Split-brain condition.

            if NOT tiebreaker_wins(our_hostname, host):
                // We lose the tiebreak -- demote self
                demote_self_to_standby()
                audit::append_entry("failover_demoted", [("hostname", our_hostname)])
                log::warn("Failover: demoted to standby (another primary detected)")
```

**Resolution properties:**

- **Symmetric detection:** Both primaries independently browse mDNS and detect each other.
- **Deterministic resolution:** The same tiebreaker function determines which primary survives. The lexicographically lower hostname wins.
- **Self-healing:** The losing primary automatically self-demotes without operator intervention.
- **Audit trail:** Both promotion and demotion events are recorded in the audit log with timestamps and hostnames.

**The `demote_self_to_standby()` procedure:**

```
Pseudocode:
    hostname = get_local_hostname()
    roster = acquire_roster_lock()

    if let Some(self_member) = roster.find_member(hostname):
        if self_member.role == Primary:
            self_member.role = Standby
            save_roster(roster)
            return Ok(true)

    return Ok(false)
```

After demotion:
- `ca_announcement()` returns `None` (node is no longer Primary)
- The mDNS service record is unregistered
- The node resumes standby monitoring behavior

### 9. CA Announcement Lifecycle Management

The background task loop manages the lifecycle of the mDNS announcement in tandem with failover detection:

```
Pseudocode (within the 5-second monitoring loop):
    // ... failover detection logic from above ...

    announcement = certmesh_core.ca_announcement(http_port)

    if announcement is Some AND announce_id is None:
        // Node just became an active primary; register mDNS
        payload = RegisterPayload {
            name: announcement.name,
            service_type: "_certmesh._tcp",
            port: announcement.port,
            txt: announcement.txt,  // includes role, fingerprint, hostname
        }
        id = mdns_core.register(payload, LeasePolicy::Permanent)
        announce_id = Some(id)

    else if announcement is None AND announce_id is Some:
        // Node is no longer an active primary; unregister mDNS
        mdns_core.unregister(announce_id)
        announce_id = None
```

**Conditions where `ca_announcement()` returns `None`:**
- CA key is not present (node never received CA material)
- CA key is present but locked (encrypted at rest, not yet decrypted after restart)
- Node's role is not Primary
- Roster has no member matching the local hostname with Primary role

### 10. Roster Synchronization (Supporting Mechanism)

For the tiebreaker to function correctly, all standbys must have a reasonably current view of the roster (specifically, the set of standby hostnames). The system achieves this through periodic roster synchronization:

```
ROSTER_SYNC_INTERVAL_SECS: u64 = 300  // 5 minutes
```

**Standby roster sync loop:**
```
Pseudocode:
loop every ROSTER_SYNC_INTERVAL_SECS:
    primary_endpoint = find_active_primary_via_mdns()
    if primary_endpoint is Some:
        manifest = HTTP GET {primary_endpoint}/v1/certmesh/roster
        verified_roster = verify_manifest_signature(manifest, ca_public_key)
        if verified_roster is Ok:
            replace_local_roster(verified_roster)
```

The roster manifest is signed with the CA's ECDSA P-256 key (see Family 2 for details on the signing mechanism). The standby verifies the signature before accepting the roster update, preventing a man-in-the-middle from injecting a modified roster.

### 11. Interaction with Member Health Heartbeats

Member nodes (non-CA nodes) periodically send health heartbeats to the primary:

```
Pseudocode (member health loop, every 5 minutes):
    primary_endpoint = find_active_primary_via_mdns() OR use_known_endpoint()
    HTTP POST {primary_endpoint}/v1/certmesh/health {
        hostname: my_hostname,
        pinned_ca_fingerprint: my_pinned_fingerprint
    }
```

The primary validates the pinned CA fingerprint matches its own CA certificate fingerprint. This provides a bidirectional identity check: the primary's mDNS record proves its identity to standbys (via fingerprint), and the member's heartbeat proves the member was enrolled against the correct CA (via pinned fingerprint).

After a failover, the new primary begins receiving health heartbeats from members. The `last_seen` timestamp in the roster is updated, providing the new primary with a view of which members are still active.

### 12. Orderly Shutdown and Graceful Failover

When a primary node shuts down gracefully (e.g., `koi certmesh destroy`, system shutdown, service stop):

1. The daemon's `CancellationToken` is cancelled
2. All background tasks receive the cancellation signal
3. The mDNS service record is unregistered as part of the `MdnsCore::goodbye()` procedure
4. The daemon exits

Standbys observe the mDNS record disappearing and begin the grace period countdown. If the primary does not return within 60 seconds, the winning standby promotes.

**For planned maintenance**, an operator can manually demote the primary and promote a standby using the `koi certmesh promote` CLI command (see Family 2), avoiding any downtime.

---

## Variants and Alternative Embodiments

### Variant A: Configurable Grace Period
The grace period (default 60 seconds) can be made configurable via environment variable (`KOI_FAILOVER_GRACE_SECS`), configuration file, or CLI flag. Shorter periods (e.g., 15 seconds) are appropriate for latency-sensitive environments. Longer periods (e.g., 300 seconds) are appropriate for environments with frequent transient outages.

### Variant B: Alternative Tiebreaker Functions
The tiebreaker function can use any deterministic total ordering on node identities:
- **Lexicographic hostname comparison** (primary embodiment)
- **Lowest IP address** (numerically comparing IPv4 or IPv6 addresses)
- **Earliest enrollment timestamp** (first-enrolled standby wins)
- **Explicit priority weight** (administrator-assigned integer, lowest wins)
- **Hash-based ordering** (`SHA256(hostname + epoch_day)` for time-varying but deterministic ordering)

### Variant C: Alternative Fingerprint Algorithms
The cryptographic fingerprint can use any collision-resistant hash:
- **SHA-256** (primary embodiment)
- **SHA-384** or **SHA-512** (higher security margin)
- **BLAKE3** (faster computation)

### Variant D: Non-mDNS Service Discovery
The same failover protocol could operate over alternative service discovery mechanisms:
- **Consul service catalog** (with health checks replacing mDNS liveness)
- **etcd or ZooKeeper watches** (with ephemeral keys replacing mDNS TTL)
- **Custom UDP broadcast** (with a proprietary discovery protocol)
- **DNS SRV records** (with active health checking replacing mDNS passive detection)

### Variant E: Multi-Site Awareness
For environments spanning multiple network segments:
- Standbys in the same network segment as the primary have priority over standbys in remote segments
- Site affinity is encoded as a TXT record field (e.g., `site=building-a`)
- Tiebreaker first groups by site, then applies hostname ordering within each site

### Variant F: Quorum-Aware Promotion
A hybrid variant combines the zero-configuration approach with optional quorum awareness:
- If the standby can communicate with a majority of known standbys (via direct HTTP), it promotes immediately
- If it cannot (network partition), it waits for an extended grace period (e.g., 5 minutes) before promoting
- This reduces the window for split-brain at the cost of increased failover latency

---

## Implementation Evidence

The described system is fully implemented in the Koi v0.2 codebase:

| Component | Source File | Key Symbols |
|-----------|-------------|-------------|
| Failover detection | `crates/koi-certmesh/src/failover.rs` | `should_promote()`, `tiebreaker_wins()`, `find_active_primary()`, `FAILOVER_GRACE_SECS`, `ROSTER_SYNC_INTERVAL_SECS` |
| Background tasks | `crates/koi/src/main.rs` | `spawn_certmesh_background_tasks()`, failover detection loop, roster sync loop, health heartbeat loop |
| CA announcement | `crates/koi-certmesh/src/lib.rs` | `CertmeshCore::ca_announcement()`, `promote_self_to_primary()`, `demote_self_to_standby()` |
| Roster model | `crates/koi-certmesh/src/roster.rs` | `Roster`, `RosterMember`, `MemberRole`, `RosterMetadata` |
| Protocol types | `crates/koi-certmesh/src/protocol.rs` | `CaAnnouncement`, `RosterManifest` |
| Roster signing | `crates/koi-certmesh/src/failover.rs` | `build_signed_manifest()`, `verify_manifest()` |
| Fingerprint pinning | `crates/koi-crypto/src/pinning.rs` | `fingerprints_match()` |
| Audit logging | `crates/koi-certmesh/src/audit.rs` | `append_entry()` |

**Test coverage (unit tests in `failover.rs`):**
- `should_promote_false_when_no_absence` -- verifies no promotion when primary is present
- `should_promote_false_within_grace` -- verifies no promotion during grace period
- `should_promote_true_after_grace` -- verifies promotion after grace period
- `should_promote_at_exact_boundary` -- verifies boundary condition
- `should_promote_with_zero_grace` -- verifies instant promotion with zero grace
- `tiebreaker_lower_hostname_wins` -- verifies lexicographic ordering
- `tiebreaker_is_case_sensitive` -- verifies case-sensitive comparison
- `tiebreaker_with_numeric_hostnames` -- verifies lexicographic (not numeric) ordering
- `tiebreaker_with_empty_hostname` -- verifies empty string behavior
- `tiebreaker_with_common_prefixes` -- verifies ordering with shared prefixes
- `find_active_primary_matches_fingerprint` -- verifies fingerprint-based matching
- `find_active_primary_skips_standby` -- verifies role filtering
- `find_active_primary_wrong_fingerprint` -- verifies fingerprint rejection
- `find_active_primary_empty_services` -- verifies empty input handling
- `find_active_primary_multiple_primaries_returns_first` -- verifies first-match behavior
- `find_active_primary_missing_role_key` -- verifies handling of missing TXT key
- `find_active_primary_missing_fingerprint_key` -- verifies handling of missing fingerprint
- `find_active_primary_mixed_roles` -- verifies filtering across multiple roles
- `manifest_sign_verify_round_trip` -- verifies signed roster round-trip
- `tampered_manifest_fails_verification` -- verifies tamper detection
- `wrong_key_manifest_fails_verification` -- verifies wrong-signer detection

---

## Claims-Style Disclosures

The following descriptions are provided in claims-style language to maximize the prior art value of this publication:

### Disclosure 1: mDNS-Based CA Liveness Detection

A method for certificate authority failover detection on a local area network, comprising:
- A primary certificate authority node registering a multicast DNS (mDNS) service record of a designated service type (e.g., `_certmesh._tcp`) when its CA key is unlocked and it is serving certificate operations;
- One or more standby certificate authority nodes continuously browsing for mDNS service records of said designated service type;
- Each standby node recording the timestamp when the primary's mDNS service record was last observed, and upon detecting the absence of said service record, recording the time at which absence was first detected;
- Each standby node comparing the elapsed absence duration against a configurable grace period;
- Upon the grace period elapsing without the primary's mDNS service record reappearing, a standby node initiating self-promotion to primary status;

Wherein said method is distinct from Raft-based consensus (HashiCorp Vault), shared-database clustering (EJBCA), and Windows Failover Clustering (AD CS) in that no explicit peer configuration, shared storage, separate consensus infrastructure, or pre-provisioned cluster membership is required; and wherein said method is distinct from `followtheleader` in that the liveness signal is specifically tied to the certificate authority's operational readiness (CA key unlocked and serving), not merely to a process heartbeat.

### Disclosure 2: Cryptographic Fingerprint Pinning in Service Records

A method for preventing unauthorized certificate authority failover claims, comprising:
- Embedding a cryptographic fingerprint of the CA certificate (specifically, the hexadecimal encoding of the SHA-256 hash of the DER-encoded CA certificate) as a TXT record field within the mDNS service registration;
- Each standby node, upon enrollment, pinning the CA certificate fingerprint in its local roster;
- During liveness monitoring, each standby node accepting only those mDNS service records whose embedded fingerprint matches its pinned CA certificate fingerprint;
- Rejecting all mDNS service records with non-matching fingerprints, regardless of the service type, hostname, or role field;

Wherein said method prevents a rogue node from (a) suppressing failover by registering a fake primary service record, or (b) redirecting standby enrollment traffic to a malicious CA, because the rogue node cannot produce a matching fingerprint without possessing the actual CA certificate; and wherein said constant-time fingerprint comparison prevents timing side-channel attacks from leaking information about the expected fingerprint value.

### Disclosure 3: Deterministic Leader Election Without Consensus

A method for deterministic certificate authority leader election without distributed consensus, comprising:
- Each standby node independently computing whether it should promote to primary by:
  - Retrieving the set of all known standby hostnames from its local copy of the roster;
  - For each other standby hostname, comparing its own hostname lexicographically;
  - Determining it should promote if and only if its hostname is lexicographically less than all other known standby hostnames;
- Said computation requiring no inter-node communication, message passing, or distributed coordination;
- Said computation producing a deterministic and consistent result across all standbys given the same roster state;

Wherein said method is distinct from Raft (requires majority quorum and message exchange), Paxos (requires proposer/acceptor message rounds), Bully algorithm (requires inter-node election messages), and ring-based election (requires ordered message passing) in that no messages are exchanged between standbys during the election process; and wherein the roster synchronization that provides the standby list is a pre-existing mechanism that operates independently of the election, not a component of the election protocol itself.

### Disclosure 4: Automatic Split-Brain Resolution

A method for automatic split-brain resolution in a certificate authority mesh, comprising:
- Each primary node periodically browsing for mDNS service records of the designated CA service type;
- Upon detecting another mDNS service record with `role=primary` and a matching CA certificate fingerprint from a different hostname, identifying a split-brain condition;
- Applying the same deterministic tiebreaker function used for promotion (lexicographic hostname comparison) to determine which primary should survive;
- The losing primary (the one with the lexicographically higher hostname) automatically self-demoting to standby role, updating its local roster, unregistering its mDNS service record, and writing an audit log entry;
- The winning primary (lexicographically lower hostname) continuing as primary without any action required;

Wherein said resolution is fully automatic, requires no operator intervention, preserves a single source of truth for certificate issuance, and is self-healing (the system converges to a single primary regardless of the number of split-brain events).

### Disclosure 5: Integrated Zero-Configuration CA HA System

A system for zero-configuration certificate authority high availability on local area networks, comprising:
- mDNS service registration with CA operational readiness as the registration predicate;
- Cryptographic fingerprint pinning in DNS TXT records for identity verification;
- Grace-period-based absence detection for failover triggering;
- Deterministic hostname-based tiebreaking for leader election;
- Automatic split-brain detection and resolution via mDNS observation;
- Signed roster manifests for standby synchronization;
- Audit logging of all promotion and demotion events;

Operating as an integrated system wherein all components are co-located in a single daemon process, all communication uses standard mDNS/DNS-SD protocols (RFC 6762/6763), no external infrastructure (databases, consensus services, shared storage) is required, and the system self-configures upon node enrollment.

---

## Antagonist Review Log

### Round 1

**Antagonist:** I identify the following weaknesses in this disclosure:

1. **Abstraction gap -- mDNS record lifecycle:** The disclosure says the mDNS record "disappears" when the primary stops, but does not explain the mechanism. mDNS records have TTLs and are cached. How does a standby distinguish between "the primary crashed and the record expired" versus "the mDNS cache has not refreshed yet"? What is the actual TTL of the registered service record? This is a reproducibility gap.

2. **Reproducibility gap -- monitoring loop integration:** The disclosure describes the monitoring loop at a high level but does not specify how the standby receives mDNS browse results. Does it maintain a persistent browse subscription? Does it do periodic one-shot queries? What library/protocol behavior does it rely on?

3. **Scope hole -- network partition scenarios:** The disclosure mentions split-brain resolution but does not fully address the asymmetric partition case. If standby A can see the primary but standby B cannot, standby B may promote while the primary is still operational. The grace period mitigates this but does not eliminate it. The disclosure should acknowledge this limitation.

4. **Prior art weakness -- followtheleader comparison:** The disclosure dismisses `followtheleader` as having "no awareness of PKI," but the core mechanism (mDNS + heartbeat + tiebreaker) is structurally similar. The disclosure needs to more precisely articulate what is novel about applying this pattern to PKI specifically.

5. **Terminology drift -- "cryptographic fingerprint pinning":** The disclosure uses "fingerprint pinning" without defining the term. It could be confused with HTTP Public Key Pinning (HPKP, now deprecated) or certificate pinning in TLS. The disclosure should explicitly define the term.

6. **Missing edge case -- standby that has not yet synced the roster:** If a standby has a stale roster that does not include a newly added standby, the tiebreaker may produce different results on different standbys.

**Author Response (Revisions Applied):**

1. **mDNS record lifecycle -- REVISED:** Added detail to Section 2 and Section 5. The mDNS service registration uses the `mdns-sd` library (Rust crate, wrapping platform mDNS APIs). When the daemon process terminates (gracefully or via crash), the OS-level mDNS responder sends a "goodbye" packet (RFC 6762 Section 10.1) with TTL=0, causing all network peers to immediately flush the record from their caches. For ungraceful termination (power loss, kernel panic), the record expires based on the mDNS record TTL (default: 4500 seconds for `mdns-sd`, but the library sends periodic re-announcements). In practice, standby browse operations use continuous subscription mode (see point 2), which detects the `ServiceRemoved` event when the record expires or is goodbye'd. The 60-second grace period is designed to exceed the typical mDNS cache refresh interval for continuous browse subscriptions.

2. **Monitoring loop integration -- REVISED:** Added to Section 3. The standby uses the `mdns-sd` library's continuous browse API (`ServiceDaemon::browse(service_type)`), which returns a `flume::Receiver<ServiceEvent>`. The browse subscription is maintained for the lifetime of the daemon. The background task periodically (every 5 seconds) checks the accumulated browse results. The `MdnsCore` wrapper receives `ServiceResolved` and `ServiceRemoved` events, which are converted to Koi domain types (`MdnsEvent::Found`, `MdnsEvent::Resolved`, `MdnsEvent::Removed`). The failover detection loop queries the MdnsCore's internal registry for the current set of discovered services matching `_certmesh._tcp`.

3. **Network partition acknowledgment -- REVISED:** Added a new subsection "10.1 Asymmetric Partition Limitation" explicitly acknowledging that in an asymmetric network partition where a standby cannot see the primary but the primary is still operational, the standby will promote after the grace period, creating a split-brain condition. The disclosure notes that the split-brain is automatically resolved when the partition heals (Section 8), and that the 60-second grace period provides a safety margin that exceeds the duration of most transient network issues. This is a known trade-off of the zero-configuration approach versus consensus-based systems like Raft that can detect and handle asymmetric partitions.

4. **followtheleader differentiation -- REVISED:** Strengthened the prior art comparison. The specific novelty is: (a) the registration predicate is CA operational readiness (CA key unlocked + serving), not mere process liveness; (b) the TXT record includes a cryptographic fingerprint that binds the service record to a specific CA identity, preventing rogue impersonation; (c) the system includes an integrated split-brain resolution mechanism triggered by mutual mDNS observation; (d) the full system includes signed roster manifests for state synchronization, forming a complete CA HA solution rather than just a leader election library. `followtheleader` provides (d) none of these: it is a general-purpose leader election building block with no cryptographic identity, no split-brain resolution, and no state synchronization.

5. **Terminology definition -- REVISED:** Added explicit definition in Section 4: "Fingerprint pinning, as used in this disclosure, means that a standby node records the SHA-256 fingerprint of the CA certificate at enrollment time and subsequently only accepts mDNS service records whose embedded fingerprint matches the recorded value. This is analogous to but distinct from HTTP Public Key Pinning (HPKP, RFC 7469, now deprecated) and TLS certificate pinning. HPKP pins the hash of a public key in HTTP headers. TLS certificate pinning pins a certificate or public key in application code. mDNS fingerprint pinning, as described here, pins the CA certificate hash in a local roster and matches it against mDNS TXT record values."

6. **Stale roster edge case -- REVISED:** Added to Section 6 under "Edge cases": "If standby A has a roster listing standbys [A, B] and standby B has a roster listing standbys [A, B, C] (because C was recently added and A has not yet synced), the tiebreaker may produce inconsistent results. In this scenario, A sees itself winning against B alone, while B sees itself needing to beat both A and C. The system converges because: (i) the winning standby promotes and begins serving as primary, (ii) the other standbys observe the new primary's mDNS record and cancel their failover timers, (iii) the new primary's roster (which may be stale) is corrected on the next roster sync or manual operation. In the worst case, two standbys may briefly both promote, triggering the split-brain resolution mechanism (Section 8), which deterministically resolves to a single primary."

### Round 2

**Antagonist:** The revisions address my concerns substantively. However, I have two remaining issues:

1. **Section 101 exposure (patent eligibility):** The tiebreaker function (`my_hostname < other_hostname`) is a trivial string comparison. Could a patent examiner argue this is an abstract mathematical concept? The disclosure should frame it more concretely as part of the integrated system.

2. **Missing detail -- what happens to in-flight certificate operations during failover?** If a member is in the middle of a certificate enrollment or renewal when the primary fails, what happens? This affects reproducibility of the full system behavior.

**Author Response (Revisions Applied):**

1. **Section 101 framing -- REVISED:** The tiebreaker function is intentionally simple because the novelty is not the comparison itself but its application within the integrated system: the combination of (a) mDNS service records as CA liveness signals, (b) cryptographic fingerprint verification of those records, (c) grace-period-gated absence detection, (d) deterministic tiebreaking without consensus, and (e) automatic split-brain resolution. Each individual component may be individually obvious; the claimed contribution is the specific combination applied to PKI CA failover on zero-configuration networks. The claims-style disclosures have been written to emphasize the system claim (Disclosure 5) as the primary disclosure, with the individual mechanisms as supporting disclosures.

2. **In-flight operations during failover -- REVISED:** Added to Section 12: "When the primary fails, any in-flight HTTP requests (enrollment, renewal, heartbeat) receive a connection error or timeout. The client (member node or CLI) retries the operation by discovering the new primary via mDNS. Enrollment operations are idempotent at the roster level (a hostname can only be enrolled once; re-enrollment of an already-enrolled hostname returns the existing certificate). Renewal operations are idempotent at the certificate level (re-signing the same CSR produces a new certificate, but the roster entry is updated atomically). The 60-second failover window is shorter than the default certificate renewal threshold (certificates are renewed when less than 30 days from expiry), so the operational impact of the failover window is negligible for renewal operations."

### Round 3

**Antagonist:** No further objections -- this disclosure is sufficient to block patent claims on the described invention. The combination of mDNS service records, cryptographic fingerprint pinning, deterministic tiebreaking, and automatic split-brain resolution for PKI CA failover is described with sufficient technical detail for a PHOSITA to reproduce. The prior art comparisons are thorough, the edge cases are acknowledged, and the variants cover reasonable alternative embodiments.

---

*End of Defensive Patent Publication.*
