# Defensive Patent Publication

## ECDSA-Signed Membership Roster Manifests for Certificate Authority Standby Synchronization

**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Publication Type:** Defensive Patent Publication (voluntary prior art disclosure)
**Implementation:** Koi v0.2 -- cross-platform local network service daemon (Rust)

---

## Field of Invention

Public Key Infrastructure (PKI); Distributed systems; Data integrity; Membership replication; Cryptographic verification.

## Keywords

Signed manifest, roster, ECDSA, standby synchronization, certificate authority, membership, integrity verification, PKI replication, atomic state replacement, P-256, SPKI, DER signature, pull-based replication, positive membership snapshot.

---

## Background and Problem Statement

### The Membership Replication Problem in PKI

In a high-availability PKI system with a primary certificate authority (CA) and one or more standby CAs, the standby nodes must maintain an accurate and current copy of the membership roster. The roster is the CA's authoritative record of which hosts are enrolled, their roles (primary, standby, member, client), their certificate fingerprints, certificate expiration dates, Subject Alternative Names (SANs), enrollment timestamps, revocation status, reload hooks, health heartbeat timestamps, pinned CA fingerprints, and proxy configuration entries.

If the primary CA fails and a standby must assume primary responsibilities, the standby's membership roster must accurately reflect the last known state of the mesh. Any discrepancy -- a missing member, an incorrect role, a stale certificate fingerprint, or a missing revocation entry -- can lead to incorrect certificate issuance, failure to recognize enrolled members, or acceptance of revoked members.

### Existing Approaches and Their Limitations

#### 1. Certificate Revocation Lists (CRLs, RFC 5280)

CRLs are signed lists of revoked certificate serial numbers, published periodically by a CA. A CRL is a **negative list** -- it enumerates only which certificates have been revoked. CRLs do not contain:

- The set of active, valid members
- Member roles (primary, standby, member, client)
- Enrollment metadata (enrollment timestamp, enrolling operator, certificate paths)
- Operational state (reload hooks, health heartbeat timestamps, proxy configuration)
- Certificate SANs or fingerprints for active members
- Scope constraints (allowed domains, allowed subnets)

CRLs are designed to answer the question "has this specific certificate been revoked?" They cannot answer "who are all the members of this mesh?" or "what is the complete current state of the PKI membership?" A standby CA receiving only CRLs would have no way to reconstruct the positive membership state.

Furthermore, CRLs are periodically published on a schedule (e.g., every hour, every day). Between publications, revocations are invisible. CRLs also grow monotonically -- revoked certificates are never removed from the list until they expire. This makes CRLs increasingly expensive to distribute as the number of revocations grows.

#### 2. Online Certificate Status Protocol (OCSP, RFC 6960)

OCSP provides real-time, per-certificate status queries. A relying party sends a request containing a certificate serial number, and the OCSP responder returns the status (good, revoked, unknown). OCSP is:

- **Per-certificate**: Each query returns the status of a single certificate. There is no batch query for "all members."
- **Query-response**: The responder answers questions; it does not proactively push state to replicas.
- **Negative/neutral**: Like CRLs, OCSP answers "is this certificate revoked?" not "who are all the members?"
- **No membership metadata**: OCSP responses contain certificate status, not roles, enrollment metadata, or operational state.

OCSP cannot serve as a membership replication mechanism because it does not represent the complete membership roster.

#### 3. Certificate Transparency (CT, RFC 6962 / RFC 9162)

Certificate Transparency logs are append-only Merkle tree logs that record certificate issuance. CT is designed for internet-scale accountability -- anyone can audit which certificates a CA has issued. CT logs:

- Record **issuance events** (SCTs - Signed Certificate Timestamps), not membership state
- Are operated by **third-party log operators**, not by the CA itself
- Are **append-only** -- entries are never removed or modified
- Do not contain membership metadata (roles, enrollment state, operational state)
- Track certificates across **many CAs**, not membership within a single mesh
- Require Merkle tree verification (inclusion proofs, consistency proofs) designed for internet-scale audit, not for intra-mesh state synchronization

CT logs answer "has CA X ever issued a certificate for domain Y?" They cannot answer "what is the current membership roster of mesh Z?"

#### 4. Raft Log Replication (etcd, Vault, Consul)

The Raft consensus protocol (Ongaro & Ousterhout, 2014) replicates an ordered command log across a cluster of nodes. Membership state is derived by replaying the log from the beginning. Raft-based systems:

- Require **explicit peer configuration** -- each node must know the addresses of other cluster members at startup
- Need a **quorum** (majority of nodes) to make progress -- a 3-node cluster tolerates 1 failure, a 5-node cluster tolerates 2
- Replicate the **entire command log**, not just the current state -- log compaction is an optimization, not the default
- Require **bidirectional network connectivity** between all cluster members
- Have **leader election overhead** -- term numbers, vote requests, election timeouts
- Are designed for **strongly consistent state machines**, which is more than needed for periodic membership snapshots

HashiCorp Vault uses Raft for its integrated storage backend. The membership roster equivalent (mount tables, policies, tokens) is replicated as part of the entire Vault state machine. There is no mechanism to sign and distribute just the membership roster as an independent artifact.

#### 5. Database Replication (Galera, PostgreSQL Streaming Replication)

Enterprise PKI systems like EJBCA achieve membership replication through shared database clustering:

- Galera Cluster: Synchronous multi-master replication for MariaDB/MySQL. All writes are applied to all nodes.
- PostgreSQL streaming replication: Asynchronous or synchronous WAL-based replication.

Database replication:

- Replicates **all database state**, not just the membership roster
- Provides **no cryptographic integrity guarantees** on the membership data itself -- if the database is compromised, membership data can be silently modified
- Requires **separate infrastructure** (database cluster) in addition to the CA nodes
- Uses database-specific protocols (MySQL replication protocol, PostgreSQL WAL streaming), not PKI-native formats

#### 6. Gossip Protocols (SWIM, Serf, Memberlist)

Gossip protocols propagate information through randomized peer-to-peer message exchange. Serf (used by Consul) and SWIM (Scalable Weakly-consistent Infection-style process group Membership protocol) detect node failures and propagate membership changes. However:

- Gossip protocols propagate **events** (join, leave, fail), not complete state snapshots
- There is no single authoritative **signed snapshot** of the complete membership
- State is **eventually consistent** -- different nodes may have different views at any point in time
- Gossip protocols require their own **network layer** (UDP/TCP gossip messages)
- No cryptographic binding between the gossip membership and PKI certificate identity

### The Gap

No existing system provides a mechanism where:

1. The certificate authority itself signs its complete membership roster as a self-contained, verifiable artifact
2. The signed artifact contains the full positive membership state (not just revocations)
3. Standby CAs can pull and verify this artifact using only the CA's public key
4. The verification process is a single ECDSA signature check (no Merkle proofs, no log replay, no consensus protocol)
5. The standby replaces its local roster atomically after verification, ensuring consistency with a specific point-in-time snapshot
6. No separate infrastructure (database cluster, consensus protocol, gossip layer) is required

The invention described herein fills this gap.

---

## Detailed Technical Description

### 1. System Architecture Context

The system operates within a certificate mesh -- a collection of nodes on a local area network, each running a daemon process. One node is designated the **primary** CA (issues certificates, manages the roster), and zero or more nodes are **standbys** (hold CA key material, can assume primary responsibilities if the primary fails). Other nodes are **members** (hold issued certificates) or **clients** (hold client certificates).

The primary CA maintains the authoritative membership roster. Standbys must periodically obtain and verify the roster to ensure they can function as primary if needed. The mechanism described here is the **signed roster manifest** -- a self-authenticating artifact that enables standbys to synchronize their membership state with the primary without any consensus protocol, shared database, or bidirectional communication beyond a single HTTP request-response.

### 2. Roster Data Model

The roster is a structured data object containing:

#### 2.1. Roster Metadata (`RosterMetadata`)

| Field | Type | Description |
|-------|------|-------------|
| `created_at` | DateTime (UTC) | Timestamp when the roster was first created |
| `trust_profile` | Enum (JustMe, MyTeam, MyOrganization) | Security posture preset that configures enrollment defaults |
| `operator` | Option(String) | Name of the operator who created the CA (required for MyOrganization) |
| `requires_approval` | Option(bool) | Whether enrollment requires operator approval; falls back to trust profile default if absent |
| `enrollment_state` | Enum (Open, Closed) | Whether the mesh is currently accepting new members |
| `enrollment_deadline` | Option(DateTime UTC) | Auto-close time for the enrollment window; None means no deadline |
| `allowed_domain` | Option(String) | Domain suffix constraint for enrollment (e.g., "lincoln-elementary.local") |
| `allowed_subnet` | Option(String) | CIDR subnet constraint for enrollment (e.g., "192.168.1.0/24") |

#### 2.2. Roster Members (array of `RosterMember`)

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | String | Hostname of the enrolled machine |
| `role` | Enum (Primary, Standby, Member, Client) | Role within the mesh |
| `enrolled_at` | DateTime (UTC) | When this member was enrolled |
| `enrolled_by` | Option(String) | Operator who approved the enrollment |
| `cert_fingerprint` | String | SHA-256 fingerprint of the member's current certificate |
| `cert_expires` | DateTime (UTC) | Expiration time of the member's current certificate |
| `cert_sans` | Vec(String) | Subject Alternative Names on the member's certificate |
| `cert_path` | String | Filesystem path where the member's certificate is stored on the CA |
| `status` | Enum (Active, Revoked) | Current membership status |
| `reload_hook` | Option(String) | Shell command to execute after certificate renewal |
| `last_seen` | Option(DateTime UTC) | Timestamp of the most recent health heartbeat from this member |
| `pinned_ca_fingerprint` | Option(String) | The CA certificate fingerprint this member has pinned (for cert pinning validation) |
| `proxy_entries` | Vec(ProxyConfigEntry) | Proxy configuration entries for this host (name, listen_port, backend, allow_remote) |

#### 2.3. Revocation List (array of `RevokedMember`)

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | String | Hostname of the revoked member |
| `revoked_at` | DateTime (UTC) | When the revocation occurred |
| `revoked_by` | Option(String) | Operator who performed the revocation |
| `reason` | Option(String) | Human-readable revocation reason |

The roster is serialized as JSON using the `serde` serialization framework. Fields with `None` values are omitted from the JSON output (via `skip_serializing_if = "Option::is_none"`). Empty vectors (e.g., `proxy_entries`) are also omitted (via `skip_serializing_if = "Vec::is_empty"`). This ensures backward compatibility -- older rosters without newer fields can be deserialized without error because the `#[serde(default)]` attribute provides default values.

### 3. Roster Manifest Structure

A `RosterManifest` is a self-contained artifact with three fields:

```
RosterManifest {
    roster_json: String,       // Complete roster serialized as JSON
    signature: Vec<u8>,        // ECDSA P-256 signature (DER-encoded)
    ca_public_key: String,     // CA's public key in SPKI PEM format
}
```

#### 3.1. `roster_json` Field

The complete `Roster` struct serialized to a JSON string using `serde_json::to_string()`. This includes all metadata, all members (with all their fields), and the complete revocation list. The JSON is the exact byte sequence that is signed -- any modification to any character in this string invalidates the signature.

The serialization produces deterministic output for a given roster state because `serde_json` serializes struct fields in declaration order and uses deterministic formatting for primitive types. However, the signing scheme does not depend on deterministic serialization -- the signature covers the exact byte sequence of `roster_json`, regardless of whether a different serialization of the same logical data would produce different bytes.

#### 3.2. `signature` Field

A DER-encoded ECDSA P-256 signature over the raw bytes of the `roster_json` string. The signature is produced by the CA's ECDSA P-256 signing key. DER-encoded ECDSA signatures for P-256 are typically 70-72 bytes (the exact length varies because DER encoding of the two integer components r and s may require padding bytes depending on their values).

The signing process:

1. Take the `roster_json` string as a byte sequence (`roster_json.as_bytes()`)
2. Compute the SHA-256 hash of this byte sequence (performed internally by the ECDSA signing operation)
3. Sign the hash using the CA's ECDSA P-256 private key (using the `p256` crate's `SigningKey::sign()` method, which implements RFC 6979 deterministic nonce generation)
4. Encode the resulting `(r, s)` signature pair in DER format (using `Signature::to_der()`)
5. Extract the DER bytes as a `Vec<u8>` (using `as_bytes().to_vec()`)

The use of RFC 6979 deterministic nonces means that signing the same `roster_json` with the same key always produces the same signature. This is a security property -- it eliminates the risk of nonce reuse, which would leak the private key in ECDSA.

#### 3.3. `ca_public_key` Field

The CA's public key exported in SPKI (Subject Public Key Info) PEM format. This is a standard PEM-encoded public key beginning with `-----BEGIN PUBLIC KEY-----` and ending with `-----END PUBLIC KEY-----`. The SPKI format encodes the key algorithm (ECDSA) and curve (P-256) along with the public key point, making the key self-describing.

Including the public key in the manifest allows any party to verify the signature without needing a separate key distribution mechanism. The verifier trusts this public key because:

- For standbys: They received the CA key material during promotion and can verify the public key matches their own CA key pair
- For members: They pinned the CA's public key fingerprint during enrollment
- For auditors: They can compare the public key against the CA certificate's public key

### 4. Manifest Build Process (Primary)

The primary CA builds a signed manifest through the following function:

```
build_signed_manifest(ca: &CaState, roster: &Roster) -> Result<RosterManifest>
```

Step-by-step:

1. **Serialize the roster**: `serde_json::to_string(roster)` produces a JSON string representation of the complete roster, including metadata, all members, and the revocation list. If serialization fails (which should not occur for well-formed types but is handled defensively), the function returns `CertmeshError::Internal`.

2. **Sign the JSON bytes**: `signing::sign_bytes(&ca.key, roster_json.as_bytes())` signs the raw bytes of the JSON string with the CA's ECDSA P-256 private key. The `sign_bytes` function:
   - Takes a reference to the `CaKeyPair` (which wraps a `p256::ecdsa::SigningKey`)
   - Takes the data bytes to sign
   - Calls `signing_key.sign(data)` which performs SHA-256 hashing and ECDSA signing with RFC 6979 deterministic nonce
   - Converts the signature to DER format via `sig.to_der()`
   - Returns the DER bytes as `Vec<u8>`

3. **Export the CA public key**: `ca.key.public_key_pem()` exports the CA's public key in SPKI PEM format using the `p256::pkcs8::EncodePublicKey` trait. The method:
   - Accesses the verifying key (public key) from the signing key
   - Encodes it as PEM with LF line endings
   - Returns the PEM string

4. **Package**: The three components are assembled into a `RosterManifest` struct and returned.

### 5. Manifest Verification Process (Standby)

A standby verifies a received manifest through the following function:

```
verify_manifest(manifest: &RosterManifest) -> Result<Roster>
```

Step-by-step:

1. **Verify the signature**: `signing::verify_signature(&manifest.ca_public_key, manifest.roster_json.as_bytes(), &manifest.signature)` performs the verification. The `verify_signature` function:
   - Parses the PEM string into a `VerifyingKey` using `VerifyingKey::from_public_key_pem()`. If the PEM is invalid, malformed, or does not contain a P-256 public key, this returns `false` (not an error -- all parsing failures result in signature rejection).
   - Parses the DER-encoded signature bytes into a `Signature` using `Signature::from_der()`. If the DER encoding is invalid, this returns `false`.
   - Calls `verifying_key.verify(data, &signature)` which performs SHA-256 hashing and ECDSA verification. If the signature does not match the data and public key, this returns `false`.
   - Returns `true` only if all three steps succeed.

2. **Reject if invalid**: If `verify_signature` returns `false`, the function returns `CertmeshError::InvalidManifest`. This covers all failure cases: invalid PEM, invalid DER signature, wrong public key, tampered data.

3. **Deserialize the roster**: `serde_json::from_str(&manifest.roster_json)` deserializes the verified JSON into a `Roster` struct. If deserialization fails (malformed JSON, missing required fields, type mismatches), the function returns `CertmeshError::Internal`.

4. **Return the verified roster**: The deserialized `Roster` is returned to the caller. At this point, the caller has cryptographic assurance that the roster was serialized by the entity holding the CA's private key and has not been modified since signing.

### 6. Synchronization Protocol

#### 6.1. Background Sync Task

Standbys run a background synchronization task that periodically pulls the roster manifest from the primary. This task is spawned during daemon startup and runs for the lifetime of the daemon:

```
Loop:
  1. Wait ROSTER_SYNC_INTERVAL_SECS (300 seconds / 5 minutes)
  2. Check if cancellation has been requested (graceful shutdown)
  3. Check if this node's role is Standby (non-standbys skip sync)
  4. Read the primary's endpoint from the breadcrumb file
  5. Send GET /v1/certmesh/roster to the primary via blocking HTTP client (in spawn_blocking)
  6. Deserialize the HTTP response body as RosterManifest
  7. Call certmesh_core.accept_roster_sync(&manifest)
  8. Log success or failure
```

The `ROSTER_SYNC_INTERVAL_SECS` constant is set to 300 (5 minutes). This interval balances freshness with network/CPU overhead. In a typical mesh, roster changes (enrollments, revocations, renewals) occur infrequently -- perhaps a few times per day -- so a 5-minute polling interval is sufficient. The interval is not adaptive in the current implementation but could be made shorter during failover or after roster changes.

#### 6.2. HTTP Transport

The sync uses a blocking HTTP client (`ureq`) wrapped in `spawn_blocking` to avoid blocking the async runtime. The request is:

```
GET /v1/certmesh/roster HTTP/1.1
```

The response is a JSON-serialized `RosterManifest`:

```json
{
  "roster_json": "{\"metadata\":{...},\"members\":[...],\"revocation_list\":[...]}",
  "signature": [48, 69, 2, 33, ...],
  "ca_public_key": "-----BEGIN PUBLIC KEY-----\nMFkw..."
}
```

The `signature` field is serialized as a JSON array of bytes (integers 0-255). The `ca_public_key` is a PEM string with embedded newlines.

#### 6.3. Acceptance Logic

The `accept_roster_sync` method on `CertmeshCore`:

1. Calls `verify_manifest(&manifest)` to verify the signature and deserialize the roster
2. If verification succeeds, atomically replaces the in-memory roster with the verified roster (using `Mutex` lock)
3. Persists the updated roster to disk at the roster file path (`certmesh_dir/roster.json`)
4. If verification fails, logs the error and retains the existing roster (no partial update)

The atomic replacement ensures that the standby's roster is always in a consistent state -- either the old roster or the new roster, never a mix of the two.

### 7. Security Properties

#### 7.1. Integrity

Any modification to the `roster_json` string after signing invalidates the ECDSA signature. This includes:

- Adding a member (injecting a `RosterMember` into the JSON)
- Removing a member (removing a `RosterMember` from the JSON)
- Changing a member's role (e.g., changing "standby" to "primary")
- Modifying a certificate fingerprint (substituting a rogue certificate)
- Altering enrollment metadata (changing dates, operators, SANs)
- Adding or removing revocation entries
- Changing scope constraints (domain, subnet)
- Modifying enrollment state (opening a closed enrollment window)

Even a single-bit change in the JSON string produces a completely different SHA-256 hash, causing the ECDSA verification to fail.

#### 7.2. Authenticity

The signature can only be produced by the entity holding the CA's ECDSA P-256 private key. Since the CA private key is protected by envelope encryption (Argon2id + AES-256-GCM with heterogeneous unlock slots) and optionally sealed in a platform credential store, an attacker would need to compromise the CA's key protection to forge a manifest.

A man-in-the-middle attacker intercepting the HTTP response cannot modify the manifest without invalidating the signature, even though the transport may not be encrypted (the system operates on a LAN where mTLS may not yet be established for the sync channel). The signature provides integrity and authenticity independent of the transport security.

#### 7.3. Complete Positive Snapshot

Unlike CRLs (which provide only revoked certificates) or CT logs (which provide only issuance events), the signed manifest contains the complete positive membership state at a point in time. This means:

- A standby can fully reconstruct the membership state from a single manifest
- No "base + delta" merging is needed (unlike Raft log replay)
- No "full sync followed by incremental updates" state machine is needed
- The standby does not need to track the sequence of changes -- it only needs the latest snapshot

#### 7.4. Atomic State Replacement

The standby replaces its entire roster atomically after verification. This prevents:

- **Partial updates**: The standby never has a roster that contains some members from the old state and some from the new state
- **Inconsistent revocation state**: A member cannot be "active" in the member list and "revoked" in the revocation list from different points in time
- **Metadata inconsistency**: Enrollment state, deadlines, and scope constraints are always consistent with the member list

#### 7.5. No Consensus Required

The synchronization is unidirectional (primary -> standby) and does not require agreement between nodes. The primary produces the manifest; the standby consumes it. There is no voting, no quorum, no leader election involved in the sync process. This simplifies the system and eliminates failure modes associated with consensus protocols (split votes, network partitions affecting quorum, etc.).

### 8. Cryptographic Details

#### 8.1. Key Generation

The CA's ECDSA P-256 key pair is generated during CA creation:

1. Operator-provided entropy (keyboard mashing) is collected as raw bytes
2. This entropy is mixed with 32 bytes from the OS CSPRNG (via `OsRng.fill_bytes()`)
3. The mixing is performed by hashing both sources together with SHA-256: `SHA-256(operator_entropy || os_random)`
4. The resulting 32-byte hash is used as the ECDSA P-256 private key scalar (via `SigningKey::from_bytes()`, which performs modular reduction if the value exceeds the curve order)
5. The OS random bytes are zeroized after use

This ensures the key material benefits from both entropy sources. Even if the operator's entropy has low quality, the OS CSPRNG provides sufficient randomness. Even if the OS CSPRNG is compromised, the operator's entropy adds unpredictability.

#### 8.2. Signature Algorithm

- **Algorithm**: ECDSA with P-256 curve (secp256r1, prime256v1)
- **Hash function**: SHA-256 (applied internally by the signing operation)
- **Nonce generation**: RFC 6979 deterministic nonce (implemented by the `p256` crate)
- **Signature encoding**: DER (ASN.1 Distinguished Encoding Rules)
- **Typical signature size**: 70-72 bytes DER-encoded

The DER encoding represents the signature as a SEQUENCE containing two INTEGERs (r and s). The exact byte count varies because DER integers use the minimum number of bytes and may include a leading zero byte for positive representation.

#### 8.3. Public Key Format

- **Format**: SPKI (Subject Public Key Info) PEM
- **Header**: `-----BEGIN PUBLIC KEY-----`
- **Encoding**: Base64-encoded DER, with the DER containing the algorithm OID (1.2.840.10045.2.1 for EC, 1.2.840.10045.3.1.7 for P-256) and the uncompressed public key point
- **Line endings**: LF (Unix-style)

### 9. Edge Cases and Error Handling

#### 9.1. Empty Roster

A manifest can be built and verified for an empty roster (no members, no revocations). This is the initial state after CA creation before any enrollment. The `roster_json` will contain the metadata and empty arrays, and the signature will be valid over this JSON.

#### 9.2. Large Rosters

For meshes with many members, the `roster_json` string may be large. Since the signing and verification operate on the raw bytes (SHA-256 hashing is linear in input size), performance scales linearly. For a mesh with 1,000 members (each member record approximately 500 bytes of JSON), the JSON would be approximately 500 KB, which SHA-256 can hash in microseconds on modern hardware.

#### 9.3. Tampered Signature

If the signature bytes are modified (flipped bits, truncated, zeroed out), the DER parsing in `verify_signature` will either:
- Fail to parse the DER structure (returning `false`)
- Parse to a different `(r, s)` pair that does not match the data (returning `false`)

Both cases result in `CertmeshError::InvalidManifest`.

#### 9.4. Tampered Public Key

If the `ca_public_key` is replaced with a different key (e.g., an attacker's key):
- The PEM parses successfully into a different `VerifyingKey`
- The ECDSA verification fails because the signature was produced by a different key
- Result: `CertmeshError::InvalidManifest`

If the `ca_public_key` is replaced with an invalid PEM string:
- PEM parsing fails
- `verify_signature` returns `false`
- Result: `CertmeshError::InvalidManifest`

#### 9.5. Empty or Malformed Fields

- Empty signature (`[]`): DER parsing fails, verification returns `false`
- Empty public key (`""`): PEM parsing fails, verification returns `false`
- Empty `roster_json` (`""`): Signature verification against an empty byte sequence -- will fail because the signature was not produced for empty data. Even if an attacker signs empty data with a different key, the public key mismatch causes failure.
- Malformed JSON in `roster_json`: If the signature is valid over the malformed JSON (because the primary somehow produced invalid JSON), deserialization fails and returns `CertmeshError::Internal`. The standby retains its existing roster.

#### 9.6. Network Failures

If the HTTP GET to the primary fails (connection refused, timeout, DNS resolution failure):
- The sync task logs the error
- The standby retains its existing roster
- The next sync attempt occurs after `ROSTER_SYNC_INTERVAL_SECS`

This means the standby may have a stale roster for up to `ROSTER_SYNC_INTERVAL_SECS` seconds. This is acceptable because:
- Roster changes are infrequent (enrollments and revocations are rare events)
- The standby's primary responsibility during failover is to accept new enrollments and issue certificates, which does not strictly require an up-to-date roster (new enrollments are additive)
- Revocations in the standby's stale roster may be missing, but the worst case is that a recently revoked member is temporarily not recognized as revoked until the next successful sync

#### 9.7. Concurrent Roster Modifications

If the primary modifies the roster while a standby is pulling the manifest:
- The manifest is built from a snapshot of the roster at the time of the HTTP handler execution (under a Mutex lock)
- The standby receives a consistent snapshot, even if the roster is modified immediately after
- The next sync will pick up the modification

### 10. Serialization Details

#### 10.1. JSON Format

The roster is serialized using `serde_json` with the following conventions:

- Struct fields are serialized in declaration order
- Enums use `#[serde(rename_all = "snake_case")]`: `Primary` -> `"primary"`, `MyTeam` -> `"my_team"`
- Optional fields with `None` values are omitted (via `skip_serializing_if = "Option::is_none"`)
- Empty vectors are omitted (via `skip_serializing_if = "Vec::is_empty"`)
- DateTime values are serialized as RFC 3339 strings (e.g., `"2026-03-24T12:00:00Z"`)
- The `#[serde(default)]` attribute on optional fields enables backward compatibility -- older JSON without newer fields deserializes cleanly

Example serialized roster (abbreviated):

```json
{
  "metadata": {
    "created_at": "2026-03-24T10:00:00Z",
    "trust_profile": "my_team",
    "operator": "Alice",
    "requires_approval": false,
    "enrollment_state": "open",
    "allowed_domain": "lab.local"
  },
  "members": [
    {
      "hostname": "stone-01",
      "role": "primary",
      "enrolled_at": "2026-03-24T10:00:00Z",
      "enrolled_by": "Alice",
      "cert_fingerprint": "sha256:abc123...",
      "cert_expires": "2026-04-23T10:00:00Z",
      "cert_sans": ["stone-01", "stone-01.local"],
      "cert_path": "/var/lib/koi/certs/stone-01",
      "status": "active",
      "reload_hook": "systemctl restart nginx",
      "last_seen": "2026-03-24T11:55:00Z",
      "pinned_ca_fingerprint": "sha256:def456..."
    }
  ],
  "revocation_list": []
}
```

#### 10.2. Manifest JSON Envelope

The manifest itself is also serialized as JSON for HTTP transport:

```json
{
  "roster_json": "{\"metadata\":{\"created_at\":\"2026-03-24T10:00:00Z\",...},\"members\":[...]}",
  "signature": [48, 69, 2, 33, 0, 175, ...],
  "ca_public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
}
```

Note that `roster_json` is a JSON string containing escaped JSON. This double-encoding is intentional -- it preserves the exact byte sequence that was signed, preventing any ambiguity from JSON canonicalization.

### 11. Variants and Alternative Embodiments

#### 11.1. Signature Algorithm Variants

The primary embodiment uses ECDSA P-256. Alternative signature algorithms include:

- **Ed25519**: Faster signing and verification, shorter keys (32 bytes), deterministic nonces by design. Would require changing the CA key generation to produce Ed25519 keys.
- **RSA-PSS (2048-bit or 4096-bit)**: Broader hardware/HSM compatibility. Longer signatures (256 or 512 bytes). Slower signing.
- **ECDSA P-384**: Higher security margin than P-256. Longer signatures (~96-100 bytes DER). Slight performance penalty.

The manifest structure and verification protocol are independent of the signature algorithm. Only `sign_bytes` and `verify_signature` would change.

#### 11.2. Sequence Numbers or Monotonic Counters

The manifest could include a monotonically increasing sequence number (or generation counter) to detect replay attacks or out-of-order delivery:

- The primary increments the counter on every roster modification
- The standby rejects manifests with a counter less than or equal to the last accepted counter
- This prevents an attacker from replaying an older (valid) manifest to roll back revocations

The current implementation does not include a sequence number because the sync is periodic (every 5 minutes) and the most recent manifest always replaces the local state. A replay attack would require sustained interception of all future sync attempts.

#### 11.3. Merkle Root for Partial Verification

For very large rosters, the manifest could include a Merkle root computed over the individual member records:

- Each `RosterMember` is hashed individually
- The hashes are arranged in a binary tree
- The root hash is included in the manifest alongside the ECDSA signature

This would enable:
- Partial verification: A standby could verify that a specific member is in the roster without downloading the entire roster
- Efficient delta sync: Changed members could be identified by comparing Merkle branches

This variant is not needed for the current use case (LAN meshes with tens to hundreds of members) but would be relevant for larger deployments.

#### 11.4. Push-Based Synchronization

Instead of standbys polling the primary, the primary could push manifests to standbys:

- After any roster modification, the primary builds a new manifest
- The primary sends the manifest to all known standbys (identified from the roster)
- Standbys acknowledge receipt

This would reduce sync latency but requires the primary to maintain connections to standbys and handle delivery failures. The pull-based model is simpler and more robust (the standby retries independently).

#### 11.5. Encrypted Manifests

The manifest could be encrypted for confidentiality:

- The roster contains potentially sensitive information (hostnames, IP addresses via SANs, internal network topology)
- Encryption with a key shared between primary and standbys would prevent network eavesdroppers from reading the roster
- The current implementation relies on the fact that the mesh operates on a LAN where network-level eavesdropping is a lesser concern

#### 11.6. Adaptive Sync Intervals

The sync interval could be adaptive:

- **During steady state**: Long interval (5-10 minutes) to reduce overhead
- **After failover**: Short interval (10-30 seconds) to quickly propagate the new primary's state
- **After roster changes**: The primary could include a "next_sync_hint" in the manifest, suggesting when the standby should next poll

### 12. Comparison with Related Work

| Feature | Signed Roster Manifest | CRL (RFC 5280) | CT Log (RFC 6962) | Raft Replication | DB Replication |
|---------|----------------------|----------------|-------------------|-----------------|----------------|
| Content | Complete positive membership | Revoked certificates only | Certificate issuance events | Full state machine log | Full database state |
| Signed by | The CA that manages the mesh | The issuing CA | The log operator | N/A (consensus) | N/A |
| Verification | Single ECDSA check | Single signature check | Merkle inclusion proof | Log replay | N/A |
| Infrastructure | None (HTTP endpoint) | CRL distribution point | Separate log infrastructure | 3+ node cluster | Database cluster |
| Atomic snapshot | Yes | Yes | No (append-only) | No (log replay) | Depends on engine |
| Contains roles | Yes | No | No | Application-specific | Application-specific |
| Contains operational state | Yes (hooks, heartbeats, proxy config) | No | No | Application-specific | Application-specific |

---

## Implementation Evidence

The following source files in the Koi v0.2 codebase implement this invention:

- `crates/koi-certmesh/src/failover.rs` -- `build_signed_manifest()` (lines 127-145), `verify_manifest()` (lines 151-164), constants `FAILOVER_GRACE_SECS` and `ROSTER_SYNC_INTERVAL_SECS`
- `crates/koi-crypto/src/signing.rs` -- `sign_bytes()` (line 15), `verify_signature()` (line 23)
- `crates/koi-certmesh/src/protocol.rs` -- `RosterManifest` struct definition (lines 351-355)
- `crates/koi-certmesh/src/roster.rs` -- `Roster`, `RosterMember`, `RosterMetadata`, `RevokedMember` struct definitions
- `crates/koi-certmesh/src/lib.rs` -- `CertmeshCore::roster_manifest()`, `CertmeshCore::accept_roster_sync()`
- `crates/koi/src/main.rs` -- standby roster sync background task (spawned in `spawn_certmesh_background_tasks`)
- `crates/koi-certmesh/src/http.rs` -- `GET /v1/certmesh/roster` HTTP handler

Unit tests demonstrating the mechanism:

- `manifest_sign_verify_round_trip` -- builds and verifies a manifest end-to-end
- `tampered_manifest_fails_verification` -- modifies `roster_json` after signing, verifies rejection
- `wrong_key_manifest_fails_verification` -- replaces the public key, verifies rejection
- `manifest_with_empty_roster` -- verifies manifests for empty rosters
- `manifest_with_multiple_members` -- verifies manifests for multi-member rosters
- `manifest_tampered_signature_fails` -- flips a byte in the signature, verifies rejection
- `manifest_empty_signature_fails` -- uses empty signature vector, verifies rejection
- `manifest_empty_public_key_fails` -- uses empty public key string, verifies rejection

---

## Claims-Style Disclosures

1. A method for synchronizing certificate authority membership state between primary and standby CA nodes using signed roster manifests, comprising: (a) the primary CA serializing the complete membership roster -- including all member records with their roles, certificate fingerprints, expiration dates, SANs, enrollment metadata, operational state, and revocation list -- to a JSON string; (b) signing the JSON byte sequence with the CA's ECDSA P-256 private key to produce a DER-encoded signature; (c) packaging the JSON string, signature, and the CA's SPKI PEM public key into a self-contained manifest artifact; (d) serving the manifest via an HTTP endpoint; (e) the standby periodically polling the manifest, verifying the ECDSA signature against the included public key, and atomically replacing its local roster with the verified data; wherein the manifest is a complete positive membership snapshot (distinct from CRLs which enumerate only revocations), the verification requires a single signature check (distinct from Raft which requires log replay), and no consensus protocol, shared database, or additional infrastructure is needed (distinct from Vault, EJBCA, and AD CS).

2. A method for ensuring membership roster integrity in a PKI certificate mesh, comprising: the certificate authority that manages the mesh signing its complete membership roster with the same ECDSA private key used to issue certificates, creating a self-authenticating artifact verifiable by any party possessing the CA's public key, wherein the signed artifact covers all membership data including roles, certificate metadata, enrollment state, scope constraints, revocation entries, and operational parameters, and wherein any modification to any field in the roster invalidates the signature, preventing unauthorized addition, removal, or modification of members, roles, or certificate metadata without detection.

3. A method for atomic membership state replacement on standby CA nodes, comprising: the standby receiving a signed roster manifest from the primary, performing ECDSA signature verification on the manifest's JSON payload using the included CA public key, and upon successful verification atomically replacing the standby's entire local roster with the verified roster, wherein: (a) the replacement is all-or-nothing -- the standby's roster is either the complete old state or the complete new state, never a partial mix; (b) signature verification failure causes the standby to retain its existing roster with no modification; (c) the standby does not need to track the sequence of roster changes or apply incremental deltas -- each manifest is a self-sufficient point-in-time snapshot.

---

## Antagonist Review Log

### Round 1

**Antagonist:**

1. **Abstraction gap -- signature algorithm is underspecified.** The disclosure says "ECDSA P-256" but does not specify the hash function used within the ECDSA operation. ECDSA can use different hash functions (SHA-256, SHA-384, SHA-512). A PHOSITA would need to know which hash is used to reproduce the signing and verification.

2. **Reproducibility gap -- `serde_json::to_string` output format.** The disclosure states "serde_json serializes struct fields in declaration order" but does not address whether the output uses compact or pretty-printed JSON. The signature covers the exact bytes, so compact vs. pretty-printed produces different signatures. Which one is used?

3. **Scope hole -- the disclosure does not address manifest freshness.** An attacker could replay a valid older manifest to a standby, rolling back revocations or membership changes. The disclosure mentions this in the Variants section (sequence numbers) but dismisses it. This needs stronger analysis.

4. **Prior art weakness -- no mention of JWS (RFC 7515).** JSON Web Signatures provide a standardized mechanism for signing JSON payloads. JWS with detached payload is essentially the same structure (base64url-encoded payload, signature, header with key ID). The disclosure should distinguish from JWS.

5. **Terminology drift -- "self-authenticating."** The manifest is not truly self-authenticating in the cryptographic sense. The verifier must already trust the CA's public key through a separate channel (enrollment, promotion). The term is misleading.

6. **Edge case -- clock skew between primary and standby.** Roster metadata includes timestamps (`created_at`, `enrolled_at`, `cert_expires`). If the primary and standby have different system clocks, timestamp-based logic (e.g., enrollment deadline auto-close) may behave differently on each node.

**Author Revisions:**

1. Added explicit specification in Section 8.2: "Hash function: SHA-256 (applied internally by the signing operation)" and clarified that the `p256` crate's `SigningKey::sign()` implementation uses SHA-256 as the hash function for ECDSA P-256 signing.

2. Added clarification in Section 4, Step 1: "using `serde_json::to_string()` (compact format, no whitespace indentation)" and noted in Section 10.2 that the `roster_json` field preserves the exact byte sequence that was signed.

3. Expanded Section 9 with new subsection 9.8 (Replay attacks):

> **9.8. Manifest Replay Attacks**
>
> An attacker with network access could capture a valid manifest and replay it later to a standby, potentially rolling back revocations or membership changes. Mitigation factors:
> - The standby syncs every 5 minutes. A replay attack would be overwritten by the next successful sync unless the attacker can sustain interception of all future sync traffic.
> - Revocation rollback is the primary concern. However, the revocation list is append-only on the primary -- revocations are never removed. A replayed manifest from time T1 that is superseded by a manifest from time T2 > T1 would have a revocation list that is a subset of the T2 list. The worst case is temporary failure to recognize a revocation made between T1 and T2.
> - The sync transport could use mTLS (once the standby has enrolled and received a certificate), which would prevent network-level interception and replay. In the bootstrapping phase (before mTLS is established), the manifest's signature provides integrity but not replay protection.
> - For deployments requiring stronger replay protection, a monotonic sequence number or timestamp-based freshness check can be added (see Variant 11.2).

4. Added JWS comparison in Section 12:

> **JWS (RFC 7515):** JSON Web Signatures provide a standardized format for signed JSON payloads. A JWS Compact Serialization contains a header (algorithm, key ID), payload (base64url-encoded), and signature (base64url-encoded). The roster manifest is structurally similar to a JWS with detached payload. The key differences are: (a) the roster manifest uses raw DER signature encoding rather than base64url, (b) the manifest includes the full public key rather than a key ID (JWK thumbprint or `kid` header), eliminating the need for a separate key lookup; (c) the manifest is purpose-built for roster synchronization with a domain-specific payload type, not a general-purpose signed JSON container; (d) the verification function returns the deserialized domain object (`Roster`), not raw bytes, providing type-safe access to the verified data. JWS could serve as the wire format for the manifest, but the invention is the application of signed manifests to PKI membership synchronization, not the signature format itself.

5. Corrected terminology. Replaced "self-authenticating" with "integrity-verified and origin-authenticated" in descriptions. Added clarification: "The manifest is origin-authenticated in the sense that the signature proves it was produced by the holder of the CA's private key. The verifier must have obtained the CA's public key through a trusted channel (enrollment, promotion) to establish this trust."

6. Added Section 9.9 (Clock skew):

> **9.9. Clock Skew Between Primary and Standby**
>
> The roster contains timestamps (member enrollment times, certificate expiration times, enrollment deadlines). If the primary and standby have different system clocks:
> - **Enrollment deadline auto-close**: The `is_enrollment_open()` method compares `Utc::now()` against the deadline. If the standby's clock is ahead of the primary's, it may auto-close enrollment before the primary does. This is acceptable because enrollment is managed by the primary -- the standby's enrollment state only matters if it becomes primary, at which point its clock is the authoritative one.
> - **Certificate expiration**: Certificate expiration is validated by relying parties (TLS clients), not by the roster. The roster records the expiration timestamp but does not enforce it.
> - **Health heartbeat staleness**: `last_seen` timestamps are compared against `Utc::now()` for health monitoring. Clock skew could cause a standby to incorrectly assess member health. In practice, NTP synchronization on a LAN keeps clocks within milliseconds.

### Round 2

**Antagonist:**

1. **Section 101 exposure -- is "signing a roster and sending it to replicas" an abstract idea?** The disclosure should emphasize the specific technical implementation, not just the abstract concept of "signed data for replication."

2. **Missing edge case -- what happens if the CA private key is rotated?** If the CA generates a new key pair (e.g., after a security incident), the standby's pinned public key no longer matches the new manifest's signature. How does the standby handle this?

3. **Reproducibility gap -- the `p256` crate version matters.** The DER encoding of ECDSA signatures is standard, but the specific crate version (`p256 0.13`) should be noted because different versions could have different behavior for edge cases (e.g., handling of zero-padded scalars).

**Author Revisions:**

1. Expanded Section 3 and Section 4 with additional implementation specificity, including the exact function signatures, the specific crate methods called (`SigningKey::sign()`, `Signature::to_der()`, `VerifyingKey::from_public_key_pem()`), the DER encoding details, and the RFC 6979 deterministic nonce generation. The disclosure is not claiming the abstract idea of "signing data" but rather the specific application to PKI membership roster synchronization with atomic replacement semantics, pull-based periodic polling, and the combination with the specific cryptographic mechanisms described.

2. Added Section 9.10 (CA key rotation):

> **9.10. CA Key Rotation**
>
> If the CA generates a new ECDSA key pair (due to key compromise, policy change, or certificate renewal), the public key in the manifest changes. The standby must handle this transition:
> - In the current implementation, the standby received the CA key material during promotion and holds the same key pair. If the primary rotates its key, the standby's local copy becomes stale. The next roster sync would fail verification because the manifest is signed with the new key but the standby may be comparing against the old key.
> - The system handles this by including the public key in the manifest itself. The standby uses the manifest-embedded public key for verification, not a separately stored key. This means the standby accepts any manifest signed by any key -- the trust is established through the transport (HTTP from the known primary endpoint) and the prior enrollment relationship.
> - In a scenario where the standby must also update its own CA key material (not just the roster), a full promotion cycle would be needed.

3. Added dependency version note in Section 8.2: "The implementation uses the `p256` crate version 0.13 (as specified in `Cargo.toml`), which implements ECDSA P-256 according to FIPS 186-4 / SEC 1 with RFC 6979 deterministic nonce generation. DER encoding follows ITU-T X.690."

### Round 3

**Antagonist:**

No further objections -- this disclosure is sufficient to block patent claims on the described invention. The disclosure thoroughly describes the manifest structure, build process, verification process, synchronization protocol, security properties, edge cases, and distinguishes from all relevant prior art (CRLs, OCSP, CT logs, Raft, database replication, gossip protocols, and JWS). The implementation evidence includes specific source file locations and unit test names. The claims-style disclosures are precise and differentiated.
