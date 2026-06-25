# Koi Trust Protocol (ADR-020) — language-neutral wire contract

This is the published, versioned wire contract for Koi's mode-transparent trust
primitives (ADR-020): the **Posture** descriptor, the signed **Envelope**, the
**Sealed** confidentiality envelope, the **same-port dual-mode handshake**, and the
**diagnose** report. It exists so a non-Rust sibling can implement *identical*
primitives and interoperate byte-for-byte with a Rust Koi node.

It is the realization of the STACK-0001 **D7** amendment ("envelope/posture
descriptor + dual-mode transport" added to the contract surface). The Rust types
backing every shape here live in `koi-common` (`posture`, `envelope`, `sealed`,
`peer`, `diagnosis`); this document is the source of truth for *other* languages.

> **Neutral vocabulary (STACK-0001 K2).** Every term here is standard security
> vocabulary — *posture / Open / Authenticated / Confidential / Assurance*. A
> consumer layer may alias these (e.g. call a level a "degree"); that naming never
> enters this contract.

---

## 1. Posture

A node's (or a discovered peer's) trust posture is two orthogonal booleans:

```json
{ "signed": false, "encrypted": false }
```

| Field       | Meaning |
|-------------|---------|
| `signed`    | A usable cryptographic identity is present (can sign / speak mTLS). |
| `encrypted` | Group-key confidentiality is available (the future Confidential rung). |

Derived **level** (the wire strings used in mDNS TXT and `/v1/status`):

| `signed` | `encrypted` | Level (`snake_case`) |
|----------|-------------|----------------------|
| false    | (any)       | `open`               |
| true     | false       | `authenticated`      |
| true     | true        | `confidential`       |

`encrypted` without `signed` is meaningless and resolves to `open`. "Secure"
≡ `signed == true`.

### Posture in discovery (mDNS TXT)

A node MAY stamp its posture into its own mDNS announcements. The keys (all
**advisory hints** — a verifier still adjudicates via §3, never trusting the wire):

| TXT key   | Value |
|-----------|-------|
| `fp`      | CA fingerprint the node anchors to — SHA-256 of the CA cert DER, lowercase hex. |
| `posture` | The level wire string (`open` / `authenticated` / `confidential`). |
| `expires` | When the node's identity expires — an **absolute** RFC 3339 timestamp (never a countdown, so a cached record cannot report a stale value). |
| `cn`      | Optional identity CN (advisory; the trusted CN comes from §3, not here). |

Posture resolution from a record: an explicit `posture=` wins; otherwise a record
carrying `fp=` is treated as `authenticated`; otherwise `open`.

---

## 2. Envelope (signed message) — `koi-envelope-v1`

A versioned, signed (or freshness-stamped) message. JSON:

```json
{
  "v": 1,
  "payload": "<base64-standard of the message bytes>",
  "nonce":   "<base64-standard of a random per-message nonce>",
  "ts":      1718900000,
  "sig": {
    "alg": "ES256",
    "signature":  "<base64-standard of the ES256 signature>",
    "signer_cert": "<base64-standard of the signer's leaf certificate, DER>"
  }
}
```

| Field      | Notes |
|------------|-------|
| `v`        | Wire version. **The verifier selects its construction from `v`**, never from `sig.alg` (this closes the JWT `alg:"none"` / algorithm-confusion class). v1 = ES256 over the canonical bytes below. |
| `payload`  | The message bytes, base64 (standard alphabet, with padding). |
| `nonce`    | A random per-message nonce, base64 — replay uniqueness input to the signing bytes. **Koi keeps no seen-nonce cache** — application-layer replay defence is the consumer's responsibility. |
| `ts`       | Signer's clock at sign time, **unix seconds** (integer). Drives freshness. |
| `sig`      | The signature block. **Absent** in Open posture (a freshness-stamped passthrough). |
| `sig.alg`  | Closed set; currently only `ES256` (ECDSA P-256 + SHA-256). Not negotiated in-band — a new algorithm is a new `v`. |
| `sig.signer_cert` | **Carry-cert model:** the signer embeds its leaf certificate (DER, base64). The verifier validates it against the pinned CA it already trusts and derives the authoritative CN + public key from it — never from a claimed field. This is what lets a pure member node (which keeps no roster of others' keys) verify. |

### Canonical signing bytes (v1)

The signature covers exactly these bytes (UTF-8), domain-separated and trivially
reproducible in any language:

```
koi-envelope-v1\n{v}\n{payload}\n{nonce}\n{ts}
```

where `{payload}` and `{nonce}` are the **base64 strings** as they appear in the
JSON (not the decoded bytes), `{v}` is the decimal version, `{ts}` is the decimal
unix-seconds, and `\n` is a single line-feed (0x0A). The domain prefix
`koi-envelope-v1` ensures a signature can never be replayed across protocols.

### Verification → Assurance

`verify` returns an **assurance level**, never a bool. Shapes (`snake_case`,
externally tagged on the variant key):

```json
{ "anonymous":     { "freshness": "fresh" } }
{ "authenticated": { "cn": "web-01", "freshness": "fresh" } }
{ "rejected":      { "reason": "expired", "signer_cn": "web-01" } }
{ "rejected":      { "reason": "bad_signature" } }
```

- **Anonymous** — no identity claim (Open posture / unsigned, or a verifier with no
  CA anchor). Carries only a `freshness` verdict.
- **Authenticated** — signature valid against a leaf that chains to the pinned CA,
  is not expired, and is not revoked. `freshness` is a sub-field, so "authenticated"
  cannot exist without a freshness verdict.
- **Rejected** — a distinct, named `reason` (never one opaque error). The optional
  `signer_cn` names the signer **only** when the carried leaf chained to the pinned
  CA but is stale (`reason` ∈ `expired` / `revoked`) — a *trusted* attribution for
  audit and a warm "your identity expired — rejoin" by name. It is **absent** for
  `malformed` / `unsupported_version` / `bad_signature` / `unknown_signer`, where the
  CN would be an attacker-controllable claim (any CN can ride a non-chained or
  bad-signature leaf) and must never be attributed.

`freshness` ∈ `fresh | stale`. **One identity door:** a trusted CN is readable
*only* when the verdict is `authenticated` AND `freshness == fresh`. A `stale` or
`anonymous` message is never a trusted identity (this makes `if !rejected { trust }`
insufficient by design).

**Request binding (authorization).** `verify` attests the *signer*, decoupled from
the payload — the verifier cannot know a consumer's request canonicalization. So
reading the CN alone authorizes a *captured* envelope replayed against a *different*
request. For request authorization, bind the identity to the request: accept the CN
only when the envelope's signed payload equals the canonical bytes of *this* request
(typically embedding a hash of the body). The reference implementation exposes this
as `identity_for(env, expected)` — `Some(cn)` iff the verdict is a trusted identity
**and** the signed payload equals `expected`. A sibling implementation should provide
the same request-bound door, not just the signer-only one.

**Freshness window:** `|now - ts| <= 300` seconds ⇒ `fresh`, else `stale`. 300 s
tolerates un-NTP'd LAN clock drift (a tighter window spuriously rejects).

`RejectReason` (`snake_case`): `malformed`, `unsupported_version`, `bad_signature`,
`unknown_signer`, `revoked`, `expired`.

Implementation note: an unsigned envelope in an Authenticated context produces
`anonymous`, **not** `rejected` — the consumer decides whether to require identity
at the application layer. A timestamp outside the ±300 s window produces
`authenticated { freshness: stale }`, **not** `rejected`; the CN is still readable,
the freshness verdict is `stale`. Only hard cryptographic failures produce `rejected`.

Revocation is **best-effort** (eventual-consistent, like the mTLS path): the CA
chain is the hard gate; a leaf whose SHA-256 fingerprint is in the verifier's known
revoked set is `revoked`.

A member sources its known revoked set from the signed **trust bundle**: it replaces the
set with the bundle's full revoked projection — the union of the `revoked[]` list and any
member with `status == "revoked"`, keyed by fingerprint — on every verified pull
(full-replace, so an un-revocation also clears), gated by the bundle's monotonic `seq`
anti-rollback floor. A non-Rust sibling implements the same: apply the whole projection,
not only your own entry. A node that finds **its own** identity revoked stands itself down —
it stops signing authenticated envelopes, so its outbound messages verify as `anonymous`
(ADR-023).

---

## 3. Sealed (confidentiality envelope)

`seal`/`open` are the confidentiality rung, shipped **today as passthrough**. JSON:

```json
{ "v": 0, "envelope": { ...an Envelope (§2)... } }
```

| `v` | Name | Meaning |
|-----|------|---------|
| `0` | passthrough | A signed Envelope, **not encrypted** (integrity + freshness only). Today's rung. |
| `1` | group-key   | AEAD group-key encryption. **Reserved**, not yet produced. |

The **version is the single source of truth** for both the `open` construction and
the confidentiality level — `open` dispatches on it and never guesses:

| `v` | `confidentiality()` (wire: `snake_case`) |
|-----|------------------------------------------|
| 0   | `none` (wire string for status: `passthrough`) |
| 1   | `group_key` (wire string for status: `groupkey`) |
| other | `none` (conservative — never claim unverifiable secrecy) |

`open` of a v0 Sealed verifies the inner Envelope (§2) and returns the payload —
**but never returns bytes from a rejected (tampered/unknown-signer/expired/revoked)
envelope.** A v1 (or unknown) version is rejected by a node that does not implement
it (anti-downgrade extension point).

When the group-key rung lands it will derive keys with the new, K3-distinct HKDF
label `koi-seal-group-v1` — each HKDF use has its own frozen, versioned `koi-*-v1` label.

---

## 4. Same-port dual-mode handshake

A Koi node MAY serve plaintext HTTP and mTLS on **one** socket, choosing per
connection by **posture at accept time** — so a posture flip never drops an
in-flight connection.

Discriminator: peek the **first byte** of each accepted TCP connection.

| First byte | Interpretation |
|------------|----------------|
| `0x16`     | A TLS record (ContentType = handshake / ClientHello) → TLS path. |
| anything else | Plaintext HTTP (a method char, or the h2c `PRI` preface) → plain path. |

(HTTP/1.x and h2c plaintext always begin with a printable ASCII byte, never `0x16`,
so one byte suffices.)

Dispatch by `(node_is_secure, connection_is_tls)`:

| Node | Connection | Action |
|------|------------|--------|
| Open          | plaintext | serve plain HTTP |
| Open          | TLS       | **refuse** (no identity to terminate TLS) |
| Authenticated | TLS       | mTLS: require a client cert chaining to the CA; inject the peer CN |
| Authenticated | plaintext | **refuse** (secure-by-default; mTLS required) |

Refusals are loud (logged with a reason), never a silent downgrade. The mTLS path
is standard RFC 8446 TLS 1.2+/1.3 with a `WebPkiClientVerifier` over the mesh CA;
the client presents the node's CA-signed leaf.

---

## 5. Diagnose report

`diagnose` returns a structured trust-doctor report (the same shape on
`GET /v1/certmesh/diagnose` and behind `koi trust diagnose --json`):

```json
{
  "posture": { "signed": true, "encrypted": false },
  "overall": "healthy",
  "checks": [
    { "name": "posture",  "status": "ok",  "detail": "Authenticated" },
    { "name": "renewal",  "status": "warn","detail": "leaf expires soon (in 5 days)" },
    { "name": "self_revocation", "status": "red", "detail": "...REVOKED...",
      "remedy": "re-enroll with a fresh invite: koi certmesh join <endpoint>" }
  ]
}
```

- `status` (`snake_case`) ∈ `ok | warn | red | not_applicable`.
- `overall` ∈ `healthy | degraded | red` — worst check wins.
- `remedy` is present only when there is an action; it is an exact, runnable command.
- A consumer of the report MUST treat `overall == "red"` as a failure (the CLI
  exits non-zero). Warnings are loud but not failures.

A check never reports a fake success over something it cannot verify (e.g. OS
trust-store membership is not queryable on all platforms — that check states the
limitation and the remedy instead of claiming "installed").

---

## 6. Versioning & compatibility

- Each wire shape carries an explicit version (`Envelope.v`, `Sealed.v`). A reader
  selects its construction from the version, never from an in-band negotiated field.
- A new algorithm or construction is a **new version**, never a renegotiated field
  on an existing one (no in-band agility).
- Unknown versions are **rejected**, not best-effort-guessed.
- The domain-separation prefixes (`koi-envelope-v1`, the reserved
  `koi-seal-group-v1`) are frozen once published.

## 7. Event-wire DTO (`GET /v1/events`)

The unified SSE event stream exposed at `GET /v1/events` (DAT-gated; see
`docs/reference/http-api.md` for auth requirements) emits `KoiEventWire` objects —
one JSON object per `data:` field. A consumer MUST skip events whose `event_v` it
does not understand (forward-compatible design).

```json
{
  "event_v":    1,
  "event_type": "certmesh.cert_renewed",
  "id":         "01j0abc123",
  "data":       { "expires_at": "2027-06-22T12:00:00Z" }
}
```

| Field        | Notes |
|--------------|-------|
| `event_v`    | Outer wire version. Currently always `1`. **Skip events with unknown versions.** |
| `event_type` | Dotted-namespace string (see table below). |
| `id`         | Monotonically increasing, globally-unique event ID (UUID v7 prefix). |
| `data`       | Event-type-specific payload. See schemas below. |

### Event types and `data` schemas

**mDNS domain:**

| `event_type`        | `data` fields |
|---------------------|---------------|
| `mdns.found`        | `ServiceRecord` (see wire-protocol.md) |
| `mdns.resolved`     | `ServiceRecord` |
| `mdns.removed`      | `{ name, service_type }` |

**DNS domain:**

| `event_type`         | `data` fields |
|----------------------|---------------|
| `dns.entry_updated`  | `{ name: string, ip: string }` |
| `dns.entry_removed`  | `{ name: string }` |

**Health domain:**

| `event_type`      | `data` fields |
|-------------------|---------------|
| `health.changed`  | `{ name: string, status: "up" | "down" | "unknown" }` |

**Certmesh domain:**

| `event_type`                    | `data` fields |
|---------------------------------|---------------|
| `certmesh.joined`               | `{ hostname: string, fingerprint: string }` |
| `certmesh.revoked`              | `{ hostname: string }` |
| `certmesh.destroyed`            | `{}` |
| `certmesh.cert_renewed`         | `{ expires_at: string (RFC 3339) }` |
| `certmesh.cert_expiring_soon`   | `{ days_left: integer }` |
| `certmesh.cert_renewal_failed`  | `{ reason: string, consecutive_failures: integer }` |
| `certmesh.bundle_updated`       | `{ self_revoked: bool }` |

**Proxy domain:**

| `event_type`            | `data` fields |
|-------------------------|---------------|
| `proxy.entry_updated`   | `ProxyEntry` — `{ name, listen_port, backend, allow_remote }` |
| `proxy.entry_removed`   | `{ name: string }` |

**Runtime domain:**

| `event_type`                   | `data` fields |
|--------------------------------|---------------|
| `runtime.instance_started`     | `{ name: string, backend: string }` |
| `runtime.instance_stopped`     | `{ name: string }` |

**Heartbeat:**

| `event_type` | `data` fields |
|--------------|---------------|
| `heartbeat`  | `{}` — emitted every 15 s to keep the connection alive |

### Posture endpoint (`GET /v1/certmesh/posture`)

Also DAT-gated. Returns the live posture as JSON:

```json
{ "signed": true, "encrypted": false, "level": "authenticated" }
```

A consumer that receives `signed: false` knows the node is Open and will route
plaintext HTTP; `signed: true` means mTLS is available and `client_for` should be
used. This is the HTTP path for consumers that cannot embed Koi — a non-Rust
sibling, a browser dashboard, any HTTP client.

---

## References

- ADR-020 (mode-transparent trust primitives) — the design + rationale.
- ADR-016 §2 (the trust plane's primary surfaces), ADR-017 (trust ledger, CSR-only
  issuance, mTLS), ADR-003 (envelope encryption — the future seal rung).
- STACK-0001 D7 (contract surface; this document realizes the ADR-020 amendment),
  K2 (consumer-neutral vocabulary), K3 (frozen HKDF labels).
- Conformance vectors: `docs/reference/vectors/` (language-neutral test vectors for
  the Envelope and Sealed shapes).
