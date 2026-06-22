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
| `nonce`    | A random per-message nonce, base64 — replay uniqueness. |
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
{ "rejected":      { "reason": "bad_signature" } }
```

- **Anonymous** — no identity claim (Open posture / unsigned, or a verifier with no
  CA anchor). Carries only a `freshness` verdict.
- **Authenticated** — signature valid against a leaf that chains to the pinned CA,
  is not expired, and is not revoked. `freshness` is a sub-field, so "authenticated"
  cannot exist without a freshness verdict.
- **Rejected** — a distinct, named `reason` (never one opaque error).

`freshness` ∈ `fresh | stale`. **One identity door:** a trusted CN is readable
*only* when the verdict is `authenticated` AND `freshness == fresh`. A `stale` or
`anonymous` message is never a trusted identity (this makes `if !rejected { trust }`
insufficient by design).

**Freshness window:** `|now - ts| <= 300` seconds ⇒ `fresh`, else `stale`. 300 s
tolerates un-NTP'd LAN clock drift (a tighter window spuriously rejects).

`RejectReason` (`snake_case`): `malformed`, `no_signature`, `unsupported_version`,
`bad_signature`, `unknown_signer`, `revoked`, `expired`, `clock_skew`,
`name_mismatch`.

Revocation is **best-effort** (eventual-consistent, like the mTLS path): the CA
chain is the hard gate; a leaf whose SHA-256 fingerprint is in the verifier's known
revoked set is `revoked`.

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

## References

- ADR-020 (mode-transparent trust primitives) — the design + rationale.
- ADR-016 §2 (the trust plane's primary surfaces), ADR-017 (trust ledger, CSR-only
  issuance, mTLS), ADR-003 (envelope encryption — the future seal rung).
- STACK-0001 D7 (contract surface; this document realizes the ADR-020 amendment),
  K2 (consumer-neutral vocabulary), K3 (frozen HKDF labels).
- Conformance vectors: `docs/reference/vectors/` (language-neutral test vectors for
  the Envelope and Sealed shapes).
