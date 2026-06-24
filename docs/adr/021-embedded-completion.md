# ADR-021: Embedded API Completion — Transport-Agnostic CA-Side Renewal

**Status:** Accepted (operator-ratified 2026-06-24)
**Date:** 2026-06-24
**Builds on:** ADR-020 (mode-transparent trust primitives), ADR-017 (certmesh trust lifecycle), ADR-008 (embedded facade)
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels)

---

## Context

An embedded consumer operating in `ServiceMode::EmbeddedOnly` — no mTLS listener, no
HTTP stack — filed a feature request after ADR-020 shipped. The request identified
**one structural gap** and two API asymmetries.

The filing was written against koi 0.5.1 on a path dependency (consumer is dogfooding
Koi in-process). Per K2, the consumer is unnamed here.

### The structural gap: renewal authorization is transport-coupled

`renew_handler` in `koi-certmesh/src/http.rs` does two distinct things:

1. **HTTP/TLS concerns** — extract `ClientCn` from TLS extensions, parse request body,
   serialize response
2. **Domain invariants** — active + non-revoked check, SANs pinned to enrollment record,
   policy lifetime, sign CSR, roster update, audit log, emit `CertRenewed` event

The domain invariants are business logic that belongs in `CertmeshCore`, not in a
transport adapter. Their current placement violates the domain facade pattern
(CONTEXT.md: "HTTP handlers delegate to domain methods — no lock management in HTTP
handlers where possible") and **blocks any caller that authenticates via a means other
than TLS `ClientCn`**: an envelope-plane caller has a verified CN from
`Assurance::identity()`, but no way to pass it to the renewal logic without running
the full mTLS listener.

Options considered:

| Option | Verdict |
|--------|---------|
| Require EmbeddedOnly consumers to stand up koi's mTLS listener | Violates the EmbeddedOnly contract — the whole point is no serving stack |
| Document that consumers must re-implement renewal invariants | Violates DRY and duplicates a security-critical code path |
| Extract invariants into `CertmeshCore::renew_member` | Correct layering; `renew_handler` becomes a thin wrapper |

### The API asymmetries

1. `CertmeshCore::verify` exists (ADR-020 P2) but is not surfaced on `KoiHandle`
   alongside `KoiHandle::sign`. Callers must unwrap `handle.certmesh()?.core()?` on
   every verify call.

2. `cert_days_left_if_member()` (added in 0.5.1 to drive `CertExpiringSoon` events) is
   `pub(crate)` in `core_renewal.rs`. Embedded consumers that want to drive their own
   renewal timer or display "next renewal in N days" must re-parse the cert file.

### EmbeddedOnly surface audit (post-0.5.1)

After ADR-020, an EmbeddedOnly consumer already has:

| Surface | API |
|---------|-----|
| Per-request signing | `KoiHandle::sign(bytes)` |
| Envelope verification | `CertmeshCore::verify(&Envelope)` (unwrap path required) |
| Posture watch | `KoiHandle::on_posture()`, `KoiHandle::posture().await` |
| CA-side enrollment | `CertmeshCore::enroll(csr_pem)` via `core_member.rs` |
| Member CSR generation | `prepare_member_csr` / `install_member_cert` |
| Trust bundle pull | `pull_trust_bundle` |
| Cert lifecycle events | `KoiEvent::CertRenewed / CertExpiringSoon / CertRenewalFailed / BundleUpdated` |
| mTLS client config | `CertmeshCore::tls_client_config_for(peer)` |
| Revocation | `CertmeshCore::revoke(hostname)` |
| CA-side member renewal | **ABSENT — this ADR closes it** |

---

## Decision

### 1. Extract `CertmeshCore::renew_member`

```rust
/// Sign a rotate-key renewal for an ALREADY-AUTHENTICATED member.
///
/// The caller is responsible for authenticating `authenticated_cn`:
/// - mTLS path: the TLS ClientCn extracted from the connection
/// - Envelope path: `Assurance::identity()` after `CertmeshCore::verify()`
///
/// This method re-applies every CA-side invariant:
///   active + non-revoked, SANs pinned to the enrollment record,
///   policy lifetime, CSR signature valid, sign new cert, roster update,
///   audit entry, emit CertRenewed event.
pub async fn renew_member(
    &self,
    authenticated_cn: &str,
    csr_pem: &str,
) -> Result<protocol::RenewalResult, CertmeshError>;
```

`renew_handler` becomes a two-line wrapper: extract `ClientCn` → call `renew_member`
→ serialize response. This matches the pattern every other handler in the codebase
already follows.

**Security invariant:** `authenticated_cn` is a **trusted input**. The method never
re-authenticates; it enforces business rules on a pre-authenticated identity. The
caller's transport is responsible for proving that identity before calling.

### 2. Surface `KoiHandle::verify`

```rust
pub async fn verify(&self, envelope: &Envelope) -> Result<Assurance, KoiError>;
```

Delegates to `self.certmesh()?.core()?.verify(envelope)`. Makes the `sign`/`verify`
pair symmetric on the handle — a consumer can hold one `KoiHandle` and use both
primitives without unpacking the certmesh sub-handle on every call.

### 3. Expose `member_cert_expiry`

```rust
// On CertmeshCore (pub, not pub(crate)):
pub fn member_cert_expiry(&self) -> Option<DateTime<Utc>>;
```

Consumers derive "days left" from the timestamp. `Option<DateTime<Utc>>` is preferred
over `Option<i64>` days — the raw timestamp is more general-purpose and doesn't embed
a relative-to-now calculation inside the method.

### 4. EmbeddedOnly is complete for the authorization plane

After items 1–3, an EmbeddedOnly consumer has:

- **CA node**: `create`, `open_enrollment`, `enroll`, `renew_member`, `revoke`,
  `trust_bundle` — the full enrollment/renewal loop without HTTP/mTLS
- **Member node**: `sign`, `verify` (both on `KoiHandle`), `on_posture`, `posture()`,
  `member_cert_expiry`, cert lifecycle events, `tls_client_config_for`,
  `reqwest_client_for`

A consumer may authenticate arbitrary requests over the envelope plane and renew
members on the CA side over its own transport. Future transports (QUIC, gRPC,
domain socket) reach the full CA loop without code duplication.

---

## Consequences

**Good:**
- `renew_handler` follows the domain facade pattern — handlers delegate, not implement
- Renewal logic is unit-testable without an HTTP/TLS server
- Any future transport gets CA-side renewal for free
- `KoiHandle::sign` / `KoiHandle::verify` symmetry makes the envelope plane feel complete
- `member_cert_expiry` removes the last reason to read cert files outside `core_renewal.rs`

**Watch out for:**
- `renew_member` is a security-critical extraction. The test suite **must** cover the
  extracted invariants directly (active check, non-revoked, SAN pinning to enrollment
  record) — not only via the HTTP handler path.
- The SAN pinning invariant ("a renewal CSR cannot expand its SANs") is the most
  easily dropped; it must be an explicit unit test on `renew_member` itself.

## Out of scope

- **Injected member-side renewal transport** — the symmetric complement: let
  `renew_self_if_due` drive its POST through a consumer-supplied transport. Deferred;
  `renew_member` on the CA side is what unblocks the immediate use case. Revisit after
  `renew_member` ships and a concrete member-side need emerges.
- **Scoped tokens** — a separate ADR when that work begins.
- **`koi tls setup` / first-run improvements** — product-scope decisions, not certmesh
  architecture.
