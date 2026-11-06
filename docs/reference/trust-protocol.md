# Trust protocol

Language-neutral contracts for posture, signed envelopes, confidentiality wrappers, peer transport, diagnosis and MCP discovery. These are advanced interfaces over implemented Koi capabilities; their existence does not certify exact-service HTTPS or change [launch scope](../launch/README.md).

Rust contracts live in `koi-common`; verification and identity custody live in `koi-certmesh`/`koi-crypto`. [Conformance vectors](vectors/trust-vectors.json) freeze interoperable examples. The preserved [trust-primitives decision](../adr/020-mode-transparent-trust-primitives.md) records rationale.

## Posture

```json
{"signed":true,"encrypted":false}
```

`signed` means usable cryptographic identity; `encrypted` represents group-key confidentiality. Derived wire levels are `open` when unsigned, `authenticated` when signed without group confidentiality, and `confidential` when both hold. Current sealing produces passthrough, not group encryption.

mDNS may publish advisory `posture`, `fp` (SHA-256 of CA DER, lowercase hex), `expires` (absolute RFC 3339 timestamp) and optional `cn`. Explicit posture wins during discovery interpretation; a fingerprint without it hints authenticated, otherwise open. None of those hints authenticates the peer. Verify its certificate/message before deriving authority.

## Signed envelope: version 1

```json
{
  "v":1,
  "payload":"<standard padded base64>",
  "nonce":"<standard padded base64>",
  "ts":1718900000,
  "sig":{
    "alg":"ES256",
    "signature":"<standard padded base64>",
    "signer_cert":"<leaf certificate DER, standard padded base64>"
  }
}
```

The signature block is absent for unsigned/Open envelopes. Verification selects the construction from `v`, not from a negotiable algorithm field. Version 1 uses ECDSA P-256/SHA-256; `signature` carries the DER-encoded ECDSA signature in standard padded base64, not the fixed-width JOSE signature encoding. Unknown versions are rejected.

Canonical signed bytes are UTF-8:

```text
koi-envelope-v1\n{v}\n{payload}\n{nonce}\n{ts}
```

Each `\n` denotes one LF byte. Payload/nonce are the exact base64 strings appearing in JSON, not decoded bytes; version and timestamp are decimal integers. Prefixes and constructions are versioned and must not be repurposed.

The carried leaf is validated against the verifier's pinned CA. Its authenticated CN/public key come from that validation, never a claimed field. The nonce contributes message uniqueness but Koi keeps no seen-nonce cache: applications requiring replay exclusion must implement it.

## Assurance and request binding

Verification returns one of these externally tagged result classes:

- `anonymous`, with `freshness`.
- `authenticated`, with certificate-derived `cn` and `freshness`.
- `rejected`, with a named `reason` and optional trusted `signer_cn`.

Freshness is `fresh` when the absolute timestamp difference is at most 300 seconds, otherwise `stale`. A valid signature can therefore return authenticated-but-stale; it must not be treated as a fresh identity. Unsigned input can remain anonymous even in an authenticated context; the consuming operation decides whether identity is mandatory.

Reject reasons are `malformed`, `unsupported_version`, `bad_signature`, `unknown_signer`, `revoked` and `expired`. Trusted attribution may accompany an expired/revoked leaf that chains to the pinned CA. Do not attribute a caller from an untrusted/bad-signature leaf.

Signer verification alone does not authorize a request. Bind the signed payload to the canonical bytes of the actual request, including relevant body/method/path context. `identity_for(env, expected)` is the request-bound interface: it returns an identity only for fresh authenticated input whose signed payload equals the expected bytes. Reusing a captured envelope against a different request must fail this comparison.

## Revocation

The CA enforces its authoritative membership state at operation boundaries. Members consume the complete revoked projection from a verified signed trust bundle, subject to its monotonic sequence anti-rollback floor. Replace the known projection rather than appending only the caller's own entry. A self-revoked node stands down its authenticated outbound identity.

Message verification rejects a leaf fingerprint in the verifier's known revoked set. Propagation depends on the latest accepted bundle; it is not a universal immediate TLS revocation mechanism. Ordinary clients receive no CRL/OCSP status and may accept a leaf until its real expiry.

## Sealed wrapper

Version 0 contains an `envelope` field and is passthrough: integrity/freshness when signed, no encryption. Version 1 reserves group-key authenticated encryption and the distinct HKDF label `koi-seal-group-v1`; current nodes reject that unsupported construction. Unknown versions must not trigger best-effort plaintext fallback.

`open` verifies the contained envelope and never returns payload bytes from a rejected message. Callers must still distinguish anonymous/stale assurance from authorized fresh identity. Status uses `passthrough` for the current confidentiality mode; a wrapper named Sealed is not evidence that its payload is secret.

## Optional same-port transport

A consumer of the peer-serving primitive can choose plaintext or mTLS at connection acceptance based on live posture. The first byte `0x16` selects a TLS handshake; other input takes the plaintext path.

| Identity posture | Connection | Action |
| --- | --- | --- |
| Open | Plain HTTP | Accept |
| Open | TLS | Refuse: no usable identity |
| Authenticated | TLS | Require CA-chained client certificate |
| Authenticated | Plain HTTP | Refuse |

This describes the peer primitive, not a claim that Koi's main port 5641 transparently changes into TLS. The daemon's management, authority and ACME listeners are separate [port contracts](ports.md). An accepted connection's transport decision does not retroactively change; operation-level authorization still applies.

## Diagnosis

Diagnosis contains posture, an overall result and named checks with detail and optional remedy. Check status is `ok`, `warn`, `red` or `not_applicable`; overall is `healthy`, `degraded` or `red`, taking the worst applicable finding. Red is a failed check and produces a nonzero CLI result. A warning is distinct from red.

The Certmesh HTTP diagnosis covers its domain facts. `koi trust diagnose` combines those with independently owned OS Trust observations. It must report unavailable verification honestly; host-root installation does not prove that a particular browser/runtime trusts the application.

## Events

`GET /v1/events` is DAT-protected SSE. A data field carries a `KoiEventWire` object with `event_v`, `event_type`, `id` and event-specific `data`. Skip unknown event versions. Use current source/schema for event payloads; do not assume a fixed event list establishes exhaustive future coverage.

Events are observations, not a replayable durable queue. Recover from loss using the corresponding latest state. The catalog has a separate full-snapshot SSE contract with process epoch/revision; see [HTTP API](http-api.md).

## MCP discovery

The public `/.well-known/mcp/server-card.json` contains a version and an `mcp` object with enabled state, transport, path and auth descriptor:

```json
{
  "name":"koi",
  "version":"<semver>",
  "mcp":{
    "enabled":true,
    "transport":"streamable-http",
    "path":"/v1/mcp",
    "auth":{"scheme":"bearer","header":"x-koi-token"}
  }
}
```

The header contains the bare DAT; the descriptor does not mean adding a `Bearer ` prefix. A disabled surface retains its descriptor shape with enabled false. The card contains no credentials, principal roster or sink secrets.

Main HTTP MCP requires DAT for resource-bearing methods. Optional authority mTLS MCP validates a CA-chained certificate and active/unexpired/unrevoked roster CN. Rejections are named and audited. Principal permissions remain coarse; tool read-only hints are not per-principal authorization scopes.

Generic TLS clients must use a server name covered by its SAN. An IP address is not automatically a valid identity name. mDNS/DNS discovery hints never bypass certificate hostname validation. [The MCP card vector](vectors/agent-door-card.json) and client/Rust tests guard the shared descriptor shape.
