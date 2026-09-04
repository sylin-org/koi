---
type: REF
domain: certmesh
title: "Trust doctor & posture — capability card"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v1.0.0-rc.2
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "code-reviewed against koi-common/src/diagnosis.rs, koi-common/src/posture.rs, koi-certmesh/src/diagnosis.rs (build_diagnosis + checks), koi-certmesh/src/http.rs (GET /v1/certmesh/diagnose), koi-serve/src/http.rs (loopback-exempt/remote-gated DAT middleware), koi/src/commands/trust.rs + cli.rs (koi trust diagnose [--fix]); the report logic is unit-tested (diagnosis::tests, format::trust_diagnosis_renders_markers_and_remedies) but the CLI flow is not named as a step in the two-box live suite"
---

# Trust doctor & posture — capability card

> One-screen map of Koi's **never-silent** trust state. Wire contract: [trust-protocol.md](../trust-protocol.md) · full trust model: [trust.md](../../guides/trust.md) · design: [ADR-020](../../adr/020-mode-transparent-trust-primitives.md) §13.

**What it does** — The trust category's defining failure is **silence**: a cert expires, a node is downgraded, or an identity half-writes itself, and nothing tells you until something breaks. Koi's answer is **transparency of trust state** — `koi trust diagnose` composes Certmesh's identity findings with the Trust domain's real OS-store presence and pending-transition status. **Every finding carries a distinct state, a cause, and an exact runnable remedy**. The tool **fails loud**: any `RED` check rolls the report up to RED and the process **exits non-zero**; a warning is loud but exits `0`. Certmesh's live status or observation-only offline projection remains authoritative for certificate-mesh facts; the CLI adds the independently owned OS Trust findings at its composition boundary.

## The one canonical pattern

Run the doctor locally; read the report; let a RED exit gate your automation. `--fix` repairs the one auto-fixable finding (install the mesh CA into the OS trust store).

```bash
koi trust diagnose            # loud report; exits non-zero if anything is RED
koi trust diagnose --fix      # also installs the mesh CA into the OS trust store
koi trust diagnose --json     # machine-readable (the TrustDiagnosis wire type)
```

A healthy secure node reads like this; a revoked or expired node turns RED with the exact recovery command:

```text
Trust diagnosis: HEALTHY
  [+] posture: Authenticated
  [+] identity: web-01 (CA 714cad0b9e2f31a8)
  [+] identity_integrity: on-disk leaf parses and chains to its CA
  [+] self_revocation: not revoked
  [+] renewal: leaf healthy (expires in 62 days)
  [+] ca_trust_presence: the Certmesh CA is present in the OS trust store
  [+] clock: local clock 2026-06-22T…; envelopes accept ±300s skew
```

## Commands & flags you'll use

| Command / flag / endpoint | What it does |
|---|---|
| `koi trust diagnose` | Run the trust-doctor; exit non-zero when any check is `RED`. |
| `koi trust diagnose --fix` | Same, plus install the mesh CA into the OS trust store (best-effort; reported, never fatal). |
| `koi trust diagnose --json` | Emit the `TrustDiagnosis` (posture + rollup + per-check `{name, status, detail, remedy?}`). |
| `GET /v1/certmesh/diagnose` | Certmesh-owned identity/renewal report over HTTP. OS trust presence remains a local Trust-domain query composed by the CLI. **Token-free for a loopback peer; the `x-koi-token` is required from a remote peer** (fail-closed when the peer is unknown). |

**Posture levels** — `Open` (no identity, plaintext/anonymous) → `Authenticated` (a cryptographic identity, mTLS) → `Confidential` (authenticated + group-key confidentiality, the future rung). The level is the `posture` check's detail and is stamped into mDNS TXT for discoverers. (`koi status` does **not** print the posture level — it shows the confidentiality `Seal:` line, `passthrough`|`groupkey`; read the level from `diagnose`.)

## Check states & the escape hatch

Each check is `Ok` / `Warn` / `Red` / `NotApplicable`. An **Open node is not an error** — the identity/renewal/revocation checks come back `NotApplicable` (valid by design), and `posture` carries a remedy to gain one (`koi certmesh join <endpoint>`). Renewal: leaf expired → `Red`; renewal overdue, or expiring within 7 days → `Warn`; else `Ok`. Self-revocation and a leaf that doesn't chain to its CA are `Red` with a re-enroll remedy. CA trust presence is read through the real platform adapter: present is `Ok`, missing or unavailable is `Warn`, and an interrupted durable Trust transition is `Red` until recovery succeeds. Plain diagnosis and listing never replay Trust transitions; `--fix` may do so explicitly. An offline Certmesh read also never recovers its repository or credential-cleanup outbox: if a transaction journal exists, start the daemon so Certmesh can recover it before reporting or exporting that generation.

## The proof it works

Unit: `koi-common::diagnosis::tests` covers rollup semantics; `koi-certmesh::diagnosis::tests` covers mesh-owned identity facts; Certmesh observation tests prove that offline projection leaves transaction journals, cleanup outboxes, and the credential vault untouched; and `koi-trust` tests cover durable recovery, platform presence, causal status/event ordering, managed replacement, and redaction. The CLI render is guarded by `format::trust_diagnosis_renders_markers_and_remedies`; remote gating of `GET /v1/certmesh/diagnose` remains covered in `koi-serve`.
