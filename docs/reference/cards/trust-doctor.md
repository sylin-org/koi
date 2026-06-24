---
type: REF
domain: certmesh
title: "Trust doctor & posture — capability card"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.7.0
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "code-reviewed against koi-common/src/diagnosis.rs, koi-common/src/posture.rs, koi-certmesh/src/diagnosis.rs (build_diagnosis + checks), koi-certmesh/src/http.rs (GET /v1/certmesh/diagnose), koi-serve/src/http.rs (loopback-exempt/remote-gated DAT middleware), koi/src/commands/trust.rs + cli.rs (koi trust diagnose [--fix]); the report logic is unit-tested (diagnosis::tests, format::trust_diagnosis_renders_markers_and_remedies) but the CLI flow is not named as a step in the two-box live suite"
---

# Trust doctor & posture — capability card

> One-screen map of Koi's **never-silent** trust state. Wire contract: [trust-protocol.md](../trust-protocol.md) · full trust model: [trust.md](../../guides/trust.md) · design: [ADR-020](../../adr/020-mode-transparent-trust-primitives.md) §13.

**What it does** — The trust category's defining failure is **silence**: a cert expires, a node is downgraded, or an identity half-writes itself, and nothing tells you until something breaks. Koi's answer is **transparency of trust state** — `koi trust diagnose` runs a structured trust-doctor that emits one finding per facet (posture, identity, identity-integrity, self-revocation, renewal, CA-trust-install, clock), and **every finding carries a distinct state, a cause, and an exact runnable remedy**. The tool **fails loud**: any `RED` check rolls the report up to RED and the process **exits non-zero**; a warning is loud but exits `0`. It never fakes an aggregate "success" over something it cannot verify — OS trust-store membership isn't queryable via `os-truststore`, so that check states the limitation and the fix instead of claiming "installed" (the mkcert-#182 honesty rule). The same `CertmeshCore::diagnose` logic backs the CLI, the daemon's `GET /v1/certmesh/diagnose`, and the dashboard, so all three render identical checks.

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
  [+] ca_trust_install: install status is not queryable via the OS trust API …
      → fix: koi trust diagnose --fix
  [+] clock: local clock 2026-06-22T…; envelopes accept ±300s skew
```

## Commands & flags you'll use

| Command / flag / endpoint | What it does |
|---|---|
| `koi trust diagnose` | Run the trust-doctor; exit non-zero when any check is `RED`. |
| `koi trust diagnose --fix` | Same, plus install the mesh CA into the OS trust store (best-effort; reported, never fatal). |
| `koi trust diagnose --json` | Emit the `TrustDiagnosis` (posture + rollup + per-check `{name, status, detail, remedy?}`). |
| `GET /v1/certmesh/diagnose` | Same report over HTTP. **Token-free for a loopback peer; the `x-koi-token` is required from a remote peer** (fail-closed when the peer is unknown), gated alongside `/v1/dns/{list,zone,entries}`. |

**Posture levels** — `Open` (no identity, plaintext/anonymous) → `Authenticated` (a cryptographic identity, mTLS) → `Confidential` (authenticated + group-key confidentiality, the future rung). The level is the `posture` check's detail and is stamped into mDNS TXT for discoverers. (`koi status` does **not** print the posture level — it shows the confidentiality `Seal:` line, `passthrough`|`groupkey`; read the level from `diagnose`.)

## Check states & the escape hatch

Each check is `Ok` / `Warn` / `Red` / `NotApplicable`. An **Open node is not an error** — the identity/renewal/revocation checks come back `NotApplicable` (valid by design), and `posture` carries a remedy to gain one (`koi certmesh join <endpoint>`). Renewal: leaf expired → `Red`; renewal overdue, or expiring within 7 days → `Warn`; else `Ok`. Self-revocation and a leaf that doesn't chain to its CA are `Red` with a re-enroll remedy. The CA-trust-install check is **deliberately not a pass/fail** — it states that membership isn't queryable and offers `--fix`, rather than lying.

## The proof it works

Unit: `koi-common::diagnosis::tests` (worst-check-wins rollup, RED → exit 1, optional-remedy serde) and `koi-certmesh::diagnosis::tests` (`open_node_marks_identity_checks_not_applicable`, `healthy_secure_node_is_healthy`, `expired_leaf_is_red_with_remedy`, `renewal_due_soon_is_a_warning_not_a_failure`, `self_revoked_node_is_red`, `broken_identity_chain_is_red`, `ca_trust_install_is_honest_not_a_fake_success`); the CLI render is guarded by `format::trust_diagnosis_renders_markers_and_remedies`; the remote-gating of `GET /v1/certmesh/diagnose` by the `protected_read_*` tests in `koi-serve`. The diagnose report is part of the **trust primitives wire contract** surface (the STACK-0001 D7 extension) guarded by [trust-protocol.md](../trust-protocol.md), the certless conformance vectors/validator, and the deterministic LAN-trust simulator `crates/koi-certmesh/tests/trust_sim.rs` ([SURFACES.md](../../SURFACES.md)).
