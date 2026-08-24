# ADR-029: Cross-OS Role-Matrix Testbed and the Standing Lab Mesh

**Status:** Accepted (operator-approved 2026-08-24)
**Date:** 2026-08-24
**Builds on:** ADR-018 (integration tiers), ADR-024 (product identity), ADR-028 (webhook sinks), the v1 epic ledger's node-abstraction working choices
**Constrained by:** workstation-class machines are daily drivers — every lane stays run-scoped and exactly restored

---

## Context

The lab grew from two identical Debian servers into a four-machine, three-OS pool:
brook/granite (dedicated Debian 13), windows (Windows 11 workstation), and test-01
(CachyOS/Arch workstation). Two structural problems surfaced as the pool grew:

1. **Roles were hardcoded in Rust.** `TrustRotation` enums pinned which host played
   CA/member/client; adding a machine meant touching rotation code, profile case
   lists, and scenario signatures. The catalog (`lab.json`) existed but only held
   addresses.
2. **Host classes were invisible.** A daily-driver workstation must never be silently
   scheduled into a lane that mutates its trust store or system services; a dedicated
   box may be. Nothing in the harness expressed that distinction.

Separately, the release strategy calls for a **standing dogfood mesh**: the RC runs
continuously on the lab for a week so the distributed artifact generates operational,
not just transactional, evidence.

## Decision

### 1. The catalog is the single source of machine truth (schema 2)

`lab.json` declares every machine with:

- `roles` — what it may play in generated assignments (`ca`, `member`, `observer`,
  `sink`, `principal`, `sdk-caller`). Empty = opts into nothing (planner skips).
- `mutations` — what may be mutated on it (`trust-store`, `systemd`). Mutating lanes
  enforce grants **independently of the operator flag**: no grant, no assignment, even
  with `--allow-system-mutation`.
- `privilege` — `dedicated-box` or `workstation`. Documentation-of-intent plus a
  guardrail anchor; workstations are expected to shut down/reboot mid-experiment.
- `password_env` — per-machine credential indirection. Credentials live in the
  environment, never in the catalog file.

Adding a machine is a data change. The planner enumerates every valid two-role
assignment (`koi-lab pairings`); scenarios accept explicit assignments
(`--primary/--probe`) alongside legacy rotations during migration.

### 2. Transport pins the interpreter

Remote snippets execute under `sh -c '…'` regardless of the account's login shell.
First surfaced by test-01 (fish): POSIX loops died with exit 127. The harness owns
interpreter choice; accounts keep their shells.

### 3. Host classes define the standing mesh's shape

| Class | Machines | Dogfood expectation |
|---|---|---|
| server | brook, granite | Always-on. Persistent data roots, long-lived daemons, CA + serving roles. |
| workstation | windows, test-01 | Reasonable shutdown/start cycles. Participation resumes on next start; absence is normal, not failure. |

Evidence collection tolerates gaps: a snapshot that saw a workstation online records
it; later snapshots record its absence without failing. Mesh membership claims cite
which hosts were up when.

### 4. Dogfood bootstrap is scoped, not installed

The public install/uninstall contract remains unclaimed (ledger). The standing mesh
therefore uses run-scoped-but-persistent locations: dedicated data roots outside
`.lab-runs`, daemons started via systemd transient scopes on servers (`systemd-run`,
sudo available) and direct starts on workstations. Teardown is one command and
removes exactly what bootstrap created.

## Consequences

- Adding hosts is now cheap enough that the matrix expands *after* RC without
  touching the gate definition.
- Mutation grants make privilege violations structurally impossible rather than
  policy-enforced.
- The planner currently covers two-role pairings; observer/three-role generation is
  deferred until a scenario needs it (YAGNI, explicitly revisitable).

## Alternatives considered

- Keep hardcoded rotations, add test-01 ad hoc — rejected: third host made the
  generalization cheaper than the fourth special case.
- SSH-key auth instead of password indirection — deferred: key setup mutates
  workstation state; revisit if credential friction grows.
