# Koi fleet task

Run this file only when the operator explicitly invokes `run fleet/task.md` on the
participating host. Editing or reading fleet documentation does not launch a host,
authorize deployment, or activate a remote session.

The only work selector is [Epic 004](epics/004-container-lan-adoption.md).
The [launch ledger](launch/LEDGER.md) records assignments, dependencies and proof.
Read the [strategy decision](../docs/adr/046-container-lan-adoption.md),
[launch guide](../docs/launch/README.md), [protocol](PROTOCOL.md) and
[coordination map](coordination.md) before selecting work.
UI assignments also read the [experience contract](../docs/ux/README.md), then
claim the dependency-ready U02–U06 package in the same ledger.

## Identify the host

Normalize the local hostname to lowercase and remove a trailing DNS suffix. Match
an exact identity:

| Hostname | Role | Brief |
| --- | --- | --- |
| `stone-leaded-sparkle` | Windows verification | [Windows](briefs/windows.md) |
| `test-01` | Source integration and Linux verification | [CachyOS](briefs/cachyos-linux.md) |
| `bluefin` | Immutable Linux verification | [Bluefin](briefs/bluefin-linux.md) |
| `test-03` | musl/OpenRC verification | [Alpine](briefs/alpine-linux.md) |
| `stone-halcyon-savanna` | Bounded headless peer verification | [Debian](briefs/debian-linux.md) |

Use `tools/koi-lab/lab.json` and private local notes to confirm host identity and
repository location. An address alone is insufficient. Refuse native execution on
an unknown host, a production host, or a host outside this table. Report the observed
hostname and OS without disclosing credentials.

## Select the next assignment

1. Inspect the worktree and preserve all intentional or unowned changes. Read the
   current epic and ledger before synchronizing or selecting an artifact.
2. CachyOS claims the first dependency-ready implementation item in the ledger.
   Other hosts perform only an explicitly addressed verification request.
3. Record the task ID, owner, bounded scope, candidate identity, required peer and
   restoration plan before work. A pending task is not a standing native dispatch.
4. Complete the applicable repository exploration and checks. This explicit fleet
   invocation authorizes its selected in-scope work; do not ask for the same approval
   again. Source ownership and host boundaries still apply.
5. If no assignment is eligible, report its dependency and leave deployment unchanged.
   Do not create unrelated work or repeat unaffected proof.

The initial workflow is container label → discovery → a real application request
from a second device → correct recreation and removal. Trusted HTTPS is a separate
milestone. Minimum scenario claims cover Windows x64 with Docker Desktop and Linux
glibc x64 with Docker Engine, backed by an independent physical pair. Other artifact
and CI requirements remain governed by repository release policy; they do not
silently expand this first scenario into an all-platform or desktop campaign.

## Execute and record

Follow the protocol for own-host mutation, exact artifact proof, cleanup and
publication. New launch results start pending. Record evidence in the ledger's
current evidence structure, with the exact source and installed artifact identities.
Never turn source tests, a local request, or a previous artifact's result into
second-device application proof. Update only the gates that the current evidence
actually satisfies.
