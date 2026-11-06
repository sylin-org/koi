# Fleet coordination

[The fleet task](task.md) is the sole entry point.
[Epic 004](epics/004-container-lan-adoption.md) defines work and release scope;
[the launch ledger](launch/LEDGER.md) defines current claims and evidence.
[ADR-046](../docs/adr/046-container-lan-adoption.md) sets the adoption strategy.

Koi serves OSS container/LAN operators, especially mixed Windows/Linux networks.
The first outcome is a labeled container discovered and used from a second device,
with recreation and removal reflected correctly. Trusted HTTPS follows as a
separately proven workflow. Early uncoached user trials are part of development.

## Responsibilities

| Role | Host identity | Repository | Assignment |
| --- | --- | --- | --- |
| CachyOS | `test-01` | `/run/media/test/WORKBENCH/repos/github/sylin-org/koi` | Sole source integrator; Linux glibc/Docker Engine proof and coordination |
| Windows | `stone-leaded-sparkle` | Checkout containing this file | Requested Windows x64/Docker Desktop native proof |
| Bluefin | `bluefin` | `~/repos/github/sylin-org/koi` | Requested immutable Linux/package/provider proof |
| Alpine | `test-03` | `~/repos/github/sylin-org/koi` | Requested musl/OpenRC proof |
| Debian | `stone-halcyon-savanna` | `~/repos/github/sylin-org/koi` | Lightweight headless and physical-peer observations |

Confirm identities through the dispatcher and private local configuration. Each
host requires its own operator invocation; coordination does not remotely activate
another host or authorize its mutations. New task owners and proofs are unclaimed
or pending until entered in the ledger.

CachyOS integrates implementation, recipes, tests, ADRs and user-facing documentation.
Verification hosts return defects to that owner and publish only their addressed
native evidence. Preserve and hand off any unreported source edits rather than
discarding or duplicating them. Explicitly authorized documentation work can update
the current planning set without transferring ongoing implementation ownership.

## Capacity and scope

Debian is a weak thin client. Assign only bounded headless/native checks and
lightweight peer observations. Do not assign feature implementation, full-workspace
build/test/clippy, cross-target matrices, release builds, sustained stress or soak
work. Required checks still run on a suitable native executor or hosted CI.

Windows is the strongest compatible build/test verification host, but this capacity
does not create a source assignment or launch a session. Bluefin builds in its
dedicated `koi-dev` toolbox; host changes follow the immutable platform's supported
runtime/package path.

Minimum preview scenario claims are Windows x64/Docker Desktop and Linux glibc
x64/Docker Engine with physical peer proof. Podman, macOS, musl and additional
distribution scenarios acquire claims only when demonstrated. Existing compile,
test and release-artifact policy still applies. Broad desktop redesign and
all-surface parity are not prerequisite gates for this focused preview.

## Recording decisions

Use the launch ledger for task ownership, candidate freezes, addressed native
requests, pending proof, defects and gate changes. Keep raw evidence scoped to its
run and exclude secrets. The [current contract](CONTRACT.md) identifies architectural
owners and the difference between source availability and workflow readiness.
