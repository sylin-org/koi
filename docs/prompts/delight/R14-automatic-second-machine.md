# R14 - Prove automatic second-machine discovery and recovery

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Installing Koi on a second supported LAN machine makes its services and Koi presence appear automatically.**

- Dependencies: [R03](R03-discovery-record-correctness.md), [R07](R07-home-launchpad.md), [R12](R12-windows-installation.md), [R13](R13-linux-installation.md)
- Epic gate: G3
- Execution class: native acceptance through the activated fleet protocol.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R14.md (or reports/R14-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-compose/src/self_announce.rs`
- `crates/koi-mdns/src/lib.rs`
- `docs/testing/mdns-provider-transition.md`
- `scripts/integration/mdns-provider-transition.sh`
- `fleet/PROTOCOL.md`
- `docs/guides/install-and-service.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Define the physical two-machine fixtures and expectations for Windows/native, Windows/Avahi and Avahi/resolved/native combinations. Use installed artifacts and both hosts' authorization; system changes belong to each host's hat.

2. Exercise install B while A already participates. Observe service appearance on B and Koi presence on A, then open an actual web endpoint. No manual scan, address entry or UI kept open is allowed for the happy path.

3. Exercise provider loss/return, application withdrawal, UI reconnect, daemon restart and network/interface change. Use existing provider-selection and owned publication mechanisms to fix any failures.

4. For blocked multicast/guest isolation, expose observed discovery limitations and one diagnosis entry instead of a false empty-success state. Measure appearance delays over multiple repetitions and report median/tail and fixture conditions.

## Acceptance cases

- [ ] The first live progress state appears immediately; in controlled same-LAN fixtures the target is service appearance within 10 seconds of readiness. Report measurements; do not turn a target into an unmeasured public guarantee.
- [ ] A and B discover expected services without trust enrollment; no root or remote management authority is silently granted.
- [ ] Recovery converges without Refresh; explicit withdrawal removes availability while favorites remain.
- [ ] Both hosts finish with their exact intended state restored; a single-host or container-only run cannot close the physical row.

## Verification

Record two-sided timestamps, expected/observed services, source/artifact hashes, process counts and actual endpoint response. Reuse the native transition test before adding another harness.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update second-machine onboarding and the native fixture evidence, including what Koi can and cannot infer about multicast blocking.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not disable unrelated networking or broaden interfaces/firewalls solely to turn a test green. Do not equate DNS-SD browse with arbitrary .local alias resolution.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
