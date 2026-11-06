# Operating rules

These rules govern reproducible source, release and native work. The current
[epic](../fleet/epics/004-container-lan-adoption.md) defines which cases are in
scope; these rules do not add an independent whole-platform campaign.

## Release identity

- RL-1: Validate a clean checkout, including every public fixture and generated
  release input. Local ignored files must not be required to make CI pass.
- RL-2: Registry versions and tags are immutable identities. Check actual
  registries, choose a fresh version, and never repoint a used version.
- RL-3: A negative lookup needs a complete or correctly filtered listing,
  not a truncated sample.
- RL-10: The exact candidate's hosted dry run is a release gate.
- RL-11: Recheck written premises against source, artifact and registry state
  before resuming. The launch ledger is the single progress authority.

## Native execution

- RL-4: Pin the interpreter in remote transport; do not assume or change a
  user's login shell to make a script work.
- RL-5: Stage complex scripts and structured payloads as files. Avoid nested
  cross-shell quoting and command interpolation.
- RL-6: Pass resolved paths and operator identity explicitly through elevation.
  Do not assume that elevated environment variables describe the desktop user.
- RL-7: Measure OS/kernel bind and provider behavior on the claimed platform.
  API presence alone is not proof of a usable operation.
- RL-8: Record relevant host constraints, pre-existing services and privilege
  posture as evidence. Apply the fleet's weak-host capacity limits.
- RL-12: Installed acceptance uses the actual product installer and intended
  service/data path. Temporary scaffolding cannot certify install or reboot behavior.
- RL-13: Resolve credentials by the target's catalog reference. Never print
  credentials to diagnose routing or reuse another machine's secret variable.
- RL-14: Normalize platform paths for the external tool receiving them and
  capture both output streams when that tool fails.
- RL-15: Stop only owner-verified run processes or the declared service.
  Do not use broad process-name patterns that can kill a transport or unrelated work.
- RL-19: Build artifacts from the claimed source, assert structured live
  capability state and keep resource ownership explicit. Revalidate affected
  paths after changes; do not rerun unrelated matrices without a reason.

## Evidence and recovery

- RL-9: Capture diagnostics even when a harness fails before producing a report.
- RL-16: Negative cases assert exit status and output together. Expected refusal
  is evidence, not an automatic harness abort.
- RL-17: Preconditions fail with named reasons. After an interrupted run, verify
  cleanup and acquire a fresh owned run before retrying.
- RL-18: Reproduce fixes through the actual shipped/fixture path. A successful
  hand-written probe does not prove the application's configured URL or transport.

Use [proof receipts](launch/proof.md) and the [fleet protocol](../fleet/PROTOCOL.md).
Preserve durable settings and identity material, retain restoration ownership,
and never claim native acceptance from an unobserved or mocked result.
