# Alpine verification

Host: `test-03`. Repository: `~/repos/github/sylin-org/koi`.
Platform: Alpine, musl, OpenRC.

Start at [the fleet task](../task.md). Execute only an Alpine verification request
addressed in [the launch ledger](../launch/LEDGER.md) under
[Epic 004](../epics/004-container-lan-adoption.md). CachyOS owns source integration.

Use native musl and supported APK/OpenRC paths for an installed claim. Record package
and binary hashes, service/supervisor identities, runtime/provider versions, ports
and relevant configuration. Do not substitute glibc behavior, another distribution's
service controls or unavailable counters.

Inspect and preserve the standing installation and actual provider enablement before
mutation. Keep one Koi and restore only current-run changes. A provider installed on
disk is not proof it is the active discovery source. Physical peers prove network
behavior; local binding alone does not.

Existing musl compile/test/artifact obligations remain in repository release policy.
An Alpine user-workflow claim is added after targeted demonstration; it is not a
default all-desktop prerequisite for the initial preview. Follow the
[protocol](../PROTOCOL.md), with new launch proof pending.
