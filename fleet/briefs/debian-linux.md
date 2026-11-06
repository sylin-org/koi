# Debian headless peer verification

Host: `stone-halcyon-savanna`. Repository: `~/repos/github/sylin-org/koi`.
Platform: headless Debian, systemd. This is a weak thin client.

Start at [the fleet task](../task.md). Execute only a bounded request addressed in
[the launch ledger](../launch/LEDGER.md) under
[Epic 004](../epics/004-container-lan-adoption.md). CachyOS owns implementation.

Allowed assignments favor short installed CLI/API checks, name-resolution observations,
a real application request to an addressed physical peer, or another lightweight
headless native check. Do not assign feature work, full-workspace build/test/clippy,
cross-target matrices, release builds or sustained stress/soak. Required checks run
on an appropriate executor; this does not waive necessary physical Debian evidence
for a Debian-specific claim.

Inspect the real installation, identity, configuration and any intentionally shifted
ports. Preserve them unless the addressed assignment explicitly migrates that state.
Use the single installed service and ordinary headless client path. Own only this
host's native mutations, capture restoration first, and report unavailable capabilities
honestly.

This role does not start peer hosts or expand initial preview scope. Follow the
[protocol](../PROTOCOL.md); all new launch proof starts pending.
