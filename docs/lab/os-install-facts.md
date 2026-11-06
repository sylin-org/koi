# Native installation checks

Use the current [fleet catalog](../../tools/koi-lab/lab.json) to identify test
machines and [fleet routing](../../fleet/task.md) for authority. Re-observe the
machine before testing; a stored address, desktop name or old installation
transcript does not prove its current state.

For each claimed platform, verify:
- the actual installer/service manager, operator identity and required elevation;
- one intended running Koi, its executable/hash/PID and durable data location;
- atomic replacement, restart, reboot, upgrade and interrupted-install recovery;
- exact Koi-owned firewall, resolver, trust-store and session changes;
- normal second-device access to the real application;
- restoration and cleanup of temporary resources.

Use systemd, OpenRC, launchd and Windows SCM only on hosts that actually provide
them. Keep build dependencies off immutable OS deployments when an isolated
build environment is available. The weak Debian peer performs bounded checks,
not heavy build/stress work.

No platform case is accepted by this checklist alone. Record
[a proof receipt](../launch/proof.md) for the selected candidate.
