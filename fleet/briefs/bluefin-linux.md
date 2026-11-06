# Bluefin verification

Host: `bluefin`. Repository: `~/repos/github/sylin-org/koi`.
Platform: immutable Fedora/Bluefin, glibc, systemd.

Start at [the fleet task](../task.md). Execute only an explicitly addressed native
request in [the launch ledger](../launch/LEDGER.md) under
[Epic 004](../epics/004-container-lan-adoption.md). CachyOS owns source integration.

Build dependencies belong in the dedicated `koi-dev` toolbox. Install runtime
artifacts only through their supported host paths. Package/image activation,
rollback and reboot requirements follow the immutable platform; a toolbox process
does not prove a host installation.

Capture actual service/package, configuration, ports, provider and firewall state.
Own only this host's mutations, keep one installed Koi, and restore unrelated state.
Use physical peer evidence for any LAN application or client-trust claim. A native
desktop check needs its separate durable installed artifact and explicit assignment.

This additional distribution can validate an addressed claim without creating a
broad immutable-desktop prerequisite for the initial Windows/Linux preview.
Apply the [protocol](../PROTOCOL.md); all new launch results start pending.
