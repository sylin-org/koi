# Windows verification

Host: `stone-leaded-sparkle`. Repository: the Windows checkout containing this file.
Platform: Windows x64; the initial scenario uses Docker Desktop.

Start at [the fleet task](../task.md). Execute only a Windows verification request
addressed in [the launch ledger](../launch/LEDGER.md) for
[Epic 004](../epics/004-container-lan-adoption.md). CachyOS integrates source fixes.
Windows capacity may support compatible native checks when requested.

Prove the supported artifact through the installed SCM service and ordinary client
path. Record the actual Docker Desktop/backend version, network profile, provider,
firewall decision, installed binary hash and PID. Use an independent physical
Linux/client peer for the real application operation. A localhost request does not
prove LAN access or container discovery.

Before changing service, trust, firewall or network state, capture and arm exact
restoration. Preserve the one Koi deployment and product-owned rules; remove only
current-run temporary artifacts. Current checks must account for
[SCM recovery](../windows/issues/001-scm-service-object-wedge.md) and
[test firewall ownership](../windows/issues/003-cargo-test-firewall-rule-residue.md).
Do not run destructive reproduction work without its addressed native assignment.

Follow the [protocol](../PROTOCOL.md). No native proof is inherited into the new
launch ledger merely because an earlier artifact worked.
