# Cargo test firewall-rule residue

Status: open

Opened: 2026-09-02 during the PH-0 advertised-contract reconciliation.

## Observation

Running the locked workspace test suite on Windows can cause Windows Defender Firewall to create automatic TCP and UDP application rules when freshly built debug executables bind listeners. The PH-0 run created one exact pair for:

`F:\Replica\NAS\Files\repo\github\sylin-org\koi\target\debug\koi.exe`

Those two current-run filters were identified by their exact application path and filter IDs, removed, and a repeat query verified zero remaining filters for that executable. The installed product rules and their `C:\Program Files\Koi\koi.exe` application path were not changed.

An inventory also found 204 automatic application filters whose paths are confined to `target` directories beneath the Koi and Koi Desktop worktrees. They predate this run and span historical build hashes and test executables. They were deliberately not mass-deleted because no before-run ownership snapshot exists for them.

## Required follow-up

1. Make the Windows test harness prevent these interactive automatic rules where possible, or snapshot and restore rules associated with the exact executables produced by the current run.
2. Perform a separately authorized, bounded cleanup of historical target-root automatic rules only after capturing a before snapshot and proving that no installed product rule is in scope.
3. Keep explicit guards for the product-managed DNS, HTTP, mDNS, and Pond rules and for every rule whose application path is outside the two repository target roots.

This is host hygiene and test-harness residue, not evidence of an installed Koi lifecycle defect. The current PH-0 installed service and workbench were left unchanged.
