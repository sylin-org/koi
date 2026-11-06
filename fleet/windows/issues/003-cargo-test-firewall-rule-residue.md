# Windows test firewall ownership

Windows can create automatic TCP/UDP application firewall rules when newly built
debug/test executables bind listeners. A passing test process does not prove that it
left host firewall state unchanged.

A native verification run must prevent this where practical or snapshot rules for
the exact executables it will produce, retain rule/filter identities, and remove only
current-run additions. Protect installed product rules, rules for other application
paths, and entries whose ownership cannot be proved. Do not mass-delete rules under
repository target directories.

Cleanup of pre-existing residue needs a separately bounded assignment and before
snapshot. Record the current run's restoration result in
[the launch ledger](../../launch/LEDGER.md), following
[the protocol](../../PROTOCOL.md). This is a test-host hygiene constraint, not proof
that the current installed product has a lifecycle defect.
