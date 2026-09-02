# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02 through `8042821`): the installed product-path SCM service
has physically closed provider truth, Bonjour read fidelity, the base standard-port
ADR-040 boundary, wrong-user rejection, breadcrumb independence, dead-session drain,
ordinary failed-candidate rollback, interruption recovery through expected-missing SCM
recreation, complete descriptor/lifecycle restoration, pre-config recovery, profile-exact
firewall rollback, Pond routes/stop/restart, executable/profile-aware firewall
applicability, and cooperative DNS. The exercised v2 path is sound evidence; it does not
prove deserialization of a real v1 manifest or rollback behavior when firewall deletion
itself fails.

## PH-001 next dispatch (after `8042821`)

1. Start now by finishing one typed Windows firewall adapter shared by installer,
   rollback, uninstall, and Pond assessment. Preserve the green v2/private-profile proof,
   then close both unexercised transaction edges:

   - deserialize fixtures containing the actual v1 wire shape, not a v2 structure whose
     version field was changed in memory. A v1 firewall snapshot never stored `profile`;
     recover only when prior semantics are provable. Otherwise retain manifest/backups,
     stop before further mutation, and report the precise recovery boundary—never default
     the missing profile to `Any` or claim all v1 manifests are recoverable;
   - replace boolean/best-effort rule deletion with a typed `removed | absent | error`
     result. Propagate errors before replacement and throughout rollback/uninstall so a
     failed delete cannot leave duplicates, widen access, or be followed by a false
     successful restoration.

   Keep each rule's application/port/profile filters correlated, keep NetSecurity errors
   fail-closed, and remove the duplicated Pond assessment seam. Add raw legacy-JSON and
   command-failure regressions, then physically rerun only the firewall rollback slice on
   the installed service and prove semantic equality plus zero residue. The already-green
   Pond/DNS journey need not be repeated unless this consolidation changes its behavior.
2. Resolve `issues/002-credential-store-test-leak.md` as a shared product ownership bug,
   not a Windows-only cleanup script. A TOTP slot owns every platform credential label it
   creates; replace, remove, failed persistence, and certmesh destroy must retire exactly
   those labels without enumeration or foreign-entry risk. Real-store tests use scoped
   cleanup that survives failures. Prove repeated suites and every currently exposed slot
   lifecycle leave the Windows credential count at baseline; do not add a product endpoint
   solely to make an acceptance test possible.
3. Then close the shifted-port ADR-040 pipe path and the installed workbench's fresh-login,
   tray, notification, Phone/Pond, lock/resume, upgrade, and uninstall/reinstall gates;
   standard-port pipe evidence is not a substitute.
4. Finally coordinate the installed mDNS/NIC/profile/lock/sleep gate with Avahi and native
   physical peers, preserving one Koi and exact host restoration throughout.

Use one serial PowerShell installed-acceptance workbook and one evidence directory,
not a script or helper daemon per capability. Capture local recovery before NIC or sleep
tests because SSH cannot restore a disconnected workstation. Verified Bonjour MSI
product identities are run-owned; protected Dnscache and LLMNR policy are not mutation
targets.
