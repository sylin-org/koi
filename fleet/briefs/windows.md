# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02 through this commit): the installed product-path SCM service
has physically closed provider truth, Bonjour read fidelity, the base standard-port
ADR-040 boundary, wrong-user rejection, breadcrumb independence, dead-session drain,
ordinary failed-candidate rollback, interruption recovery through expected-missing SCM
recreation, complete descriptor/lifecycle restoration, pre-config recovery, profile-exact
firewall rollback, Pond routes/stop/restart, executable/profile-aware firewall
applicability, and cooperative DNS.

## PH-001 next dispatch (after this commit)

1. Start now by consolidating firewall assessment, snapshot, restoration, and ownership
   into one typed Windows adapter shared by the installer and Pond. NetSecurity already
   fails closed and the installed rollback physically preserved enabled/direction/action/
   protocol/ports/program/profile over a Private-only rule with semantic equality and no
   residue; retain those facts while removing the remaining duplicate assessment seam.
   Do not repeat the already-green Pond/DNS or destructive rollback journeys unless the
   consolidation changes their artifact.
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
