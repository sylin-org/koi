# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02 through `a34be05`): the installed product-path SCM service
has physically closed provider truth, Bonjour read fidelity, the base standard-port
ADR-040 boundary, wrong-user rejection, breadcrumb independence, dead-session drain,
ordinary failed-candidate rollback, Pond routes/stop/restart, executable/profile-aware
firewall applicability, and cooperative DNS. Those Pond/DNS journey results stand; the
firewall rollback path was not exercised by that successful run.

## PH-001 next dispatch (after `a34be05`)

1. Start now by finishing one interruption-safe Windows install transaction across SCM,
   files, operator policy, ports, and firewall. Every manifest transition must be
   fallible and durably precede its corresponding external mutation; never discard a
   manifest-write error, including `set_http_port`, `mark_rule_created`, and
   `mark_service_created`. Capture either the complete prior SCM descriptor or an explicit
   canonical Koi-owned descriptor, preserve quoted arguments losslessly, close service
   handles before delete/recreate, recreate an expected-but-missing prior service, reapply
   lifecycle policy after recreation, and verify the SCM process image/PID as well as
   `/healthz` before committing. Deterministic interruption tests and a real installed
   recovery run must cover each irreversible boundary, including recreation; the
   signature fallback in `issues/001-scm-service-object-wedge.md` is not closed merely
   because the original wedge did not recur.
2. Keep firewall assessment, snapshot, restoration, and ownership in one typed Windows
   adapter. Fail closed when NetSecurity cannot answer; correlate port, application, and
   profile filters per individual rule; preserve at least enabled/direction/action/
   protocol/ports/program/profile without translating `Inbound` into invalid `netsh`
   vocabulary or widening a restored rule to every profile. Physically force rollback
   over non-default profile-scoped Koi rules and prove semantic equality plus no residue.
   Do not repeat the already-green Pond/DNS journey except where this rollback changes
   its artifact or the final candidate requires it.
3. Resolve `issues/002-credential-store-test-leak.md` as a shared product ownership bug,
   not a Windows-only cleanup script. A TOTP slot owns every platform credential label it
   creates; replace, remove, failed persistence, and certmesh destroy must retire exactly
   those labels without enumeration or foreign-entry risk. Real-store tests use scoped
   cleanup that survives failures. Prove repeated suites and every currently exposed slot
   lifecycle leave the Windows credential count at baseline; do not add a product endpoint
   solely to make an acceptance test possible.
4. Then close the shifted-port ADR-040 pipe path and the installed workbench's fresh-login,
   tray, notification, Phone/Pond, lock/resume, upgrade, and uninstall/reinstall gates;
   standard-port pipe evidence is not a substitute.
5. Finally coordinate the installed mDNS/NIC/profile/lock/sleep gate with Avahi and native
   physical peers, preserving one Koi and exact host restoration throughout.

Use one serial PowerShell installed-acceptance workbook and one evidence directory,
not a script or helper daemon per capability. Capture local recovery before NIC or sleep
tests because SSH cannot restore a disconnected workstation. Verified Bonjour MSI
product identities are run-owned; protected Dnscache and LLMNR policy are not mutation
targets.
