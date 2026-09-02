# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02): the installed product-path SCM service has physically
closed provider truth, Bonjour read fidelity, the base ADR-040 named-pipe boundary,
wrong-user rejection, breadcrumb independence, and dead-session drain on the standard
endpoint. The SCM service-object wedge remains open, the new pipe probe did not exercise
a shifted endpoint, and Pond/cooperative-DNS/workbench/resilience gates remain.

## PH-001 next dispatch (after `3a5a6d1`)

1. Start now with the SCM lifecycle architecture. Reproduce and isolate
   `issues/001-scm-service-object-wedge.md`; arm durable recovery before the first
   service stop; make service inspection fail closed; snapshot and restore the semantic
   SCM configuration rather than treating the raw launch command as a path; retain
   manifest/backups until restored start, identity, and health all pass. A delete/recreate
   fallback is acceptable only after the service descriptor is complete and the wedge
   trigger or discriminating failure is physically understood.
2. Make firewall snapshot/applicability independent of localized `netsh` labels and
   close Pond plus cooperative DNS through the one installed service. Assess executable,
   port, direction, action, and active profile; do not modify ICS, system DNS, protected
   Dnscache, or LLMNR policy to manufacture success.
3. Re-run the destructive failed-candidate transaction and prove `koi install` alone
   restores a healthy product-path service with no residue. Then close the shifted-port
   ADR-040 pipe path and the installed workbench's tray/notification/Phone/Pond path;
   standard-port probe evidence is not a substitute.
4. After those corrections settle, coordinate the installed mDNS/NIC/profile/lock/
   sleep gate with Avahi and native physical peers, preserving one Koi and exact host
   restoration throughout.

Use one serial PowerShell installed-acceptance workbook and one evidence directory,
not a script or helper daemon per capability. Capture local recovery before NIC or sleep
tests because SSH cannot restore a disconnected workstation. Verified Bonjour MSI
product identities are run-owned; protected Dnscache and LLMNR policy are not mutation
targets.
