# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-01): one installed SCM service physically proved ADR-039
native publication, official Windows DNS-SD browse/resolve, and live Bonjour
appearance/promotion/loss/uninstall against an Avahi peer. That installed candidate
predates ADR-040, ADR-042, and current `dev`; high-port Windows lab-daemon evidence is
regression input, not acceptance for today's installed product.

## PH-001 assignment

1. Correct provider truth first. `EnableMulticast` is documented LLMNR policy, not an
   mDNS switch. Remove that inference, narrow required DNSAPI exports to the operations
   actually used, and complete Bonjour address/interface/domain fidelity through its
   single-owner session.
2. Make `koi install` a transactional fixed-product-path SCM upgrade with a verified
   health cutover and rollback of the prior binary, service config, operator policy,
   and exact Koi-owned firewall rules. Never leave SCM pointing into a checkout.
3. Close authenticated local control under the installed LocalSystem service: intended
   operator, SYSTEM, and Administrators follow the declared DACL contract; another
   ordinary account is denied; shifted discovery/events/mutations and session drain use
   the named pipe without reading the system breadcrumb.
4. Close Pond and cooperative DNS physically. Firewall assessment includes executable,
   port, direction, action, and active profile. Koi does not modify ICS, system DNS, or
   protected Dnscache to obtain a green result.
5. Coordinate the installed mDNS resilience gate with CachyOS Avahi and Alpine native
   peers: verified Bonjour install/promotion/stop/fallback/restore/uninstall, NIC churn,
   profile facts, lock, and sleep/resume, with one unchanged Koi and exact rollback.
6. Install and exercise the real workbench through upgrade, fresh login, tray,
   notification, Phone/Pond start/stop, lock/resume, uninstall/reinstall, and
   sustained soak.

Use one serial PowerShell installed-acceptance workbook and one evidence directory,
not a script or helper daemon per capability. Capture local recovery before NIC or sleep
tests because SSH cannot restore a disconnected workstation. Verified Bonjour MSI
product identities are run-owned; protected Dnscache and LLMNR policy are not mutation
targets.
