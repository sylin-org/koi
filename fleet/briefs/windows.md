# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02 through `0026951`): the installed product-path SCM service
has physically closed provider truth, Bonjour read fidelity, the base standard-port
ADR-040 boundary, wrong-user rejection, breadcrumb independence, dead-session drain,
ordinary and interrupted installer recovery, complete SCM descriptor/lifecycle recovery,
profile-exact firewall rollback, Pond routes/stop/restart, executable/profile-aware
firewall applicability, cooperative DNS, and exact TOTP credential ownership/cleanup.
`c9cba31` closed the real-v1 and failed-firewall-deletion boundaries through one typed
adapter; `0026951` closed the shared slot-lifecycle leak. Do not repeat those destructive
workbooks unless later implementation changes their behavior.

## 2026-09-02 next dispatch (after `0026951`)

1. Close the two remaining Windows firewall-truth seams found in the independent
   post-merge review:

   - remove the separate `netsh` text/substring scan in
     `platform::windows::check_firewall`. Startup diagnostics must consume the same typed
     `koi_serve::windows_firewall` assessment as Pond, including `open`, `inactive`, both
     blocked reasons, and query failure. There is one firewall interpretation boundary;
     do not retain a compatibility parser or add another command runner;
   - canonicalize connection categories inside that adapter before making a verdict.
     `Get-NetConnectionProfile` reports a domain network as `DomainAuthenticated`, while
     Windows Firewall names the corresponding profile `Domain`. Map those identities
     explicitly, keep `Private`/`Public` exact, and fail closed on an unknown category.
     Determine applicability from the active networks: if no active network uses an
     enabled firewall profile, report `Inactive`; do not infer activity merely because a
     different, inactive-network profile is enabled globally.

   Add deterministic adapter regressions for `DomainAuthenticated -> Domain`, an active
   profile whose firewall is disabled while another profile is enabled, mixed active
   profiles, and unknown categories. Preserve per-rule application/port/profile
   correlation and the existing command-failure behavior. Run the native gates and full
   Windows target gates, deploy the exact candidate through the normal product path, and
   exercise only the affected installed startup-diagnostic/Pond assessment slice against
   the real current profile. This is an observation test: do not mutate firewall or domain
   policy to manufacture a green state. Record the authoritative Microsoft profile
   semantics and prove one installed Koi plus zero residue.
2. Then close the shifted-port ADR-040 pipe path and the installed workbench's fresh-login,
   tray, notification, Phone/Pond, lock/resume, upgrade, and uninstall/reinstall gates;
   standard-port pipe evidence is not a substitute.
3. Finally coordinate the installed mDNS/NIC/profile/lock/sleep gate with Avahi and native
   physical peers, preserving one Koi and exact host restoration throughout.

Use one serial PowerShell installed-acceptance workbook and one evidence directory,
not a script or helper daemon per capability. Capture local recovery before NIC or sleep
tests because SSH cannot restore a disconnected workstation. Verified Bonjour MSI
product identities are run-owned; protected Dnscache and LLMNR policy are not mutation
targets.
