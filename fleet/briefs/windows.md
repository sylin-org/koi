# Hat: windows (stone-leaded-sparkle, Windows workstation)

Repo: the Windows checkout containing this file. You are both the fleet orchestrator
and the Windows product reference. Those roles do not grant permission to mutate
another hat's system state.

Measured evidence (2026-09-02 through `97a0817`): the installed product-path SCM service
has physically closed provider truth, Bonjour read fidelity, the base standard-port
ADR-040 boundary, wrong-user rejection, breadcrumb independence, dead-session drain,
ordinary and interrupted installer recovery, complete SCM descriptor/lifecycle recovery,
profile-exact firewall rollback, Pond routes/stop/restart, executable/profile-aware
firewall applicability, cooperative DNS, and exact TOTP credential ownership/cleanup.
`c9cba31` closed the real-v1 and failed-firewall-deletion boundaries through one typed
adapter; `0026951` closed the shared slot-lifecycle leak; `97a0817` made startup and Pond
consume the same batched verdict and canonicalized connection categories. Do not repeat
those destructive workbooks unless later implementation changes their behavior.

## 2026-09-02 next dispatch (after `97a0817`)

1. Finish effective Windows Firewall truth. The assessment path currently calls
   `Get-NetFirewallProfile` and `Get-NetFirewallRule` without `-PolicyStore ActiveStore`,
   so it reads the default local `PersistentStore` rather than the effective resultant
   policy after Group Policy and other applicable stores. Query `ActiveStore` for both
   assessment inputs and their associated filters; otherwise Pond/startup can report
   `Open` for a locally installed rule that organizational policy does not actually
   admit. Keep installer snapshot, replacement, deletion, and rollback explicitly scoped
   to Koi's local persistent rules—this change belongs only to read-side applicability.
   Add a command-shape regression that prevents either assessment query from silently
   reverting to the default store, preserve typed/fail-closed outcomes, then run the
   affected live installed assessment slice without changing policy. Record the effective
   store/profile facts and restore the prior Pond desire.
2. Remove the test harness race exposed by the ordinary parallel workspace gate in the
   `two_daemon_certmesh` suite. `free_port()` currently binds port zero, returns the
   number, and drops the listener before the child daemon binds it; concurrent tests can
   claim the same port. Replace that check-then-use helper with a small RAII reservation
   owned for each daemon's lifetime (distinct HTTP/mTLS ports, released on failure, panic,
   and normal drop), and serialize only the unavoidable allocate-and-spawn handoff if the
   cross-platform child-process boundary requires it. Do not serialize the whole suite,
   weaken the five-second readiness contract, add sleeps, or merely retry a collision.
   Detect early child exit and retain actionable stderr so a real startup failure is not
   mislabeled as a listener timeout. Prove the exact test binary and full
   `cargo test --locked` pass repeatedly with default parallelism on Windows; the serial
   suite is diagnostic evidence, not the acceptance gate.
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
