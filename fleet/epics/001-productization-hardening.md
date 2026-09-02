# PH-001 — Productization hardening: delight under real conditions

**Status:** active
**Started:** 2026-09-02
**Entry point:** `run fleet/task.md`
**Scope:** Windows, CachyOS, Bluefin, Alpine/musl, and headless Debian

## Objective

Turn Koi's coherent early-beta foundation into an evidence-backed daily driver across
the supported fleet without expanding the feature set. A user should install Koi once,
receive the best facilities already present on the OS, retain a dependable native
fallback, and recover from ordinary machine and network churn without learning Koi's
internal architecture.

This epic hardens the existing Find → Name → Trust → Serve/Pond promise. It does not
add another domain, daemon, updater, provider facade, remote-control plane, generic
plugin system, reflector, telemetry service, or project-management layer.

## Product law

- One DDD-aligned monolith and one real installed Koi per machine.
- Adapters own detection, native resources, capabilities, recovery, and teardown.
- Orchestration owns policy and desired-vs-observed reconciliation.
- Existing OS facilities win when genuinely usable; native Koi is always available at
  lower priority.
- Platform facts come from real operations, not filenames, registry folklore, stubs,
  or optimistic messages.
- Safe expected failures recover automatically. User action is reserved for boundaries
  Koi cannot legitimately cross and names one precise remedy.
- No new advertised capability until this epic closes.

## Dependency map

```text
PH-0 → PH-1 → PH-2 ─┐
  └──────→ PH-3 ────┼→ PH-4 → PH-5
```

PH-0 and PH-1 proceed per hat; one slow OS does not block another's local correction.
PH-3 may run beside PH-1/2 but must close before the frozen-candidate matrix.

| ID | Workstream | State | Exit gate |
|---|---|---|---|
| PH-0 | Freeze and reconcile the product contract | in progress | Every advertised capability, OS, artifact, and install path maps to a current real gate or an explicit unverified/unsupported state; stale claims are corrected. |
| PH-1 | Platform truth and durable lifecycle | ready per hat | Clean install, in-place upgrade, failed-upgrade recovery, reboot, uninstall, and reinstall use product-owned paths and preserve intended identity/configuration. |
| PH-2 | Environmental recovery | waits on local PH-1 | Process crash, provider loss/return, link/IP churn, firewall change, runtime disconnect, boot, lock, and sleep/resume recover without duplicates or manual re-arming. |
| PH-3 | Security-boundary hardening | ready after local PH-0 | Local-control identity, Pond allowlist, operator auth, installer privilege, key custody, hostile LAN input, and resource bounds have executable negative gates; no unresolved critical/high finding remains. |
| PH-4 | Installed whole-story matrix | waits on PH-1/2/3 | One frozen source revision completes Find → Name → Trust → Serve/Pond using installed artifacts across physical OS/provider families. |
| PH-5 | Onboarding, diagnostics, and soak | waits on PH-4 | Fresh users reach a useful result without checkout/toolchain paths; the exact candidate survives a preferably 24-hour mixed-OS soak with bounded resources and exact restoration. |

## Immediate correctness work

These are observed defects, not speculative framework work.

### Windows

1. `windows_dnsapi.rs::multicast_enabled()` treats `DNSClient\EnableMulticast`
   as mDNS policy. [Microsoft's ADMX mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast)
   documents that value as the LLMNR switch. Remove it as an mDNS fact unless a
   genuine Microsoft mDNS authority is found; assess DNS-SD exports, Dnscache
   availability, and real session operations.
   Require only the exports used by the adapter's read routes.
2. Complete Bonjour read fidelity: retain callback interface/domain identity and
   resolve addresses through the native API. Publication, browse, resolve, removal,
   and teardown remain single-owner and acknowledged.
3. Reconcile the named-pipe DACL and peer authorization contract for the recorded
   operator, SYSTEM, and Administrators while continuing to reject an unrelated user.
4. Make SCM installation transactional and product-owned. Do not register a source
   build path. Binary, service config, operator policy, and exact Koi firewall rules
   roll back together after a failed health check.
5. Pond firewall assessment must include active profile and executable/port filters;
   the existence of a display-name match is not an open-path verdict.

### Alpine

1. Replace the workbench's unconditional Linux `systemctl` calls with one small
   service-manager adapter (`Systemd | OpenRC | Unavailable`) that owns assessment,
   status, start, and stop. `Run once` must recognize either installed manager and
   refuse a second Koi.
2. Use OpenRC's native supervision with bounded respawn and health behavior rather
   than an unsupervised background process, following OpenRC's
   [`supervise-daemon` contract](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md).
   Start/enable/health failures make `koi install` fail and restore the prior
   installation; success is not a warning.
3. Produce a native package-owned desktop artifact through `abuild`, with canonical
   entry/icon/runtime dependencies and ordinary `apk upgrade` ownership. Acceptance
   never uses the checkout binary.
4. Bound or rotate daemon logs using the platform's native mechanism.

## Hat assignments

### Windows — first-class Windows control plane

- Land the immediate Windows corrections above on current `dev` and install through
  the real product path.
- Close ADR-040 and ADR-042 through the installed service/workbench: pipe DACL and
  wrong-user rejection, shifted endpoint/events/mutations, narrow Pond routes, exact
  firewall applicability, stop, and SCM restart recovery.
- Exercise cooperative DNS against the real port-53 incumbent without changing ICS,
  adapter DNS, or resolver policy to manufacture success.
- Run a single installed-service provider workbook with CachyOS (Avahi) and Alpine
  (native): Windows DNS-SD reads + native publication; verified Bonjour promotion,
  loss/fallback, and restoration; NIC down/up; Public/Private profile facts; lock and
  sleep/resume. Protected Dnscache and LLMNR policy are not test levers.
- Complete desktop install/upgrade/uninstall, fresh login, tray, notification, and
  one-process gates, followed by an installed-product soak.

### Alpine — retainable musl workstation

- Land the OpenRC, installer-truth, desktop service-manager, APK, and log-lifecycle
  corrections above.
- Prove package install/upgrade/uninstall/reinstall, cold boot, supervised SIGKILL
  recovery, fresh Plasma login, one SNI item, notification, lock/unlock, and exact
  service controls.
- Generalize the focused provider gate by provider/service capability, then prove
  Avahi selection when installed, native fallback on Avahi loss, restoration, primary
  interface churn, and suspend/resume against one unchanged physical peer.
- Re-run full native musl gates and Pond after every shared candidate settles.

### CachyOS — Plasma reference and integration driver

- Keep the Arch package lifecycle, native decoration, Plasma tray/notification,
  autostart, and local-control experience as the desktop reference.
- Prove login/lock/suspend/network churn, UFW blocked→open→restored reconciliation,
  Avahi/resolved/native transitions, and wrong-user/Pond negative boundaries.
- Drive the final cross-host provider and Pond gates on the frozen candidate; do not
  absorb another OS's platform logic locally.

### Bluefin — immutable workstation reference

- Prove RPM build, rpm-ostree upgrade and rollback, reboot, one GNOME-autostarted UI,
  SNI reveal, notification, lock/suspend recovery, and removal without layering build
  dependencies onto the host.
- Exercise firewalld applicability and Avahi/resolved/native recovery after interface
  and service churn. Validate shared fixes independently rather than copying Fedora
  behavior into common policy.

### Debian — headless lifecycle and soak anchor

- Repeatedly prove real install → in-place upgrade → failed-upgrade rollback → reboot →
  uninstall → reinstall, including partial-install and corrupted-state diagnostics.
- Exercise every non-desktop capability through CLI/API/Pond with useful headless
  recovery, and act as the stable peer for workstation absence/recovery.
- Host the long mixed-OS soak evidence collector without replacing installed Koi with
  an isolated lab daemon.

## PH-3 adversarial minimum

- Another ordinary local account cannot cross the Unix socket or named-pipe boundary;
  intended operator/system identities can.
- LAN clients cannot reach operator mutations, excluded Pond reads, OpenAPI, MCP, or
  local-only data through the Pond port.
- Installer rollback cannot weaken ACLs, widen binds, strand firewall rules, replace
  another executable, or report success after a failed start/health check.
- Malformed and hostile mDNS/DNS/HTTP inputs remain bounded and non-fatal; provider
  callbacks cannot outlive reclaimed contexts.
- Secrets never enter argv, journals, evidence bundles, URLs, or public status. Final
  evidence explicitly attests redaction.

## Frozen-candidate exit matrix

PH-4 freezes one `dev` commit after all fixes land. Every host installs an artifact
built from that revision and records source SHA, platform artifact SHA-256, installed
path/owner, service identity, PID, and desktop PID where applicable.

The epic cannot close until:

1. Windows↔Avahi, Windows↔native Koi, and Avahi/resolved↔native Koi prove bidirectional
   publish, browse, resolve, address/TXT/interface data, withdrawal, provider loss, and
   exact restoration through installed Koi APIs.
2. Every advertised capability completes a physical composed journey on its supported
   OS or reports a precise unavailable state without disabling an independent route.
3. Desktop hats pass boot/login, tray, notification, local control, Phone/Pond,
   close/reopen, lock/unlock, suspend/resume, and duplicate-process/item checks.
   Debian passes equivalent boot/operator/Pond checks without a GUI.
4. Install, upgrade, rollback, uninstall, and reinstall use durable product paths on
   every claimed OS. No checkout path survives into a service or login entry.
5. A minimum six-hour soak, with 24 hours required for release-quality evidence,
   samples RSS, handles/descriptors, threads, cache size, provider generations, retry
   rate, desired/established counts, process identity, and cross-host traffic while
   executing controlled faults.
6. Full native gates rerun after the soak; temporary provider, package, firewall,
   resolver, login, network, credential, and test state is absent or byte-exactly
   restored. Each machine retains exactly its intended healthy Koi deployment.

macOS has no physical hat in this fleet. Cross-compilation may remain green, but macOS
must be described as unverified/preview until a real launchd/login/provider lifecycle
meets the same contract.

## Coordination and evidence

Every agent starts with `fleet/task.md`, researches its own OS, fixes shared contracts
at the shared boundary, commits directly to `dev`, rebases on push races, and leaves no
orphan branch or local-only commit. Cross-host system mutations are serial; the host's
own hat owns them. The peer supplies run-owned API traffic and observations.

One meaningful physical run needs one journal entry: PH ID, source/artifact identities,
PIDs, peers/run ID, verdict, important observation, exact restoration result, final
installed state, and fix commit or unresolved issue. Issues are for residue only.
`docs/SURFACES.md` changes when a public claim changes. This epic table changes only
when a whole gate closes.

External signing, registry publication, package-manager submission, tagging, and a
public release remain separate operator-authorized actions. Their absence is reported
truthfully and never papered over with an unsigned-success claim.
