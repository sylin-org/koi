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
| PH-0 | Freeze and reconcile the product contract | **green at frozen source** | Every advertised capability, OS, artifact, and install path maps to a current real gate or an explicit unverified/unsupported state; stale claims are corrected. |
| PH-1 | Platform truth and durable lifecycle | **green fleet-wide** | Clean install, in-place upgrade, failed-upgrade recovery, reboot, uninstall, and reinstall use product-owned paths and preserve intended identity/configuration. |
| PH-2 | Environmental recovery | **green fleet-wide** | Process crash, provider loss/return, link/IP churn, firewall change, runtime disconnect, boot, lock, and sleep/resume recover without duplicates or manual re-arming. |
| PH-3 | Security-boundary hardening | **green fleet-wide** | Local-control identity, Pond allowlist, operator auth, installer privilege, key custody, hostile LAN input, and resource bounds have executable negative gates; no unresolved critical/high finding remains. |
| PH-4 | Installed whole-story matrix | **active — source re-frozen at `9134b32c87db990f18b09c56038d8c6255607ffa`** | One frozen source revision completes Find → Name → Trust → Serve/Pond using installed artifacts across physical OS/provider families. |
| PH-5 | Onboarding, diagnostics, and soak | collector ready; waits on PH-4 | Fresh users reach a useful result without checkout/toolchain paths; the exact candidate survives a preferably 24-hour mixed-OS soak with bounded resources and exact restoration. |

### 2026-09-03 PH-4 source re-freeze and execution contract

The exact Koi source candidate is
`9134b32c87db990f18b09c56038d8c6255607ffa`. It is already present on
`origin/dev`. Every PH-4 daemon/package artifact must be built from a clean export or
detached worktree of that commit, even while later journal and dispatch commits advance
`dev`. Record both the full source SHA and installed artifact SHA-256. Existing native
workbench artifacts may remain only where their own source and installed bytes are
unchanged; record that separate provenance explicitly.

This supersedes and invalidates `f53d568a871e952576988e543126160bfd41aaaa`.
Windows's installed PH-4 transaction proved that the proxy API persisted its supported
`[proxy]` section into the shared `config.toml`, while that same candidate's strict
launch parser rejected the section during the next install or restart. The shared
parser now recognizes and validates the proxy-owned schema without weakening unknown
top-level-key rejection. Any PH-4 artifact or local verdict built from the invalidated
source must be rebuilt and rerun from the exact re-freeze above.

PH-0 through PH-3 are reconciled green at this boundary. Their final pre-freeze input
includes the accepted Windows SCM recovery correction, Bluefin immutable reboot,
Debian and Alpine ownership-aware installs, and CachyOS runs
`20260903T041144Z-866860` (Avahi/resolve1/native) and
`20260903T041803Z-869519` (Pond through Bluefin). Full native tests, strict clippy,
surface/documentation/publish/embedded checks, one-process invariants, and exact host
restoration are green. The first Pond diagnostic run is deliberately excluded because
its old harness wrote PASS before verifying cleanup; the accepted rerun used the
restoration-gated workbook in the frozen commit.

PH-4 uses the real installed service and production ports. Its whole-story transaction
drives authenticated local control and public product APIs against run-owned resources
on the standing deployment. It must not use the legacy `koi-lab capability-story` mode
as acceptance: that older mode stops standing services and launches isolated daemons.
Preserve an existing enrolled identity rather than reinitializing certmesh merely for a
test. Compose Find → Name → Trust → Serve/Pond through real workload/discovery,
DNS/mDNS, current trust diagnosis and certificate paths, health/proxy where supported,
and the narrow peer-read Pond surface; report a genuinely unavailable optional adapter
without disabling independent routes.

Local artifact installation may proceed concurrently across machines; destructive
cross-host provider/network work remains serial and each hat mutates only its own OS.
CachyOS coordinates the shared run IDs after peers publish artifact-ready evidence.
Windows↔Avahi, Windows↔native, and Avahi/resolve1↔native are the minimum provider
rotations. Every participant also proves withdrawal and exact restoration, while each
Pond subject is read from an independent physical host. No second Koi, fake endpoint,
alternate acceptance port, or checkout deployment is permitted.

Evidence-only, harness-only, journal, and dispatcher commits after the freeze do not
move the candidate. Any correction to product code, dependencies, installer/package
recipes, or shipped assets invalidates it: update this section with one new exact SHA,
rebuild every affected artifact, and rerun the affected PH-4 slices. Never silently
test different revisions under the same candidate name. PH-5 starts only after all five
hat journals show the frozen artifact and PH-4 is reconciled green.

### 2026-09-03 convergence checkpoint

Windows, CachyOS, Bluefin, Debian, and Alpine have closed their current local PH-2/PH-3
physical gates. Alpine has also closed package ownership, transactional OpenRC
supervision, the native musl foundation, and its installed Plasma/session lifecycle.
The two shared
corrections formerly owned by the CachyOS integration driver landed in `41ad76b`:

1. Linux install planning must distinguish the Koi deployment being replaced from a
   genuinely foreign port owner. Systemd and OpenRC must preserve an existing
   explicit or effective port run without manufacturing a shifted configuration,
   while a fresh install must still coexist with a real incumbent.
2. A `systemd-resolved` publication must own conflict observation for its complete
   lease. The initial quiet-settlement window may acknowledge establishment, but a
   later `Conflicted` signal or lost signal channel must invalidate the materialized
   publication and drive ordinary provider reconciliation rather than leave Koi
   reporting a withdrawn record as established.

CachyOS accepted both corrections on its one real deployment: an in-place upgrade
kept `5641:5644` without creating a config, a deliberately unhealthy candidate
restored the exact prior deployment, and physical run
`20260903T000933Z-837819` observed a late resolve1 conflict as
`desired=3, established=1, pending=2` before automatic recovery to `3/3/0`.
The Koi PID stayed fixed and both hosts' provider state was restored exactly.
CachyOS then retained that daemon and its one packaged Plasma workbench through
lock/unlock, primary-interface loss/return, and a real suspend/resume. A fresh
Plasma Login Manager session armed exactly one minimized workbench from its native
package, and an unrelated UID remained outside authenticated local control.

Alpine has also closed its provider/interface recovery gate on the installed OpenRC
service: physical run `20260903T014605Z-1730` held one daemon through
`avahi → native → avahi`, restored installed-but-stopped Avahi, and recovered a
pre-armed primary-interface down/up cycle with bidirectional Debian-peer discovery
and withdrawal. Alpine's local PH-3 gate is also closed: an unrelated UID was denied
at the owner-private socket, and two bounded Debian-origin hostile-input passes left
PID, resources, native routes, and publication state stable while every excluded
Pond/operator route stayed unreachable. Alpine then accepted the ownership-aware
installer on dated APK source `32172ba`: its standing `5651:5654` decision survived
ordinary indexed upgrade, a deliberately unhealthy candidate restored the exact
accepted deployment, and the full locked musl plus physical Debian-peer Pond gates
passed. Alpine's dispatch is complete and its exact installed APK/index are retained
as a PH-4 candidate. Debian accepted the shared installer decision on its one real
deployment. Bluefin's install, rollback, serial real-incumbent, and immutable reboot
activation phases are green. Windows accepted the same final-before-mutation contract
through SCM: its owned no-config deployment retained the standard run, an unhealthy
`StartPending` candidate rolled back exactly after image-verified termination, and a
serial real foreign listener moved a genuinely fresh install to `5651:5654` before
the intended standard deployment was restored without residue.
Debian prepared the reusable PH-5 collector without starting the soak. CachyOS then
accepted the generalized systemd provider and Pond workbooks, reconciled PH-0 through
PH-3, and froze the exact PH-4 source named above.

### Pre-freeze critical path — complete

1. **Fleet PH-1 acceptance closed.** Bluefin, Windows, and Debian published their final
   ownership-aware installed lifecycle verdicts on `dev`; Alpine and CachyOS had
   already accepted the same shared decision.
2. **The integration regression closed.** CachyOS passed the generalized systemd
   provider and corrected Pond workbooks against Bluefin with one installed Koi per
   host and exact restoration.
3. **PH-0 through PH-3 reconciled.** All five hats' public-contract, lifecycle,
   recovery, and adversarial evidence is green; the surface ledger and repository
   contract gates pass.
4. **Freeze handed off to PH-4.** The exact source is named above. Every hat now installs
   its artifact from that revision and owns its system mutations; CachyOS drives the
   serial cross-provider/Pond matrix. The long soak remains gated on PH-4.

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
- Windows local PH-2 gate green on 2026-09-02: one installed candidate retained its PID
  through Windows DNS-SD reads/native publication, verified Bonjour promotion/loss/return,
  Public/Private categories, primary-NIC disable/enable, lock, and real S3 resume while
  unchanged CachyOS/Avahi and Alpine/native peers provided bidirectional publications and
  reads. Provider packages, profile/link state, Dnscache/LLMNR policy, recovery tasks, and
  peer registrations restored exactly.

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
- Local PH-2/PH-3 workbook green on 2026-09-02: the one installed service survived
  Avahi/resolved/native loss and return, pre-armed primary-link/address churn, real
  independent-peer Pond allowlist and negative-route checks, and bounded hostile
  DNS/mDNS/HTTP input with stable process/resource bounds. Debian correctly reported
  that neither UFW nor firewalld was active and made no acceptance-only firewall change.

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
