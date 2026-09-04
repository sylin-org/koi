# fleet/coordination.md — the shared campaign map

This is the shared campaign map; [`fleet/task.md`](task.md) is the only agent
entry point. The Windows workstation (`stone-leaded-sparkle`) may launch sessions
and watch the shared `dev` branch, but it does not manufacture another hat's prompt
or perform that hat's system mutations. KISS: one branch (`dev`), direct
authenticated pushes from every agent, no patch harvesting and no orphan branches
or local-only commits. A hat's work is not complete until its commit is present on
`origin/dev`.

Every agent receives the same prompt: **`run fleet/task.md`**. That file resolves
the local hostname, loads the current epic and native brief, and executes the first
unfinished dependency-ready assignment. Do not assemble per-hat prompts.

## The hats

One machine, one hat, one specialty. A hat has exclusive ownership of its own
`fleet/<hat>/` evidence namespace and must not edit another hat's namespace. It
is authorized to change the shared implementation, tests, ADRs, and user-facing
documentation needed to make its platform work; those changes go directly to
`dev` under the synchronization rules below. Facts live in
`tools/koi-lab/lab.json` (addresses, users, host keys) and `local/NOTES.md`
(credentials, repo paths); this table is the index.

| hat | machine | desktop (last measured) | repo path | UX modus operandi |
|---|---|---|---|---|
| `windows` | stone-leaded-sparkle (.137) | Windows workstation | repository containing this file | SCM service + per-user native workbench; official DNS-SD/Bonjour when usable, native Koi fallback |
| `cachyos-linux` | test-01 (.109) | KDE Plasma 6, Wayland | `/run/media/test/WORKBENCH/repos/github/sylin-org/koi` | Plasma systemtray hosts SNI natively → Koi tray lamp belongs there; XDG autostart honored; Plasma notifications |
| `bluefin-linux` | bluefin / test-02 (.95) | Bluefin 44, GNOME 50.3, Wayland (2026-09-01) | `~/repos/github/sylin-org/koi` | immutable Fedora image: system Koi in `/usr/local`, native RPM layered with rpm-ostree, XDG autostart, SNI through GNOME's watcher, GNOME notifications |
| `alpine-linux` | test-03 (.221) | KDE Plasma, Wayland, **musl** | `~/repos/github/sylin-org/koi` | Plasma tray + XDG autostart as on cachyos; shared-musl WebKitGTK workbench builds and runs natively; Pond remains the universal browser surface |
| `debian-linux` | halcyon-savanna (.112) | headless | `~/repos/github/sylin-org/koi` | no desktop by design: the surface is the daemon + HTTP API + pond UI; UX = everything reachable and truthful without a GUI |

Non-agent machines: brook/granite are lab production (hands off);
limpid-dune/topaz-butte/silent-cascade are phase-two Debian twins. The Windows
workstation may supervise launches; Epic 003 coordination is assigned to CachyOS.
Every hat still owns only its own system mutations.

## The UX charter (what "simply works" means on each hat)

The product promise is identical everywhere; the *mechanism* is the OS's own:

1. **Presence** — where the desktop offers a tray/status area, Koi shows its
   lamp there (SNI on Plasma/Wayland bars); clicking it reveals the workbench.
   Where no tray exists, presence degrades honestly to notifications only.
2. **Startup** — Koi (or its workbench) starts at login through the OS's own
   mechanism: XDG autostart where honored (Plasma), exec-once/uwsm on
   Hyprland, `koi install`/`--user` service where headless.
3. **Notifications** — watched-fade alerts arrive through the session's
   notification daemon (Plasma notifications; dunst/mako-class daemons on
   minimal WMs), never through a bespoke channel.
4. **The surface** — the native workbench where webview support is real
   (glibc boxes); the pond UI in the browser everywhere, always (it is the
   same interface, read-only, served by the daemon). A Phone/Pond claim passes
   only when a second LAN host opens the advertised URL; publishing files behind
   a loopback-only listener is not mobile access.
5. **Truthful everywhere** — capability ladder reflects reality per OS
   (e.g. mDNS names every active capability route and its provider evidence);
   no surface shows a state the daemon did not declare. Finding Avahi is not a
   reason to remove discovery: on an Avahi host, Koi uses Avahi's real operations.

Each hat's brief turns its row of this table into concrete first tasks.

## Hat mandate: research toward delight

The briefs name first tasks, not a closed checklist. Every hat is expected to
do its own research — on the machine, in this repository and its history, and
online — to determine the native conventions and quality bar for its OS and
session. Inspect the real environment, consult authoritative platform guidance,
compare established applications, and test assumptions instead of treating the
table above as exhaustive.

The objective is a **delightful lived-in experience**, not merely a successful
build or the presence of integration files. Within the ownership and safety
rules in `fleet/PROTOCOL.md`, hats are authorized to research, install required
platform/build dependencies, build, upgrade, restart, enroll, uninstall/reinstall
when the lifecycle calls for it, and exercise the relevant native surfaces needed
to reach that objective. This authority applies to the hat's own machine and Koi
deployment only; production and other fleet machines remain out of scope. Record
material sources, observations, decisions, commands, and evidence in the hat
journal; file a reproducible issue when the acceptable experience requires work
outside the hat's permitted scope. Platform behavior observed on the real machine
outranks an assumption in a brief, but the discrepancy must be reported explicitly
and the brief corrected.

## Current epic

[Epic 003 - delight realignment](epics/003-delight-realignment.md) is the current
dispatcher target. The owner delegated implementation to the Linux machines through
`fleet/task.md` on 2026-09-04. [The Linux dispatch](delight-dispatch.md) routes each
bounded R task through one [assignment/progress ledger](../docs/prompts/delight/LEDGER.md).
CachyOS owns product/UX coordination, Debian the core service/trust work, Bluefin
documentation/containers/integration, and Alpine installation/CI/portability.
All four retain exclusive ownership of their own native evidence and mutations.

**Handover pending:** Epic 002's OD-3 run was scheduled on frozen source
`b3eb47e08817045f9371703d780ada9aab00995d` for 2026-09-04, with collectors and Bluefin's
Pond peer. Its actual completion/restoration has not been asserted by this dispatch
change. Finish an active assigned run and reconcile its journals through R01 before
new product implementation/deployment. R01 contract preparation may proceed now.
Do not restart the dated schedule, assume it passed, cancel it implicitly, or ask
again for activation once its recorded handover conditions are met.

[Epic 002](epics/002-observable-domain-boundaries.md) retains the precise inherited
run procedure and evidence. [Epic 001](epics/001-productization-hardening.md) is also
historical. Their accepted artifacts/results remain intact; old PH selectors and
retained brief dispatches do not assign new Epic 003 feature work.

Windows source preparation belongs to named Linux owners; Windows physical proof
remains reserved for its own later operator-dispatched hat. This does not reduce
the native release matrix. The ledger permits explicitly qualified Linux progress
while Windows-only evidence is pending; full acceptance still requires it.

## Mechanics (hardened by the canary — v1's traps are protocol now)

- **Windows-side, always**: prefix every plink/pscp carrying absolute Linux
  paths with `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"` — Git Bash
  otherwise rewrites `/run/...` into `C:/Program Files/Git/run/...` and the
  remote command dies on a phantom path (v1 canary, test-01).
- **Preflight**: for each hat — reachable via plink (host keys in lab.json),
  repo at path, `~/.cargo/bin/cargo --version`, `codex --version` (agents),
  and authenticated read/write access to `origin/dev`.
- **Sync**: fresh clones can land on the default branch, so pin them to `dev`
  once: `git config remote.origin.fetch
  '+refs/heads/*:refs/remotes/origin/*'`, `git fetch --depth 5 origin`, then
  `git checkout -B dev origin/dev`. Begin every later session clean on `dev`
  with `git pull --ff-only origin dev`. Before publishing a completed commit,
  run `git pull --rebase origin dev`; if another agent wins the push race,
  repeat the rebase and push. Never force-push.
- **Launch (agent sessions)**: update the checkout, then use the same instruction
  everywhere: `codex exec 'run fleet/task.md'` (inside tmux when headless). The task
  resolves its own hat and brief. Always `. ~/.cargo/env` first in Linux remote shells.
- **Publish**: each agent commits its owned change directly on `dev`, rebases
  onto the latest `origin/dev`, and pushes `HEAD:dev` itself. A rejected push
  is a synchronization event, not a reason to leave a local-only commit.
  Discipline: never force-push, never push another hat's namespace. (Boxes
  hold GitHub credentials in `~/.git-credentials` via credential.helper
  store, LF-only — a CRLF copy silently breaks the token.)
- **Report**: read `fleet/<hat>/journal.md`; integrate; the board is the
  journals.

## Canary (the first execution)

Agentless, orchestrator-driven, proves the whole path end-to-end:

per hat: pull → `cargo check -p koi-net` (toolchain truth per libc) →
record the desktop stack + the daemon's capability ladder → write
`fleet/<hat>/journal.md` (entry: commit under test, check result, stack,
ladder) → commit on the box → `git pull --rebase origin dev` → push directly
to `origin/dev`.

**Canary v2 ran 2026-08-31: 4/4 hats green** — cachyos (glibc, fresh
checkout, 48s), omarchy (glibc, warm), **alpine (the first full koi-net
check on musl)**, and debian (glibc, warm). It taught the Windows
path-conversion guard and the dev-pinning rule above; its orchestrator-mediated
publication mechanism is retired in favor of direct agent pushes.

The canary is transport and toolchain proof only. It does **not** establish that
Koi works as part of a lived-in workstation or server environment.

## Lived-in validation (the complement to the canary)

Before changing the standing Koi shape, each hat records a real baseline from
inside the environment users actually inhabit, then repeats the relevant checks
after the upgrade. Do not infer success from a generated file, a passing unit
test, or a process that merely started.

- **All hats:** observe the real launch/supervision path, process ownership,
  ports, persistent state, logs, health, capability ladder, and certmesh posture;
  exercise restart/reconnect behavior; soak logs beyond periodic retry intervals;
  prove there is exactly one intended Koi;
  leave it healthy and journal the final state.
- **One real deployment:** validation uses the machine's intended production
  shape and standard ports. Do not start an isolated daemon, a second service,
  a temporary alternate-port trio, or a `KOI_DATA_DIR` shelter alongside it.
  Capture rollback material first, then transition serially: stop the owned old
  shape, upgrade or migrate it through the product path, start the replacement,
  and prove that exactly one Koi remains. A shifted port is acceptable only when
  a pre-existing non-Koi service genuinely owns the standard trio and the final
  deployment must coexist with it; it is not a testing convenience.
- **Desktop hats:** validate from the active graphical login session, including
  its session environment and D-Bus. Exercise tray/status presence and reveal,
  notifications while foregrounded and backgrounded, default-browser Pond
  launch and truthful parity, and ordinary session transitions such as app
  close/reopen and lock/unlock. Check for duplicate processes, stale tray items,
  startup races, missing runtime environment, and terminal-only success.
  Exercise Phone/Pond from a second physical host. Preserve loopback as the
  default for the full operator API; Pond uses the separately armed read-only
  adapter in ADR-042 and the workbench must display its returned URL, never a
  guessed operator endpoint.
- **Pond physical gate:** use the one installed Koi and its real data root. Through
  authenticated local control, publish the fixed bundle and arm Pond; assert the
  operator API still listens only where configured and the derived fourth port is
  the only new LAN socket. From at least one independent physical server, open every
  returned URL, load all five assets plus health, status, mDNS snapshot, and DNS
  entries, and prove mutation and excluded operator routes are absent. Stop sharing
  and prove the socket closes. Re-arm, restart the installed service, and prove
  persisted desire restores the same narrow surface without the workbench staying
  open. Record firewall assessment and do not change host policy merely to turn a
  red result green; any coordinated test change captures and restores exact prior
  state. End with the desired Pond state documented and exactly one Koi process.
  Current three-host reference run `20260902T002655Z-542877` used test-01's
  installed artifact SHA-256
  `8e3b94a9cfcaaa66f8c751bbb10e59f5b2196a2057d848c0ff8020d9395e24c3` and
  independent peers test-02 and test-03. Its sole PID changed `542572→542996`
  only at the required serial restart-recovery step; both peers exercised every
  allowlisted read and refused every excluded/mutation route before and after the
  restart. Exact UFW files were restored and the original disabled desire remained.
  A gate may write PASS only after it has re-read and verified the original desired
  state; a disabled baseline additionally requires the listener closed and peer
  access refused. Signal or ordinary-exit cleanup failure makes the gate fail rather
  than leaving restoration as an unaudited afterthought.
- **Desktop provenance and visual proof:** before enabling login startup, prove
  the executable is installed at a durable product-owned path rather than inside
  a source checkout. Capture the visible workbench and compare its window frame,
  scale, controls, and layout with the project's established reference on that
  desktop. Consult sibling products and upstream toolkit history when behavior
  diverges; a window that merely stays open has not passed.
- **mDNS provider transition:** use exactly one installed Koi on each of two
  independent LAN hosts to prove bidirectional publish/browse/resolve/TXT/removal
  across Avahi → best fallback → native-only → restoration, without a Koi restart
  or overlapping route. The peer must exercise its Koi API, not stand in as an
  Avahi command-line fixture. Agents may
  stop/restart mDNS facilities on their own machine after recording exact state and
  installing fail-safe restoration. PID/hash on both hosts, structured route and
  provider/session evidence, route generation, publication synchronization, peer
  evidence, and final restored state are required; prose summaries and loopback are
  not gates. Linux runs
  `scripts/integration/mdns-provider-transition.sh`; the precise contract and
  Windows adaptation are in `docs/testing/mdns-provider-transition.md`.
  Current frozen-candidate Linux reference pass `20260903T125812Z-925941`
  used the unchanged installed test-01 systemd subject PID `924696` (SHA-256
  `f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`)
  and Alpine OpenRC peer PID `24201` (SHA-256
  `4db6a257b9303157bd8dff03887b478b2c8f5a20f777166d35a59f77436a95e9`),
  with generations 1–5, late-conflict recovery, and exact restoration on both
  service managers; use its structured evidence shape as the minimum Windows gate.
- **Windows local control:** the workbench gate also uses the one installed service.
  Reinstall/upgrade it through `koi install` so ADR-040 records the interactive SID,
  then prove the owner-private breadcrumb is not the workbench's dependency: shifted
  endpoint discovery, `/v1/events`, mutations, tray posture, and pond publishing must
  all work through the authenticated named pipe. Record its explicit DACL, prove a
  different unelevated account is denied, and prove a broken mDNS client connection
  drains session registrations. Do not loosen the breadcrumb ACL, add a loopback DAT
  exemption, or launch a parallel daemon to make the UI green.
- **Trust truth:** distinguish local CA ownership from enrolled membership.
  Use certmesh diagnosis/posture and the on-disk member identity together; an
  empty local roster or `ca_initialized: false` is normal on a member and must
  not be rewritten as Open. Compare the ladder, diagnosis, and post-restart logs
  so contradictory surfaces and role-driven retry loops are caught.
- **Startup proof:** inspecting an XDG desktop file, Hyprland directive, or
  service definition is insufficient. Coordinate and perform a real
  logout/login or equivalent fresh-session test, because this disrupts the
  user's graphical session, then verify Koi appears once and is usable without
  terminal intervention.
- **Headless hats:** treat a normal remote/operator session as the lived-in
  environment. Verify boot supervision, CLI discovery, HTTP/Pond reachability,
  authentication, restart recovery, and actionable diagnostics without a GUI.

The before/after evidence belongs in `fleet/<hat>/journal.md`; defects belong in
`fleet/<hat>/issues/`. The result sought is not "integration installed" but a
native, reliable, truthful experience a user would choose to keep running.
