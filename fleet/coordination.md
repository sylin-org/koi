# fleet/coordination.md — the campaign entry point

**Execute this file.** It is the complete instruction for the orchestrator
(the Windows workstation, `stone-leaded-sparkle`): run the fleet hats,
harvest their commits, integrate onto `dev`. Everything needed is here or
referenced from here. KISS: one branch (`dev`), no deploy keys — agents
commit locally, the orchestrator harvests patches over the existing SSH
paths and pushes once.

## The hats

One machine, one hat, one specialty. A hat owns `fleet/<hat>/` and nothing
else. Facts live in `tools/koi-lab/lab.json` (addresses, users, host keys)
and `local/NOTES.md` (credentials, repo paths); this table is the index.

| hat | machine | desktop (measured 2026-08-31) | repo path | UX modus operandi |
|---|---|---|---|---|
| `cachyos-linux` | test-01 (.109) | KDE Plasma 6, Wayland | `/run/media/test/WORKBENCH/repos/github/sylin-org/koi` | Plasma systemtray hosts SNI natively → Koi tray lamp belongs there; XDG autostart honored; Plasma notifications |
| `omarchy-linux` | test-02 (.95) | Hyprland (uwsm), Wayland | `~/repos/github/sylin-org/koi` | tiling compositor: XDG autostart **NOT honored** (exec-once/uwsm is the path); tray = the session bar via SNI (verify which bar); notifications = the session daemon |
| `alpine-linux` | test-03 (.221) | KDE Plasma, Wayland, **musl** | `~/repos/github/sylin-org/koi` | Plasma tray + XDG autostart as on cachyos; the open question is webkit2gtk on musl for the native workbench — the pond UI in a browser is the honest fallback until proven |
| `debian-linux` | halcyon-savanna (.112) | headless | `~/repos/github/sylin-org/koi` | no desktop by design: the surface is the daemon + HTTP API + pond UI; UX = everything reachable and truthful without a GUI |

Non-agent machines: brook/granite are lab production (hands off);
limpid-dune/topaz-butte/silent-cascade are phase-two Debian twins;
the Windows workstation is the orchestrator and dev box.

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
   same interface, read-only, served by the daemon).
5. **Truthful everywhere** — capability ladder reflects reality per OS
   (e.g. mDNS skip under avahi); no surface shows a state the daemon did
   not declare.

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

## Mechanics (hardened by the canary — v1's traps are protocol now)

- **Windows-side, always**: prefix every plink/pscp carrying absolute Linux
  paths with `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"` — Git Bash
  otherwise rewrites `/run/...` into `C:/Program Files/Git/run/...` and the
  remote command dies on a phantom path (v1 canary, test-01).
- **Preflight**: for each hat — reachable via plink (host keys in lab.json),
  repo at path, `~/.cargo/bin/cargo --version`, `codex --version` (agents).
- **Sync**: fresh clones are DEFAULT-branch clones; pin every box to dev
  once (idempotent): `git config remote.origin.fetch
  '+refs/heads/*:refs/remotes/origin/*'` + `git fetch --depth 5 origin` +
  `git checkout -B dev origin/dev`. Then `git pull --ff-only` per session
  (public read; no credentials).
- **Launch (agent sessions)**: ship `fleet/briefs/<hat>.md` if changed, then
  start headless in tmux: `tmux new-session -d -s koi-fleet 'codex exec ...'`.
  Always `. ~/.cargo/env` first in any remote shell line.
- **Harvest**: on each box `git format-patch origin/dev..HEAD -o /tmp/fleet-patches`
  (or `-N` for the last N commits), `pscp` them back, `git am`, push `dev`
  once. Authorship preserved; patches apply clean because hats own disjoint
  namespaces.
- **Report**: read `fleet/<hat>/journal.md`; integrate; the board is the
  journals.

## Canary (the first execution)

Agentless, orchestrator-driven, proves the whole path end-to-end:

per hat: pull → `cargo check -p koi-net` (toolchain truth per libc) →
record the desktop stack + the daemon's capability ladder → write
`fleet/<hat>/journal.md` (entry: commit under test, check result, stack,
ladder) → commit on the box → format-patch → `git am` at the orchestrator →
push `dev`.

**Canary v2 ran 2026-08-31: 4/4 hats green** — cachyos (glibc, fresh
checkout, 48s), omarchy (glibc, warm), **alpine (the first full koi-net
check on musl)**, debian (glibc, warm) — four patches harvested via
format-patch and applied with `git am` at the orchestrator. v1 taught the
Windows path-conversion guard and the dev-pinning rule above.

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
- **Desktop provenance and visual proof:** before enabling login startup, prove
  the executable is installed at a durable product-owned path rather than inside
  a source checkout. Capture the visible workbench and compare its window frame,
  scale, controls, and layout with the project's established reference on that
  desktop. Consult sibling products and upstream toolkit history when behavior
  diverges; a window that merely stays open has not passed.
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
