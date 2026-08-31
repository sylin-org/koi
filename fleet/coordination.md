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
