# ADR-036: Recipe-Based Installer — One Pipeline, Per-Init Recipes

**Status:** Accepted (operator-approved 2026-08-31)
**Date:** 2026-08-31
**Builds on:** ADR-031 (config substrate), ADR-029 (host classes), ADR-035 (detect/yield/declare)
**Evidence:** `docs/lab/os-install-facts.md` — measured on the 2026-08-31 fleet
(10 machines, 4 OS families: Windows 11, Debian 13, Arch×2, Alpine 3.24)

---

## Context

Onboarding the fleet measured the installer against reality. The binary is
universal — static-pie, zero dependencies on every distro tried — and the config
substrate (ADR-031) is universal. What varies is exactly three things:

1. **how the daemon is supervised** (SCM / systemd / OpenRC / launchd / nothing),
2. **which ports are free** (machine state — twice the standard run was already
   held by another product),
3. **what tools exist for verification** (curl is missing on half the fleet).

Against that reality the installer had four defect classes (all reproduced
physically):

- **No init detection.** `koi install` on Alpine copies the binary, then dies
  writing `/etc/systemd/system/koi.service` (ENOENT). No OpenRC support, no
  honest fallback.
- **ETXTBSY self-copy.** Installing from the installed path
  (`sudo /usr/local/bin/koi install`, the natural upgrade move) fails
  `Text file busy` because the installer copies its own running executable onto
  itself.
- **Silent port collisions.** The unit always declares 5641/2/3; a collision
  surfaces later as a crash-loop, and the workaround (manual env drop-ins) is
  operator folklore.
- **curl-assumed verification.** Health checks and post-join flows break on
  boxes without curl (three of ten).

## Decision

**One install pipeline, parameterized by a small internal recipe table.** The
per-OS knowledge lives in *recipes* keyed on **capabilities, not distro names**:
the load-bearing signal is the init system (does `/run/systemd/system` exist?
is `rc-update` present?), and `/etc/os-release` is only a hint for messages.
Distro names drift; capabilities don't.

### The pipeline (identical everywhere)

1. **Stage the binary atomically.** If source and destination are the same file,
   skip the copy (the ETXTBSY case). Otherwise copy to a unique sibling,
   flush the complete file, atomically replace the destination, and make the
   containing-directory update durable. Renaming over a running executable is
   legal on Linux/macOS. On Windows, a destination the running service holds
   fails the replace and the installer says exactly what to do instead of a raw
   OS error.
2. **Detect the init system** → pick a recipe. Unknown is a recipe too (below),
   never an ENOENT stack trace.
3. **Ownership-aware port pre-flight.** Each recipe first reports whether it is
   creating a deployment or replacing its own durable Koi registration (SCM
   service, systemd unit, OpenRC script, or launchd plist). A declared machine
   decision always wins. A replaced legacy Koi with no declaration keeps its
   effective standard 5641/2/3/4 run without probing its own live listener.
   Only a fresh deployment probes the standard configured trio plus Pond's
   derived fourth port (`http + 3`) by binding all four. All free → standard
   plan. Occupied → shift the whole run by tens
   (5641/2/3/4 → 5651/2/3/4 → …) until a free run is found. Only the
   existing three configurable ports are persisted; Pond remains derived. The
   final decision is checkpointed in the install transaction before the first
   service mutation; there is no provisional health-check port.
4. **Persist a shifted plan in the config substrate**, not in ad-hoc env
   (ADR-031 precedence applies). System services resolve their config at
   `/etc/koi/config.toml` (the unit/init script sets `XDG_CONFIG_HOME=/etc`);
   user services use the natural `~/.config/koi/config.toml`; Windows uses
   `%ProgramData%\koi\config.toml`. Existing port declarations are never
   changed. Creating an absent config is an atomic create-if-absent operation,
   so a file that appears during planning wins rather than being overwritten;
   adding a missing port declaration to an existing config is one durable
   atomic replacement.
5. **Install the service via the recipe** (enable + start).
6. **Verify with koi's own client** — a raw loopback HTTP GET of `/healthz`
   from the installer process. No curl, no wget, nothing to be missing.
7. **Print the honest end state**: ports (and why), logs, status command.

### The recipes

| recipe | trigger | shape |
|---|---|---|
| `scm` | Windows | transactional installer: binary staged to `%ProgramFiles%\Koi\koi.exe` (never the checkout the installer ran from), prior binary/service config/operator policy/config substrate/Koi-owned firewall rules roll back together on a failed health check; interrupted installs recover on the next run |
| `systemd` | `/run/systemd/system` present | system unit, `Type=notify`, drop-ins honored |
| `systemd --user` | same + `--user` | `~/.config/systemd/user` unit, linger enabled |
| `openrc` | `rc-update` present | `/etc/init.d/koi` (`supervise-daemon`, bounded respawn + health checks), `rc-update add … default` |
| `launchd` | macOS | LaunchDaemon plist (config env aligned with the above) |
| `manual` | nothing detected | **no service is pretended.** The binary is staged, exact run instructions (nohup line, cron `@reboot`) are printed, and the command exits non-zero so automation cannot mistake guidance for installation. |

`--user` on shapes without a user service manager (OpenRC, bare, Windows,
macOS for now) prints the honest state and exits non-zero — the Windows user
path is the workbench autostart (ADR-034 P-A), not a fake SCM user service.

### Exit semantics

Full install (service registered + healthz verified and the transaction
durably settled) → 0. Partial (binary staged, no service possible) → non-zero
with the exact manual steps. Failure before settlement rolls back. Failure to
remove backup/staging debris after durable settlement does not roll back a
verified installation: Koi leaves the `Settled` journal in place, reports the
cleanup problem, and retries cleanup only on the next install.

Systemd and OpenRC system installs are durable transactions. Before either
manager is mutated, Koi checkpoints the installed binary, registration,
configuration, local-operator policy, and prior active/enabled state under the
machine data root. A failed enable, start, process-identity check, or `/healthz`
probe returns non-zero and restores the previous healthy service; an interrupted
transaction is recovered before a later install begins. OpenRC additionally
requires `supervise-daemon` and `logrotate`, writes a bounded rotation policy,
and refuses to claim installation when either facility is unavailable.

### Durable transaction protocol (2026-09-03 amendment)

The systemd, OpenRC, and SCM recipes share these persistence invariants:

1. One stable OS-native lock serializes installation and recovery for the
   machine-wide service even when invocations select different data roots.
   User-recipe locking is likewise anchored to the one HOME-owned install
   shape, not a configurable data root. Lock files are retained; closing the
   native handle releases ownership without an unlink split-brain window.
2. `Preparing` is durable before checkpoint work starts. Existing targets are
   copied to create-if-absent backups through the common atomic persistence
   boundary; each manifest records the length and SHA-256 identity of the
   exact staged backup. A backup path that appears concurrently is never
   clobbered.
3. `Armed` is durable before the first service-manager, firewall, file, or
   lifecycle mutation. A visible replacement whose durability could not be
   confirmed is not sufficient at this boundary. Private Unix modes or Windows
   ACLs are installed on empty stages before bytes are written.
4. Recovery validates every required backup before its first native effect.
   Each restore hashes the exact bytes copied into its replacement stage and
   compares them with the manifest again, then uses the same durable atomic
   replacement primitive. On Unix, target and removal commits include the
   parent-directory flush.
5. Verification is followed by a durable `Settled` transition. That transition,
   not deletion of an `Armed` manifest, is the semantic commit. Once settled,
   every restart is cleanup-only and can never restore the superseded files.
   If settlement cannot be proven durable, the live transaction is durably
   re-armed before rollback begins.

The result is interruption-convergent: every durable phase has exactly one
safe retry behavior, and backup deletion is never mistaken for the point at
which an installation became accepted.

## Consequences

- Alpine installs use bounded native crash supervision and rotated logs; unknown inits degrade honestly; upgrades from the
  installed path work; occupied ports are chosen, recorded, and printed — not
  crashed on later.
- The fleet's manual env drop-ins keep working and are now *honored inputs* on
  upgrade (no truth drift between unit env and config file).
- Templates are embedded (`include_str!`) and golden-tested; detection is
  root-parameterized and fake-tested; port planning is pure and unit-tested.
  Physical proof rides the real fleet: test-03 (Alpine, occupied-port shift,
  install + uninstall) and a from-installed-path upgrade on a standing Debian
  box.
- Verification never assumes third-party tools; the installer's HTTP check is
  the same loopback surface the daemon serves.
- Windows rollback first requests an ordinary SCM stop. If a replacement fails
  before registering its control handler, SCM can retain it in `StartPending`
  while rejecting `Stop`. Only for that exact state and control-rejection
  result, recovery waits within the stop bound for SCM's raw process-status
  record to publish a PID, treats that pending-state PID as untrusted, opens
  the reported process, verifies its image through the same handle against
  Koi's product path, terminates it, and waits for SCM to publish `Stopped`
  before restoring bytes and the service descriptor.
- Reinstalling a live, no-config Koi no longer manufactures a shifted config
  by classifying Koi's own sockets as foreign. Fresh machines still yield to a
  real incumbent, and every platform recipe consumes the same pure decision.
- CachyOS physical acceptance installed candidate `41ad76b` through the sole
  standing system service while it owned the standard ports. The transaction
  retained `5641:5644`, did not create `/etc/koi/config.toml`, and a deliberately
  mismatched candidate health port drove rollback of the exact binary, unit,
  operator policy, config absence, and active/enabled state.

## Deferred

- runit/s6 recipes (no fleet machine runs them; the manual recipe covers them
  honestly until one does).
- macOS `--user` (LaunchAgent) — plist shape is known; no physical mac in the
  fleet to verify against.
- Windows `--user` via a logon scheduled task (the workbench autostart covers
  the user shape today).
