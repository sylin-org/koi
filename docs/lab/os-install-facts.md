# OS install facts — what the physical fleet taught us

**Purpose:** every fact below was measured on a real machine while onboarding
the 2026-08-31 fleet (rc.2 musl artifact, git 2ebb868). This is the input for
making `koi install` non-flaky across OSes. Fleet: 10 machines, 4 OS families,
all enrolled into brook's mesh — roster 10/10 active (wait: 9 remote members +
brook = the CA itself; `/v1/certmesh/status` lists all of them).

| machine | address | OS | init | class | koi shape |
|---|---|---|---|---|---|
| windows (stone-leaded-sparkle) | .137 | Windows 11 | SCM | workstation | system service, 5641 |
| brook (stone-platinum-brook) | .44 | Debian 13 | systemd | dedicated | system service, 5641, LAN HTTP via drop-in |
| granite (stone-granite-spring) | .55 | Debian 13 | systemd | dedicated | system service, 5641 |
| test-01 | .109 | CachyOS (Arch) | systemd | workstation | user-level cyclical, 5641 |
| test-02 | .95 | Omarchy (Arch) | systemd | workstation | user-level cyclical, 5641 |
| stone-limpid-dune | .97 | Debian 13 | systemd | dedicated | system service, **21441/2/3** (drop-in; Moss owns 5641) |
| stone-topaz-butte | .111 | Debian 13 | systemd | dedicated | system service, **22441/2/3** (drop-in; Moss owns 5641) |
| stone-silent-cascade | .103 | Debian 13 | systemd | dedicated | system service, **23441/2/3** |
| stone-halcyon-savanna | .112 | Debian 13 | systemd | dedicated | system service, **24441/2/3** |
| test-03 | .221 | **Alpine 3.24** | **busybox/OpenRC** | workstation | user-level (nohup), 5641 |

## Per-OS findings

### Debian 13 trixie (brook, granite, limpid-dune, topaz-butte, silent-cascade, halcyon-savanna)

- `koi install` (systemd) works, **but fails with `Text file busy (os error 26)`
  when the installer is invoked from the same path it installs to** (running
  `/usr/local/bin/koi install` copies the executing binary onto itself).
  Measured twice on limpid-dune. Workaround used: stage the binary at `/tmp/koi`,
  `chmod +x`, run the installer from there.
- **curl is often MISSING on fresh boxes** (limpid-dune, silent-cascade,
  halcyon-savanna). wget and python3 are usually present. Verification scripts
  that assume curl break; use wget or the binary itself.
- Passwordless sudo for the lab user on dedicated boxes; the systemd drop-in
  mechanism (`/etc/systemd/system/koi.service.d/*.conf` with `KOI_PORT`,
  `KOI_MTLS_PORT`, `KOI_ACME_PORT`) is the proven coexistence lever — needed
  where another daemon (garden-moss) already holds 5641.
- Fresh boxes had **no legacy koi at all** — but the installer must preserve
  any pre-existing `/usr/local/bin/koi` (brook/granite doctrine: copy aside,
  never delete).

### Arch family — CachyOS (test-01) and Omarchy (test-02)

- systemd present; `curl` present; GNU setsid (supports `-f`).
- Workstation class: the **user-level cyclical daemon** pattern
  (`mesh-start-user.sh`: setsid + pidfile + persistent `KOI_DATA_DIR`) is the
  working shape; membership survives restarts via the persistent data root.
- test-02 note: the join CLI must be pointed at the daemon's breadcrumb via
  `XDG_RUNTIME_DIR` — a fresh shell defaults elsewhere and reports
  "No running Koi service found" even though healthz answers.

### Alpine 3.24 (test-03) — the flaky one

- **No systemd** (`/sbin/init -> /bin/busybox`, OpenRC runlevels). `koi install`
  copies the binary to `/usr/local/bin/koi` fine, then **hard-fails writing
  `/etc/systemd/system/koi.service` (ENOENT)** — no OpenRC fallback, no honest
  guidance. This is the single biggest installer gap measured on the fleet.
- **The musl static-pie binary runs natively** (Alpine IS musl): zero library
  dependencies, `file` reports `static-pie linked`. The binary is never the
  problem; the install path is.
- Toolchain gaps on a fresh box: **no curl**; busybox `setsid` has **no `-f`**
  (the user-start script's `setsid -f` prints usage and fails — use `nohup sh -c
  … &` instead); `wget`, `python3`, `ss`, `sha256sum`, `install` present.
- **Both `sudo` and `doas` exist**; wheel-doas rule configured; sudo accepts a
  stdin password (`echo pw | sudo -S`). SSH sudo may need a tty (`ssh -tt`).
- No iptables/nftables installed — ports open by default.
- `/run/user/1000` exists; the user daemon's breadcrumb lands in
  `XDG_RUNTIME_DIR` when the daemon is started with it set.
- avahi-daemon package present but NOT in the default runlevel — mDNS rung off
  while the package could provide it.

## Status after ADR-036 (2026-08-31)

The gap list below is now the ADR-036 implementation record. Physical
evidence after the implementation:

- **Alpine (test-03):** `koi install` detects OpenRC, stages the binary,
  writes `/etc/init.d/koi`, enables the default runlevel, starts, and
  self-verifies — with the standard trio occupied by the standing user
  daemon it shifted to 5651/2/3 and wrote `/etc/koi/config.toml`.
  `koi uninstall` removed exactly the system shape; the user daemon on 5641
  was untouched throughout. (One real defect found and fixed on the way:
  the init script template shipped CRLF from a Windows checkout — the
  shebang's trailing  made the kernel hunt a phantom interpreter;
  templates now render LF and are pinned `eol=lf` in .gitattributes.)
- **Debian (stone-silent-cascade):** upgrade from `/tmp` honored the
  standing drop-in verbatim ("ports stay as declared"), rewrote the unit
  with the config env, restarted healthy on 23441. The same-file upgrade
  `sudo /usr/local/bin/koi install` — the exact invocation that used to die
  with `Text file busy` — now stages as a no-op and restarts healthy.
  No config was invented while a drop-in governed (no truth drift).

## Installer gap list (flake source → required behavior)

1. **Init-system detection.** No systemd → currently a hard ENOENT failure.
   Needed: OpenRC support (an `/etc/init.d/koi` confd-style service), and when
   neither exists, a loud, honest message plus printed supervision instructions
   instead of a stack trace.
2. **Self-copy ETXTBSY.** Installing from the target path (or restarting the
   service during upgrade) fails. Needed: copy `/proc/self/exe` to a temp file
   and `rename(2)` (atomic replace works on a running binary), or refuse with
   guidance when source == destination.
3. **No user-level install shape.** Workstations (the majority of real users)
   currently get a shell script. `koi install --user` (systemd --user unit on
   systemd distros, nohup/OpenRC user service elsewhere) would erase a whole
   class of flakiness.
4. **Verification assumes curl.** Health checks should use the binary's own
   HTTP client (it has one — the same one that serves) or wget.
5. **Port collisions are silent until crash-loop.** The fleet needed manual
   drop-ins (Moss on 5641 twice). The installer should probe 5641/2/3 before
   writing the unit and, when occupied, configure + print the alternates it
   chose (the config substrate already supports it).
6. **Windows-origin transfers lose exec bits.** Any pscp/scp-from-Windows stage
   must `chmod +x` (or the installer's docs must say so).
7. **Breadcrumb discovery on user daemons.** A fresh shell doesn't share the
   daemon's `XDG_RUNTIME_DIR`; the CLI reports "no service" misleadingly.
   Checking the documented user-runtime path (or recording the pidfile's
   runtime dir in the data root) would remove the surprise.

## What already worked everywhere (keep)

- The **musl static-pie binary** — zero dependencies on every distro measured.
- Breadcrumb + DAT auth; the join flow with invite-pin preflight; roster
  convergence; trust diagnose as the single source of "am I in".
- systemd drop-in env overrides for ports (the honest coexistence lever).
- Persistent `KOI_DATA_DIR` making cyclical user daemons membership-stable.
