# Shared-shell own-host verification helpers

These are test-01 native test helpers, not product code or remote-control tools.
Historical renderer-comparison helpers remain archived under `koi-ui-spike/native`;
do not run those against new artifacts or reuse their old baseline archives.

`restore-cachyos.sh` accepts only a fresh root-owned mode-0700
`/var/tmp/koi-r06-shell.XXXXXXXX` checkpoint. Before any package/window/service
change, copy the exact installed ccee0fc Arch package as `prior.pkg.tar.zst`, copy
this helper, and integrity-check both with `checkpoint.sha256`. Arm a root timer
against that root-owned helper and verify it is waiting. It restores the package,
normal workbench, already-running unchanged daemon and explicit true GTK animation
preference. It does not restore or delete daemon data. Accept/disarm only under
`restore.lock` after verifying baseline identity/configuration and one healthy
daemon/workbench. Retain the private prior package; remove the executable helper
and transient units after acceptance. A changed baseline needs a reviewed guard.

`kwin-narrow.js` activates and resizes only one Koi workbench, identified by resource
class and caption. Load for a check, then unload. Inspect actual client geometry
and visible captures rather than assuming requested width equals observed width.

Compile the navigation probe with:

```sh
cc -Wall -Wextra -Werror -O2 tools/koi-ui-native/key-once.c $(pkg-config --cflags --libs libevdev) -o target/koi-ui-key-once
```

It supports one `tab`, `enter`, `home`, or `end`; only Tab admits a count (1–8).
Activate Koi immediately before input; inspect visible focus before Enter. Use
existing user input permissions only. Device lifetime ends with the invocation.
Screenshots and native observations—not this helper's exit status—prove behavior.

R07 also permits `text 'lowercase search'`: 1–80 lowercase ASCII letters, digits,
spaces or hyphens on the ordinary US keyboard layout. Validate/focus the sole Koi
search field first, then inspect its actual value before submitting. Unsupported
characters are rejected before creating a device; no modifiers or clipboard access.

`restore-r07-cachyos.sh` is the desktop-only guard for the measured e010086
baseline (binary c874a638), not the older R06 baseline. Use a fresh root-owned
0700 `/var/tmp/koi-r07.XXXXXXXX` checkpoint containing the exact prior package,
root-owned helper and their `checkpoint.sha256`; arm and inspect a root timer
before mutation. It starts only the unchanged daemon (dc1ebd15), serially restores
the prior package and launches one normal workbench. It does not change motion,
firewall, credentials, provider configuration or daemon data. Window probes are
one-shot and must be unloaded; restore measured geometry before completing a run.
Accept/disarm under its lock only after checking identity/configuration, exact
process counts and health. On rollback verify the `restored` marker and those same
facts. Remove the root executable helper/transient timer after either outcome;
retain the private package and baseline evidence.

`restore-r07-full-cachyos.sh` covers the later measured daemon dc1ebd15 / desktop
0e8a88c3 pair. It requires a fresh private `/var/tmp/koi-r07-full.XXXXXXXX` with
`prior-koi`, `prior.pkg.tar.zst`, `baseline.tar` (only `/var/lib/koi` and the Koi
system unit), `state.sha256`, `policy.sha256`, and the root-owned helper, protected
by `checkpoint.sha256`. Capture `preferences-absent` only after proving the file
absent. Arm/inspect a root timer before installation. This guard restores through
the prior daemon's public installer and ordinary pacman; it is not the desktop-only
guard. Its only temporary-workload units are the exact dated Notes/announcement
names in the helper. Preference removal refuses foreign records. Preserve the
private archive/packages and remove copied executables/timer after settled cleanup.

## Bounded native pointer probe

Compile `pointer-once.c` with the same libevdev flags as `key-once.c`:

```sh
cc -Wall -Wextra -Werror -O2 tools/koi-ui-native/pointer-once.c $(pkg-config --cflags --libs libevdev) -o target/koi-ui-pointer-once
```

The interface is `pointer-once PID move DX DY` (each delta -2048 through 2048),
or `pointer-once PID click` (one left click). Invalid arguments and a PID whose
executable is not exactly `/usr/bin/koi-desktop` are rejected before device creation.
Only existing user input permissions are used. Each invocation creates and destroys
its own device; there is no listener, service, drag, keyboard chord or browser API.

**This low-level helper is not window-confined.** A PID check does not establish
focus or the destination of a global pointer event. Before movement, activate and
inspect the sole installed Koi. Before every click, load/run/unload
`pointer-state.js` through the existing KWin scripting mechanism and require a fresh
`KOI_POINTER_STATE` observation: expected PID, `active`, `overKoi`, and the cursor
strictly inside a currently visible, inspected internal control. Check its actual
URI is the intended `koi-ui://localhost/` navigation, never external Open. Abort on
an unexpected window, stale observation, changed geometry or user activity. The
caller must account for the short device-discovery delay and remaining focus race;
this is not a security boundary or a general unattended desktop agent.

Move and click are deliberately separate. KDE acceleration changes requested
deltas; observe the resulting cursor instead of calculating a click from the delta.
On the measured Wayland/WebKit build, AT-SPI SCREEN rectangles were view-relative:
only use a mapping after confirming it against the native capture/client geometry.
After clicking, require the expected accessible state transition and inspect the
native capture. A zero exit status proves event submission, not navigation.
Restore the captured pointer/geometry and unload probes; verify no temporary input
device remains. Never apply this helper to evade browser protected-host restrictions.

Measured R07 wide-layout service selection/Back and320px search/select/Back/
no-match/clear passed on desktop24d619f; see `docs/prompts/delight/reports/R07.md`.
Browser load/save remains unverified. The existing semantic AT-SPI action remains useful for
inspection/setup, but does not count as pointer evidence.
