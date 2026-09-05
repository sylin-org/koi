# CachyOS native evaluation guard

`restore-cachyos.sh` is deliberately bound to the measured `test-01` baseline,
not a fleet installer. It restores the exact previous service/package and preserves
post-upgrade data privately if the native evaluation is interrupted or rejected.
It contains no credential and never contacts a peer. Do not use it on another host
or after the baseline has changed.

Before any mutation, create a root-owned mode-0700
`/var/tmp/koi-r06-native.XXXXXXXX` checkpoint. Copy the reviewed helper there mode
0700, the verified old Arch package as `prior.pkg.tar.zst`, and an owner/mode-
preserving `baseline.tar` of `usr/local/bin/koi`, `etc/systemd/system/koi.service`
and `var/lib/koi` relative to `/`. Confirm `/etc/koi` is absent. Record hashes of
the archive, old package and helper in `checkpoint.sha256`; never publish the
archive because it contains identity material. Arm a root systemd transient timer
to invoke the checkpoint's helper with its absolute checkpoint path before any
service/workbench stop or package upgrade. Keep the window bounded and inspect
the timer state before continuing. The product installer additionally owns its
own durable transaction rollback.

On acceptance, verify the healthy service, package-owned normal workbench,
unchanged identity/policy/config/provider/firewall/autostart, closed Pond listener
and absence of temporary processes. Under the same `restore.lock`, stop the timer
and create `accepted` to disarm the guard. Retain the root-private recovery archive;
remove the root-private executable helper and transient units. On rejection, run
the helper rather than disarming it. A nonzero recovery exit is a failed run that
requires immediate investigation, never a passing checkpoint.

`kwin-narrow.js` and `kwin-close.js` target exactly one explicitly titled
evaluation window using the [KWin API](https://develop.kde.org/docs/plasma/kwin/api/).
Load each by name only for its check, then unload it; they set no persistent rule.
`tab-once.c` uses installed libevdev to send one real Tab event to the active
window (or one PageDown with explicit `--page-down` for a scrolled card capture),
with automatic device removal when it exits (including interruption).
Build with `cc -Wall -Wextra -Werror -O2 tab-once.c $(pkg-config --cflags --libs
libevdev) -o ../target/tab-once` using the appropriate working-directory paths.
Run as the existing desktop user, never grant new input permissions, and activate
the evaluation first. The device has no Enter/text/pointer capabilities. Visible
captures, not successful event injection alone, establish keyboard focus.

## Native motion follow-up

The older `restore-cachyos.sh` belongs only to its historical daemon/package
baseline. For the desktop-only motion upgrade use `restore-motion-cachyos.sh`
in a **fresh** root-private `/var/tmp/koi-r06-motion.XXXXXXXX` directory, with the
accepted `c497b3b` package as `prior.pkg.tar.zst` (SHA-256
`c95ae640911e5624ac1fdee99ec35b056352f023252fd4c7c1c118553155bf20`). Integrity-check
the copied helper/package in `checkpoint.sha256` and arm a root 25-minute timer.
This helper never stops, reinstalls or restores daemon data. Accept/disarm under
its `restore.lock` only after real checks; retain the prior package privately.

`gtk-motion-observer.c` reads GTK/GDK and identifies the actual backend. Compile
with `cc -Wall -Wextra -Werror -O2 native/gtk-motion-observer.c $(pkg-config
--cflags --libs gtk+-3.0) -o target/gtk-motion-observer` from the spike directory.
An optional diagnostic build with `-DMOTION_MODULE -fPIC -shared` produces
`target/gtk-motion-observer.so`; it logs the installed process's settings and
notifications without writing any preference. Do not infer a Wayland GTK value
from an XSettings dump: the backend may use GSettings or the desktop portal.

`bash native/motion-cachyos.sh target/native/motion-cachyos-<run-id> <installed-sha>`
requires an existing evidence directory, the exact installed executable hash,
one normal workbench in `app-koi-r06-normal`, and explicit GSettings=true baseline.
It arms a separate user three-minute restoration timer before serially switching
the installed workbench to evaluation mode. It captures motion on/off/on in the
same process, requiring AE greater than zero / zero / greater than zero, then
restores the preference and normal workbench. AE is ImageMagick's absolute-error
metric, not necessarily an integer count. The default proof loads no diagnostic
module; opt in only for diagnosis with `KOI_MOTION_OBSERVER_MODULE=1`.
`KOI_MOTION_START_REDUCED=1` additionally checks a launch with motion already
disabled, before the same on/off/on sequence. Live/focus captures precede the
scrolled card; inspect them visually rather than treating input injection as proof. Neither
helper changes the daemon, package, graphical config files or input permissions.
