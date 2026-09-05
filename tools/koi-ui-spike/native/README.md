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
window, with automatic device removal when it exits (including interruption).
Build with `cc -Wall -Wextra -Werror -O2 tab-once.c $(pkg-config --cflags --libs
libevdev) -o ../target/tab-once` using the appropriate working-directory paths.
Run as the existing desktop user, never grant new input permissions, and activate
the evaluation first. The device has no Enter/text/pointer capabilities. Visible
captures, not successful event injection alone, establish keyboard focus.
