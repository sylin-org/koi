# Native integration and development deployment

[U02-shared-view-intent.patch](patches/U02-shared-view-intent.patch) adds shared Rust view-state parsing and rendering to the native protocol adapter. It permits bounded query navigation and same-origin GET forms, retains the existing window/origin/method guards, and adds adapter tests. It introduces no native JavaScript or service opener.

[U03-native-typed-open.patch](patches/U03-native-typed-open.patch) replaces the
desktop's prefix-only, `cmd /C start` Windows opener. It calls Koi's shared strict
HTTP(S) validator, then dispatches the canonical URL through `ShellExecuteW` as a
UTF-16 value. Linux and macOS retain direct argument-based process launch. The
validation rejects credentials, port zero, malformed authority, leading/trailing
whitespace, control characters and non-HTTP schemes before platform dispatch.

U02 deliberately passes `EndpointActions::None`. U03 makes the existing desktop
command safe enough to serve as a future bridge, but does not yet expose Open in
the shared native pane. Keep the pane action-free until that typed bridge and its
installed behavior are verified.

| Input | Revision / requirement |
| --- | --- |
| Desktop patch base | `sylin-org/koi-desktop` at `d432b9ed207307f1825f0706473eaef4dbeb227b` |
| Desktop's existing `koi-client` / `koi-ui` pin | `b4c32fa9b524549509b34b01bb24cc06455407ad` |
| Paired Koi source | `791f87ebe0a8ba93246f60ce0b283c13fb86595b` **plus the U02 working-tree changes** exporting `UiState`, `render_with_state`, and the shared form CSP |
| Release status | Unsigned development NSIS installed; production pin, candidate and usability acceptance pending |

The existing desktop dependency pin lacks the new API. For reproduction from the
recorded base, first use an isolated desktop worktree/copy paired with the updated
Koi source. Adjust these example paths as needed:

```powershell
git apply --check E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U02-shared-view-intent.patch
git apply E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U02-shared-view-intent.patch
git apply --check E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U03-native-typed-open.patch
git apply E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U03-native-typed-open.patch
cargo test ui::tests --config 'patch."https://github.com/sylin-org/koi".koi-client.path="E:/repo/github/sylin-org/koi/crates/koi-client"' --config 'patch."https://github.com/sylin-org/koi".koi-ui.path="E:/repo/github/sylin-org/koi/crates/koi-ui"'
```

The local source overrides may update that copy's `Cargo.lock`; they do not update the production dependency pin. Before merging native integration, select the new Koi revision, regenerate and verify the desktop lockfile, run the native tests/build, and complete the native acceptance checks in [U06](../../docs/ux/README.md).

Validation recorded for these patches: each patch and the pair pass `git apply
--check` against the desktop base. On Windows, an isolated paired-source worktree
passed all 25 desktop tests with one existing cross-host test ignored, plus strict
Clippy and formatting. The test build resolved the pinned registry dependencies;
its transient lockfile is not part of either patch. On 2026-09-13 the patches
were then applied to the sibling checkout, its Koi dependencies were pointed at
the adjacent current source, and an unsigned NSIS package was built with
`npx @tauri-apps/cli@2.11.4 build --bundles nsis`. That package was installed and
launched against the real installed development daemon. The checkout and
lockfile are now modified. This is not a selected release candidate or physical
Open receipt; the shared pane remains action-free.

## CachyOS own-host probes (test-01)

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

It also accepts `text 'lowercase search'`: 1–80 lowercase ASCII letters, digits,
spaces or hyphens on the ordinary US keyboard layout. Validate/focus the Services
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

These rollback guards pin measured historical baselines and refuse others; a new
acceptance needs a reviewed guard. `restore-browser-cachyos.sh` guards the parked
browser-invitation feature and is not applicable; it is scheduled for removal.

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
