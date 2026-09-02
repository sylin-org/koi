# Linux desktop has no durable install artifact from CachyOS

**Status: resolved by koi-desktop `d2951f6` and its native Arch VCS package.**

## Impact

The Plasma autostart toggle cannot be accepted as a real deployment test while
the only runnable workbench is `koi-desktop/target/release/koi-desktop`. Enabling
it would persist a source-checkout build path rather than an installed Koi path.

## Reproduction

On test-01 (CachyOS, Plasma Wayland), from the `koi-desktop` repository:

```text
cargo tauri build --bundles appimage --verbose
...
linuxdeploy ... strip: unknown type [0x13] section `.relr.dyn'
Error: failed to run linuxdeploy
```

The ordinary release build succeeds and runs after the Wayland renderer fix,
but the README documents no Linux installation path beyond that development
build. This is the same Arch `.relr.dyn` incompatibility previously measured by
Ghostlight's Tauri packaging pass.

## Acceptance

- Produce or document a durable Linux installation artifact/path appropriate
  for Plasma and Hyprland machines.
- The desktop entry and XDG/uwsm startup mechanism point to that installed path.
- Install, update, autostart toggle, fresh login, and uninstall are exercised
  without leaving source-checkout paths or duplicate Koi processes.

## Resolution

The native `koi-desktop-git` package builds with Arch's installed WebKitGTK and
app-indicator libraries instead of sending modern RELR binaries through the
incompatible AppImage strip step. On test-01, `makepkg` produced and installed
`koi-desktop-git 0.1.2.r43.gd2951f6-1`; pacman owns
`/usr/bin/koi-desktop`, the desktop entry, and the icon.

The real Plasma workbench ran from `/usr/bin/koi-desktop`. Its UI autostart
switch created `~/.config/autostart/Koi.desktop` with exactly
`Exec=/usr/bin/koi-desktop --minimized`, then removed it when switched off while
the process count remained one. A package-only uninstall then proved all owned
runtime files absent; reinstalling the exact built `.pkg.tar.zst` restored them and
launched one packaged workbench. Bluefin independently exercised the same installed
path through a fresh GNOME login and package upgrade. No source-checkout path,
orphan startup entry, or duplicate process remains. AppImage remains a documented
upstream bundler limitation, not Koi's Linux installation contract.
