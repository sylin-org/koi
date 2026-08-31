# Linux desktop has no durable install artifact from CachyOS

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
