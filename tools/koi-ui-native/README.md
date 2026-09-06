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
