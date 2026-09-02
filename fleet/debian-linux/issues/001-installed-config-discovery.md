# PH-001 — installed service config is invisible to the ordinary CLI

## Status

Open. Observed on headless Debian 13 after a real system install from current
`dev` on 2026-09-02.

## Reproduction

The one installed `koi.service` is active as root. Its generated unit sets
`XDG_CONFIG_HOME=/etc`, and the effective durable config is
`/etc/koi/config.toml`. The authenticated `stone` operator can reach that
service through `/run/koi.sock`; `koi status` and `koi trust diagnose` both
return its live state.

As that same operator:

```text
$ koi config path
/home/stone/.config/koi/config.toml

$ koi config show
none (default location: /home/stone/.config/koi/config.toml)
```

Running the commands as root similarly reports `/root/.config/koi/config.toml`.
Neither command names the active service's real config, even though
`/etc/koi/config.toml` exists and owns its preserved `24441:24442:24443` port
run.

## Expected boundary

Installed-service configuration must be discoverable without guessing from a
well-known path or weakening the owner-private breadcrumb. Prefer an additive
authenticated local-control fact (parallel to `data_root`) or another explicit
platform-owned contract, then make `config path/show` distinguish the installed
service from the invoking user's foreground/user-service config. Preserve the
current explicit `--config` precedence and user-service behavior.
