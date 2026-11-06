# Operate the daemon and preserve its state

Koi's daemon owns discovery, naming, runtime observation and configured services.
The CLI inspects or changes that daemon. For the first adoption task, use
[containers](../../CONTAINERS.md); for native installation and logs, use
[install and service](install-and-service.md).

These commands describe current source. [Release readiness](../launch/README.md)
identifies supported artifacts. The shell binary and installed service can differ.

## Select the process deliberately

- koi --daemon starts a foreground daemon.
- Normal capability commands use the installed local service or explicit endpoint.
- Bare koi reports status/help; it does not start a new daemon.
- --standalone requests an explicit local composition and refuses an existing local owner.
- koi install uses the platform service recipe; koi uninstall removes that service.

Preserve an existing installed service instead of launching a second process
against its state or network identity.

## Inspect observed state

```sh
koi version
koi status
koi status --json
koi mdns admin status --json
koi health status
```

koi version identifies the invoked binary. Also inspect the native service's
executable and daemon version. A row marked unavailable or not observed is not
an empty successful result. Provider state, runtime inventory and service checks
have different meanings.

koi launch opens the local web interface when available. Dashboard/workbench
capabilities vary with the artifact; CLI and HTTP suffice for the initial
container task.

## Configuration and access

```sh
koi config path
koi config show
```

Inspect the actual durable configuration, service environment and overrides
before changing a port, runtime or data root. A variable in an interactive shell
does not configure an existing service. Native recipes and settings are described
in [installation](install-and-service.md).

HTTP is loopback by default; authentication and plaintext exposure are distinct.
Use the [security model](../reference/security-model.md) before remote access.
Engine permissions belong to the running account, not merely the installer user.

## System HTTP endpoints

| Endpoint | Meaning |
| --- | --- |
| GET /healthz | Minimal daemon liveness |
| GET /v1/status | Aggregate observed capability state |
| GET /v1/host | Host identity/interface information |
| POST /v1/admin/shutdown | Authenticated graceful shutdown |
| GET /v1/dashboard/snapshot | Dashboard projection |
| GET /v1/dashboard/events | Event feed |
| GET /docs | Interactive API documentation |
| GET /openapi.json | HTTP API schema |

Consult [route authorization](../reference/http-route-auth-matrix.md) for read
and mutation credentials. A live healthz endpoint does not prove engine access,
peer discovery, application readiness or TLS trust.

<a id="when-things-go-wrong"></a>

## Restart and recovery

Restart through SCM, systemd, OpenRC or launchd as appropriate. In PowerShell use
sc.exe, not its unrelated sc alias. Inspect the service log if startup fails.
An interrupted transactional install should recover through the installer, not
manual deletion of its checkpoint.

After restart, repeat the known application's second-client access and inspect
runtime reconciliation. If using TLS, verify the actual leaf and client trust,
then the intended renewal/reload path. Record any changed state.

## Uninstalling

koi uninstall removes the service and its owned registration/policy according to
the platform recipe while preserving application data for reinstallation.
Read its result; do not assume all external resolver, proxy or client-root
configuration has been removed.

Uninstall is not a factory reset. It is not required for routine
[upgrades](upgrading.md).

<a id="factory-reset"></a>

## Destructive operations

| Command | Scope |
| --- | --- |
| koi certmesh destroy | CA/member material and certmesh state; review dependent services and client roots |
| koi factory-reset | The configured Koi data directory; destroys local certificate/private-key and other persistent state |

Factory reset requires platform elevation and explicit confirmation. In an
interactive terminal the confirmation is RESET; noninteractive use requires the
global --yes option. It is never a generic startup or networking repair.

Before an intentional destructive operation, preserve an encrypted CA backup
and a consistent copy of necessary service/configuration/state. Factory reset
keeps no recovery copy. An external valid backup may restore continuity; without
the CA key, future renewal/recovery cannot recreate the same authority.

Deleting a CA's local files does not magically invalidate every already-issued
certificate on other clients. Existing leaves retain their actual expiry and
client trust until those clients' policies change. Plan removal of dependent
listeners, names and roots explicitly.

[CA recovery](certmesh-ha-recovery.md) and [troubleshooting](troubleshooting.md)
cover the relevant operations. Protect unrelated services and data when cleaning
up a trial.
