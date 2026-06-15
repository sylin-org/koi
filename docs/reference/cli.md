# CLI Reference

Binary: `koi` (installed as `koi-net` from crates.io)

Global flags work with any subcommand:

| Flag              | Env var           | Default          | Description                        |
| ----------------- | ----------------- | ---------------- | ---------------------------------- |
| `--json`          | -                 | off              | JSON output (NDJSON for streaming) |
| `--timeout SECS`  | -                 | varies           | Auto-exit (0 = run forever)        |
| `--endpoint URL`  | -                 | auto-detect      | Connect to specific daemon         |
| `--standalone`    | -                 | off              | Skip daemon detection              |
| `-v`, `-vv`       | -                 | off              | Increase verbosity (debug, trace)  |
| `--log-file PATH` | `KOI_LOG_FILE`    | -                | Write logs to file                 |
| `--port PORT`     | `KOI_PORT`        | `5641`           | HTTP API port                      |
| `--http-bind`     | `KOI_HTTP_BIND`   | `loopback`       | HTTP bind: loopback / bridge / `<ip>` / 0.0.0.0 |
| `--pipe PATH`     | `KOI_PIPE`        | platform default | IPC socket/pipe path               |
| `--log-level`     | `KOI_LOG`         | `info`           | Log level                          |
| `--no-http`       | `KOI_NO_HTTP`     | false            | Disable HTTP adapter               |
| `--no-ipc`        | `KOI_NO_IPC`      | false            | Disable IPC adapter                |
| `--no-mdns`       | `KOI_NO_MDNS`     | false            | Disable mDNS                       |
| `--no-certmesh`   | `KOI_NO_CERTMESH` | false            | Disable certmesh                   |
| `--no-dns`        | `KOI_NO_DNS`      | false            | Disable DNS                        |
| `--no-health`     | `KOI_NO_HEALTH`   | false            | Disable health                     |
| `--no-proxy`      | `KOI_NO_PROXY`    | false            | Disable proxy                      |
| `--no-udp`        | `KOI_NO_UDP`      | false            | Disable UDP bridging               |
| `--no-runtime`    | `KOI_NO_RUNTIME`  | false            | Disable runtime adapter            |
| `--runtime KIND`  | `KOI_RUNTIME`     | `auto`           | Runtime backend (docker/podman/auto) |
| `--dns-port`      | `KOI_DNS_PORT`    | `53`             | DNS server port                    |
| `--dns-zone`      | `KOI_DNS_ZONE`    | `lan`            | Local DNS zone                     |
| `--dns-public`    | `KOI_DNS_PUBLIC`  | false            | Allow non-private DNS clients      |

---

## Service discovery (mDNS)

```
koi mdns discover [TYPE]                          # browse for services (5s default)
koi mdns announce NAME TYPE PORT [KEY=VALUE ...]  # advertise a service
koi mdns unregister ID                            # stop advertising
koi mdns resolve INSTANCE                         # look up a specific instance
koi mdns subscribe TYPE                           # stream lifecycle events
```

### Admin commands

```
koi mdns admin status                             # daemon mDNS status
koi mdns admin ls                                 # list all registrations
koi mdns admin inspect ID                         # detailed view (prefix matching)
koi mdns admin drain ID                           # start grace timer
koi mdns admin revive ID                          # cancel drain
koi mdns admin unregister ID                      # force-remove
```

---

## Certificate mesh

```
koi certmesh create [--profile just-me|team|organization]
                    [--operator NAME]             # interactive ceremony
koi certmesh status                               # show mesh status
koi certmesh join [ENDPOINT]                      # join existing mesh
koi certmesh unlock                               # decrypt CA key
koi certmesh log                                  # show audit log
koi certmesh set-hook --reload "COMMAND"          # set renewal hook
koi certmesh promote [ENDPOINT]                   # promote standby CA
koi certmesh open-enrollment                      # open enrollment window
koi certmesh close-enrollment                     # close enrollment
koi certmesh rotate-auth                          # rotate auth credential
koi certmesh backup PATH                          # encrypted backup
koi certmesh restore PATH                         # restore from backup
koi certmesh revoke HOSTNAME [--reason REASON]    # revoke a member
koi certmesh destroy                              # destroy all state (requires typing DESTROY)
```

---

## DNS

```
koi dns serve                                     # start resolver
koi dns stop                                      # stop resolver (daemon mode)
koi dns status                                    # resolver status
koi dns lookup NAME [--record-type A|AAAA|ANY]    # query a name
koi dns add NAME IP [--ttl SECS]                  # static entry
koi dns remove NAME                               # remove static entry
koi dns list                                      # list all resolvable names
```

---

## Health

```
koi health status                                 # current state of all checks
koi health watch [--interval SECS]                # live dashboard
koi health add NAME --http URL                    # register HTTP check
koi health add NAME --tcp HOST:PORT               # register TCP check
koi health remove NAME                            # remove a check
koi health log                                    # transition history
```

---

## Proxy

```
koi proxy add NAME --listen PORT --backend URL    # add proxy entry
koi proxy remove NAME                             # remove entry
koi proxy status                                  # active proxy status
koi proxy list                                    # list entries
```

---

## Runtime adapter

The runtime adapter is controlled via daemon flags (no CLI subcommands). Status and instances are available via the HTTP API:

```
GET /v1/runtime/status                            # adapter status
GET /v1/runtime/instances                         # tracked instances
```

Runtime backend selection:

```
koi --daemon --runtime auto                       # auto-detect (default)
koi --daemon --runtime docker                     # explicit Docker
koi --daemon --runtime podman                     # explicit Podman
koi --daemon --no-runtime                         # disable
```

---

## MCP (AI agents)

```
koi mcp serve                                     # serve MCP over stdio for an agent host
```

Launched by an MCP host (Claude Code/Desktop, or any stdio MCP client), not run
interactively. Talks to a running daemon via the breadcrumb, or `KOI_ENDPOINT` /
`KOI_TOKEN`. Exposes read tools (`lan_discover`, `lan_resolve`, `dns_lookup`,
`lan_inventory`, `health_snapshot`, `runtime_instances`, `mcp_servers_on_lan`) and
write tools (`lan_announce`, `lan_unregister`, `dns_add`, `dns_remove`). CA-admin
operations are not exposed. See the [MCP guide](../guides/mcp.md).

---

## System

```
koi status                                        # unified capability status
koi token show                                    # print the daemon access token (tty only)
koi token write /run/koi/token                    # write the token to a 0600 file for containers
koi factory-reset                                 # destroy data directory
koi install                                       # install system service
koi uninstall                                     # remove system service
koi version                                       # show version
```

`koi token` reads the daemon's current access token from the breadcrumb file so it
can be handed to another process or mounted into a container as a secret. `show`
refuses to print into a non-tty unless `--force`; `write` creates the file
owner-only (0600 on Unix, ACL-restricted on Windows). See
[CONTAINERS.md](../../CONTAINERS.md) and the
[security model](security-model.md) for `--http-bind` exposure and the token recipe.

---

## Piped JSON mode

When stdin is a pipe, Koi reads NDJSON commands and writes NDJSON responses:

```bash
echo '{"browse":"_http._tcp"}' | koi
echo '{"register":{"name":"test","type":"_http._tcp","port":8080}}' | koi | jq '.registered.id'
```

---

## Mode detection

1. **Subcommand present** → CLI mode (client if daemon running, standalone if not)
2. **`--standalone`** → forced standalone mode
3. **`--endpoint URL`** → forced client mode
4. **Stdin is a pipe** → NDJSON piped mode
5. **No subcommand** → daemon mode (HTTP + IPC)
6. **Windows, no args, launched by SCM** → Windows Service mode
