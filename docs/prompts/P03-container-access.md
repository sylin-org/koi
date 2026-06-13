# P03 — Container Access Path (`--http-bind` + token UX)

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none (pairs with P01) · Read `docs/prompts/CHARTER.md` first.

## Mission

Koi's headline pitch — *"containers gain LAN capabilities through plain HTTP"* — is
currently impossible on native Linux Docker: the HTTP adapter binds `127.0.0.1` only,
no flag exists to change it, and all mutations require an `x-koi-token` that containers
have no documented way to obtain. Design and ship the secure opt-in exposure path and
the token-distribution UX, then make CONTAINERS.md true again. Charter principle 5
governs everything here: *the secure path is the easy path* — exposure must be
deliberate, loud, and still authenticated.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `crates/koi/src/adapters/http.rs` (bind ~238, DAT middleware ~455–495, CORS ~230)
3. `crates/koi/src/cli.rs` (flag patterns, env-var mirrors), `crates/koi/src/main.rs`
   (daemon wiring), `koi-config` breadcrumb (token distribution today)
4. `CONTAINERS.md` (the 914-line promise you are making true)
5. `docs/assessment/research/landscape-2026.md` §2 (why this use case matters)

## Research phase

- How does the breadcrumb file distribute the token today (path per OS, format,
  permissions)? Who reads it?
- How do comparable daemons expose bind config (Docker's `-H`, Tailscale's authkey
  file, syncthing's GUI address)? Pick the least-surprise shape.
- Docker specifics to verify: `host-gateway` / `172.17.0.1` reachability semantics on
  native Linux vs Docker Desktop; what a compose `extra_hosts: host.docker.internal:host-gateway`
  stanza provides.
- Where else binds happen: mTLS adapter (0.0.0.0:5642), and whether the Windows
  firewall helper (`platform/windows.rs`) needs a rule when exposure is enabled.

## Target experience (north star)

```console
$ koi --daemon
HTTP: 127.0.0.1:5641 (loopback only — use --http-bind to expose)

$ koi --daemon --http-bind bridge
HTTP: 172.17.0.1:5641 (docker bridge) — mutations require x-koi-token
hint: containers read the token from a mounted secret; see `koi token --help`

$ koi --daemon --http-bind 0.0.0.0          # explicit, loudest warning
WARNING: Koi is reachable from your entire LAN. Mutations still require the
daemon token; GET endpoints are readable by any device. (--http-bind 0.0.0.0)
```

Token UX (new `koi token` domain-less utility command or `koi admin token` — research
which fits the moniker rules; justify in plan):

```console
$ koi token show                 # prints the current daemon token (tty only; refuses
                                 # when stdout is not a tty unless --force)
$ koi token write /run/koi/token  # 0600 file for mounting into containers
```

Compose recipe that must work end-to-end and goes into CONTAINERS.md:

```yaml
services:
  app:
    extra_hosts: ["host.docker.internal:host-gateway"]
    environment: [ "KOI_URL=http://host.docker.internal:5641" ]
    secrets: [ koi_token ]
secrets:
  koi_token: { file: /run/koi/token }
```

```bash
TOKEN=$(cat /run/secrets/koi_token)
curl -H "x-koi-token: $TOKEN" -X POST "$KOI_URL/v1/mdns/announce" \
  -d '{"name":"My App","type":"_http._tcp","port":8080}'
```

`--http-bind` accepts: `loopback` (default), `bridge` (resolve the docker/podman bridge
interface IP at startup; fail with a clear message if none), `<ip>`, `0.0.0.0`. Env
mirror `KOI_HTTP_BIND`. The chosen bind must appear in `koi status`, the breadcrumb,
and the startup log.

## Plan, then implement

Per charter. Cover: flag + config plumbing → bind resolution (incl. bridge detection)
→ warning UX → token subcommand → breadcrumb/status surfacing → CONTAINERS.md rewrite
(remove the P01 quarantine banner if present; every example tested) → guides/reference
updates → catalog entries.

## Acceptance criteria

- [ ] `--http-bind` / `KOI_HTTP_BIND` with the four forms above; default unchanged
      (loopback); non-loopback binds log the warning and reflect in `koi status` +
      breadcrumb.
- [ ] `koi token show|write` exists, follows charter output rules, never echoes into
      non-tty without `--force`, writes 0600.
- [ ] Windows: exposure path creates/updates the firewall rule like the mTLS port does.
- [ ] Tests: bind-mode parsing unit tests; an integration-style test that a
      non-loopback bound daemon rejects tokenless POST (401) and accepts tokened POST.
- [ ] CONTAINERS.md examples verified working on native-Linux semantics (document the
      Docker-Desktop difference explicitly); README container section updated.
- [ ] Catalog (`koi <cmd>?`) and OpenAPI/docs updated and truthful.

## Verification

`cargo check && cargo test && cargo clippy -- -D warnings`; manual: start daemon with
each bind mode and run the documented compose curl (or its host-side equivalent
`curl --interface` simulation); confirm 401-without-token / 200-with-token.

## Do NOT

- Change the default bind (loopback stays).
- Weaken or exempt anything from DAT auth; do not add token query-params (header only).
- Touch the mTLS adapter's design or implement TLS for the HTTP port (out of scope).
- Implement `--endpoint` remote-client token UX (P09 territory) beyond not regressing it.
