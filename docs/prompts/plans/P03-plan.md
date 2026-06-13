# P03 — Container Access Path (`--http-bind` + token UX) — Implementation Plan

> Per CHARTER. Rebuild after the prior attempt was reverted (see PROGRESS divergence log).

## Goal

Make Koi's headline use case real: containers reach the daemon over plain HTTP.
Add a deliberate, loud, still-authenticated exposure path (`--http-bind`) and a
token-distribution UX (`koi token show|write`), then make CONTAINERS.md true.
Default stays loopback. DAT auth is never weakened.

## Bind modes

`--http-bind` / `KOI_HTTP_BIND`, default `loopback`:
- `loopback` → `127.0.0.1` (unchanged default, quiet)
- `bridge` → first docker/podman bridge IPv4 (docker0/podman0/cni-podman0, then
  `br-*`/`docker*`/`podman*`/`cni-*` prefixes); hard error with a clear message if none
- `<ip>` → parse as `IpAddr`; error on malformed
- `0.0.0.0` → all interfaces, loudest warning

Non-loopback binds log a warning naming the flag, and surface in `koi status`,
the breadcrumb endpoint, and the startup log.

## File-by-file change list

### Code
1. **`crates/koi/src/cli.rs`**
   - `Cli`: add `--http-bind` (`env = "KOI_HTTP_BIND"`, default `"loopback"`).
   - `Config`: add `http_bind: String`; set it in `from_cli`, `from_env`, `Default`.
   - `Command`: add `Token(TokenCommand)`; define `TokenCommand` + `TokenSubcommand`
     (`Show { force: bool }`, `Write { path: PathBuf }`).
   - Unit tests for bind parsing live with `resolve_http_bind_ip` (main.rs); add a
     test asserting `Config` carries the default `loopback`.
2. **`crates/koi/src/main.rs`**
   - Add `resolve_http_bind_ip(&str) -> anyhow::Result<IpAddr>` + `#[cfg(test)]` unit
     tests (loopback / 0.0.0.0 / IPv4 / IPv6 / invalid → err). Do **not** unit-test
     bridge (environment-dependent) beyond the no-bridge error shape.
   - `daemon_mode`: resolve bind ip once; pass to `startup_diagnostics` and
     `http::start`; derive breadcrumb endpoint from it (unspecified → 127.0.0.1 for
     client reachability).
   - `startup_diagnostics(config, Option<IpAddr>)`: new arg; emit the mode-specific
     warning/hint UX.
   - Add `Command::Token(tc) => commands::token::run(tc, cli.json)` dispatch arm.
   - **Leave `init_logging` untouched** (the prior attempt regressed it).
3. **`crates/koi/src/adapters/http.rs`**
   - `start(...)`: add `bind_ip: IpAddr` param; bind to it; log actual addr.
   - `AppState`: add `http_bind: String`.
   - `UnifiedStatusResponse`: add `http_bind: String`; include in
     `unified_status_handler` JSON.
4. **`crates/koi/src/commands/token.rs`** (new) + register in `commands/mod.rs`
   - `run(cmd: &TokenCommand, json: bool) -> anyhow::Result<()>`.
   - Reads `koi_config::breadcrumb::read_breadcrumb()`; if absent → friendly
     "daemon not running / no token" error.
   - `show`: refuse when `stdout` is not a TTY unless `--force` (charter rule 5: never
     echo secrets into a pipe by accident); `--json` prints `{"token": "..."}`.
   - `write <path>`: write token `0600` (unix `mode(0o600)`; windows best-effort via
     the same restricted-write the breadcrumb uses). Print confirmation to stderr.
5. **`crates/koi/src/format.rs`**
   - `unified_status`: add a `Bind:` line; update its unit test.
6. **`crates/koi/src/platform/windows.rs`**
   - Update the service-path call sites for `startup_diagnostics` and
     `adapters::http::start` (the two the prior attempt missed).
   - `firewall_ports_for_config`: include the HTTP port when `http_bind` is
     non-loopback (mirror the mTLS rule), so `install`/`check_firewall` cover it.
7. **`crates/koi/src/surface.rs`**
   - Add `token show` / `token write` `CommandDef` entries; note `--http-bind` where
     daemon flags are described.

### Tests
- `resolve_http_bind_ip` unit tests (main.rs).
- DAT-auth router test (http.rs, `tower::ServiceExt::oneshot`): tokenless `POST` →
  401, tokened `POST` → not 401. Exposure does not change auth — the test documents
  that the bind address is independent of the token requirement.
- `format::unified_status` shows `Bind:`.

### Docs
- **CONTAINERS.md**: remove the P01 quarantine banner; document `--http-bind`
  (bridge/0.0.0.0), the compose recipe (`extra_hosts` + `secrets`), and
  `koi token write` for mounting; every curl example carries the token; spell out the
  native-Linux vs Docker-Desktop difference.
- **README** container section: point at the working path.
- **docs/reference/security-model.md** + **http-api.md**: document the bind modes and
  `koi token`.
- Catalog/OpenAPI truthful (covered by surface.rs + the status struct).

## Target shapes

`koi status --json` gains `"http_bind": "127.0.0.1"`.
`koi token show --json` → `{"token":"<dat>"}`.
Startup log lines per mode as in the prompt's north-star.

## Risks
- **Duplicate daemon wiring**: Windows service path (`windows.rs`) mirrors
  `daemon_mode`; both call sites must move together (the prior bug).
- **Bridge detection** is host-dependent; keep the error message actionable and don't
  let it panic. `bridge` resolves at startup only.
- **Breadcrumb on 0.0.0.0**: clients still need a connectable endpoint → write
  `127.0.0.1` in the breadcrumb when bound unspecified.
- **TTY refusal** must not break `--json` piping use; `--force` (and explicit `write`)
  are the escape hatches.

## Verification
`cargo check --workspace` after each phase; then `cargo test`,
`cargo clippy -- -D warnings`, `cargo fmt --check`. Manual: start daemon in each mode,
confirm log + `koi status` + breadcrumb reflect the bind; `koi token show|write`
behave per rules; tokenless POST 401 / tokened POST 200 against a non-loopback bind.

## Acceptance criteria mapping
- `--http-bind`/`KOI_HTTP_BIND` four forms, default loopback, warning + status +
  breadcrumb → cli.rs, main.rs, http.rs, format.rs.
- `koi token show|write`, tty refusal, 0600 → commands/token.rs.
- Windows firewall on exposure → windows.rs.
- Tests (bind parse + 401/200) → main.rs, http.rs.
- CONTAINERS.md verified, README updated → docs.
- Catalog + OpenAPI truthful → surface.rs, http.rs status struct.
