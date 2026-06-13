# P04 — Proxy Rebuild: TLS Passthrough

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none · Read `docs/prompts/CHARTER.md` first. Break-and-rebuild
> is explicitly authorized for this crate.

## Mission

koi-proxy's data plane is **broken and has plausibly never worked**: it registers an
axum route `"/*path"` which panics under the workspace's axum 0.8.8 — inside a
`tokio::spawn`, so silently — while `status()` hardcodes `running: true`; a second
panic lurks in the cert-watch callback (`tokio::spawn` from notify's non-tokio thread);
and the reqwest-based forwarding can never support WebSockets. Do not patch it.
**Rebuild the data plane as a TLS-terminating TCP passthrough** — fewer lines, fixes
all three defects structurally, and matches the crate's honest role: *the pre-wired TLS
endpoint for certmesh certs*, not a Caddy competitor.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/findings/verification-2026-06.md` claim 1 (re-verify every part:
   listener.rs:46, lib.rs spawn site, status(), watch_certs).
3. All of `crates/koi-proxy/src/` (954 lines — read it fully); its HTTP routes and
   protocol types (keep the management API shape stable unless improvement is obvious);
   `docs/guides/proxy.md`.
4. How certmesh delivers certs to proxy entries today (cert_dir layout, reload hooks).

## Research phase

- Confirm the panic empirically: write a 10-line test that builds the current router
  and observe the panic message, before deleting the old code (this becomes your
  regression context).
- Study `tokio_rustls::TlsAcceptor` + `tokio::io::copy_bidirectional` patterns; how
  rustls `ServerConfig` hot-reload is typically done (ArcSwap of the config, or
  rustls' `ResolvesServerCert` for lazy per-handshake cert resolution — the latter
  makes "hot reload" free; evaluate and choose, justify in plan).
- notify-thread → tokio bridging: capture a `tokio::runtime::Handle` before
  constructing the watcher, or use a std channel polled from a tokio task.
- Check what koi-embedded and the dashboard read from ProxyRuntime (status shape
  consumers).

## Target experience (north star)

```console
$ koi proxy add grafana --listen 8443 --backend 127.0.0.1:3000
✓ grafana: TLS :8443 → 127.0.0.1:3000 (cert: certmesh, auto-reload)

$ koi proxy status
NAME      LISTEN  BACKEND          TLS        STATE
grafana   :8443   127.0.0.1:3000   certmesh   running
old-app   :9443   127.0.0.1:9000   certmesh   error: address in use
```

`STATE` is **real**: derived from the listener task's actual liveness (a watch channel
or JoinHandle probe), with the bind/accept error preserved and shown. WebSockets work
by construction (byte-level passthrough). Architecture shape:

```rust
// listener task per entry — owns a TcpListener; accepts; for each conn:
let tls = acceptor.accept(tcp).await?;                  // terminate TLS
let upstream = TcpStream::connect(backend).await?;      // plain TCP to backend
tokio::io::copy_bidirectional(&mut tls, &mut upstream)  // pump bytes both ways
// state: Arc<watch::Sender<EntryState>> updated on bind error / panic / shutdown
// certs: ResolvesServerCert impl reading an ArcSwap'd CertifiedKey,
//        swapped by the (runtime-Handle-bridged) cert watcher
```

Keep: `ProxyEntry`/config persistence, the HTTP management routes, events
(EntryUpdated/EntryRemoved), `allow_remote` (loopback vs 0.0.0.0 listen — preserve its
security semantics). Delete: forwarder.rs's HTTP-level forwarding, the axum data-plane
router, `load_entries_with_certmesh` (verified dead code).

## Plan, then implement

Per charter. Sequence: failing regression test → new listener module → state/liveness
plumbing → cert hot-reload → wire into ProxyRuntime keeping the facade API → delete
dead code → docs.

## Acceptance criteria

- [ ] No axum route patterns remain in koi-proxy's data plane; crate compiles against
      workspace axum 0.8.8 with zero panics at entry start.
- [ ] `status()` reflects real listener state including error detail; the
      hardcoded `running: true` is gone (HTTP response type gains a state/error field —
      breaking change is fine, update consumers: dashboard, embedded, CLI formatting).
- [ ] Cert change on disk is picked up without restart, no panic from the watcher path
      (test: swap cert files, next handshake serves the new cert).
- [ ] Integration test: start an entry with a self-signed cert → HTTPS request through
      it reaches a stub backend and returns its body; a WebSocket (or raw bidirectional
      bytes) round-trips.
- [ ] Bind-conflict test: second entry on the same port → status shows error state, no
      panic, daemon unaffected.
- [ ] `docs/guides/proxy.md` rewritten for the passthrough model (honest about what a
      passthrough cannot do: no path routing, no header injection — link Caddy/Traefik
      collaboration for that); catalog + OpenAPI updated.
- [ ] Crate is smaller than before the rebuild (it should land well under 954 lines of
      src excluding tests).

## Verification

`cargo check && cargo test -p koi-proxy && cargo test && cargo clippy -- -D warnings`;
the integration test above runs in CI without Docker or network beyond loopback.

## Do NOT

- Add HTTP-layer features (routing, rewrites, middlewares, ACME) — passthrough only.
- Compete with Caddy/Traefik in docs framing; position as certmesh's convenience
  endpoint per the collaboration doctrine.
- Change the management API paths (`/v1/proxy/*`) — shape evolution OK, paths stable.
