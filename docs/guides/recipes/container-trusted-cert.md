# Recipe: a container with a stable name and a trusted TLS cert

Goal: start a container, give it one set of labels, and reach it over real HTTPS from
another machine on the LAN — DNS name and trusted certificate, no manual cert wiring.

This is a cross-cutting recipe: it leans on four capabilities at once (mDNS, DNS,
certmesh, proxy) and the runtime adapter that ties them together. If you only want one of
those, read its guide instead — [runtime.md](../runtime.md), [proxy.md](../proxy.md),
[dns.md](../dns.md), [certmesh.md](../certmesh.md). This page is the assembled flow, and
it is honest about the one part labels *cannot* do for you.

---

## What you'll have at the end

- `app.lan` resolves to the host running the container.
- A TLS listener on the host that proxies to the container.
- A certificate that chains to a CA your network trusts, so clients that trust the root
  don't see an "unknown issuer" warning.

One catch, stated up front because it shapes the whole recipe: the labels get you a
*trusted chain* and a *DNS name*, but they do **not** mint a certificate whose name is
`app.lan`. The proxy serves the **host's** certmesh member certificate, whose SANs are the
host's own name — not `app.lan`. So the genuinely warning-free address is the host's name;
making `https://app.lan` itself warning-free is the last-mile step at the end. No magic
per-container cert is injected — see [The honest reality](#the-honest-reality).

---

## Prerequisites

A Koi daemon running on the container host, with mDNS, DNS, certmesh, and the proxy all
enabled (they are on by default), and a certmesh CA that is **created and unlocked**:

```bash
koi install                 # or: koi --daemon
koi certmesh create         # one-time, on the host that owns the CA
koi certmesh unlock         # after each daemon restart, unless auto-unlock is on
koi certmesh status         # CA locked: false  ← required for a trusted cert
```

If certmesh is locked or uninitialized the proxy still starts, but it serves a
*self-signed* cert (warning everywhere). Confirm `CA locked: false` before continuing.

The runtime adapter connects to Docker (or Podman) automatically. Check it sees the
daemon:

```bash
curl -s http://localhost:5641/v1/runtime/status
```

---

## The label set that works

```bash
docker run -d \
  -p 8080:80 \
  --label koi.announce=app \
  --label koi.proxy.port=443 \
  nginx:alpine
```

That is the whole thing. What each label does — verified against the runtime adapter's
label parser:

| Label | Effect |
| --- | --- |
| `koi.announce=app` | Shorthand that sets the service **name**, the **DNS name** (`app`), and `enable=true`. Result: `app._http._tcp` on mDNS (port 80 → HTTP heuristic) and `app.lan` in the local resolver, pointing at the host. |
| `koi.proxy.port=443` | Adds a TLS proxy entry named `app` that **listens on host port 443** and forwards to the container's published port (`8080` here, over plain HTTP on the host loopback). |

The proxy listener binds `0.0.0.0`, so it is reachable from other machines on the LAN
(unlike the daemon's management API, which is loopback by default).

> A `koi.certmesh=true` label exists and is parsed, but it is **inert** today: it does not
> trigger a per-container certificate. The proxy uses the host's existing member cert
> regardless. Setting it changes nothing — don't rely on it.

Want the proxy reachable from another host *and* the backend on a different machine? Add
`koi.proxy.remote=true` (the proxy→backend hop is then plaintext on the wire — opt in
knowingly). For a custom service type, health path, or TXT records, see the
[full label reference](../runtime.md#full-label-reference).

---

## Verify the wiring

```bash
koi mdns discover _http._tcp      # → app._http._tcp on port 8080
koi dns lookup app                # → app.lan = <host IP>
koi proxy status                  # → app  :443  127.0.0.1:8080  certmesh  running
```

The `TLS` column in `koi proxy status` is the tell. `certmesh` means the proxy found the
host's member cert on disk and is serving it. `self-signed` means certmesh is locked or
the member cert hasn't been issued — go back and `koi certmesh unlock`.

From the host itself, the host's own name is already warning-free once the root is trusted
locally (certmesh installs the CA into the host's trust store at creation time):

```bash
curl https://$(hostname):443/        # trusted: the member cert's SAN is the host name
```

---

## Trust the root on the client

Any *other* machine needs the certmesh CA root in its trust store. Export it from the host
and install it on the client with `koi trust` (local-only; touches the OS store directly,
needs elevated privileges):

```bash
# On the host: print the CA root.
koi trust export --ca > koi-root.pem

# Copy koi-root.pem to the client, then on the client:
koi trust install ./koi-root.pem
koi trust list                       # confirm it's there
```

`koi trust install` validates that the PEM is a real CA certificate and rejects a
leaf/server cert, so you can't install the wrong file as a root. It tracks only the roots
it installed and never touches the rest of your OS store; `koi trust remove <name>` undoes
it. Full details and the step-ca/Caddy/mkcert variations are in the
[trust how-to](../integrations.md#trust-root-distribution).

Now, from the client, the host's name is trusted:

```bash
curl https://<host>.lan:443/         # if the host is itself in the zone as <host>.lan,
                                     # but see the catch below for app.lan specifically
```

---

## The honest reality

Here is the part the labels can't finish, and why.

The proxy serves the **host's certmesh member certificate**. That certificate's Subject
Alternative Names are the host's identity — its hostname, `localhost`, `127.0.0.1`, `::1` —
**not** `app.lan`. (See [certmesh.md → Certificate details](../certmesh.md#certificate-details).)

So after you trust the root on the client:

- `https://<host-with-a-SAN-match>` → **fully trusted, no warning.** The chain is trusted
  *and* the name matches a SAN.
- `https://app.lan:443` → trusted chain, but the browser/`curl` still flags a **name
  mismatch**, because `app.lan` is not in the certificate. The `koi.certmesh` label does
  not fix this — there is no per-container cert.

To make `https://app.lan` itself warning-free, you need a certificate whose SAN includes
`app.lan`. Koi gives you two first-class ways to get one — both produce a cert the same
trusted CA signed:

1. **ACME, in-zone (recommended).** Koi runs an [RFC 8555 ACME server](../acme.md) in front
   of the CA that issues for any name **inside your Koi DNS zone** (`app.lan` qualifies).
   Point Caddy/Traefik/`lego` at Koi's directory, have it trust the root once, and it gets
   (and auto-renews) a cert for `app.lan`. Front your service with that proxy instead of —
   or behind — Koi's passthrough.
2. **Per-entry cert on disk.** Place a `fullchain.pem` + `key.pem` at
   `<data-dir>/certs/app/` (the proxy entry name). The proxy prefers a per-entry cert over
   the host member cert, so it will serve that one. You issue it however you like, as long
   as it's signed by the trusted CA and lists `app.lan`. See
   [proxy.md → Certificates](../proxy.md#certificates).

This is the substrate doctrine: the labels assemble name + listener + trusted chain
automatically; the SAN-matching cert is the deliberate step, and Koi hands you a standard
ACME endpoint to automate it rather than inventing a private mechanism.

---

## Cleanup

Stop the container and every resource it created is removed within seconds — the mDNS
announcement, the `app.lan` DNS entry, the health check, and the `:443` proxy listener:

```bash
docker stop <container>
koi proxy status        # the app entry is gone
koi dns lookup app      # no longer resolves
```

Untrust the root on a client when you're done with it:

```bash
koi trust remove <name>     # the name from `koi trust list`
```

---

## See also

- [runtime.md](../runtime.md) — every label, the start/stop lifecycle, port heuristics.
- [proxy.md](../proxy.md) — how the proxy resolves its cert and the per-entry override.
- [certmesh.md](../certmesh.md) — what the member cert covers, unlock, the CA file layout.
- [acme.md](../acme.md) — getting an in-zone cert (the warning-free `app.lan` path).
- [trust how-to](../integrations.md#trust-root-distribution) — `koi trust` in full.
- [security model](../reference/security-model.md) — the daemon access token, for any
  mutating HTTP call you script instead of using the CLI.
