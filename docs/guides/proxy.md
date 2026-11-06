# Terminate TLS in front of a local service

Koi's proxy accepts TLS and forwards decrypted bytes to a TCP backend. Use it
when a known service needs a TLS endpoint and its certificate matches the client
URL. It does not route HTTP paths, rewrite headers or configure client trust.

For the first adoption trial, establish [container application access](../../CONTAINERS.md)
before adding this layer. This guide describes current source; consult
[release readiness](../launch/README.md) and release-matched docs for a packaged artifact.

## Create and inspect a listener

With a running daemon and an application on port 3000:

```sh
koi proxy add app --listen 9443 --backend 127.0.0.1:3000
koi proxy status
koi proxy list
```

Status reports listener state and selected TLS source; list reports configured
entries. A bind failure is an error, not a running listener. Adding the same name
updates its configuration.

The backend is host:port. The proxy-to-backend hop is plaintext. A non-loopback
backend requires explicit consent through the command flag:

```sh
koi proxy add app --listen 9443 --backend 192.0.2.20:3000 --backend-remote
```

Replace the documentation address. This flag concerns the backend destination,
not client authorization on the listener.

## Certificate selection

Current source selects the first usable source:

1. `<data-dir>/proxy-certs/<entry-name>/{fullchain.pem,key.pem}`,
   an explicit override owned by Proxy.
2. A healthy local member identity supplied live by Certmesh.
3. A generated self-signed certificate.

Status identifies override, certmesh or self-signed, and HTTP status includes a
certificate revision. A usable self-signed listener still requires deliberate
client trust; it is not a successful warning-free HTTPS setup by itself.

Certmesh identity changes reach Proxy through composition. An explicit override
is watched on disk. A new handshake uses the replacement certificate without
requiring existing connections to close. Inspect status and perform a real
handshake after renewal; file replacement alone is not proof.

## Verify the client URL

Inspect the actual SANs. Host-member certificates do not automatically cover a
container's vanity name. Do not assume localhost appears in every certificate.
The client must resolve the chosen name, reach the listener, trust the intended
root and receive an unexpired matching leaf.

Follow [host-member HTTPS](../tutorials/trusted-https.md). Test the intended
browser/runtime independently; OS root installation is not proof that every
client uses that source.

Container labels currently do not compose an exact service-name grant with this
listener. See [container TLS limits](recipes/container-trusted-cert.md).

## Existing reverse proxies and protocols

Keep Caddy/Traefik or another application proxy for routing, redirects and
application-specific policy. Koi's [ACME](acme.md) interface requires an exact
account-bound name grant and a DNS provider; its public end-user grant workflow
is incomplete.

Byte forwarding can carry bidirectional application traffic, but TLS negotiation
and backend protocol expectations still need verification. Do not infer support
for every HTTP/2, gRPC or upgraded protocol from the TCP forwarding design.

## HTTP interface

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /v1/proxy/status | Runtime listeners and TLS state |
| GET | /v1/proxy/list | Configured entries |
| POST | /v1/proxy/add | Add/update an entry |
| DELETE | /v1/proxy/remove/{name} | Remove an entry |

Example authenticated mutation body:

```json
{"name":"app","listen_port":9443,"backend":"127.0.0.1:3000"}
```

Use [API authentication](api-authentication.md) for tokens and protected reads.
Exposing management HTTP is separate from exposing a proxy listener.

<a id="troubleshooting"></a>

## Failure and removal

- Address in use: choose a free listener port or resolve the existing owner.
- Self-signed source: inspect Certmesh state and identity health, or the configured override.
- Name mismatch: use an actual SAN or obtain a certificate covering the intended name.
- Unknown issuer: configure the intended client's root source.
- Backend refusal: verify the published application endpoint from the proxy host.
- Remote backend rejected: understand the plaintext hop before using backend-remote.

Remove only the entry intended for removal:

```sh
koi proxy remove app
```

A runtime-owned entry should instead be removed by changing the owning
container configuration/lifecycle.
