# ACME integration: prerequisites and current limits

Koi implements a private-CA ACME endpoint for dns-01 clients. It is an advanced
integration for an operator already using a reverse proxy or certificate client.
It is not required for the initial [container/LAN trial](../../CONTAINERS.md).

**Current 1.0.0-dev.0 source is not a complete public ACME setup.** It requires an
exact service-name grant bound to an ACME account, while the public operator
workflow creating that grant and composing the listener is incomplete. The
protocol and provider notes below do not fill that missing step.

Published stable 0.9.0 and prerelease 1.0.0-rc.2 have their own contracts.
Use [release readiness](../launch/README.md) and matching docs before adopting
an artifact.

## Required pieces

1. An initialized, unlocked Koi CA and its intended trust/recovery policy.
2. DNS enabled for the configured Koi zone.
3. An ACME client with P-256/ES256 account support and private-root configuration.
4. A DNS provider mapping challenge present/cleanup to Koi TXT operations.
5. One exact service-name grant bound to that persisted ACME account.
6. A listener consuming the resulting certificate and a client that trusts it.

A stock Caddy configuration with only a custom acme_ca URL lacks the required DNS
provider. Traefik/lego also need a compatible provider and account configuration.
Format compatibility is not evidence that a complete maintained integration has
been accepted.

## Inspect the server

With a running daemon and CA:

```sh
koi certmesh acme enable
koi certmesh acme status
```

The command prints the directory/bootstrap information. The dedicated server-auth
TLS listener normally uses port 5643 and /acme/directory. It starts when the CA
is initialized and unlocked; DNS is required. --no-acme disables it.

The listener's own certificate chains to the private CA. Configure the chosen
ACME client's root source; an OS root installation is not proof that the client
uses that source.

## Authorization and protocol scope

- Only dns-01 challenges are supported; no http-01 or tls-alpn-01 path is provided.
- Account signatures use ES256/P-256; RSA account signing is rejected.
- Orders contain one exact account-granted, non-wildcard configured-zone name.
  Being inside the zone alone is not authority to issue.
- The grant is checked when an order is created and again before signing.
- CSR SAN expansion beyond the authorized name is rejected.
- A service certificate is recorded against its grant, not as a new mesh member.
- Requests validate JWS signatures, URL binding and replay nonces.
- Errors use the RFC 8555 application/problem+json shape.

Open enrollment permits account registration but grants no names.
Closed enrollment requires External Account Binding for registration; that also
does not replace the exact service-name grant.

## DNS provider operations

A provider must present and clean up the exact challenge value:

```sh
koi dns txt set _acme-challenge.app.internal "$VALUE"
koi dns txt clear _acme-challenge.app.internal "$VALUE"
```

These POSIX examples assume VALUE is supplied by the provider. The equivalent
authenticated API uses PUT/DELETE /v1/dns/txt with name and value fields.
Cleanup removes only its own value, preserving concurrent challenges.
koi dns add creates address records and is not the challenge operation.

Run the hook where it can reach Koi with the required credentials. Do not embed
a daemon token in images or source control. Challenges are ephemeral; hooks need
error handling and exact cleanup.

## Listener and client completion

A completed integration must place the correct leaf/key/chain in the consuming
proxy, renew it, verify reload, recover from CA/listener interruptions and
preserve the working endpoint on replacement failure.

Koi's Proxy accepts explicit overrides in its own proxy-certs directory.
Do not write into Certmesh's private storage to simulate an absent public
operation. See [Proxy](proxy.md) and [container TLS](recipes/container-trusted-cert.md).

The second client must resolve the name and validate the real leaf through the
intended browser/runtime. Do not declare success based solely on issuance or
root installation.

## Revocation limits

There is no OCSP or CT service. Koi-aware verification can consume signed
revocation metadata; ordinary TLS clients do not receive CRL/OCSP and may accept
a copied leaf until its expiry. Account or grant removal is not instant
revocation in those clients.

## Endpoint reference

| Path on the dedicated TLS listener | Purpose |
| --- | --- |
| GET /acme/directory | Protocol endpoints and metadata |
| HEAD/GET /acme/new-nonce | Fresh nonce |
| POST /acme/new-account | Account registration |
| POST /acme/new-order | One exact granted service name |
| POST /acme/authz/{id} | Authorization state |
| POST /acme/chall/{id} | Trigger validation |
| POST /acme/order/{id}/finalize | CSR validation and signing |
| POST /acme/cert/{id} | Certificate download |
| POST /acme/revoke-cert | Record revocation |

[Certmesh](certmesh.md) · [Trust roots](trust.md) ·
[API authentication](api-authentication.md) · [Release readiness](../launch/README.md)
