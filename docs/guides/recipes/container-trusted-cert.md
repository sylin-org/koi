# Container HTTPS: names, certificates and current limits

[Publication and second-machine application access](../../../CONTAINERS.md) is
the first adoption task. Trusted exact service-name HTTPS is a separate extension.
This page explains current pieces and the missing public operation; it is not a
finished label-to-HTTPS recipe.

These limits describe 1.0.0-dev.0 source. Stable 0.9.0 and prerelease 1.0.0-rc.2
have separate contracts. [Release readiness](../../launch/README.md) states
artifact-specific support.

## What labels configure

```yaml
services:
  app:
    image: nginx:alpine
    ports:
      - "8080:80"
    labels:
      koi.announce: app
      koi.health.path: /
      koi.proxy.port: "9443"
```

This illustrative app requests discovery, naming, health and a host TLS proxy.
It does not issue a certificate for app.internal. Record a pinned image digest
for acceptance; this example is not an accepted fixture.

The koi.certmesh label is request metadata. It does not create a workload
identity or inject a private key.

## Inspect the certificate source

```sh
koi proxy status
koi certmesh status --json
```

Current Proxy selects:

1. A Proxy-owned override at
   `<data-dir>/proxy-certs/<entry-name>/{fullchain.pem,key.pem}`.
2. A healthy local member identity supplied by Certmesh.
3. A generated self-signed fallback.

A certmesh chain does not imply the service name is in the SANs. Inspect the
actual certificate, which may differ between releases or persisted installations.
Root trust and name matching are both required.

## Manual configurations

If a host member name is acceptable, follow
[host-member HTTPS](../../tutorials/trusted-https.md) and verify it using the
intended client's ordinary resolver and browser root source.

Existing proxy/CA tooling can continue to manage service certificates.
An explicit Proxy-owned override is possible, but the operator owns its secure
permissions, renewal and reload verification. Inspect the SAN, chain, key match
and expiry; a filename is not certificate identity.

## Exact service-name setup in development

Certmesh implements durable grants binding one service and configured-zone name
to either the host proxy owner or a named ACME account. Host leaf issuance and
renewal preserve prior usable material if replacement cannot commit.

The public operation granting the name and composing the certificate with Proxy
is incomplete. Neither container labels nor the ordinary CLI finish this workflow.
Do not hand-edit Certmesh's private state.

External ACME requires one exact account-bound grant and a provider mapping DNS
challenges to Koi's TXT operations. Its [guide](../acme.md) explains why a stock
proxy configuration alone is not a complete setup.

## Evidence needed for a trusted-service extension

- The intended name resolves through the second client's ordinary resolver.
- The listener serves an unexpired certificate covering that exact name.
- The actual browser/runtime trusts the intended chain without a bypass.
- The app remains usable after container recreation and daemon restart.
- Renewal replaces the certificate and key without losing the endpoint.
- Failure/recovery exposes a precise action and retains usable prior state where possible.
- Removal cleans up trial resources without affecting unrelated services.

Ordinary TLS clients do not consume Koi's revocation metadata. Removing a grant
does not force rejection of a copied unexpired leaf by those clients.

## Cleanup and related guides

Remove runtime-owned resources through their container lifecycle; manually
created listeners through koi proxy remove; trial roots by their tracked names
only when no longer needed.

[Runtime](../runtime.md) · [Proxy](../proxy.md) ·
[Root trust](../trust.md) · [CA recovery](../certmesh-ha-recovery.md)
