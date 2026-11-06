# Exact service HTTPS

Trusted HTTPS requires a reachable listener, a certificate containing the exact service name, and a client application that trusts the issuing CA.

## Use and verify

Use the [launch gate](../../launch/README.md) for the current status of the service-name-to-certificate-to-listener workflow. This extension follows the container discovery/reachability preview.

## Boundaries

Creating a CA or seeing an authenticated host posture does not establish HTTPS for every container. The current service-grant facade is implemented, but the public operator workflow remains incomplete. Self-signed fallback is not browser-trusted service HTTPS.

See [the capability guide](../../guides/certmesh.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
