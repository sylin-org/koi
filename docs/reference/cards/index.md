# Capability reference cards

Start with [container discovery and lifecycle](container-autowire.md): label a real application, reach it from a second device, then verify stop/recreate behavior. The [launch gate](../../launch/README.md) distinguishes implemented capabilities, supported platform builds and certified scenarios.

## Initial journey

- [Install and verify](install-and-verify.md)
- [Container discovery and lifecycle](container-autowire.md)
- [mDNS discovery](mdns-discovery.md)
- [Local DNS names](internal-zone.md)
- [Health observations](machine-health.md)

## Service trust extension

- [Exact service HTTPS](trusted-https.md)
- [TLS proxy](tls-proxy.md)
- [Certmesh enrollment](certmesh-invite.md)
- [Trust diagnosis](trust-doctor.md)
- [ACME issuance](acme-issuance.md)

## Advanced interfaces

- [UDP bridge](udp-bridge.md)
- [Webhook events](webhook-events.md)
- [MCP interface](mcp-agent-door.md)
- [Embedded Rust interface](embedded.md)

These interfaces remain documented independently of launch scope. A capability's existence does not make it a prerequisite for the container preview or certify every third-party integration.
