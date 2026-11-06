# koi-mdns

mDNS/DNS-SD service discovery and publication with registration leases, a shared discovery hub and a capability-aware provider control plane.

Linux adapters include Avahi and systemd-resolved; Windows adapters include DNS-SD APIs and Bonjour when available. Native Koi is the reserved fallback provider. Selection follows observed capabilities and live session health; a provider's presence is not proof that every operation works on a particular network.

mDNS is link-local. Container bridge isolation, VLANs, Wi-Fi client isolation, VPNs and host firewalls must be accounted for in a real second-device check.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-mdns --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
