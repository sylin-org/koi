# mDNS provider transition test

This specialist test verifies that one installed Koi process keeps truthful discovery/publication state while its real native provider facilities change. It complements the container/second-device journey; it does not itself prove the application is reachable. Current scenario acceptance belongs in [launch readiness](../launch/README.md).

## Prerequisites

Use a subject and an independent LAN peer, each with one installed Koi service. Capture exact process/package/configuration/provider/firewall baselines under [the fleet contract](../../fleet/CONTRACT.md). The subject needs the selected native facilities, service-control privileges and the tools listed by the script. The peer needs established SSH access and peer-local access to its Koi identity/breadcrumb.

The current Linux driver requires explicit subject and peer executable hashes:

```sh
EXPECTED_KOI_SHA256=<subject-binary-sha256> \\
EXPECTED_PEER_KOI_SHA256=<peer-binary-sha256> \\
scripts/integration/mdns-provider-transition.sh \\
  --allow-system-mutation --peer user@independent-lan-host
```

These are placeholders for verified current bytes, not values to infer. Run on the real subject host. Read `--help` for current scope/manager/profile and SSH options. Tokens and elevation secrets are consumed locally on their owning participant and must not enter retained public evidence.

## Profiles and assertions

The systemd-resolved profile exercises Avahi, complementary systemd-resolved/native behavior, native-only behavior and recovery/promotion. The OpenRC profile uses `MDNS_PROVIDER_PROFILE=openrc-avahi-native` with the matching manager and exercises Avahi/native/Avahi without inventing absent resolved facilities. Per-user Koi scope is selected explicitly; provider changes remain system-level.

In each settled plan, verify publication, independent peer discovery/resolution, removal and synchronization. Record desired/established/pending/failed state through structured control-plane status. Bounded settling observes convergence; one instantaneous sample is not sufficient.

Native fallback can provide continuous browse/cache without a direct point-resolve route. Interpret missing routes against declared provider capabilities. Check meaningful peer records and exact-address publication, not solely a provider's self-publish response.

## Restoration

The driver captures service/socket activity, enablement and resolved mDNS configuration, installs cleanup before mutation and avoids conflicting simultaneous responders. Its script must not launch another Koi process. Both installed service identities/PIDs/hashes remain stable, and peer provider state remains unchanged.

Restore activation sockets, runtime masks, global/link mDNS settings and service enablement exactly. A restoration failure invalidates acceptance. Retain the structured observations and baseline comparison with the candidate in [the launch ledger](../../fleet/launch/LEDGER.md).

Windows uses its own DNS-SD/Bonjour/native facilities and requires a platform-specific, baseline-preserving procedure. Do not treat a Linux shell profile or cross-target compile as physical Windows provider proof. Read [the driver](../../scripts/integration/mdns-provider-transition.sh) and [validation limits](../qa/validation-suite.md) before running this test.
