# ADR-001: Host Service as the Container mDNS Bridge

**Status:** Accepted  
**Date:** 2025-01-15

## Context

Docker's default bridge network is a Layer 3 NAT construct that does not forward UDP multicast. Containers on `docker0` never see mDNS traffic from the physical LAN, and their multicast announcements never leave the bridge. Every workaround sacrifices something: `--network=host` loses container network isolation entirely, `macvlan` is Linux-only with no host↔container connectivity, mDNS reflectors are fragile and require `--privileged`, and running Avahi inside each container means heavy images plus D-Bus socket mounting.

The core constraint: mDNS requires multicast on a physical network interface, but containers live in an isolated network namespace by design.

## Decision

Koi runs on the host as a system service (Windows SCM, systemd, or launchd). It participates in mDNS on the physical network via multicast UDP and exposes all capabilities through a TCP-based HTTP API on port 5641. Containers reach the host via the standard Docker gateway (`host.docker.internal` or `172.17.0.1`) and make plain HTTP calls. Koi translates between the multicast world of the LAN and the unicast world inside Docker's network namespace.

An IPC path (Unix domain socket / Named Pipe) provides zero-network-overhead access for same-host containers via volume mount.

This is not a library - it is infrastructure. The single shared daemon mirrors Apple's `mDNSResponder` architecture: one system process multiplexes mDNS for all applications.

## Consequences

- Containers gain full mDNS capability without special network modes, multicast forwarding, or language-specific libraries.
- Container-side integration requires only an HTTP client - the most universally available abstraction.
- Koi must handle platform service lifecycle (install, uninstall, start, stop) across Windows, Linux, and macOS.
- Operators must install Koi on the host before containers can use it. There is no in-container fallback for mDNS.
- The socket mount option gives containers mDNS access with zero TCP overhead, but requires a volume mount in the container's orchestration config.
