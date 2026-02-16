# ADR-010: Docker Adapter Kept Separate from Core

**Status:** Accepted  
**Date:** 2025-12-15  

## Context

Containerized applications registering with Koi must advertise the host-side mapped port, but they only know their internal container port. The Docker port mapping information lives in the orchestration layer, not inside the container. Solving this in Koi core would require a hard dependency on the Docker socket (which grants root-equivalent access), container runtime detection heuristics across Docker/Podman/containerd, and coupling a DNS-SD protocol daemon to a specific orchestration runtime.

## Decision

Docker/container integration is kept out of Koi core entirely. A separate standalone adapter (`koi-docker`, not yet built) would watch Docker API lifecycle events, read declarative `koi.*` labels from containers, resolve host-side ports from Docker's port mapping, and call Koi's existing HTTP API to register/unregister services with heartbeat-based leases. The adapter would accept a configurable socket path for Docker/Podman compatibility.

Koi's current container story is explicit: operators pass the host port via environment variables or entrypoint scripts. This is documented in [CONTAINERS.md](../../CONTAINERS.md).

## Consequences

- Koi core maintains zero coupling to any container runtime, preserving its role as a runtime-agnostic DNS-SD daemon.
- Operators who don't use containers pay no complexity cost.
- Container deployments require manual port configuration or a future sidecar adapter — an additional process to run.
- The adapter's language and repository placement remain open questions (Rust for consistency vs. Go for Docker ecosystem fit).
