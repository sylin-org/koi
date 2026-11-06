# Product acceptance plan

The preview serves container/LAN developers and capable homelab operators. Acceptance proves an actual labeled application on a second physical device, followed by accurate stop/recreate behavior. Exact service HTTPS and one certified existing-tool integration follow as separate extensions. [Launch readiness](../launch/README.md) defines the current gate; [the launch ledger](../../fleet/launch/LEDGER.md) holds evidence.

## Initial scenario matrix

Use a physical Windows x64 host with Docker Desktop and a physical Linux glibc x64 host with Docker Engine. Test the application in both directions when both host scenarios are claimed. Record runtime version/backend, interface, firewall profile and the client/application used.

Other existing platform builds remain subject to repository support policy. A successful build or older domain test does not certify the complete journey on that platform. macOS, arm64, musl, Podman and alternative supervisors need their own explicitly scoped evidence before receiving the same journey claim.

## Preview sequence

1. Verify exact installed source/artifact and native service health; record one intended Koi instance on each participant.
2. Start a fixture application with an identifiable response, explicit published host port and Koi opt-in/name labels.
3. Observe its metadata/endpoint through Koi on the independent device.
4. Request the real application from that device and assert its expected body/marker, not only status 200 or a Koi page.
5. Stop it and verify withdrawal within the defined observation bound. Preserve an honest unavailable/stale state during convergence.
6. Recreate it and verify the replacement endpoint and actual response. Reject duplicates, stale address/port reuse and user-preference identity corruption.
7. Recover from daemon/runtime reconnect, then remove run-owned resources and restore the captured host baseline.

Record timings and failures. A failed application request cannot be waived by a healthy daemon/API, successful same-host curl, screenshot or synthetic event test.

## Follow-on acceptance

For exact service HTTPS, add the intended service name, authority grant, matching SAN, selected proxy certificate and the actual client's CA trust. Verify renewal/restart and honest failure states. Do not claim this path complete while public grant/listener wiring is absent.

For the existing-tool integration, name one tool/version/configuration and prove clean installation, expected format/protocol consumption, updates and removal. Source compatibility or an illustrative configuration is not certification of every Caddy/Traefik/Prometheus version.

## Execution ownership

Use [the fleet contract](../../fleet/CONTRACT.md) for host changes, native restoration and evidence custody. Keep machine credentials in existing private channels, not this runbook. Code tests may use isolated synthetic/loopback fixtures; installed-product acceptance uses the actual installed candidate and independent peer.

The [validation suite](validation-suite.md) lists relevant guards and their limits. Mark each attempted assertion pass, fail, skipped or not run. Skipped means no evidence, not success. A release gate requires fresh exact-artifact evidence, not a green historical checklist.
