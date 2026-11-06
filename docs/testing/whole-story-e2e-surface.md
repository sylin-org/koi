# End-to-end container/LAN acceptance

The complete preview story is: opted-in container, observed reachable host endpoint, real application response on a second physical device, accurate stop, accurate recreation. The [launch gate](../launch/README.md) defines the certified matrix. Advanced domain coverage remains useful without becoming a prerequisite for this story.

## Evidence levels

| Level | Existing mechanisms | Limit |
| --- | --- | --- |
| Domain/synthetic composition | Unit suites and orchestrator tests | Does not prove a real runtime or network |
| Real processes on one host | `crates/koi/tests/two_daemon_certmesh.rs`, embedded whole-story tests | Does not prove physical multicast/firewalls/interfaces |
| Separate containers | `scripts/cross-host-certmesh.sh` | Distinct namespaces, not native installed-host behavior |
| Installed physical pair | Candidate services plus independent application client | Required for the named preview platform scenarios |

Use the existing fixtures where they establish the intended invariant. Do not label a Certmesh-only exchange as the complete container journey.

## Fixture contract

Use the copyable [operator-preview fixture](../../docker/operator-preview/README.md).
It produces a run-identifiable response, publishes a real host port and carries
the implemented Koi labels. Record container identity, rendered image digest,
host port, listener address, Koi artifact and peer identity before asserting
discovery.

Observe through the peer's Koi/network path; request the application with that peer's actual client. Compare expected content, not just HTTP success. A Koi dashboard or inventory row does not substitute for application data.

Keep the observation active through stop and recreation. Assert withdrawal/convergence within a recorded bound, distinguish a replacement endpoint from stale cached metadata, and reject duplicate rows. When a runtime or daemon reconnects, compare reconstructed state with actual current containers.

Apply the fixture's 60-second observation deadline to each catalog, resolver and
client transition, recording actual elapsed time and the last state seen. Treat
the deadline as a case acceptance budget rather than a broad latency promise.

## Trust and integration extensions

The HTTPS extension needs an exact service-name grant, certificate SAN, selected listener certificate and trust in the actual client. CA creation or host enrollment alone is insufficient. Until the public service-grant/listener flow exists, protocol tests do not satisfy that user journey.

The existing-tool extension names one integration and exact tool/version/configuration. Exercise update/removal as well as the initial response. Preserve the user's existing tool; do not require adopting every Koi capability to demonstrate interoperability.

## Installed-host discipline

Follow [the fleet contract](../../fleet/CONTRACT.md). Capture exact native service/artifact/configuration/provider/firewall baselines, use bounded temporary changes and prove restoration. The acceptance subject is the installed candidate; a parallel high-port daemon is a diagnostic fixture, not a substitute.

Retain redacted application/discovery observations, timestamps, artifact hashes and cleanup results in [the launch ledger](../../fleet/launch/LEDGER.md). Never publish tokens, private keys, machine credentials or private recovery archives. Use [the QA plan](../qa/test-plan.md) to select the next run and [validation suite](../qa/validation-suite.md) for appropriate automated guards.
