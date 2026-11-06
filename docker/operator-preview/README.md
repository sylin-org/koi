# Operator-preview lifecycle fixture

This pinned Compose application supports the L03 container-to-LAN acceptance
run. Every HTTP response carries the operator-selected run ID and current
container hostname, so a client can distinguish the intended application from a
cached record or unrelated listener. The fixture publishes one host port on all
interfaces and uses Koi's implemented `koi.announce` shorthand plus an explicit
HTTP health path.

Copy `.env.example` to `.env`, replace the run ID with a unique non-secret value,
and confirm the selected ports are unoccupied. Use the installed Koi artifact and
runtime provider required by the acceptance run; do not start a parallel Koi
daemon for this fixture.

```sh
docker compose config --quiet
docker compose up -d --wait
docker compose ps
curl --fail --show-error http://127.0.0.1:18080/
```

Record the exact Compose-rendered image digest, container ID, published binding,
Koi artifact/configuration/process identity, catalog service ID, announced name,
resolver result and application JSON from both host and physical client. The
client request must use the intended LAN address or configured delegated name;
loopback and Koi's own lookup are not second-device proof.

Use a 60-second observation deadline for every Koi catalog, resolver and client
transition below, and record the actual elapsed time rather than reporting only
that it eventually converged. This is the preview acceptance budget, not a
general product SLA: a timeout fails the case and keeps the last observed state
in the receipt. The fixture requests a five-second Koi health interval with a
two-second probe timeout. Current source caps Docker observation reconnect delay
at five seconds and retries composition every five seconds; physical mDNS,
resolver and application observations still determine whether the budget holds.

Exercise this sequence while retaining the same run ID:

1. Start the container before Koi and verify initial reconciliation after Koi starts.
2. `docker compose restart app`; verify the service identity remains singular and
   the client receives the same run ID after recovery.
3. Change `KOI_FIXTURE_PORT` to an unoccupied port and run
   `docker compose up -d --wait --force-recreate`; verify a new container ID and
   endpoint, with no old endpoint presented as currently usable.
4. Restart the runtime, then restart the installed Koi service. After each,
   compare the reconstructed catalog with `docker compose ps` and the client.
5. `docker compose stop app`; verify current Open disappears within the measured
   convergence interval. Then run `docker compose rm -f app` and confirm no
   duplicate or orphaned current service remains.
6. Run `docker compose down` and verify the published ports and run-owned
   resources are gone.

Repeat the full sequence for Windows host to Linux client and Linux host to
Windows client. Record name collisions as explicit ambiguous state. Do not mark
L03 accepted from this fixture's local validation or from an inventory row alone.
