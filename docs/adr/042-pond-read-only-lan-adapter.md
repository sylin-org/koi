# ADR-042: Pond is an operator-armed read-only LAN adapter

- **Status:** Accepted
- **Date:** 2026-09-01
- **Supersedes/relates:** ADR-031, ADR-033, ADR-035, ADR-040, ADR-041

## Context

The desktop's Phone action published a browser bundle into the daemon, but the bundle was
served by the full operator HTTP adapter. That adapter is loopback-only by default, so the
displayed LAN URL was usually unreachable. Broadening its bind would also expose a large
mixed read/mutation surface and make the DAT the only boundary. The desktop guessed the URL
from a routing-table heuristic rather than reporting a socket Koi had actually acquired.

Mobile access is presentation, not another daemon or domain. It still needs real runtime
semantics: explicit operator desire, a narrow public surface, exact observed addresses,
retry after interface or port changes, persistent intent, firewall truth, and a clean stop.

## Decision

Pond is one in-process serving adapter in the existing DDD monolith.

1. `PondRuntime` owns desired and observed state. `PUT /v1/pond` persists desire and arms the
   listener; `DELETE /v1/pond` persists stop before closing it; `GET /v1/pond` returns exact
   state. All three are DAT-gated operator routes on the full loopback adapter. Desired state
   survives daemon restart and a desired listener retries and re-observes interfaces without
   a desktop process remaining open.
2. The public listener binds wildcard IPv4 on the derived fourth installation port
   (`http_port + 3`; standard `5644`). It is another router over the same in-process cores,
   not a proxy to the operator API and not a filtered copy of that router. Its allowlist is
   the five fixed UI assets, liveness, a privacy-reduced status projection, mDNS browser
   snapshot, and DNS entries. Unknown and mutation routes do not exist there.
3. The desktop publishes exactly one complete five-file bundle through the authenticated
   `PUT /v1/ui`, then arms Pond and renders the daemon-returned `url`. It never guesses an
   interface or substitutes the operator HTTP port. “Stop sharing” disarms Pond explicitly;
   closing the QR dialog does not silently change persistent intent.
4. Pond reports `disabled`, `reconciling`, `running`, `waiting`, or `error`, plus desire,
   exact URLs, port, firewall assessment, and reason. The canonical capability ladder
   projects that live state as a ninth rung. A bound socket without a routable interface or
   admitted known firewall rule is waiting, not advertised as reachable.
5. Host policy remains separate from runtime desire. Linux observes firewalld or UFW and
   never edits either. Windows installation manages a program-scoped Pond rule and
   uninstall removes it, so ordinary activation needs no elevation. Platforms Koi cannot
   assess report unknown;
   they do not invent success.
6. Port planning probes all four ports as one contiguous run but persists only the existing
   three configurable ports. Pond remains derived, avoiding a fourth independent knob and
   preventing configuration drift.

## Consequences

- The full operator API stays loopback by default while a phone receives only intentional
  read models.
- One Koi process owns the operator and Pond sockets, their cores, cancellation, and status;
  there is no sidecar, second instance, proxy process, or parallel domain model.
- Phone activation is truthful: success includes a URL backed by a real bound socket and
  observed host policy; failures preserve desire and heal when the condition changes.
- IPv6 Pond URLs are not claimed yet. Adding them requires scoped-interface URL handling and
  equivalent firewall observation rather than formatting unvalidated addresses.

## Validation

Unit tests pin the allowlisted router, complete-bundle contract, port derivation, desired
state serialization, DAT protection, and four-port installer probe. The fleet gate uses the
one installed deployment on each subject: publish and arm locally, open every returned URL
from an independent physical server, exercise the public read projections and mutation
rejection, stop and prove the socket closes, re-arm and restart to prove intent recovery,
then leave exactly one healthy Koi and restore any host policy changed for the test.
