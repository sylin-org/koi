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
   the content-addressed five-file UI generations, liveness, an explicitly allowlisted coarse
   status DTO, mDNS browser snapshot, and DNS entries. Unknown and mutation routes do not
   exist there. The public status DTO carries only product version, platform, uptime, aggregate
   revision, daemon/surface identity, and each known capability's name, enabled flag, and
   healthy flag. It is not a redaction pass over an internal status: summaries, endpoints,
   reasons, firewall detail, and domain snapshots never enter the public value.
3. The desktop publishes exactly one complete five-file bundle through the authenticated
   `PUT /v1/ui`. Pond validates all five members, calculates the bundle digest, durably stores
   the immutable generation under that digest, atomically advances a separate durable current
   pointer, retains the generation bytes, selects that revision in the authoritative
   `PondStatus`, and only then acknowledges the command. HTTP selection reads that status;
   there is no second mutable in-memory "current UI" value. Every accepted generation remains addressable by
   digest across later publishes and daemon restarts. A failed validation, generation write,
   or pointer commit leaves the preceding complete revision current and serving.

   Authenticated `DELETE /v1/ui` clears only the durable current pointer. Pond publishes the
   unavailable UI status and `UiCleared` event after that commit and before acknowledging the
   command; an already-clear selection is a complete no-op. Retained immutable generations
   are not garbage-collected by clear and remain addressable across restart.

   Startup migrates the preceding single-bundle repository and the older exact five-loose-file
   layout into the same generation-plus-pointer model. Migration is fail-closed: malformed,
   incomplete, hash-incoherent, or pointer-without-generation state is an initialization
   error, not an absent UI or permission to assemble a partial bundle. Damage to any retained
   generation fails closed because its URL may already be open in a browser. A missing marker
   never authorizes recursive cleanup of a previously selected generation or an unknown entry;
   only the exact empty/interrupted initialization shape can resume in place.

   `GET /` captures the current pointer once and returns a non-cacheable temporary redirect to
   `/_koi/ui/<64-lowercase-hex>/`. That generation root serves the stored `index.html`
   unchanged; its relative `styles.css`, `sentences.js`, `app.js`, and `koi.png` references
   therefore stay within the same immutable generation even when another publish becomes
   current between browser requests. Only those exact generation routes exist: the flat
   `/app.js`, `/styles.css`, `/sentences.js`, and `/koi.png` routes do not. Root-absolute
   browser reads (`/healthz` and the allowlisted `/v1/...` reads) intentionally remain live
   requests to the Pond listener and are not rewritten into a UI generation. Generation HTML
   permits same-origin external scripts with `script-src 'self'`; `base-uri 'none'` remains in
   force.

   The desktop then arms Pond and renders the daemon-returned `url`. It never guesses an
   interface or substitutes the operator HTTP port. “Stop sharing” disarms Pond explicitly;
   closing the QR dialog does not silently change persistent intent.
4. Pond reports `disabled`, `reconciling`, `running`, `waiting`, or `error`, plus desire,
   exact URLs, port, firewall assessment, active UI availability/content revision, and reason.
   UI repository and publication state do not add another lifecycle enum case. The canonical
   capability ladder projects the existing live state as a ninth rung. A bound socket without
   a routable interface or admitted known firewall rule is waiting, not advertised as
   reachable.
5. Host policy remains separate from runtime desire. Linux observes firewalld or UFW and
   never edits either. Windows installation manages a program-scoped Pond rule and
   uninstall removes it, so ordinary activation needs no elevation. Platforms Koi cannot
   assess report unknown;
   they do not invent success. Linux assessment owns, kills, and waits for each child command
   under one bounded probe deadline, so a hung host utility cannot accumulate detached work.
6. Port planning probes all four ports as one contiguous run but persists only the existing
   three configurable ports. Pond remains derived, avoiding a fourth independent knob and
   preventing configuration drift.
7. One instance-scoped publication gate serializes every `PondStatus` transition and its
   corresponding semantic event. Durable truth is committed first, the immutable status is
   published second, the event is emitted third, and only then may a command report success.
   Lifecycle work and filesystem/network waits remain outside that short gate. Every lifecycle
   update preserves the UI projection owned by the current pointer; UI publication cannot
   overwrite listener truth, and listener observation cannot erase the active UI revision.
   Stop first installs a fence derived from the latest status while holding this same gate,
   then cancels the reconciler. Both HTTP graceful drain and the complete reconciler have hard
   deadlines; expiry drops/aborts the owned task and socket rather than detaching it.

## Consequences

- The full operator API stays loopback by default while a phone receives only intentional
  read models.
- One Koi process owns the operator and Pond sockets, their cores, cancellation, and status;
  there is no sidecar, second instance, proxy process, or parallel domain model.
- Phone activation is truthful: success includes a URL backed by a real bound socket and
  observed host policy; failures preserve desire and heal when the condition changes.
- A browser selected into one content generation cannot combine old HTML with newly current
  scripts, styles, or imagery, and a retained generation remains refreshable after restart.
- IPv6 Pond URLs are not claimed yet. Adding them requires scoped-interface URL handling and
  equivalent firewall observation rather than formatting unvalidated addresses.

## Validation

The implementation is accepted when tests pin all of the following:

- forced publish/read interleavings always assemble one digest-identical generation across
  the index, scripts, stylesheet, and image; `/` is a no-store temporary selector, and unknown
  or malformed generation paths never fall back to current bytes;
- accepted generations and the current pointer survive restart, while failed publish/pointer
  commits preserve the preceding generation, status, and event stream;
- clear commits the empty pointer before unavailable status and `UiCleared`, duplicate clear is
  a persistence/status/event no-op, cancellation before command admission changes nothing, and
  retained generation URLs survive clear plus restart;
- valid legacy repositories migrate exactly once into a content-addressed generation, while
  partial, corrupt, hash-incoherent, and dangling-pointer states fail initialization without
  serving or rewriting them; loss of the marker and damage to any retained generation also
  fail without deleting accepted or unknown state;
- the public status wire value contains only its coarse allowlisted fields and cannot disclose
  internal summaries, endpoints, errors, firewall detail, or domain snapshots;
- lifecycle/status/event interleavings preserve the active UI revision, publish status before
  its event, and do not create a UI-specific `PondState`;
- the allowlisted public router has no flat asset, mutation, operator, OpenAPI, audit, or DAT
  routes; generation HTML admits its same-origin external scripts while keeping
  `base-uri 'none'`;
- port derivation, desired-state serialization, DAT protection, and the four-port installer
  probe retain their existing contracts; malformed, missing-field, or unknown-field intent is
  never interpreted as disabled;
- stalled HTTP clients, cancellation-insensitive reconcilers, and hung Linux firewall helpers
  are terminated and reaped within their explicit deadlines.

The fleet gate uses the one installed deployment on each subject: publish and arm locally,
open every returned URL from an independent physical server, exercise the public read
projections and mutation rejection, publish a second UI generation while the first remains
open, restart and revisit both generations, stop and prove the socket closes, re-arm and
restart to prove intent recovery, then leave exactly one healthy Koi and restore any host
policy changed for the test. The gate requires the expected installed artifact hash and the
sole enabled supervisor PID, refuses an overlapping installed-service run, restores the prior
selected UI from all five captured immutable assets (or clears the selection when none
existed), and changes a blocking Linux firewall only through an explicit opt-in transaction
whose reloaded final policy/configuration equals its captured baseline.
