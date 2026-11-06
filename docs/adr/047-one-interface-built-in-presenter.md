# ADR-047: One built-in interface across Koi surfaces

Status: **Accepted and implemented**. Decision: 2026-09-13 UTC.

Supersedes ADR-042's desktop-published Pond bundle and ADR-043's durable UI
generation repository. Refines ADR-045 by making the shared Rust renderer the
only shipped product presentation. The Pond lifecycle and public authority
boundary from ADR-042 remain binding.

## Context

Koi had accumulated four presentations: the shared Rust interface, an older
Tauri application, embedded dashboard HTML and an mDNS browser page. Pond also
accepted and retained copies of the old Tauri bundle. Links labelled Advanced
or Open system tools crossed between those applications.

This preserved useful commands, but exposed competing navigation, terminology,
status interpretation and visual systems. It also allowed a retired bundle to
remain executable after the current interface changed. For a pre-1.0 product,
carrying those compatibility paths creates more risk and confusion than value.

## Decision

Koi ships one presentation owner: `koi-ui`. It renders the same five top-level
destinations in this order: **Services, mDNS, Certmesh, Settings, About**. About is
last and owns the single product card, observed facts and documentation links.

Owner amendment, 2026-09-13: mDNS is a first-class destination because raw
network inspection and active DNS-SD queries are a distinct operator task from
the normalized service catalog. Legacy Services/mDNS links canonicalize to the
new destination; this does not create another renderer or inventory owner.

The native desktop, authenticated daemon browser and explicitly enabled Pond
listener render those components. Their adapters provide only permitted state
and effects:

- the authenticated browser maps bounded forms to exact DAT-protected routes;
- the native shell maps bounded forms to typed Tauri commands and retains OS
  integration such as service state, autostart, URL opening and the tray;
- Pond has no mutation bridge and receives only mDNS-derived service rows plus
  coarse allowlisted capability health.

Access differences may remove controls or redact facts. They do not create a
different navigation tree or application.

The old dashboard and mDNS HTML assets, old Tauri screens and assets, native
Home/Advanced bridge, Pond publication API, retained UI repository and UI
generation routes are removed. `/` redirects to `/ui`; `/mdns-browser`
redirects to the Services destination. Snapshot, event and mDNS data adapters
remain where they still serve current behavior.

Pond keeps only durable enabled/disabled intent. Its built-in renderer is part
of the daemon binary and is always the current revision. No migration reads or
executes older UI files. Removing an obsolete generated UI cache does not touch
preferences, configuration, Certmesh identity, rosters, audit data or Pond
enablement intent.

## Consequences

- A screen or operation is complete only when it has a discoverable place in
  the shared interface and reads current domain contracts.
- New presentation behavior belongs in `koi-ui`; adapters may not grow another
  screen renderer or independent product state model.
- A bookmark to retired HTML reaches the canonical interface or a 404. A stored
  Pond generation can no longer reactivate code from the old application.
- Pond intentionally shows less data than the operator interface. Its catalog
  projection strips preferences, checks, active operations, identity posture,
  local candidates and non-mDNS services before rendering.
- The removed `/v1/ui` publication contract is a pre-1.0 breaking change. No
  compatibility shim is retained because it would restore the retired execution
  path this decision removes.

## Verification

[Epic 004 U07](../../fleet/epics/004-container-lan-adoption.md#u07--consolidate-and-retire-the-separate-interfaces)
owns source deletion, route inspection, adapter tests and installed artifact
evidence. Independent usability acceptance remains U06.
