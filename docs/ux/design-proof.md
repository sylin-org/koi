# U01 experience design evidence

Task: [U01 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#u01--establish-the-experience-contract).
Owner: coordinating agent, under the maintainer's request for a coherent UX.
Date: 2026-09-12.
Source baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus preserved uncommitted documentation work.
Verdict: accepted for the U01 design artifact only.

## Delivered contract

- [Experience direction](README.md): three destinations, service and private-space
  journeys, evidence language, failure states, visual/interaction rules, source
  placement and implementation boundaries.
- [Interactive concept](concept.html): returning services, first container,
  unavailable daemon, client DNS failure, private-space onboarding and membership.
  The populated view uses a dense table of 36 invented services across six hosts,
  combined search/host/state filters, stable sorting and single-line desktop
  columns. Selecting a row expands a details pane beside the wide inventory;
  narrow screens use a modal drawer. It performs no backend operations.
- Epic U02–U06, launch gates, cohort observation and contributor routing now use
  that contract. U02 is the first UX implementation package. L02/L03 and early
  L05 preparation remain independently actionable.

The audit checked the shared renderer/catalog/adapters and the sibling desktop
source. It identified missing service controls, disjoint entry surfaces, current
action-eligibility/diagnosis gaps, obsolete desktop Certmesh status assumptions,
and the native URL-dispatch boundary. Their implementation belongs to U02–U05.
A separate read-only review found no circular dependencies or contradictory
preview/UX acceptance gates in the integrated documents.

## Design verification

- Inline concept JavaScript passes `node --check` after final edits.
- Density at 1280×800 and default zoom: eleven complete service rows with navigation
  and toolbar visible, 49px row height and at least 44px action targets. The
  earlier card layout showed two complete rows at the same viewport. This
  comparison measures the concept, not a production performance improvement.
- Browser inspection covers desktop, 390px and 320px layouts. Services and Private
  space remain readable; measured page width does not exceed the tested viewport.
- Mobile rows retain the hosting device, full address, condition and action.
  At 390px ordinary rows measure about 88px; at 320px the address uses the full
  row width and ordinary rows measure about 106px. Long content may grow a row.
- Combined host/state filtering and reverse-name sorting preserve correct counts
  and targets. A selected Site preview opens its own endpoint; a Vaultwarden DNS
  diagnosis names its actual sample host/client. The attention filter contains
  no Open actions. Search/reset and a late-list Zigbee2MQTT detail path work.
- The wide pane reserves space beside an operable list and exposes one expanded
  row at a time. Switching rows updates the pane; filtering out its service closes
  it. Cross-row Open/Diagnose also updates the pane to the intended service.
- Escape closes a task modal back to its pane, then the pane back to its row.
  The 390px/320px drawer retains full evidence, contains keyboard focus and restores
  the originating control. Resizing during a task modal defers the pane's modality
  change until that task closes, preserving the active task and return path.
- Details close with list context preserved; Tab cycles within modal surfaces.
  Desktop column headers remain visible while scrolling.
- Exercised sample Open, details, search/no matches/reset, host filter, initial
  container setup, unavailable/reconnect and DNS guidance.
- Exercised sample client-record validation, private-space name validation,
  creation, Join explanation and contextual Settings details. Simulated success
  remains explicitly labeled; no network or certificate action is claimed.
- Filtering does not leave an open pane for an excluded selected service.
- Reduced-motion CSS removes animation/transitions; focus and live/error semantics
  are present. This inspection is not a full assistive-technology or WCAG audit.
- Current-document link/anchor checks and the surface/document guards pass;
  the known protected ADR/research link exceptions remain unchanged.

The dense layout is the default implementation contract in U02/U03/U06. The
controlled 30-or-more-entry renderer fixture is separate from the real L05
participant task; operators do not need to deploy that many services. Live-update
focus/reordering behavior is specified for production, not simulated or accepted
by this static-data concept.

## Claim limit

No production renderer, native bridge, daemon behavior, installation, independent
operator outcome or published artifact is accepted by this receipt. U06 requires
the actual selected UI and real L05 attempts. Invite/recovery dialogs and manual
client observations illustrate a proposed interaction; they do not implement
enrollment, recovery or a new observation subsystem.
