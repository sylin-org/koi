# R10 - Make changes, favorites and notifications useful

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Home explains meaningful changes while ordinary repeated network traffic stays quiet.**

- Dependencies: [R07](R07-home-launchpad.md)
- Epic gate: G2
- Execution class: repository implementation; any native evidence uses the fleet protocol.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R10.md (or reports/R10-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `../koi-desktop/ui/sentences.js`
- `../koi-desktop/ui/app.js`
- `crates/koi-dashboard/src/forward.rs`
- `crates/koi-compose/src/webhook.rs`
- `crates/koi-health/src/log.rs`
- `docs/adr/028-outbound-event-fanout.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Define a small typed episode vocabulary over authoritative changes: service ready, favorite unavailable, device returned, share changed, trust action needed and recovered. Keep raw events/audit available as evidence.

2. Deduplicate repeated observations and group a failure/recovery into one episode with stable service identity. Persist only the bounded history and last-viewed cursor needed for 'since you last looked'.

3. Handle event lag by rereading state without inventing missing historical events. Bound memory/disk retention and define clock/restart behavior.

4. Show a short summary on Home and a deeper activity route. Send OS notifications only for relevant watched transitions, once per episode, with actionable wording; use native notification APIs and respect OS suppression.

## Acceptance cases

- [ ] A burst of repeated resolutions does not grow the Home feed or send repeated notifications.
- [ ] A watched service disappears, notifies once, returns and records one verified recovery.
- [ ] Restart and reconnect preserve favorites/cursor and avoid replaying old alerts.
- [ ] No events does not imply every capability is healthy; current state remains sourced from snapshots.

## Verification

Use deterministic burst/lag/restart tests plus native notification handoff verification on the assigned desktop. Check bounds using a large synthetic event sequence.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document meaningful activity, notification behavior and retention; state that OS acceptance does not guarantee a visible banner.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not treat watch as a durable event queue, synthesize events lost during downtime, or add analytics/telemetry to measure engagement.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
