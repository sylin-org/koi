# R22 - Guide users from a service to verified HTTPS

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **The user sets up secure access from a service and opens the right URL on a second client.**

- Dependencies: [R07](R07-home-launchpad.md), [R15](R15-container-ready-service.md), [R21](R21-secure-service-operation.md)
- Epic gate: G5
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
4. Write the bounded plan in reports/R22.md (or reports/R22-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `creation-and-joining`, `service-setup-ui`, `client-verification`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `../koi-desktop/ui/app.js`
- `../koi-desktop/src/local_daemon.rs`
- `crates/koi-certmesh/src/init_ceremony.rs`
- `crates/koi-certmesh/src/invite.rs`
- `crates/koi-trust/src/http.rs`
- `docs/tutorials/trusted-https.md`
- `docs/guides/trust.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Render R21's real operation from service details. Lead with the intended URL and benefit, then show the applicable setup action. Reuse an existing trust group when possible; explain create/invite/join in device terms and preserve fingerprint/pinning checks.

2. Review first-CA ceremony with the current crypto owner: remove redundant novice interactions only through an explicit ADR amendment and preserved cryptographic invariants. Keep key custody, recovery responsibility and required OS authorization understandable. Do not invent an extra approval ritual.

3. Separate device identity enrollment from client root trust. Supply a bounded public client setup package/invitation with fingerprint, correct root, verification URL and client-specific instructions; exclude private keys/secrets from URLs/logs. Name supported browsers/runtimes and verify against current official docs.

4. Complete one named second-device browser/native-client flow and one container trusted-service flow. Persist progress across UI closure, allow advanced certificate details, and finish with Open plus a receipt of what was actually verified.

## Acceptance cases

- [ ] A novice-facing journey never requires raw TXT/SAN/CA-role vocabulary before it is relevant.
- [ ] The second client resolves the intended URL and accepts its real leaf without disabling validation; root installation alone is not accepted as this proof.
- [ ] Invalid/expired/reused invitation, wrong fingerprint and denied OS root import produce specific recoverable states.
- [ ] A restarted app/daemon retains setup progress and the container's secure endpoint follows lifecycle; unauthorized clients do not gain management authority.

## Verification

Run wizard/backend interaction tests and real second-client HTTPS with recorded platform/browser/runtime versions. Test rejection and resume. Include key-handling/security regression checks if ceremony behavior changes.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Replace trusted-https and container-trusted-cert recipes with executed steps, supported-client matrix and honest trust/revocation limits.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not promise every browser/runtime honors OS roots, ship key-mashing theater without justification, or use 'Trust and finish' as proof of network-wide success.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
