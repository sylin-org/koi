# R24 - Finish one maintained external-proxy integration

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A user with an existing proxy can complete one documented private-HTTPS integration without replacing it.**

- Dependencies: [R20](R20-authorized-service-certificates.md), [R22](R22-secure-access-and-client-onboarding.md)
- Epic gate: G6
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
4. Write the bounded plan in reports/R24.md (or reports/R24-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `docs/guides/acme.md`
- `docs/guides/integrations.md`
- `crates/koi-serve/src/acme.rs`
- `crates/koi-certmesh/src/acme/router.rs`
- `crates/koi-certmesh/src/acme/challenge.rs`
- `docs/adr/STACK-0001-sylin-stack-canon.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Inspect the existing ACME recipes and choose exactly one maintained proxy/client combination, recording versions, dns-01 support and why it is supportable. Use current primary documentation; do not imply stock Caddy works without the required provider/module.

2. Build or finish the minimum hook/provider recipe for that combination using current auth and ephemeral TXT lifecycle. Keep secrets out of argv/URLs/evidence and scope credential authority to what the existing system enforces.

3. Provide a runnable fixture that obtains the right service certificate, serves the backend, renews/reloads and cleans up challenge records/resources. Exercise interruption and a bad directory/provider configuration.

4. Publish one compatibility row with exact tested versions and an ordinary-client HTTPS result. Keep other products as unverified recipe ideas until individually tested.

## Acceptance cases

- [ ] The fixture follows the documented full ACME directory URL and resolves its dns-01 challenge from the actual issuer.
- [ ] Certificate issuance and a renewal cycle work through the external proxy, then the second client opens the exact service URL.
- [ ] Failure cleanup removes owned ephemeral TXT and preserves unrelated DNS/proxy configuration.
- [ ] Claims state the required modules/auth/client trust setup; no 'no special config' shortcut contradicts the recipe.

## Verification

Run the selected client's real issue/renew/reload flow plus failure cleanup. Reuse the existing ACME harness and record the client/module/source versions.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update ACME/integrations guide and copyable fixture with prerequisites, verification and teardown.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not build two proxy integrations, an enterprise ACME product, or product-specific knowledge of downstream Sylin consumers into Koi.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
