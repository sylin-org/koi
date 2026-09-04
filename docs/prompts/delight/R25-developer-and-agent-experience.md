# R25 - Align CLI, SDK, MCP and embedding with service tasks

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Human commands and programmatic clients expose the same service identity, truthful state and permitted actions.**

- Dependencies: [R05](R05-catalog-api-and-preferences.md), [R17](R17-reversible-service-sharing.md), [R19](R19-url-diagnosis.md), [R21](R21-secure-service-operation.md)
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
4. Write the bounded plan in reports/R25.md (or reports/R25-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `cli-rust-client`, `typescript-python`, `mcp`, `embedded`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `crates/koi/src/cli.rs`
- `crates/koi/src/dispatch.rs`
- `crates/koi/src/help`
- `crates/koi-client/src/lib.rs`
- `crates/koi-mcp/src/lib.rs`
- `crates/koi-embedded/src/lib.rs`
- `packages/ts/lib/client.js`
- `packages/python/src/koi_client/__init__.py`
- `docs/guides/mcp.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Run one ledger subrow per execution, with cli-rust-client first to stabilize transport/error shapes. Implement CONTRACT.md's task-oriented service listing/open/diagnose/share entry points without duplicating lifecycle logic; existing precise domain commands remain available.

2. For TypeScript/Python, add matching typed operations and version/transport compatibility handling. For embedding, consume the same composition owner and preserve lean feature builds and orderly shutdown. Separate domain ownership from adapter conveniences.

3. For MCP, expose catalog/evidence and allowed operations through the established stdio/HTTP architecture. Treat discovered metadata as untrusted data; never let it become an instruction or identity proof. Use a named supported client recipe instead of assuming DNS-SD or custom auth interoperates universally.

4. Update the command/help/OpenAPI/error catalog and transport matrix. Provide one minimal complete example per claimed subrow, including unavailable/stale state and denied mutation.

## Acceptance cases

- [ ] A service has the same ID/condition/evidence through CLI, HTTP, SDK and MCP where permitted.
- [ ] Human output, JSON and exit status are correct under NO_COLOR, non-TTY, cancellation and expected negative outcomes.
- [ ] TS/Python clients handle denied auth and version mismatch; MCP stdio/HTTP update behavior is accurately stated.
- [ ] A small external embedded example builds lean, observes changes and shuts down without leaked owners; no test uses hidden parallel installed daemons.

## Verification

Run only the selected adapter's focused tests plus required Rust gates when touched. For final task acceptance, execute all four subrows: TS/npm Node tests, Python unittest with packages/python/src on PYTHONPATH, actual named MCP-client flow and external lean embedded build.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update CLI/API/reference, package READMEs and MCP/embedded recipes with exact versions and supported transports.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not add fine-grained RBAC/OAuth servers or move domain state into clients. A remote automation client must never cause the daemon to open a browser on an unintended user's machine.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
