# Epic 003 execution charter

Status: Linux execution authorized through fleet/task.md on 2026-09-04; R01 contract
and inherited-run handover pending. Read this charter for every R01-R30 work order.
The task and linked local sources are sufficient; no prior conversation is required.

## Authority and current work

The owner requested the epic, then delegated execution to the Linux machines through
fleet/task.md on 2026-09-04. [The Linux dispatch](../../../fleet/delight-dispatch.md)
and LEDGER.md now route those assignments. This includes repository work, direct dev
publication and own-host native work under the fleet protocol once dependencies
permit. It does not terminate an active Epic 002 run or authorize a public release.

R01 prepares the source contract and reconciles the inherited native run before
product implementation. Complete its recorded handover conditions; do not ask for
activation again. Windows source may be prepared on Linux; Windows physical proof
is reserved for a subsequent operator-dispatched Windows session.

An explicit instruction to execute a named R task authorizes that task's repository
work within its dependencies. Executing the whole epic selects one dependency-ready
task/slice at a time. No separate approval of a routine written implementation plan
is required. Product work cannot begin until R01's contract and inherited-run
handover are accepted. Fleet invocation may repeat bounded iterations according
to the dispatcher; a standalone named-prompt invocation completes that slice only.

Repository execution does not inherit host-mutation or push authority merely
because an agent reads fleet/task.md. Native acceptance tasks execute through the
activated fleet dispatcher and its own-host protocol. Active native collection
must finish or be explicitly superseded with restoration before a changed artifact
is deployed. Preserve old candidate evidence; never label a new build with its SHA.

Follow existing user authorization for commits/pushes. In an activated fleet
assignment, use its dev synchronization/publication rules. In a standalone repository
task, do not push, merge, tag, sign, submit packages, or publish unless authorized.
Do not send Slack/email, recruit participants, or launch other agents implicitly.
Working on a native host does not itself authorize changes to other hosts.

The old docs/prompts/CHARTER.md and P01-P14 are the June campaign. They are historical
context, not this epic's execution contract. In particular:

- A task-oriented user surface may change the old domain-only CLI organization.
- A break-and-rebuild does not authorize losing settings, favorites, identities,
  keys, certificates, roots or unrelated native configuration.
- The current user mandates supersede the earlier assessment's incremental-only
  preference and the old instruction to request plan approval.
- Frozen cryptographic labels and stack/layering constraints remain binding.
  Amend an architectural decision explicitly; never silently change wire identity.

## Non-negotiable product requirements

1. Recommended installation ends with Koi usable, started and able to participate.
   Defaults choose supported native capabilities. A binary download is not proof.
2. A second installation on the supported shared LAN automatically discovers and
   publishes presence. Browsing, publication and consumer hostname resolution are
   distinct capabilities that must each be tested where promised.
3. Home answers what can be used. Services have prominent valid actions; devices
   host services. Simple task language comes before raw network/PKI vocabulary.
4. Preserve Rust for application/platform logic and portability. R06 chooses the
   shared rendering implementation with evidence, including musl/headless constraints.
   No renderer migration is accepted on a framework's advertised target list alone.
5. Preserve the Sylin source language: dark night-garden ground, lamp/status band,
   horizontal Home/Devices/Settings/About buttons, exact Koi accent, original mascot
   artwork and trading card. Preserve diagram grammar and motion; improve critical
   legibility/accessibility using the family's tokens where needed.
6. The announced container follows actual app readiness. Local-only offerings are
   suggestions until the user deliberately shares. Stop reverses only Koi-owned work.
7. Discovery, reachability, identity, caller authority and client TLS trust remain
   separate facts. A .local service announcement is not proof of hostname resolution.
8. A supported secure journey ends in real second-client HTTPS without bypass.
   Enrollment and client root acceptance are distinct, deliberate operations.
9. Advanced capabilities remain directly reachable. New information architecture
   must not erase raw diagnostics, audit, DNS, health, proxy, UDP or automation.
10. No invented success, surprise broad exposure, telemetry, or needless rituals.
    Good default automation must still report the exact failed step and recovery.

## Repository and source map

Resolve from the repository containing this charter; do not hard-code a drive.
The root path from here is ../../.. . The primary source is this Koi workspace.
The adjacent desktop is normally ../koi-desktop from the root. Ghostlight source is
normally ../browser-mcp, despite its product name. R06 may read its styles; this
epic does not require changing Ghostlight or the website.

Read .agentic/CONTEXT.md, docs/reference/architecture.md and applicable ADRs for code.
ADR-043 governs commands/status/events and lifecycle; ADR-040 governs local control;
ADR-042 governs Pond. Domain facades retain mutation truth. koi-compose explicitly
coordinates domains; koi-serve owns transport; presentation renders declared state.
Do not add cross-domain imports, read another domain's persistence, or invent a
global state/event bus. Preserve the feature/lean-embedding contracts already tested.

Every prompt lists existing starting paths. New paths/types/routes are established
once in R01's CONTRACT.md and R06's component map, then consumed verbatim. If a path
moves, search with rg and inspect its successor. Update the map in the same change.
Do not create a second module because the expected file is absent. Missing sibling
source blocks only the task that needs it; finish independent local work and record
the exact missing checkout. Do not read gitignored personal/machine notes implicitly.

## One iteration, one bounded slice

1. Inspect git status in every repository you will touch. Preserve concurrent work;
   do not stash, reset, clean or overwrite it to obtain a clean tree.
2. Read the epic, this charter, LEDGER.md and the selected prompt. Check dependencies
   against ledger evidence and current code, including its narrow Linux readiness
   rule. R01 must be accepted (including handover) before product work.
3. Select only this hat's assigned dependency-ready task/subrow; table order governs
   slices. Claim exact write paths before shared edits and honor peer reservations.
   Never mark the entire task accepted because one OS passed.
4. Read the bounded source set, nearby tests/constants and applicable ADRs. Follow
   the installed explore skill if available for production code. Record an exact
   file-by-file plan in reports/Rxx.md (or reports/Rxx-subrow.md): existing pattern,
   proposed owner/types, steps, tests and expected result. Then implement.
5. Finish the selected behavior and its negative cases, update affected docs, and
   verify at the right layer. Do not leave production TODOs, placeholder actions or
   mock responses. Fakes belong in tests and cannot close a native acceptance row.
6. If the slice exceeds a session, checkpoint coherent work: exact changed paths,
   tests/results, unresolved issue and the next concrete command. Mark in_progress
   or implemented, not accepted. Never force a design guess just to finish.
7. Update only the selected ledger row/report and owned fleet namespace. Record
   changed repo SHAs/worktree state, tested artifact, commands/results, docs and next
   dependency. No private host data or credentials in reports.

A technical contradiction should first be resolved from the current typed contract
and evidence. Ask a narrow question only when the missing decision changes scope or
authority and cannot be resolved there. An absent external prerequisite is blocked;
ordinary incomplete work is in_progress. Do not execute a different feature just to
avoid reporting a missing prerequisite.

## Check levels and evidence

For production Rust changes, run focused tests during implementation and these final
native repository gates unless a more specific current repository rule adds a gate:

    cargo check --workspace --all-targets --locked
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo fmt --all --check

Before tests, follow existing test-environment isolation rules and inspect tests
that may invoke credential/firewall/native facilities. Use test-specific controls
already in CI (including KOI_NO_CREDENTIAL_STORE=1 where applicable); never loosen
the product to make tests pass. Keep an isolated build target if installed binaries
are locked; that build is not physical acceptance until installed through the real path.

For the current desktop, run cargo test --locked, strict native Clippy and
node --test ui/app.test.mjs until R06 replaces the frontend test path. Its component
map must provide exact replacement commands. Keep architecture, lifecycle,
authorization, startup and asset boundaries covered across the migration.

Client/version baseline checks (run when relevant, all in R29):

    node --test packages/ts/test/client.test.js packages/npm/test/launcher.test.js scripts/release-version.test.mjs scripts/release-manifest.test.mjs

Python: set PYTHONPATH to packages/python/src in the current shell, then run
python -m unittest discover -s packages/python/tests -v. Respect shell-specific
environment assignment. Lean/publish/ledger/doc guard paths include
scripts/check-lean-embedded.sh, scripts/check-publish-list.sh,
scripts/lint-surfaces.sh and scripts/check-doc-leaks.sh; inspect supported invocation.

Documentation-only work uses link/diff/example checks, not a ceremonial workspace
rebuild. Do not add tests that merely assert a CSS number or mirror a line of code.
Behavioral tests must catch a meaningful regression. Native and usability claims
require native and participant evidence; a simulated fixture is labeled as such.

Success evidence includes the expected failure: wrong authority, wrong identity,
name/port conflict, source loss, interruption and cleanup where relevant. Record
status and useful output; a nonzero exit can be the expected passing assertion.
Never put secrets into argv, URLs, reports, screenshots or logs.

## Done means

All selected acceptance cases pass; shared ownership and migration are intact;
relevant checks pass; actual docs match behavior; and only intended changes remain.
Implementation evidence and native acceptance are separate states. The ledger's
linux-ready marker permits only qualified Linux development with explicit pending
Windows evidence; it never accepts a task/gate/release. A parent is accepted only
when every required subrow passes. A platform without physical proof remains
unverified, never presumed green from cross-compilation.

Use this report shape:

    Task and selected slice:
    Starting revisions and dependency evidence:
    Plan / exact owner and changed files:
    Before -> after:
    Positive and negative acceptance results:
    Commands and exit/result evidence:
    Native artifact/peer/restoration evidence (if required):
    Docs / ADR / contract changes:
    Current status, dependency readiness and remaining Windows/external cases:
    Next concrete action:

No giant repository refactor for its own sake. Split oversized touched modules along
real ownership/test boundaries, retain useful guards, remove superseded UI paths once
their replacements are proved, and leave the next executor a smaller problem.
