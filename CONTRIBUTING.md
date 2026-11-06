# Contributing to Koi

Help container/LAN operators label a container, open its application from another
computer, and keep names and state correct when it changes. Reproducible failures,
clear setup instructions, recovery fixes and integrations are valuable contributions.

Read [ADR-046](docs/adr/046-container-lan-adoption.md), the
[launch epic](fleet/epics/004-container-lan-adoption.md) and
[task ledger](fleet/launch/LEDGER.md) before choosing substantial work.
The first operator preview does not require a full desktop redesign or new domains.

## Choose a bounded contribution

Start with a concrete user task or failing supported scenario. Explain the current
alternative, the expected result and how to reproduce it. For a bug report include
the Koi artifact, OS/runtime/client versions, sanitized output and attempted recovery.
Do not post tokens, private keys or personal network details. Report vulnerabilities
through [SECURITY.md](SECURITY.md).

Coordinate shared source claims through the ledger. [fleet/task.md](fleet/task.md)
governs native host assignments; it does not run merely because a contributor opens
the repository. Review existing worktree changes before editing.

## Build and check

Install the Rust version required by Cargo.toml, then:

    cargo check --workspace --all-targets --locked
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo fmt --all --check

For client and release-tooling changes, run the relevant existing Node and Python
contracts and the lean/publish-list guards from .github/workflows/ci.yml. POSIX
installer tests need a POSIX shell; cross-language CSR tests need the documented
cryptography dependency. A skipped environment-dependent case is not a pass.

Documentation-only work needs link/example checks and the surface-ledger lint,
not an unrelated full Rust rebuild. Generate and inspect the default current
documentation bundle with:

    ./scripts/AiDocDist.ps1 -Validate

Use -IncludeADRs and -IncludeResearch only when the evidence corpus is required.

When changing the generator, run its navigation and corpus regression checks
with Node and PowerShell 7 (`pwsh`) available:

    node --test scripts/ai-doc-dist.test.mjs

## Architecture and implementation

Use the [exploration workflow](.codex/skills/explore/SKILL.md) before production
code. Read relevant source, find existing types/constants, identify the closest
pattern, and state exact placement and meaningful verification.

Domains own commands, durable state, snapshots, events and lifecycle. Shared
contracts belong in koi-common; cross-domain coordination in koi-compose;
transport/auth assembly in koi-serve. The catalog and UI consume authoritative
state. Do not introduce another inventory or lifecycle owner.

Keep errors typed, constants co-located, visibility narrow and dependencies
justified. Reuse maintained protocol/crypto libraries. Prefer explicit readable
control flow. Change abstractions when actual consumers justify them.

Test risky behavior: reconnect/reconciliation, cancellation/cleanup, name
collisions, authorization, normal client DNS/TLS, renewal and recovery. Mocks
support unit tests; they do not prove physical network or installed-service
behavior. See [architecture](docs/reference/architecture.md) and
[proof receipts](docs/launch/proof.md).

## Documentation and release claims

Update the guide, reference and example affected by a behavior change.
[Security model](docs/reference/security-model.md) owns bind/auth/trust limits.
[Readiness](docs/launch/README.md) owns artifact/channel facts.
[SURFACES](docs/SURFACES.md) indexes guards, not inferred native acceptance.

Every advertised journey must work on its named artifact and matrix. Keep
current instructions distinct from preserved research/ADRs. Do not add chronology,
superseded task lists or unverified compatibility claims to operating docs.

A release needs a clean-checkout hosted dry run, affected native evidence and an
independent post-publication install. Never repoint a used registry version or
tag. Community drafts require explicit communication authorization before posting.
