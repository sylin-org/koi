---
name: explore
description: Map source ownership, existing types and patterns before Koi production code changes; plan exact placement and risk-focused verification. Documentation-only edits need relevant source/example checks rather than a full code exploration.
---

# Explore before implementation

Use this workflow before changing production code. Keep it proportional to the
actual task; documentation tooling does not require surveying unrelated domains.

1. Read [.agentic/CONTEXT.md](../../../.agentic/CONTEXT.md), the current epic and
   ledger. State the user task, affected layers and intended observable outcome.
2. Read the relevant existing implementation, callers and tests. Search with rg
   for existing types, constants and the closest working pattern. Summarize what
   already exists and what must be created.
3. Identify the owner of each proposed change. Use current source paths, not a
   hand-maintained module inventory:
   - domain state/commands/events stay in their owning crate;
   - shared contracts and small status/event primitives belong in koi-common;
   - cross-domain coordination belongs in koi-compose;
   - listener/auth/transport assembly belongs in koi-serve;
   - CLI commands and platform entry points belong in crates/koi/src;
   - UI rendering belongs in koi-ui and consumes authoritative projections;
   - documentation generation remains in scripts/AiDocDist.ps1.
4. State exact file placement, the reused pattern and required tests/checks.
   Search new protocol names and constants before adding them. Keep constants
   co-located; avoid parallel inventories and lifecycle owners.
5. Check architecture: no domain-to-domain imports, no native provider types
   crossing their adapter, no mdns-sd import outside
   crates/koi-mdns/src/native.rs, no secrets in public output, and no guessed
   success/readiness. Preserve cancellation, durable identity and teardown rules.
6. Present a concise implementation plan with task, files read, reuse, new
   placement, risks and verification. Proceed when the work is already authorized.
   Ask only for genuinely missing authority or requirements.

For an HTTP change, inspect the domain's route module and
crates/koi-serve/src/http.rs. For a CLI change, inspect crates/koi/src/cli.rs and
the relevant commands module. For container behavior, inspect
crates/koi-runtime/src/instance.rs and crates/koi-compose/src/orchestrator.rs.
For docs/tooling, verify examples, source links, release claims and generated
outputs without treating documentation edits as fresh native acceptance.
