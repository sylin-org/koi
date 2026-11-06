---
name: explore
description: Map source ownership, existing types and patterns before Koi production code changes; plan exact placement and risk-focused verification. Documentation-only edits need relevant source/example checks rather than a full code exploration.
---

# Explore before implementation

Use this workflow before changing production code. Keep it proportional to the
actual task; documentation tooling does not require surveying unrelated domains.
Reuse recently inspected, unchanged evidence instead of repeating the same reads.
Prefer a usable vertical slice; add infrastructure only for a concrete dependency
or safety requirement of that slice.

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
   - the HTTP client belongs in koi-client;
   - CLI commands and platform entry points belong in crates/koi/src;
   - UI rendering belongs in koi-ui as pure presentation; the native adapter
     (sibling koi-desktop) owns the webview, OS integration and URL opening;
   - documentation generation remains in scripts/AiDocDist.ps1.
4. State exact file placement, the reused pattern and required tests/checks.
   Search new protocol names and constants before adding them. Keep constants
   co-located; avoid parallel inventories and lifecycle owners.
5. Check architecture: no domain-to-domain imports, no native provider types
   crossing their adapter, no mdns-sd import outside
   crates/koi-mdns/src/native.rs, no secrets in public output, and no guessed
   success/readiness. Preserve cancellation, durable identity and teardown rules.
6. Record intended behavior, exact files, reused pattern and risk-based checks
   briefly in commentary or the existing task record — no fixed table, transcript
   or separate claim commit is required for solo source work. Implement
   already-authorized work without a routine second approval pause; ask only when
   authority, scope or a material requirement is missing.

For an HTTP change, inspect the domain's route module and
crates/koi-serve/src/http.rs. For a CLI change, inspect crates/koi/src/cli.rs and
the relevant commands module. For container behavior, inspect
crates/koi-runtime/src/instance.rs and crates/koi-compose/src/orchestrator.rs.
For docs/tooling, verify examples, source links, release claims and generated
outputs without treating documentation edits as fresh native acceptance.

Verify proportionally as [fleet/PROTOCOL.md](../../../fleet/PROTOCOL.md)
describes: focused local checks, broad CI at coherent milestones, targeted native
checks only for affected journeys. Test behavior and meaningful failure cases, not
source spelling or incidental CSS constants.
