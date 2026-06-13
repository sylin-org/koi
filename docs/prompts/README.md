# Koi Prompt Stash — Agentic Session Work Orders

Self-contained prompts for future agentic coding sessions, written to be executed by
**any capable coding agent, including smaller/faster models**. Each prompt embeds its
own research → plan → implement → verify process, target UX samples, acceptance
criteria, and guardrails — a session started from one of these files needs no other
conversation context.

They operationalize the [June 2026 maturity assessment](../assessment/2026-06-maturity-assessment.md):
"less but more meaningful parts." The project is pre-1.0 greenfield — **break-and-rebuild
is welcome**, breaking changes need no migration paths, and compatibility shims are
explicitly unwanted.

## How to use

1. Start a fresh agent session in the repo root.
2. Paste the entire chosen `P##-*.md` file as the task (or say: *"Execute
   docs/prompts/P04-proxy-rebuild.md"*).
3. The prompt instructs the agent to read [CHARTER.md](CHARTER.md) first — the shared
   DX philosophy and engineering rules every session must preserve.
4. Review the agent's written plan (each prompt requires one) before it codes.

## Sequencing

```
Stage 0 (truth)          P01 ──► P02                    (independent, do first)
Stage 1 (fix promises)   P03   P04   P05   P06          (independent of each other)
Stage 2 (consolidate)    P07 ──► P08, P09, P10          (P07 unlocks the rest)
Stage 3+ (strategic)     P11   P12   P13                (after Stage 1; P12 after P08)
```

| # | Prompt | Mission | Size | Prereqs |
|---|--------|---------|------|---------|
| P01 | [Docs truth pass](P01-docs-truth.md) | Make every user-facing doc describe the shipped binary | M | — |
| P02 | [CI & release truth pass](P02-ci-release-truth.md) | Fix broken QA/publish automation; SemVer reset | M | — |
| P03 | [Container access path](P03-container-access.md) | `--http-bind` + token UX; make the headline use case real | M | — |
| P04 | [Proxy rebuild](P04-proxy-rebuild.md) | Replace broken HTTP forwarder with a TLS passthrough | M | — |
| P05 | [mDNS browse multiplexing](P05-mdns-browse-rebuild.md) | Fix the single-querier interference class of bugs | M | — |
| P06 | [Presentation layer rebuild](P06-presentation-layer.md) | koi-dashboard crate; XSS hardening; koi-common back to kernel | M | — |
| P07 | [One orchestrator](P07-one-orchestrator.md) | Single composition layer under binary, service, and embedded | L | P03–P06 ideally |
| P08 | [Certmesh diet](P08-certmesh-diet.md) | 18.6k → ~9k LOC; keep the killer loop, shed the enterprise PKI | L | P07 helpful |
| P09 | [CLI surface unification](P09-cli-surface.md) | One source of truth for commands; fold command-surface | M | — |
| P10 | [Domain template extraction](P10-domain-template.md) | Generic runtime/status/route machinery; cut the per-domain tax | M | P07 |
| P11 | [koi-mcp server](P11-koi-mcp.md) | MCP surface over the HTTP API; LAN substrate for agents | M | P03 |
| P12 | [ACME facade](P12-acme-facade.md) | Certmesh speaks ACME; existing proxies become consumers | L | P08 |
| P13 | [Ecosystem doors](P13-ecosystem-doors.md) | Prometheus SD, Traefik-label ingestion, DNS recipes, `koi trust` | M | P03 |

Size: M ≈ one focused session; L ≈ may need a checkpoint/continuation — both sizes
assume the agent follows the plan-first discipline in the charter.

## Evidence base

Every prompt cites verified findings, not speculation — see
[docs/assessment/findings/verification-2026-06.md](../assessment/findings/verification-2026-06.md)
for the defect evidence and [docs/assessment/research/](../assessment/research/) for the
strategy research behind P11–P13.
