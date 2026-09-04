# Project Memory — pointer index

Durable, model-agnostic project memory lives in tracked files; this page only
points at it. Working/sensitive memory (credential locations, operator
out-of-band answers) lives in gitignored `local/NOTES.md` — see
`local/README.md` for the split. Never duplicate state between them.

| Kind | Where |
|---|---|
| Universal fleet entry (self-routing execution contract) | [`fleet/task.md`](../fleet/task.md) |
| Current native fleet campaign and dispatch (single live pointer) | [`fleet/coordination.md`](../fleet/coordination.md) |
| Linux delight realignment dispatch, executable prompts and progress | [`dispatcher`](../fleet/delight-dispatch.md), [`Epic 003`](../fleet/epics/003-delight-realignment.md), [`prompt pack`](prompts/delight/README.md), [`ledger`](prompts/delight/LEDGER.md) |
| Historical v1 campaign ledger and release-gated residue | [`SESSION-HANDOFF.md`](../SESSION-HANDOFF.md) |
| Product experience mandates and proposed UX direction (2026-09-04; requirements distinguished from recommendations) | [`docs/assessment/2026-09-delight-mandates-and-ux-direction.md`](assessment/2026-09-delight-mandates-and-ux-direction.md) |
| Source-derived Sylin visual dictionary for Koi (2026-09-04) | [`docs/assessment/2026-09-sylin-visual-dictionary.md`](assessment/2026-09-sylin-visual-dictionary.md) |
| Lessons/rules that govern how work is done (RL-1..RL-16) | [`docs/lessons-learned.md`](lessons-learned.md) |
| Decision records (why things are built this way) | [`docs/adr/`](adr/) |
| Standing lab facts (hosts, credentials-by-env-name, catalog) | [`tools/koi-lab/lab.json`](../tools/koi-lab/lab.json), `local/NOTES.md` |
| Tool-agnostic agent bootstrap | [`.agentic/CONTEXT.md`](../.agentic/CONTEXT.md) |

Update rule: record discoveries in the same breath as the work that produced
them, not at session end. Fleet evidence belongs in the hat journals selected by
`fleet/task.md`; update the epic table only when a whole gate changes state.
