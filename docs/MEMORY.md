# Project Memory — pointer index

Durable, model-agnostic project memory lives in tracked files; this page only
points at it. Working/sensitive memory (credential locations, operator
out-of-band answers) lives in gitignored `local/NOTES.md` — see
`local/README.md` for the split. Never duplicate state between them.

| Kind | Where |
|---|---|
| Canonical continuation ledger (epic state, evidence, next action) | [`SESSION-HANDOFF.md`](../SESSION-HANDOFF.md) |
| Lessons/rules that govern how work is done (RL-1..RL-16) | [`docs/lessons-learned.md`](lessons-learned.md) |
| Decision records (why things are built this way) | [`docs/adr/`](adr/) |
| Standing lab facts (hosts, credentials-by-env-name, catalog) | [`tools/koi-lab/lab.json`](../tools/koi-lab/lab.json), `local/NOTES.md` |
| Tool-agnostic agent bootstrap | [`.agentic/CONTEXT.md`](../.agentic/CONTEXT.md) |

Update rule (same as SESSION-HANDOFF): record discoveries in the same breath as
the work that produced them, not at session end.
