# Contributor instruction map

[CONTEXT.md](CONTEXT.md) is the tool-neutral entry point for authorized work.
It routes to the focused release epic, current architecture and security model.

- [mDNS rules](rules/mdns-boundary.md): provider and lifecycle ownership.
- [HTTP rules](rules/http-adapter.md): thin domain adapters and auth classification.
- [Source lookup](reference/utilities.md): find canonical types and constants.
- [API lookup](reference/api-endpoints.md): canonical interfaces.
- [Explore](../.codex/skills/explore/SKILL.md): pre-implementation source mapping.

Keep instructions concise and tied to existing behavior. Product instructions
belong in [docs/index.md](../docs/index.md); task state belongs in
[the launch ledger](../fleet/launch/LEDGER.md). Do not create tool-specific copies
of product plans or protocol contracts.

Generate a current AI documentation bundle with:

    ./scripts/AiDocDist.ps1 -Validate

Research and decision evidence are opt-in through the generator's corresponding
flags. They do not replace the active execution contract.
