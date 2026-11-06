# MCP interface

`koi mcp serve` exposes the stdio transport. The daemon can expose the tool surface at `/v1/mcp`; discovery metadata is available at `/.well-known/mcp/server-card.json`.

## Use and verify

Authenticate the selected transport and inspect tool permissions. Remote management can use a mesh client certificate and roster authorization when enabled.

## Boundaries

MCP support is an advanced interface, not a launch requirement. A client principal currently has coarse authority; a read-only tool annotation is not a scoped authorization policy. Do not distribute the operator token to an untrusted process.

See [the capability guide](../../guides/mcp.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
