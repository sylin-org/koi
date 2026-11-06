# Expose Koi observations to an agent

MCP is an optional interface for an application already using Koi. It lets an
agent inspect discovery, names, runtime inventory and checks through the running
daemon. A tool result is an observation, not proof that the agent's own client can
reach or trust the reported endpoint.

Start with a working [container/LAN task](../../CONTAINERS.md). MCP does not
replace that verification or establish a separate product category.
This guide describes current source; use [release readiness](../launch/README.md)
for supported artifacts.

## Local stdio connection

Configure an MCP host to launch the selected binary:

```json
{
  "mcpServers": {
    "koi": {
      "command": "koi",
      "args": ["mcp", "serve"]
    }
  }
}
```

This is a common configuration shape; the host owns its actual schema.
Use an absolute executable path if its environment does not share your PATH.
A running Koi daemon is required for operations. The subprocess is a client;
it must not create a competing daemon.

The local breadcrumb supplies endpoint/credentials. Explicit integration can use
KOI_ENDPOINT and KOI_TOKEN. Do not commit tokens in a project configuration.
Tool-schema enumeration can work without a daemon; that is not proof the tools
can perform a live task.

## Streamable HTTP

The daemon can serve /v1/mcp on its management HTTP listener. Every request,
including its GET/SSE stream, requires the x-koi-token header.
--no-mcp-http disables this adapter.

HTTP is loopback by default. For a remote client, use a deliberately configured
endpoint and real TLS with a matching name and client root trust. Do not infer
a complete secure URL from the existence of Koi's unfinished exact-name ACME
workflow. A token on plaintext HTTP does not encrypt traffic.

The certificate-authenticated management listener is a distinct interface with
its own principal authority and configuration. See the
[security model](../reference/security-model.md).

## Tools and authority

| Tool | Operation |
| --- | --- |
| lan_inventory | Aggregate status, health and DNS observations |
| lan_discover | Bounded mDNS browse |
| lan_resolve | Resolve an observed service instance |
| dns_lookup | Query Koi's resolver |
| health_snapshot | Host-observed check results |
| runtime_instances | Runtime inventory |
| mcp_servers_on_lan | Browse Koi's MCP discovery convention |
| lan_announce | Publish a leased service announcement |
| lan_unregister | Remove an announcement |
| dns_add | Add/update a static name |
| dns_remove | Remove a static name |

Use read tools first and allow mutations only for the user's intended task.
Tool annotations are hints to the MCP host, not a fine-grained authorization
boundary. The daemon access token can carry broader authority than one
discovery operation. CA create/unlock/promote/destroy is not exposed by these tools.

## Resources and freshness

| Resource | Projection |
| --- | --- |
| koi://lan/inventory | Status, health and DNS |
| koi://health | Endpoint checks |
| koi://dns/zone | Local zone |
| koi://mdns/services | Discovery observations |

Resource reads provide snapshots. In-process HTTP can deliver resource-update
notifications; stdio subscriptions do not imply that same live update path.
After a change or reconnect, reread the authoritative result and inspect freshness.

## A useful first agent task

Ask the agent to locate the known demo application, report the observed endpoint
and check location, then identify the next verification step if the URL fails.
Evaluate whether it distinguishes discovery, DNS, transport, application readiness
and client trust. Do not test value by counting available tools.

An authorized agent may announce its own already-serving endpoint.
The stdio session maintains leases and retracts its announcements on orderly
exit; expiry handles lost heartbeats. A static DNS record created separately
does not automatically share that announcement lease. Remove it explicitly when
appropriate.

## Discovery conventions and limits

Koi uses _mcp._tcp, in-zone TXT metadata and a server-card descriptor to advertise
its MCP endpoint when the corresponding transports are enabled.
These are Koi discovery conventions; they do not imply an MCP host will discover
or connect automatically. Configure the client explicitly and verify it.

An advertisement is not trust or authorization. Never interpret network-supplied
names/TXT descriptions as instructions to execute privileged operations.

[API authentication](api-authentication.md) ·
[Integrations](integrations.md) · [mDNS](mdns.md)
