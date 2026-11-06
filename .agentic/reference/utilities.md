# Canonical source lookup

Search source before creating a type, constant or helper. Values and signatures
live with their owners; this index deliberately does not copy them.

| Concern | Owner |
| --- | --- |
| Shared status subscription | crates/koi-common/src/status.rs |
| Semantic event channels | crates/koi-common/src/events.rs |
| Service/device/connection contracts | crates/koi-common/src/service.rs |
| Registration IDs | crates/koi-common/src/id.rs |
| mDNS request/response wire shape | crates/koi-mdns/src/protocol.rs |
| Browse demand and canonical keys | crates/koi-mdns/src/discovery.rs |
| Provider route ownership | crates/koi-mdns/src/control_plane.rs |
| Runtime label parsing | crates/koi-runtime/src/instance.rs |
| Runtime-to-domain composition | crates/koi-compose/src/orchestrator.rs |
| Authoritative service catalog | crates/koi-compose/src/catalog.rs |
| Service-name grants and issuance | crates/koi-certmesh/src/service_names.rs |
| HTTP client | crates/koi-client/src/lib.rs |
| Listener/auth assembly | crates/koi-serve/src/http.rs |
| CLI syntax | crates/koi/src/cli.rs and crates/koi/src/commands/ |
| Platform installation | crates/koi/src/platform/ |

Use rg to locate the exact current symbol. Check its callers, tests and ownership
before reuse. Follow [architecture](../../docs/reference/architecture.md) and
[the current epic](../../fleet/epics/004-container-lan-adoption.md) for placement
and priority. No duplicated constant registry is required.
