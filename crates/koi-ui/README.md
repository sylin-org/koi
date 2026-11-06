# koi-ui

Pure Rust/Maud presentation shared by the native desktop, authenticated operator
view and read-only Pond view. It consumes current typed status contracts and
embedded assets; it does not own clients, domain state, native windows or
persistence.

The architecture guard explicitly permits its existing `koi-certmesh` and
`koi-dns` dependencies only for named status types: `CertmeshStatus`,
`CertmeshRole`, `IdentityCondition`, `DnsCatalogSnapshot`, and `DnsRuntimeStatus`.
This reconciles the guard with ADR-044/047's domain-owned contracts. The renderer
retains the Presentation classification; cores, commands, wildcard imports and
crate/module aliases are rejected. This source guard constrains usage, not the
compiled dependency closure, and is not a security sandbox. Transport, resource
ownership and mutation remain in the adapters/domains.

`render` creates a script-free default document. `render_with_state` and
`fragment_with_state` accept bounded `UiState` presentation intent. Rust filters,
sorts and selects from one authoritative snapshot; adapters carry GET view
queries and manage focus. Adapters apply `DOCUMENT_CSP` and keep credentials out
of content. Endpoint values remain inspectable text; an adapter must explicitly
opt into endpoint actions, and Open receives independent HTTP(S) URL validation.

Navigation is Services, mDNS, Certmesh, Settings and About, with About last. Services uses
single-line desktop columns with an optional details pane; narrow screens reflow
the rows. Device context lives in service details. About has the standalone
Sylin card, snapshot statistics and source-owned documentation links. Its foil
interaction is shared by the authenticated browser and native adapters. Both
adapters preserve its 30px navigation chrome within 44px interaction targets.
This source slice provides search/filter/sort, evidence, browser and native
Open/Copy, Favorite/friendly-name controls, current Certmesh membership and
authority operations, DNS names, LAN sharing, host service controls and composed
capability diagnosis. See the [implementation receipt](../../docs/ux/implementation-proof.md)
and [endpoint-action receipt](../../docs/ux/action-proof.md).

Open uses one validator, `catalog_view::BrowserDestination` (strict HTTP(S), no
credentials, unspecified or link-local-without-interface hosts, API-only, absent,
stale or ambiguous services). Browser, native and Pond adapters share it. Search
requires every word to match a name, friendly name, host or device name, device
address, endpoint or category. Services reports `CatalogSnapshot.discovery`
independently of rows. The authenticated browser transport re-reads the view
every five seconds, marks failures stale with Open disabled, and backs off.

The `home` and `devices` modules and `screens::{home,devices}` are retained,
unrendered projections from the retired Home/Devices line.
`fragment_with_operator_state` does not call them; `tests/home.rs` and
`tests/devices.rs` keep them honest until comparison is placed and they are
removed.

[U07's single-UI plan](../../docs/ux/single-ui-plan.md) records the consolidation
and the retired HTML entry points.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-ui --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.

## Presentation checks

```sh
cargo run -p koi-ui --example components --locked -- loading > target/ui-loading.html
node crates/koi-ui/tests/browser-smoke.mjs target/ui-loading.html
cargo run -p koi-ui --example components --locked -- fixture > target/ui-fixture.html
node crates/koi-ui/tests/browser-smoke.mjs target/ui-fixture.html
```

The snapshot example reads a schema-1 catalog from stdin and rejects invalid
input. `fixture` explicitly generates 36 invented services across six hosts;
it never substitutes for a failed live read. A second argument carries a view
query, for example `"tab=services&selected=fixture_service_00"`; an optional third
argument `browser` omits the native refresh link when an outer transport owns it.
Browser smoke checks need Chromium and establish offline layout/keyboard/motion
behavior; installed native acceptance is separate.

mDNS is a first-class technical inspection destination beside the normalized
Services catalog. The authenticated mDNS projection
preserves reported types, instances, TXT, recent removal observations and source
availability. Local text/type filters are presentation intent; browse, resolve
and restart actions use the bounded operator bridge. The shared
`MDNS_INTERACTION_SCRIPT` retains only drafts, expanded details and the last
explicit query response across fragment refreshes, and drops pending responses
when the authenticated adapter calls `KoiMdns.reset()`.

The mDNS fixture includes unresolved and removed instances, a type with no
instances, a failed provider and hostile TXT values. Its browser check exercises
query outcomes, refresh retention and late-response removal after logout:

```sh
cargo run -p koi-ui --example components -- mdns-fixture "tab=mdns" browser > target/mdns-fixture.html
node crates/koi-ui/tests/browser-smoke.mjs target/mdns-fixture.html
```
