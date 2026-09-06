# koi-ui

Pure Rust/Maud presentation shared by the native workbench and the authenticated
operator web view. Depends on `koi-common` types, not clients, domains, GTK or Tauri.
`render` creates a script-free document; `fragment` supplies the same components to
the authenticated browser transport. Adapters apply `DOCUMENT_CSP` as a response
header and never pass catalog-derived URLs as `Links`.

Home shows the complete declared catalog with timestamp and explicit refresh.
Devices groups by exact catalog device ID, with native HTML disclosure controls.
Settings preserves access to existing advanced controls; About uses the original
card. R07–R09 own the subsequent action-oriented journeys, not a second renderer.

The R07 foundation lives in `home`: `project` borrows one catalog and applies
search, favorite grouping, stable-ID ordering/selection and bounded attention.
`EmptyState` describes filtered catalog contents, not discovery health or transport
freshness. Adapters must report loading/unavailable/reconnecting independently.
`BrowserDestination::for_service` only narrows declared Open/browser eligibility;
`parse` validates an already supplied HTTP(S) URL at a native opening boundary.
Neither proves reachability, TLS trust or authorization. API-only services need
connection details, not an inferred dashboard. These helpers do not yet change
the R06 rendered Home or provide live interactive controls; that is remaining R07
work. Behavioral coverage is `tests/home.rs`.

Assets are embedded: the unchanged original sprite SHA-256 is
`91aea43e2587f53242b9dbc4bf794d8147dcd915a7e356fa3943422900fdd33c`.
`family-v1.css` and `card.html` retain the R06 extraction from desktop `ba39faf`,
verified against Ghostlight `2255a0ec` with Koi's blue accent. See ADR-045 and the
R06 renderer-decision report for exact provenance. No runtime sibling or CDN.

From the Koi workspace:

```sh
cargo test -p koi-ui --locked
cargo run -p koi-ui --example components --locked -- loading > target/ui-loading.html
cargo run -p koi-ui --example components --locked -- unavailable > target/ui-unavailable.html
node crates/koi-ui/tests/browser-smoke.mjs target/ui-loading.html
node crates/koi-ui/tests/browser-smoke.mjs target/ui-unavailable.html
```

The `snapshot` example mode consumes a schema-1 catalog JSON on stdin; it fails
instead of inventing a live row. Browser checks require Chromium and prove only
offline layout, keyboard and motion. Installed native acceptance is separate.
