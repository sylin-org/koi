# R06 renderer experiment (not a product surface)

Two Rust renderers consume the **same** `koi-common::service::CatalogSnapshot`:
Maud 0.27.0 (the view candidate for the existing Tauri shell) and Dioxus 0.7.10
(the view candidate for a Dioxus desktop replacement and server-rendered web).
The optional desktop check compiles Dioxus's desktop dependencies; it does not
launch or package a new workbench. There is no selection yet.

This nested workspace has its own lockfile. It does not alter Koi's product
dependency graph, create a daemon, bind a listener, expose the catalog on Pond,
or modify preferences. Output is a point-in-time read, not a monitored UI. All
screens beyond the row are explicitly labeled experiment scope, not working
product journeys. Remove these variants after a measured renderer decision.

## Reproduce from Koi root

```sh
cargo test --manifest-path tools/koi-ui-spike/Cargo.toml --locked --features dioxus-renderer
cargo clippy --manifest-path tools/koi-ui-spike/Cargo.toml --locked --all-targets --features dioxus-renderer -- -D warnings
cargo fmt --manifest-path tools/koi-ui-spike/Cargo.toml --check
cargo check --manifest-path tools/koi-ui-spike/Cargo.toml --locked --no-default-features --features dioxus-desktop-check
cargo build --manifest-path tools/koi-ui-spike/Cargo.toml --locked --release --features dioxus-renderer
tools/koi-ui-spike/target/release/koi-ui-spike maud > tools/koi-ui-spike/target/maud.html
tools/koi-ui-spike/target/release/koi-ui-spike dioxus > tools/koi-ui-spike/target/dioxus.html
node tools/koi-ui-spike/browser-smoke.mjs tools/koi-ui-spike/target/maud.html
node tools/koi-ui-spike/browser-smoke.mjs tools/koi-ui-spike/target/dioxus.html
```

Windows uses the corresponding `.exe` path; the browser smoke currently invokes
`chromium` and requires that executable on PATH. It is a Chromium component check,
not a WebKit/WebView2/package gate. It creates and removes its own temporary
browser profile and uses a debugging pipe, not a new network listener.

The executable discovers the installed service through `KoiClient::from_local`.
It never takes a DAT on argv, falls back to a test fixture, reads another domain's
storage or starts a service. Unavailable access/schema emits the unavailable
page and **exit 1**. Bad/uncompiled renderer selection exits 2. Both are expected
negative cases, not a successful live row. A valid catalog with no services
renders an honest empty state. Credentials/raw server errors are never embedded.

For separate **SSR reader** size measurements, build each renderer independently
with `--no-default-features --features maud-renderer` or `dioxus-renderer`; measure
the resulting stripped executable before the next build overwrites it. These
are not sizes of a complete Tauri or Dioxus desktop app. Both readers include the
same authenticated HTTP client and original assets. Normal dependency counts use
`cargo tree --edges normal --prefix none`, removing the ` (*)` suffix and deduping
package/version lines; they include the experiment itself, exclude build/dev edges,
and are target-specific. Timings with shared caches/concurrent builds are not a
controlled performance benchmark.

## Asset provenance

Source: sibling koi-desktop `ba39faff62ea758baaac5cffe2a8ac4ac206bfb3`.

- `family-v1.css`: byte-exact stylesheet prefix before the `policy` section,
  covering original tokens, band, common components and card (terminal whitespace
  normalized only).
- `card.html`: exact original `div.tcg` markup, terminal whitespace normalized.
  The Rust renderer substitutes only `src="koi.png"` with the original embedded
  PNG data URI. No user-controlled input enters raw HTML.
- `koi.png`: original bytes, SHA-256
  `91aea43e2587f53242b9dbc4bf794d8147dcd915a7e356fa3943422900fdd33c`.
- `spike.css`: separate narrow-layout, focus, readable-text and reduced-motion
  overrides. The lamp stays neutral because a static read cannot claim an active
  connection. The card retains the 200/300 px sprite geometry; its outer width
  may shrink to the available 320 px viewport content area.

Ghostlight was found at `../ghostlight`, revision
`2255a0ec2ac5bf709a8dcfdd333df82c55697b11`. Its original night-garden/ink/surface/
motion tokens match Koi apart from the intentional teal-to-blue accent. No
Ghostlight file was changed. All required assets are now local to the experiment;
neither sibling nor a CDN is needed at runtime or when rebuilding this probe.

See [R06 report](../../docs/prompts/delight/reports/R06-renderer-decision.md) and
[proposed ADR](../../docs/adr/045-shared-rust-renderer.md) for measured limits and
the native work that must precede a renderer selection.
