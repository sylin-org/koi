# U02 implementation evidence

Task: [U02 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#u02--build-the-shared-shell-and-consistent-entry).
Owner: coordinating agent with bounded renderer, transport and verification work.
Date: 2026-09-12.
Source baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus the preserved working tree.
Verdict: this dated U02 slice is superseded by the integrated
[U07 receipt](single-ui-proof.md). It remains evidence for its renderer checks,
not a description of current navigation.

## Implemented scope

The [shared Maud renderer](../../crates/koi-ui/src/lib.rs) now presents Services,
Certmesh and Settings. Services uses dense, single-line desktop rows and
on-demand details. [Typed view state](../../crates/koi-ui/src/state.rs) bounds and
validates query parameters for search, host/state filters, deterministic sorting
and exact service selection. [Presentation helpers](../../crates/koi-ui/src/catalog_view.rs)
format supplied names, addresses and check evidence without creating health,
trust or action eligibility.

The [browser adapter](../../crates/koi-serve/src/ui.rs) requires the daemon access
token for catalog HTML, including loopback requests. The [browser transport](../../crates/koi-serve/assets/ui-transport.js)
keeps that token in page memory and sends it only to the fixed authenticated
endpoint. Rust owns filtering and catalog meaning; JavaScript handles requests,
focus, scroll and responsive details.

At this receipt's U02 boundary, the slice exposed no service Open/Copy controls,
preference mutations, live event updates or composed diagnosis. The subsequent
[U03 endpoint-action receipt](action-proof.md) records the bounded browser action
addition. [Certmesh](../../crates/koi-ui/src/screens/private_space.rs)
explicitly lacks current Certmesh status; it points to the real
`koi certmesh status` and `koi certmesh --help` commands and system tools. It does
not advertise enrollment or recovery as browser controls. U03–U06 and the
container/release work retain their own acceptance requirements.

## Verification recorded

| Check | Result and limit |
| --- | --- |
| Affected Rust suites | 231 passed; one live-firewall test ignored. [Renderer tests](../../crates/koi-ui/tests/render.rs) cover escaping, exact host identity, conditions, endpoint/evidence details, filters/sorts, missing selection and read-only actions. |
| Workspace check and Clippy | Passed. |
| Browser transport tests | 18 passed in [the transport test suite](../../crates/koi-serve/assets/ui-transport.test.mjs), including the explicit modal keyboard focus trap. |
| Full workspace tests | Final `cargo test --workspace --locked --no-fail-fast` passed, including all 63 DNS tests. A prior README MSRV wording failure was corrected without changing Rust 1.92. Earlier Windows DNS socket failures also occurred; a later pass does not resolve the port-pair acquisition issue recorded below. |

[Windows issue 005](../../fleet/windows/issues/005-dns-port-zero-pair-acquisition.md)
records the intermittent DNS failures, direct socket observations and bounded
remediation. DNS production code and host configuration were unchanged.

Browser observations used the actual Maud output from the
[component example](../../crates/koi-ui/examples/components.rs), its explicitly
marked [36-service, six-host fixture](../../crates/koi-ui/examples/support/catalog.rs),
and the real browser transport. A loopback Python stand-in supplied the rendered
responses. This exercises production presentation code with invented data; it is
not integration with a running Koi daemon or proof of application reachability.

| Observed browser case | Result |
| --- | --- |
| Desktop, 1280×800 CSS px | 49px ordinary rows; at least ten complete rows, including the 24px fixture notice; measured controls at least 44px. |
| Wide details | 368px nonmodal pane beside the inventory. |
| Narrow, 320 CSS px | Ordinary rows about 101.67px; no page-wide horizontal overflow; details presented as a modal. |
| Combined filters | Archive + This Koi host + Responding returned the one matching service. |
| Selection removed by filtering | Details closed and focus returned to search. |
| Details opened by chevron | Closing returned focus to that exact chevron. |
| Modal keyboard containment | Explicit modal trap verified in Chromium: six forward and six reverse Tab presses stayed inside the drawer; Escape restored the exact chevron. Wide panes remain nonmodal. |
| Reduced motion | Settings verified at 320px with the emulated system preference: zero elements with active CSS animation names, mascot halo animation `none`, all three embedded images loaded. The temporary preference was reset. |
| Invalid initial view query | A visible error offered Refresh; Refresh recovered the default 36-service view without requiring token re-entry. |

## Native and release boundary

The native adapter change is retained as
[U02-shared-view-intent.patch](../../tools/koi-ui-native/patches/U02-shared-view-intent.patch),
based on desktop source `d432b9ed`. On 2026-09-13 it was applied to the sibling
desktop checkout with U03, paired directly to this Koi working tree, built in
release mode, packaged through the npx Tauri NSIS route, installed and launched
against the newly installed development daemon. The
original desktop dependency pin `b4c32fa9` does not supply the new shared-view
API; a production integration still needs a real Koi revision and regenerated
lockfile.

The daemon and current-user workbench were installed locally; nothing was
published. The unsigned development package is not a selected candidate.
Endpoint-action bridging, physical acceptance and the candidate receipt remain
outstanding. [Launch
readiness](../launch/README.md) and [the launch
ledger](../../fleet/launch/LEDGER.md) govern those decisions.
