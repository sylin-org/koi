# U03 endpoint-action evidence

Task: [U03 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#u03--open-services-and-preserve-identity-through-change).
Owner: coordinating agent.
Last verified: 2026-09-13.
Source baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus the preserved working tree.
Verdict: browser endpoint and personal-intent slice verified in source and fixture presentation;
U03 remains in progress. This is not native, lifecycle, second-device or release proof.

## Implemented boundary

The shared renderer exposes endpoint controls only when its adapter opts into
browser actions and the authoritative service includes the corresponding
`AvailableAction`. Open additionally requires an endpoint marked browser-usable
and a complete, independently parsed HTTP or HTTPS URL with a host, nonzero port,
no credentials and no control characters. It opens in a separate browser context
with `noopener noreferrer`. Invalid or hostile endpoint text remains visible and
copyable when Copy is authorized, but cannot become an Open target.

Copy address writes the exact displayed endpoint through the browser clipboard
API after an explicit click. It neither sends a request nor carries the daemon
token. Success is announced and reflected on the button; failure remains visible
with a manual fallback. The browser continues to keep the token in page memory
and sends it only to the fixed authenticated shell endpoint.

Current services with unambiguous identity expose Favorite and friendly-name
eligibility in the composed catalog. The browser renders those controls only when the
preferences core is mounted and the authenticated request comes from a loopback
peer. An explicit action reads the typed preferences document and writes the one
fixed, percent-encoded service route with its expected revision. The mutation
preserves the other field: Favorite keeps the friendly name, and name editing
keeps Favorite. A blank friendly name restores the discovered label. Revision
conflicts remain visible and retryable instead of claiming success from stale
state; other failures keep the current rendered catalog and memory-only token.

A temporary catalog failure retains the last rendered snapshot, view query and
memory-only token for an explicit Refresh retry. A successful retry replaces it
with a complete authoritative snapshot and restores the matching focus key.
Authentication rejection and an unexpected content type still fail closed by
clearing the catalog and token.

Native rendering remains action-free through `EndpointActions::None`. The
[native integration changes](../../tools/koi-ui-native/README.md) preserve that
boundary while replacing the existing Windows command-shell opener with the
shared URL validator and direct `ShellExecuteW` dispatch. The changes were
applied to the sibling checkout, built and packaged in release mode against this
Koi working tree, then installed and launched against the installed development
daemon. The shared pane does not yet expose native Open.

## Verification

- `cargo test -p koi-compose -p koi-ui -p koi-serve --locked`: 275 tests
  passed; two tests were explicitly ignored, including the live Windows Firewall
  check.
- Renderer coverage proves catalog gating, adapter opt-in, one exact valid Open
  link, rejection of a user-info-shaped hostile host, inert rendering without
  action eligibility, per-endpoint Copy values and escaped hostile input.
- Composition coverage proves that current, unambiguous services permit
  Favorite and alias intent while ambiguous identity cannot be personalized.
  Adapter coverage proves browser preference controls require both the mounted
  preferences core and an observed loopback peer.
- `node --test crates/koi-serve/assets/ui-transport.test.mjs`: 25 tests passed.
  The cases cover exact clipboard content, no extra Copy request or token
  transmission, feedback and retained state, typed Favorite/friendly-name
  read/write, cross-field preservation, rerendered focus, visible revision
  conflict recovery and transient daemon-loss/reconnect behavior.
- The production renderer and transport were inspected in Chromium against the
  explicitly invented 36-service fixture. The wide pane displayed complete
  endpoint text with 44px Open, Copy address, Favorite and Save name controls
  while the dense list remained operable. Mutations and Open were not invoked
  because the stand-in does not implement preferences and its targets are not
  live applications; this check proves presentation, not reachability.
- `cargo fmt --all --check` and `git diff --check` passed.
- The paired desktop patches pass `git apply --check`. In an isolated Windows
  worktree, all 25 desktop tests passed with one existing cross-host test ignored;
  strict Clippy and formatting passed. A release-mode development workbench was
  subsequently packaged through Tauri's npx NSIS route, installed and launched
  against the real installed daemon. This is a local unsigned development
  deployment, not a selected candidate or physical Open receipt.

## Remaining U03 acceptance

Authoritative process-level lifecycle, the L03 restart/recreation/removal
fixture, the shared-pane native Open bridge, installed focus/Open behavior and
actual second-device application access remain unproved. A dispatched browser
URL will remain an attempt rather than a claim that the application responded.
