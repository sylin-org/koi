# Sylin visual alignment: implementation and local deployment

**Scope correction:** this receipt records a visual slice, not a unified product.
The owner found that Certmesh's tool link opens a different existing interface.
[U07's single-UI plan](single-ui-plan.md) now requires consolidation and deletion
of the separate screens. The checks below did not establish that outcome.

Date: 2026-09-13. Owner: coordinating agent, following the owner's approved
[visual-signature direction](visual-signature-plan.md) and navigation/About
refinement. This is a completed visual slice of U02, not acceptance of the full
launch epic or the remaining native service actions.

## Delivered behavior

- Navigation now reads **Services → mDNS → Certmesh → Settings → About**. Refresh
  and browser session controls precede the destinations. About is always last.
  The Ghostlight reference's 30px painted height, 12.5px regular type, 13px
  desktop horizontal padding, 7px corners and 2px gap are retained, with 44px
  interaction targets. Narrow views reduce horizontal padding to fit.
- About is a typed shared destination. Its single 300×478 family card sits
  beside the product story, snapshot service/host/favorite counts, timestamp,
  accurately labeled interface version, license and grouped documentation links.
  It stacks on narrow screens. Missing catalog evidence does not become zero
  statistics or a readiness claim.
- The card now uses the same two foil layers, pointer coordinates, mascot echo,
  hover lift and halo motion as Ghostlight. The shared interaction driver is
  adapter-applied so the Rust-rendered document retains its script-free CSP.
- The shell reuses family ink, surface and separator tokens. Operational
  headings are lighter; secondary ink is closer to Ghostlight while retaining
  the established 4.5:1 normal-text contrast baseline. Settings uses task
  strips; Certmesh retains an
  explicit unavailable-status explanation and existing system-tool access.
- Service columns, filters, selection and detail behavior are retained. Rows
  have quieter separators and selection treatment. Their left rail and state
  label use the real service condition: blue for discovery, green for a
  response, amber for no response, violet for ambiguity, gray for stale and
  red for absent. Endpoint groups in the pane use rules instead of repeated
  nested boxes.
- Browser session controls occupy a real header slot. Their existing listeners
  survive navigation; authorization loss, Forget and page exit return them to
  the login surface before the old view is discarded.
- Browser documentation links use a separate tab with `noopener noreferrer`.
  The native window handles new-window requests only for the exact documentation
  URLs owned by the shared About module, dispatches through its existing
  validated browser opener, and denies creation of a remote native window.
  This does not enable native catalog endpoint actions.

## Source and verification

Koi baseline: `791f87ebe0a8ba93246f60ce0b283c13fb86595b` plus the preserved
working tree and this slice. Desktop baseline:
`d432b9ed207307f1825f0706473eaef4dbeb227b` plus the existing U02/U03 integration
and this documentation handoff. The desktop checkout resolves its Koi dependencies
from the adjacent source tree. Neither build is claimed as a clean tagged release.

Affected owners: `crates/koi-ui` owns state/rendering/assets;
`crates/koi-serve/assets/ui-login.html` and `ui-transport.js` own browser session
placement; sibling `koi-desktop/src/main.rs` owns native new-window dispatch and
`src/ui.rs` retains the bounded protocol guard.

- `cargo test -p koi-ui --locked`: 21 tests passed, including active-page routing,
  opaque view-query round trips, About facts/unavailable state, source-owned
  documentation targets and existing service action/escaping checks.
- `node --test crates/koi-serve/assets/ui-transport.test.mjs`: 26 tests passed,
  including reparenting controls through navigation and authorization loss.
- `node --test crates/koi-ui/tests/card-effect.test.mjs`: the shared card driver
  passed exact coordinate, parallax and pointer-leave checks.
- `cargo test -p koi-serve --lib --locked`: 175 passed and the existing live
  firewall test remained ignored; the browser transport contains the shared
  foil driver without exposing its operator credential.
- Desktop `cargo test --locked ui::tests`: five native protocol tests passed,
  including admission of `tab=about` and rejection of unsupported requests.
- Existing offline Chromium smoke passed for About and the 36-service fixture
  at 1280×800, 390px and 320px: 11 complete desktop service rows, 49px ordinary
  rows, four ordered destinations, 30px painted navigation controls, 44px hit
  areas, keyboard skip-link focus, no page-width overflow and reduced motion.
- A separate Chromium session exercised the real installed daemon at
  `127.0.0.1:5641`, using its authorized local-control handoff with credentials
  confined to memory. Its 26-service catalog rendered; About, Settings,
  Certmesh and selected details were visited and captured. About had one card,
  eight links, the expected heading focus and no horizontal overflow at 320px
  or 390px. The card was armed once, pointer movement set `--mx` to `46.5%`
  and its transitioning foil reached observed opacity `0.148244`. Forget
  removed the catalog and restored the session-control home.
- All six linked GitHub guide pages returned HTTP 200. The project and Sylin
  destinations are the existing public sites. No catalog action or preference
  mutation was needed for this visual review.
- Rust formatting and scoped whitespace checks passed. Both release builds and
  the Tauri NSIS bundle completed successfully.

Captures and machine-specific verification output are in the ignored
`.tmp/visual-family/` directory. The reusable offline captures and measurements
are generated under `target/`. They are layout evidence, not published assets.
The installed native window was launched and observed as responding; its physical
click-through documentation handoff and platform accessibility remain separate
from the browser/source checks above.

## Installed artifact receipt

The daemon was updated through its elevated transactional `koi install` recipe.
SCM reported the automatic service running as PID 35792 at observation time,
and `/healthz` returned HTTP 200. The release-mode build and staged
`C:\Program Files\Koi\koi.exe` matched SHA-256:

`51B404AFFDCA3E39B8F6041DDAEC53A9E1E2B1A26F4E715D3AC39ED92E77059E`

The desktop package was built with
`npx --yes @tauri-apps/cli@2.11.4 build --bundles nsis` and installed successfully
through the NSIS installer. The preceding installer was retained in ignored
deployment scratch. Koi was reopened from
`C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe` and reported responding as
PID 49924 at observation time. The installed executable contains the expected
`KoiCardFoil` and `Certmesh` markers and was observed responding after launch.

| Artifact | SHA-256 |
| --- | --- |
| `Koi_0.1.3_x64-setup.exe` | `F21200A91AFC08ABE1D7EB2BDB86326AE81E997A5283862A49F03209CFCDDE39` |
| Installed `koi-desktop.exe` | `89CC36CEBF267FD5A74255F8CE00675FE4B08315353F52C6DABE2BF07B59CF8C` |

These are unsigned local development artifacts. The existing ledger continues
to own candidate selection, physical-client lifecycle, native endpoint actions,
Certmesh state migration and independent operator acceptance.
