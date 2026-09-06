# R06/shared-shell — Home return correction

## Task / exploration / exact write claim

Correct the rejected Windows Advanced → Home transition, then publish an exact
replacement verification request. Starting Koi 9422a0b, desktop bd8121c (product
e010086); both clean. Alpine accepted e010086; Windows rejected and restored it.
Neither result is overwritten or relabeled. CachyOS remains sole source owner.

**Task:** Desktop presentation/native-transport bug fix, no daemon/domain change.

**Files read:**

- Desktop `src/ui.rs`: native protocol admission, URLs and return command.
- Desktop `ui/app.js`: owned listener disposal, Home click and generic tab handler.
- Desktop `ui/index.html`: Home shares tab styling but has no legacy data-view.
- Desktop `ui/app.test.mjs`: existing source tripwires/disposal tests miss native clicks.
- Desktop `ui/dom-stub.mjs`: browser-only startup and empty tab query hide the collision.

Also inspected locked Tauri 2.11.5/runtime-wry 2.11.4/Wry 0.55.1 implementation:
`navigate` dispatches `load_url` directly to WebView2 `Navigate`; unlike initial
custom-protocol setup, that path does not rewrite the scheme. Windows needs the
already-admitted `http://koi-ui.localhost/` origin. Official
[Tauri documentation](https://docs.rs/tauri/2.11.5/tauri/webview/struct.WebviewBuilder.html#method.use_https_scheme)
documents Windows custom-protocol HTTP origins. This is source diagnosis; new
Windows physical success remains pending.

**Reusing:** Existing command, protocol allowlist, main window, listener ownership,
CSS and test harness. Explicit constant/type searches covered binary, common,
client, DNS/Health/Proxy/Certmesh and mDNS `protocol.rs` (not a directory). No
shared/domain/wire type or new dependency is needed. Architecture/context and
R06 contract retain Rust catalog/auth ownership and existing Advanced storage.

**Creating new / claimed source:**

| Code | Exact desktop path | Reason |
|---|---|---|
| Native return URL and admission regression | `src/ui.rs` | Platform origin belongs to existing native adapter |
| Home/tab separation, bounded cleanup and visible failure | `ui/app.js`, `ui/index.html` | Only legacy composition root owns these DOM controls |
| Native startup hook and click/disposal/failure regression | `ui/dom-stub.mjs`, `ui/app.test.mjs` | Exercise actual handlers rather than source-text matches |
| Corrected behavior/build notes | `README.md` | Existing desktop operator/build documentation |
| Exact replacement product archive pin | `packaging/alpine/APKBUILD` | Published recipe must not silently build old assets |

Koi documentation claims: this report, `docs/prompts/delight/{LEDGER.md,CONTRACT.md}`,
`docs/SURFACES.md`, `fleet/cachyos-linux/journal.md`. No peer namespace/source edits,
remote session launch, installed mutation or repeated daemon failure run is claimed.

**Pattern:** Existing `src/ui.rs` platform URL split and `app.js` listener ownership.

**Risks / guardrails:** Preserve the active pane until native navigation; avoid
double submissions, synchronous unlisten exceptions and unbounded cleanup waits.
Retain late-registration cleanup, do not silently abandon subscriptions. Test
browser mode and valid legacy tabs. No mdns-sd imports, duplicate domain types,
centralized constants, protocol schemas or upward dependencies are introduced.

## Planned verification (not results)

First reproduce the Home/tab collision using real registered handlers in the
existing Node VM harness. Add delayed/rejected/throwing cleanup and failed-native
navigation cases. Run desktop locked Rust tests/check/strict Clippy/format and
full Node suite; verify platform URL admission even on Linux. No Koi Rust change
means documentation/surface guards, not a ceremonial whole-workspace rebuild.
Publish exact product and Alpine archive identity. Request native navigation-only
revalidation on affected platforms, Windows also completing its unclaimed tray
menu case. Existing full runs remain evidence for their exact old artifacts.

Status: **in progress**, not R06 acceptance. The active R06 charter explicitly
supersedes the older explore plan-approval pause; user instructed this correction.

## Implementation and results — 2026-09-06 UTC

Status: **correction implemented / native verification pending**. Published desktop
product **d9480158a073586ed7865c711b65954be5c7a9db**, recipe-only follow-up
**d432b9ed207307f1825f0706473eaef4dbeb227b**. Shared renderer/client remain exactly
**b4c32fa9b524549509b34b01bb24cc06455407ad**; Cargo manifests, lockfile, shared
renderer, daemon and native motion code are unchanged.

Before → after:

- Home's second generic `.tab` listener deactivated every legacy `.view`, since
  Home has no `data-view`. Only controls with a real legacy destination now
  register that handler. Current content stays visible during navigation/failure.
- The native command now supplies Windows' registered HTTP protocol origin;
  Linux/macOS retain the original custom scheme. Initial launch remains unchanged.
- Listener disposal shares its completion across Home retries/pagehide, settles
  synchronous throws and rejected releases, and still releases late registrations.
  Home waits at most three seconds for cleanup, suppresses duplicate submissions,
  and shows an alert at the top of the content scroller on failure. A timed-out
  attempt cannot navigate later; after cleanup settles the user can retry. Reopen
  restores live subscriptions if native navigation fails after disposal.
- Native-mode tests derive navigation elements from the actual HTML and install
  the bridge before the actual composition-root handlers register. The former
  browser-only harness did not execute those handlers together.

Verification:

- New tests against the old implementation: **43 pass / 4 fail**. The actual
  handler test reproduced the disappearing Glance pane; other failures covered
  missing visible navigation-error handling, throwing releases and no cleanup bound.
- Final `node --test ui/app.test.mjs`: **47 pass**, including the five new native/
  browser navigation cases and all 42 previous cases.
- Final `KOI_NO_CREDENTIAL_STORE=1 CARGO_BUILD_JOBS=4 cargo test --locked`:
  **26 pass / 1 pre-existing ignored**. The new native URL test checks both Windows
  and non-Windows mappings against the real protocol allowlist even on Linux.
- Locked all-target check, strict all-target Clippy, formatting and whitespace:
  **pass**. Full final tests/Clippy repeated after the shipped HTML/JS settled.
  Logs: `/var/tmp/koi-r06-home-{node-red,node-final,rust-final,check,clippy-final}.log`.
- Alpine recipe is `0.1.3_git20260906-r1`; all **38** files in the downloaded
  product archive match the published d948015 Git tree byte-for-byte. SHA-512
  `2f69c378f7d3c9f2d55b7eb2cfe0292a19c11bdbf78b63a4a5dd49f63481f73491d325760665b30dc29fcd78315bc5ddf916ab7f9398115ca0b3d6aa4795b1b9`.
  `bash -n` and diff guard pass. Archive verification is not an Alpine package run.
- Koi source/hosted run d20c3d4 and later evidence run 9422a0b are complete green
  (all 13 jobs); the former pending hosted gate is reconciled. No Koi production
  source changed in this correction. There is no desktop branch hosted workflow;
  native desktop gates above are local source checks, not a Windows runtime pass.

No installed package, daemon, service, host preference, trust, firewall or peer
was changed during this source correction. Previous installed evidence remains
attached to its exact product: CachyOS/Alpine accepted e010086; Windows rejected
e010086 and restored its prior package. No new native pass is implied.

## Bounded replacement native requests

New requests **R06/windows-home-return-v2** and **R06/alpine-home-return-v2** are
ready for their addressed operators through `run fleet/task.md`. The old requests
stay terminal. Each new request expires **2026-09-08 05:00 UTC** or on an affected
product change. Before mutation, acknowledge with fresh run ID, exact current
installed baseline, prior package and independently verified rollback guard.
Do not reuse a historical checkpoint's baseline. No remote launch or source edits.

Exact product: desktop **d9480158a073586ed7865c711b65954be5c7a9db**; shared/client
**b4c32fa9b524549509b34b01bb24cc06455407ad**. Alpine uses APKBUILD from desktop
**d432b9ed207307f1825f0706473eaef4dbeb227b**, pinned to that product. Instruction
branch is current Koi dev; it does not silently replace these product revisions.

1. Inspect/preserve local work, verify exact sources and run locked desktop Rust
   tests, strict all-target Clippy, format and all **47** Node tests with
   `KOI_NO_CREDENTIAL_STORE=1`. No shared-crate rebuild or daemon replacement is
   needed: neither changed. No heavy work goes to Debian.
2. Build/install the exact ordinary package: Windows
   `cargo tauri build --bundles nsis --ci -- --locked` then normal-user NSIS;
   Alpine detached native `abuild` with the published recipe. Preserve installed
   identity, data and exact prior package. On Alpine keep system keyring trust
   available alongside any run-only signing key; do not repeat the prior narrow
   keys-directory invocation that temporarily removed keyring dependencies.
3. Normal installed launch from outside the checkout, one workbench and unchanged
   healthy daemon. At 320px use actual keyboard and pointer/native accessibility
   controls for **Shared Home → Advanced → Home**, at least three round trips in
   the same PID. Each Home must display the real Rust snapshot/card, not a blank
   legacy pane or reopen workaround. Check ordinary legacy tab switching too.
4. Exercise Home immediately after Advanced loads, then once after it settles;
   check that only one navigation occurs on repeated activation and no visible
   error/blank pane or accumulating stale-event warnings appear. Use real input;
   no JavaScript navigation injection or diagnostic webview instrumentation.
   Record observed URLs if already exposed by normal platform diagnostics, but
   never broaden permissions just to inspect them. Manual Refresh must work after
   return. Source tests cover injected timeout/rejection branches, not native proof.
5. Windows additionally completes the formerly unclaimed **actual tray-menu Open
   Workbench** route: close to tray, invoke the real menu, verify the same process
   returns; a second normal invocation must still leave one workbench. Alpine
   checks normal close/menu/singleton after the changed navigation as well.
6. No daemon stop/recovery, motion-toggle, firewall or external-network experiment
   is requested again: those untouched paths have earlier exact-artifact evidence.
   The new result is targeted change validation, not a replay of the full original
   native matrix or final R29 candidate acceptance. Restore temporary helpers,
   preferences and startup shape; accept only after one healthy daemon/workbench
   and unchanged identity/configuration are verified. If any required case fails,
   restore the exact prior desktop and report the defect to CachyOS.
7. Publish hashes/PIDs/captures, test results, case verdicts and exact restoration
   only in the host's journal/request row. Release on result/restoration or expiry.
   Do not fix source/recipes, clean unknown ignored data or relabel prior captures.

Next: reconcile the two new exact native results. R06/R07/R11 remain gated;
physical macOS remains unverified. CachyOS owns any further source correction.
