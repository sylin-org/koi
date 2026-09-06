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
already-admitted `http://koi-ui.localhost/` origin. Official [Tauri documentation]
(https://docs.rs/tauri/2.11.5/tauri/webview/struct.WebviewBuilder.html#method.use_https_scheme)
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
