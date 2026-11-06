# U07 single-interface implementation receipt

Task: [U07 in Epic 004](../../fleet/epics/004-container-lan-adoption.md#u07--consolidate-and-retire-the-separate-interfaces).
Decision: [ADR-047](../adr/047-one-interface-built-in-presenter.md).
Owner: coordinating agent. Date: 2026-09-13.

Source bases are Koi `791f87ebe0a8ba93246f60ce0b283c13fb86595b`
and koi-desktop `d432b9ed207307f1825f0706473eaef4dbeb227b`,
each plus the preserved working tree described here. This is a local development
deployment receipt, not a published release or independent U06 usability result.

## Delivered result

- `koi-ui` owns Services, mDNS, Certmesh, Settings and About, in that order. It owns
  their markup, dense service rows, details pane, operational forms, visual
  system, foil card and interaction behavior.
- The authenticated browser and native Tauri adapters supply current product
  status and bounded effects to that renderer. Certmesh reads the current typed
  role/identity/authority model. Settings contains preferences, DNS, Pond and
  native service/autostart controls. Endpoint Open/Copy uses the same eligibility
  and URL-validation boundary.
- The old dashboard and mDNS browser HTML, the desktop's old eight-screen
  application, duplicate CSS/JS/card assets and the Home/Advanced bridge are
  deleted. `/` and `/mdns-browser` lead to the canonical destinations.
- Pond renders the built-in shared interface. Its public projection includes
  mDNS-derived services and coarse capability health only. Preferences, local
  candidates, checks, operations, Certmesh state and host integration do not
  enter the public document.
- The `/v1/ui` upload/clear contract, retained generation routes, desktop
  publisher, client method, repository module, startup migration and UI event
  variants are deleted. The generated `C:\ProgramData\Koi\ui` cache from the
  preceding local build was removed with an elevated, root-checked PowerShell
  operation. Pond was temporarily enabled for the installed review and then
  restored to its preceding disabled intent.

Preferences, configuration, Certmesh identity/roster/audit material and the
Pond intent file were not deleted or rewritten by this cleanup.

## Verification

| Boundary | Result |
| --- | --- |
| Shared Rust renderer | 7 unit and 14 render tests passed. The offline Chromium run rendered 36 entries as 49px desktop rows, 11 complete rows at 1280×800, 44px controls and no page-wide overflow at 390px or 320px. |
| Browser interaction | 26 authenticated transport tests and the shared foil test passed. They cover token confinement, bounded navigation, Open/Copy, preferences, focus, responsive details, recovery and session clearing. |
| Serving and Pond | Full `koi-serve` suite: 144 passed, 1 explicit live-Windows-firewall probe ignored. The route, authentication, shared Pond root and public-status redaction checks passed. |
| Observation adapters | `koi-dashboard`: 33 unit plus 1 hostile-JSON test passed. The crate contains no HTML product assets. |
| Native host | koi-desktop: 22 passed, 1 explicit live cross-host probe ignored. Shared protocol admission, unavailable state, URL opening, preferences and host lifecycle guards passed. |
| Formatting | `cargo fmt --all --check` passed in both repositories after the final source change. |

The deployed Pond view was opened from the real daemon in the in-app browser.
It showed 22 current mDNS services in the shared dense table, the four canonical
destinations, About last, the single About card/facts/documentation layout,
read-only LAN wording in Settings and “Operator access required” for redacted
Certmesh state. No old header, Advanced link or alternate application appeared.

## Installed Windows identities

| Artifact or process | Evidence |
| --- | --- |
| Daemon release binary | `C8350D0403659DF94E48B96992E5DA79760F6286FB17C59DF3135DE3F2D12A0D` SHA-256; source and `C:\Program Files\Koi\koi.exe` hashes match. |
| Windows service | SCM state `Running`, PID `34648` at receipt time; `/healthz` returned 200. |
| Canonical routes | `/` → 307 `/ui`; `/mdns-browser` → 307 `/ui?tab=services`; retired `/v1/ui` → 404. |
| Pond | Installed review passed while `running` on public port 5644 with firewall state `open`; it was then restored to `disabled`. UI revision remains `shared-renderer`. |
| Desktop installer | `Koi_0.1.3_x64-setup.exe`, 3,517,897 bytes, SHA-256 `0203975B4DBBA5D326A341C5C0A87A4B0EBFC6B4A1DBF8249F3EB99C694E2F49`. |
| Installed desktop | `C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe`, version `0.1.3`, 14,390,784 bytes, SHA-256 `FEB218366F3F769EF589A43E6C62E4B10E656AB1EB9DE44E9900B20BF0BF37CA`; launched as PID `33276` at receipt time. |

The single-presentation architecture and local deployment above are recorded.
The owner's subsequent [retained-task audit](retained-task-audit.md) found that
the promised mDNS inspection/query workflow had not reached the shared UI and
that opening the shell did not arm browse-all demand. The earlier completion
claim therefore does not establish complete retained-capability acceptance.
The ledger tracks the owner-directed correction while preserving ADR-047.
U06 still owns independent operator observation, destructive Certmesh trials
on disposable identities, broader accessibility review and candidate acceptance.
