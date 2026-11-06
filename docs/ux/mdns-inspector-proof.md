# mDNS inspector restoration and adversarial evaluation

Owner-directed correction, 2026-09-13. Source bases: Koi
`791f87ebe0a8ba93246f60ce0b283c13fb86595b` and koi-desktop
`d432b9ed207307f1825f0706473eaef4dbeb227b`, plus their preserved working trees.
The [ledger](../../fleet/launch/LEDGER.md) owns execution and acceptance status.
This is local development evidence, not a published release or independent U06
operator trial.

## Restored task

The shared navigation contains distinct Services and mDNS destinations. Services
owns the normalized catalog; mDNS owns technical inspection and active queries.
The inspector activates the existing lazy browse-all worker, shows reported
types (including zero-instance types), resolved and unresolved instances,
host/address/port, full TXT and source-specific evidence. Local filters search
all displayed source records, including provider disagreements. Browser
projection times and recent removals are labeled separately from packet time
or service health.

The authenticated browser and native adapter share bounded type-browse,
full-instance resolution and browse-all restart operations. Feedback distinguishes
started, answers, no answer and errors, includes observation time/query scope,
and discloses result limits. Inputs, expanded details, query results, keyboard
focus and scroll survive automatic refresh. Logout discards late query results.

Unresolved observations belong to the mDNS domain. They appear as
`MdnsDiscoveryValue::UnresolvedInstance`, while the compatibility `records`
projection and resolution cache remain resolved-only. A subsequent Found event
cannot downgrade an already resolved record; source replacement and withdrawals
retire the corresponding evidence. The catalog's existing semantics are retained.

The operator state endpoint now requires DAT. Main-adapter mDNS browser reads
also require DAT; the separate Pond router retains an explicit public allowlist,
omitting operator provenance, query results and newly added unresolved evidence.
Pond enablement is preserved.

## Independent review and corrections

Three implementation agents owned backend/browser, shared UI and native
integration. A separate read-only reviewer challenged the implementation and
reproduced interaction failures in isolated Chromium; the coordinator integrated
the corrections and performed delivery checks.

| Finding | Correction and evidence |
| --- | --- |
| Live unresolved instances were omitted even though a hand-built UI fixture could show them | Domain-owned unresolved observations and lifecycle/replay/resolve regression cases; the UI fixture now uses the real observation variant. |
| Differently cased withdrawals could leave query answers behind | DNS identity comparison is ASCII-insensitive; regression covers the mixed-case goodbye. |
| An empty replacement generation could retain earlier query answers | Final reconciliation treats the authoritative empty snapshot as empty; generation replacement regression added. |
| Query result insertion could erase the inventory | Corrected the malformed result container; actual browser interaction checks preserve rows after submission. |
| Refresh lost summary/button focus or restored a stale input caret | Stable shared focus identities and sampling of current focus at replacement; the independent reviewer reproduced the fixes through both adapters. |
| Filtering missed an alternate provider's displayed address/TXT | Search includes every associated source record; independent rebuilt-renderer checks returned the expected row for both alternate IP and TXT. |
| Result limits were undisclosed and malformed decimal escapes became no-answer results | Explicit capped/early-stop wording and validated three-digit DNS escapes, with boundary regressions. |
| Operator state was not covered by the DAT read guard | Exact route classification plus unauthenticated/authorized route tests. |

The broader test run also exposed an earlier consolidation mismatch: `koi-ui`
already imported immutable Certmesh/DNS status types, while its dependency guard
permitted only `koi-common`. The rule is now deliberately narrow: Presentation
may depend on those two crates only through the five named status types used by
the shared renderer. A companion source guard rejects cores, commands, modules,
wildcards and aliases. The independent reviewer checked this against ADR-044/047.
This is a documented rule reconciliation, not permission for UI runtime ownership;
the lexical guard is not a security sandbox and does not reduce the compiled
domain dependency closure.

The independent reviewer reported no remaining blocker in the inspected DAT,
Pond, native dispatch, cancellation or interaction paths after the corrections.
Final verification and delivered artifact identities are recorded separately
below.

## Final source and browser checks

`cargo test -p koi-common -p koi-mdns -p koi-dashboard -p koi-serve -p koi-ui`
passed **526 tests**, with six explicit exclusions: four real native mDNS/peer
environment cases, one live Windows Firewall enumeration and one documentation
example. The total includes 18 architecture guards and the new domain,
query-generation, cancellation and UI regression cases. `cargo check --workspace`
passed.

The paired desktop `cargo test` passed **25 tests**, with one explicit
environment exclusion. Both repositories passed `cargo fmt --all --check`.

The final shared foil, browser transport and native JavaScript bridge run passed
**34 tests**. Chromium task checks passed at 1280×800, 390px and 320px; Catalog
retained ten complete 49px rows, and mDNS records, expanded evidence and query
results reflowed without page-wide horizontal overflow. The coordinator inspected
the generated screenshots. The independent reviewer additionally used deferred
responses and the actual DOM to verify the focus and source-filter fixes.

Local fixture images are under `target/mdns-inspector-fixture-*`; their invented
data is visibly labeled. They are not evidence of live provider answers.

## First-class navigation amendment

Owner-directed refinement, 2026-09-13: mDNS moved from a Services subview to a
first-class destination. The shared order is now **Services → mDNS → Certmesh →
Settings → About**. `UiState` owns `Destination::Mdns`; newly rendered links use
`tab=mdns`, while bookmarked `tab=services&services_view=mdns` links parse and
canonicalize to the new route. Services now presents only the normalized catalog.
The same mDNS projection, lazy demand, query transport and polling lifecycle are
retained.

Focused Koi UI/serve tests passed: 179 tests with one live-firewall exclusion.
The paired native suite passed 25 tests with one cross-host exclusion, and all
34 shared/native JavaScript tests passed. Workspace and native checks and format
checks passed. The rendered five-item navigation preserved its order, one active
destination, 44px targets and no horizontal overflow at 1280px, 390px and 320px.

## Installed development evaluation

Both Windows installers exited successfully on 2026-09-13. The daemon was
updated through elevated `koi install`; SCM reported it running as PID 50980,
and `/healthz` returned 200. Its version is `1.0.0-dev.0`. The desktop was
packaged with `npx --yes @tauri-apps/cli@2.11.4 build --bundles nsis` and installed
silently. No subsequent native launch or WebView2 walkthrough is claimed.

| Artifact | SHA-256 |
| --- | --- |
| Release and installed `C:\Program Files\Koi\koi.exe` (matching) | `A5742E7847BE93EC7851FB521B7EFCC09F60DC9FCDC395D76DF0FECCD44CFFC1` |
| `Koi_0.1.3_x64-setup.exe` | `6B8A5B79C2F7C7442819AE9B7041389ECBC6ABFDB100CC0A0C1D9D33D45C7128` |
| Installed `C:\Users\Leo\AppData\Local\Koi\koi-desktop.exe` | `A01B72C8AF741C3E21F71A5E78164D3A3FFFF6ED43C13C7F2F7D4BF0374DB870` |
| Unbundled desktop release executable | `0AEC34698AAF17DCE2782909C2CEB9531EC7BB5907D610D152DA456D7A0B9C92` |

The installed and unbundled desktop executables have the same 14,774,272-byte
length and differ only at the three-byte bundle marker (`UNK` → `NSS`); the
Tauri build log records patching bundle type information for NSIS.

The live acceptance run began at `2026-09-13T16:11:36Z`, using the local pipe
access contract and keeping DAT in memory. It observed 20 reported types,
24 current instances, 24 authoritative resolved records and 21 provider/query
sources; two types had no instances. Opening mDNS activated browse demand.
Restart returned `started`, a known type browse returned one record, full
instance resolution returned one record, and an absent type returned
`no_answer` with zero records. The first harness attempt incorrectly submitted
a short instance label for resolution; correcting it to the required full name
produced the passing run. No production change was needed for that correction.

Anonymous operator state, mDNS shell and browser snapshot reads returned 401;
malformed query input returned 400. The normal Catalog projection omitted mDNS
inspection state. Pond desired/running remained false, and the final read
confirmed its desired state was unchanged. Rendered HTML contained the
inspector/query controls and no DAT. Identity, roster and preferences were not
changed for this evaluation.

Actual HTML fetched from the installed daemon was rendered in an isolated,
offline Chromium process at 1280×800, 390px and 320px. All 24 rows were present,
with nine complete rows visible at desktop size and no page-wide horizontal
overflow at any width. Expanded query/evidence and desktop/narrow screenshots
were inspected. This establishes the installed renderer's layout; it is not an
interactive installed browser session or an installed native walkthrough.

Local receipts: `local/mdns-acceptance-receipt.json`,
`target/koi-installed-mdns-layout.json`, and
`target/koi-installed-mdns-{1280,390,320,details}.png`. These ignored artifacts
contain local development evidence; the screenshots may show LAN names.

## Limits

- The mDNS provider projection retains one selected address per record. The
  inspector exposes the domain's records and source disagreements; it is not
  packet capture or complete native-provider/interface inspection.
- The owner stopped Computer Use with Escape. Further desktop control stopped.
  Isolated Chromium evidence and installed HTTP evidence must not be presented
  as a completed native WebView2 walkthrough.
- [Other retained-task gaps](retained-task-audit.md) remain separate. This slice
  does not complete comparison, recent activity, temporary TXT controls or U06's
  independent operator evidence.
