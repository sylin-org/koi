# Native integration and development deployment

[U02-shared-view-intent.patch](patches/U02-shared-view-intent.patch) adds shared Rust view-state parsing and rendering to the native protocol adapter. It permits bounded query navigation and same-origin GET forms, retains the existing window/origin/method guards, and adds adapter tests. It introduces no native JavaScript or service opener.

[U03-native-typed-open.patch](patches/U03-native-typed-open.patch) replaces the
desktop's prefix-only, `cmd /C start` Windows opener. It calls Koi's shared strict
HTTP(S) validator, then dispatches the canonical URL through `ShellExecuteW` as a
UTF-16 value. Linux and macOS retain direct argument-based process launch. The
validation rejects credentials, port zero, malformed authority, leading/trailing
whitespace, control characters and non-HTTP schemes before platform dispatch.

U02 deliberately passes `EndpointActions::None`. U03 makes the existing desktop
command safe enough to serve as a future bridge, but does not yet expose Open in
the shared native pane. Keep the pane action-free until that typed bridge and its
installed behavior are verified.

| Input | Revision / requirement |
| --- | --- |
| Desktop patch base | `sylin-org/koi-desktop` at `d432b9ed207307f1825f0706473eaef4dbeb227b` |
| Desktop's existing `koi-client` / `koi-ui` pin | `b4c32fa9b524549509b34b01bb24cc06455407ad` |
| Paired Koi source | `791f87ebe0a8ba93246f60ce0b283c13fb86595b` **plus the U02 working-tree changes** exporting `UiState`, `render_with_state`, and the shared form CSP |
| Release status | Unsigned development NSIS installed; production pin, candidate and usability acceptance pending |

The existing desktop dependency pin lacks the new API. For reproduction from the
recorded base, first use an isolated desktop worktree/copy paired with the updated
Koi source. Adjust these example paths as needed:

```powershell
git apply --check E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U02-shared-view-intent.patch
git apply E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U02-shared-view-intent.patch
git apply --check E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U03-native-typed-open.patch
git apply E:/repo/github/sylin-org/koi/tools/koi-ui-native/patches/U03-native-typed-open.patch
cargo test ui::tests --config 'patch."https://github.com/sylin-org/koi".koi-client.path="E:/repo/github/sylin-org/koi/crates/koi-client"' --config 'patch."https://github.com/sylin-org/koi".koi-ui.path="E:/repo/github/sylin-org/koi/crates/koi-ui"'
```

The local source overrides may update that copy's `Cargo.lock`; they do not update the production dependency pin. Before merging native integration, select the new Koi revision, regenerate and verify the desktop lockfile, run the native tests/build, and complete the native acceptance checks in [U06](../../docs/ux/README.md).

Validation recorded for these patches: each patch and the pair pass `git apply
--check` against the desktop base. On Windows, an isolated paired-source worktree
passed all 25 desktop tests with one existing cross-host test ignored, plus strict
Clippy and formatting. The test build resolved the pinned registry dependencies;
its transient lockfile is not part of either patch. On 2026-09-13 the patches
were then applied to the sibling checkout, its Koi dependencies were pointed at
the adjacent current source, and an unsigned NSIS package was built with
`npx @tauri-apps/cli@2.11.4 build --bundles nsis`. That package was installed and
launched against the real installed development daemon. The checkout and
lockfile are now modified. This is not a selected release candidate or physical
Open receipt; the shared pane remains action-free.
