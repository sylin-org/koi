# Retired R06 renderer comparison

The Maud and Dioxus experiments are retired. Production rendering lives in
`crates/koi-ui`; native intake is `koi-desktop/src/ui.rs`, and authenticated
headless serving is `crates/koi-serve/src/ui.rs`. There is no renderer-selection
feature, alternate production runtime or desktop probe flag.

Historical comparison sources/lockfiles remain reproducible at Koi `72cb286`
and desktop `ccee0fc`; see ADR-045 and the immutable R06 renderer-decision report.
The `native/` helpers are historical procedures tied to their original exact
artifacts and rollback hashes. **Do not execute them against a new installation.**
Current own-host helper instructions are in `tools/koi-ui-native/README.md`.

Ignored `target/` captures, binaries and recovery evidence were deliberately
preserved. Retirement removed only tracked experiment sources/assets, recoverable
from Git. Replacement checks are documented in `crates/koi-ui/README.md` and the
R06/shared-shell report. Old experiment acceptance is not new-package acceptance.
