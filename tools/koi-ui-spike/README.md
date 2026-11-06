# UI helper compatibility

Production shared rendering lives in [koi-ui](../../crates/koi-ui/README.md); its operator browser adapter is in `crates/koi-serve/src/ui.rs`. This directory is not a selectable production renderer or installation path.

Helpers retained under `native` contain fixture-specific paths, artifact identities and recovery assumptions. They must not run against a new installation without source-level baseline verification and a compatible recovery contract. See [native helper boundaries](native/README.md).

Use [current native verification helpers](../koi-ui-native/README.md), the [fleet contract](../../fleet/CONTRACT.md) and the [launch gate](../../docs/launch/README.md) to select present acceptance work. Comparison captures or helper exit codes do not certify a current package or the application-reachability journey.
