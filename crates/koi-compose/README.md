# koi-compose

The composition layer for the [Koi](https://github.com/sylin-org/koi) toolkit: the single
source of truth for constructing domain cores, wiring the cross-domain integration
bridges, running the container-runtime orchestrator, assembling capability status, and
performing ordered shutdown.

The `koi` daemon, the Windows service, and `koi-embedded` all consume it, so daemon
parity across platforms and embedding is true *by construction* rather than maintained by
hand in three diverging places.

This is a **composition crate**, not a domain crate — it depends on every domain it wires.
Nothing else depends on it, so the `koi-common` kernel and the domain crates keep clean
dependency closures.
