//! Koi composition layer — the single place that constructs domain cores, installs the
//! cross-domain integration bridges, runs the container orchestrator, assembles
//! capability status, and tears everything down in order.
//!
//! Three consumers share it: the `koi` daemon (`daemon_mode`), the Windows service
//! (`run_service`), and `koi-embedded`. Building the composition once makes Windows and
//! embedded parity true *by construction* — the verified `koi install` defect (a weaker
//! Windows daemon missing the orchestrator + certmesh background loops) cannot recur,
//! because all three call the same code.
//!
//! This is a **composition crate**, not a domain crate: it depends on every domain it
//! wires. Nothing depends on it except the top-level consumers, so the `koi-common`
//! kernel and the domain crates keep clean dependency closures.

// Modules are filled in across the P07 checkpoint steps:
//   bridges     — the integration-trait bridges (moved from the binary's integrations.rs)
//   orchestrator— the container-runtime orchestrator (moved from the binary)
//   status      — assemble_capabilities (the single capability-status source)
//   cores       — init_cores + ordered_shutdown
