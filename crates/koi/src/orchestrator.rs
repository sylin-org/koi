//! Runtime lifecycle orchestrator.
//!
//! The implementation moved to `koi_compose::orchestrator` (P07) so the daemon, the Windows
//! service, and koi-embedded share one copy. Re-exported here so the binary's existing
//! `orchestrator::*` call sites are unchanged.

pub use koi_compose::orchestrator::*;
