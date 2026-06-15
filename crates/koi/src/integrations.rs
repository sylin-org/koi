//! Cross-domain integration bridges.
//!
//! The implementations moved to `koi_compose::bridges` (P07) so the daemon, the Windows
//! service, and koi-embedded share one copy. Re-exported here so the binary's existing
//! `integrations::*` call sites are unchanged.

pub use koi_compose::bridges::*;
