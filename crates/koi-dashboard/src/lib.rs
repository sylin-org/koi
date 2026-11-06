//! Koi observation adapters for snapshot/event feeds and mDNS browsing.
//!
//! Human-facing HTML lives in `koi-ui`. This crate owns retained snapshot/SSE
//! endpoints, the unified domain-event forwarder, the mDNS browse adapter, and
//! the lazy LAN-wide meta-browse worker.
//!
//! It is a **composition crate**: it depends on the event-bearing domain crates so
//! that a single forwarder and a single browse adapter can live here instead of being
//! duplicated across the binary and `koi-embedded`. No domain crate depends on
//! `koi-dashboard`, so the `koi-common` kernel and every domain crate keep clean
//! dependency closures.

pub mod browse_source;
pub mod browser;
pub mod dashboard;
pub mod forward;
pub mod meta_browse;
mod well_known;

pub use dashboard::{DashboardSseEvent, KoiEventWire};
