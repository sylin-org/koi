//! Koi presentation layer — dashboard and mDNS network browser.
//!
//! This crate owns the two single-file HTML surfaces (served verbatim), their
//! snapshot/SSE endpoints, the unified domain-event forwarder, the mDNS browse
//! adapter, and the lazy LAN-wide meta-browse worker.
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

pub use dashboard::{DashboardSseEvent, KoiEventWire};

/// Content-Security-Policy for the served HTML pages. The pages are single-file with
/// one inline `<script>` and inline styles, and use `data:` SVG backgrounds. Confining
/// everything to `'self'` (plus inline script/style and `data:` images) means a future
/// XSS regression can neither exfiltrate to a third-party origin nor execute a
/// `javascript:`/remote-script payload — defense-in-depth behind the structural fix.
pub(crate) const HTML_CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; \
     style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";
