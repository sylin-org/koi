//! Cross-domain event wiring (Phase 1+).
//!
//! This module will subscribe to domain event channels and wire them
//! together. For example, when certmesh generates a new certificate,
//! the proxy domain might need to reload its TLS configuration.
//!
//! Currently empty — the only domain is mDNS, which operates independently.
