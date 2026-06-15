//! RFC 8555 ACME server (dns-01 only, EC/ES256 only) — a facade over the
//! certmesh CA that lets any standard ACME client (Caddy, Traefik, lego, certbot)
//! obtain certificates for names inside the Koi DNS zone with zero Koi knowledge.
//!
//! See `docs/guides/acme.md` and `docs/prompts/plans/P12-plan.md` for the full
//! design. This module is mounted by the binary's dedicated server-auth TLS
//! listener under `/acme`.
//!
//! Module map:
//! - [`problem`] — the `application/problem+json` responder (NOT the flat certmesh shape).
//! - [`nonce`] — the replay-nonce store (RFC 8555 §6.5).
//! - [`jws`] — assembled ES256 JWS verification + RFC 7638 thumbprints.
//! - [`account`] — account registration + JSON persistence.
//! - [`order`] — order/authorization state, finalize, certificate, revoke.
//! - [`challenge`] — dns-01 challenge: write TXT → validate in-process → clear.

pub mod account;
pub mod challenge;
pub mod jws;
pub mod nonce;
pub mod order;
pub mod problem;

mod state;

pub use state::{AcmeState, AcmeStateConfig};

mod router;
pub use router::routes;
