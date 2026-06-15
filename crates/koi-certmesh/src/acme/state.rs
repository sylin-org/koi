//! ACME server state: the wiring between the RFC 8555 endpoints and the certmesh
//! CA, plus the account/nonce/order stores and the dns-01 solver.
//!
//! `AcmeState` is constructed in the composition layer (the binary) from a
//! `CertmeshCore`'s shared state, the Koi DNS zone, and the
//! [`AcmeDnsSolver`](koi_common::integration::AcmeDnsSolver) bridge. It is then
//! handed to [`crate::acme::routes`] and mounted under `/acme` on the dedicated
//! server-auth TLS listener.

use std::sync::Arc;

use chrono::Utc;
use koi_common::integration::AcmeDnsSolver;

use crate::acme::account::AccountStore;
use crate::acme::challenge;
use crate::acme::nonce::NonceStore;
use crate::acme::order::OrderStore;
use crate::error::CertmeshError;
use crate::roster::{MemberRole, MemberStatus, RosterMember};
use crate::CertmeshState;

/// Default leaf validity (days) for ACME-issued certificates. Matches the
/// 30-day member-cert convention used elsewhere in certmesh.
pub const ACME_CERT_VALIDITY_DAYS: u32 = 30;

/// Construction parameters for [`AcmeState`].
pub struct AcmeStateConfig {
    /// The base URL clients use to reach this ACME server, e.g.
    /// `https://daemon.lan:5643`. Endpoint URLs in the directory and account/
    /// order objects are built relative to this.
    pub base_url: String,
    /// The Koi DNS zone (e.g. `lan`). The CA issues ONLY for in-zone names.
    pub zone: String,
    /// The in-process dns-01 solver (writes/reads `_acme-challenge.*` TXT).
    pub dns: Arc<dyn AcmeDnsSolver>,
}

/// The ACME server's shared state.
pub struct AcmeState {
    /// The certmesh shared state — for CA access (signing) and roster updates.
    certmesh: Arc<CertmeshState>,
    /// Base URL for building absolute endpoint/resource URLs.
    base_url: String,
    /// The issuance zone.
    zone: String,
    /// dns-01 solver bridge.
    dns: Arc<dyn AcmeDnsSolver>,
    /// Persisted account registry.
    accounts: AccountStore,
    /// In-memory replay-nonce store.
    nonces: NonceStore,
    /// In-memory order/authz/cert store.
    orders: OrderStore,
}

impl AcmeState {
    /// Build the ACME state from certmesh's shared state and the ACME config.
    pub(crate) fn new(certmesh: Arc<CertmeshState>, cfg: AcmeStateConfig) -> Arc<Self> {
        let accounts = AccountStore::load(&certmesh.paths.acme_accounts_path());
        Arc::new(Self {
            certmesh,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            zone: cfg.zone,
            dns: cfg.dns,
            accounts,
            nonces: NonceStore::new(),
            orders: OrderStore::new(),
        })
    }

    // ── Accessors ────────────────────────────────────────────────────

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn accounts(&self) -> &AccountStore {
        &self.accounts
    }

    pub fn nonces(&self) -> &NonceStore {
        &self.nonces
    }

    pub fn orders(&self) -> &OrderStore {
        &self.orders
    }

    pub fn dns(&self) -> &Arc<dyn AcmeDnsSolver> {
        &self.dns
    }

    /// Build an absolute URL from a path under the ACME base.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Whether the mesh is in open enrollment (free newAccount) or closed
    /// (newAccount requires EAB). Read from the roster's posture boolean.
    pub async fn enrollment_open(&self) -> bool {
        self.certmesh.roster.lock().await.metadata.enrollment_open
    }

    /// Whether an identifier is issuable (in-zone). The wildcard `*.<zone>` is
    /// allowed; out-of-zone names are not.
    pub fn is_issuable(&self, identifier: &str) -> bool {
        challenge::is_in_zone(identifier, &self.zone)
    }

    // ── Issuance ─────────────────────────────────────────────────────

    /// Sign a finalize CSR for an order, enforcing the SAN-authorization gate,
    /// and record the issued cert in the roster as an `acme`-sourced member.
    ///
    /// `authorized_names` is the order's identifier set (the allow-list).
    /// `csr_der` is the raw DER CSR from the finalize body.
    ///
    /// Returns the full chain PEM (leaf + CA). Errors map to ACME problems by
    /// the caller. THIS is the issuance enforcement point — the underlying
    /// [`crate::sign_csr`] further guarantees the issued cert carries only
    /// `authorized_names`, never the CSR's embedded SANs.
    pub async fn sign_finalize_csr(
        &self,
        account_id: &str,
        authorized_names: &[String],
        csr_der: &[u8],
    ) -> Result<String, CertmeshError> {
        // Parse the CSR (DER → PEM, then sign_csr verifies the self-signature).
        let csr_pem = der_to_csr_pem(csr_der);

        // SECURITY: enforce that every SAN requested in the CSR is one of the
        // order's authorized identifiers. sign_csr already discards CSR SANs and
        // substitutes the authorized set, but we ALSO reject up-front so a CSR
        // that asks for an unproven name fails loudly rather than silently
        // getting a cert for different names.
        let csr_sans = csr_requested_sans(&csr_pem)?;
        for san in &csr_sans {
            if !authorized_names.iter().any(|n| names_match(n, san)) {
                return Err(CertmeshError::InvalidPayload(format!(
                    "CSR requests unauthorized identifier '{san}' not in the order"
                )));
            }
        }

        // Acquire the CA and sign. The issued cert carries exactly the
        // authorized names (sign_csr substitutes them).
        let ca_guard = self.certmesh.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.certmesh.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;
        let leaf_pem = crate::sign_csr(ca, &csr_pem, authorized_names, ACME_CERT_VALIDITY_DAYS)?;
        let chain_pem = format!("{leaf_pem}{}", ca.cert_pem);
        let fingerprint = {
            let parsed =
                pem::parse(&leaf_pem).map_err(|e| CertmeshError::Certificate(e.to_string()))?;
            koi_crypto::pinning::fingerprint_sha256(parsed.contents())
        };
        let expires = Utc::now() + chrono::Duration::days(i64::from(ACME_CERT_VALIDITY_DAYS));
        drop(ca_guard);

        // Record in the roster as an acme-sourced member so `koi certmesh status`
        // and renewals-due account for it. The hostname is the first authorized
        // name (the cert's primary identity).
        self.record_acme_member(account_id, authorized_names, &fingerprint, expires)
            .await;

        Ok(chain_pem)
    }

    /// Record (or update) a roster entry for an ACME-issued certificate.
    async fn record_acme_member(
        &self,
        account_id: &str,
        names: &[String],
        fingerprint: &str,
        expires: chrono::DateTime<Utc>,
    ) {
        let Some(primary) = names.first() else {
            return;
        };
        let mut roster = self.certmesh.roster.lock().await;
        if let Some(existing) = roster.find_member_mut(primary) {
            // Update the existing acme member (renewal).
            existing.cert_fingerprint = fingerprint.to_string();
            existing.cert_expires = expires;
            existing.cert_sans = names.to_vec();
            existing.last_seen = Some(Utc::now());
            existing.status = MemberStatus::Active;
        } else {
            roster.members.push(RosterMember {
                hostname: primary.clone(),
                role: MemberRole::Client,
                enrolled_at: Utc::now(),
                enrolled_by: Some(format!("acme:{account_id}")),
                cert_fingerprint: fingerprint.to_string(),
                cert_expires: expires,
                cert_sans: names.to_vec(),
                // ACME clients hold their own key; certmesh does not store the
                // cert on disk. An empty cert_path marks an external holder.
                cert_path: String::new(),
                status: MemberStatus::Active,
                reload_hook: None,
                last_seen: Some(Utc::now()),
                pinned_ca_fingerprint: None,
                proxy_entries: Vec::new(),
            });
        }
        let roster_clone = roster.clone();
        let roster_path = self.certmesh.paths.roster_path();
        drop(roster);
        if let Err(e) = crate::roster::persist_roster(&roster_clone, &roster_path).await {
            tracing::warn!(error = %e, "Failed to persist roster after ACME issuance");
        }
    }

    /// Revoke an ACME-issued certificate by its leaf fingerprint, reflecting the
    /// revocation in the roster. Returns whether a member was revoked.
    pub async fn revoke_by_fingerprint(&self, fingerprint: &str) -> bool {
        let mut roster = self.certmesh.roster.lock().await;
        let hostname = roster
            .members
            .iter()
            .find(|m| m.cert_fingerprint == fingerprint && m.status == MemberStatus::Active)
            .map(|m| m.hostname.clone());
        let Some(hostname) = hostname else {
            return false;
        };
        let _ = roster.revoke_member(&hostname, Some("acme".into()), Some("revokeCert".into()));
        let roster_clone = roster.clone();
        let roster_path = self.certmesh.paths.roster_path();
        drop(roster);
        if let Err(e) = crate::roster::persist_roster(&roster_clone, &roster_path).await {
            tracing::warn!(error = %e, "Failed to persist roster after ACME revoke");
        }
        true
    }

    /// The CA certificate PEM, for the certificate chain and bootstrap.
    pub async fn ca_pem(&self) -> Option<String> {
        self.certmesh
            .ca
            .lock()
            .await
            .as_ref()
            .map(|ca| ca.cert_pem.clone())
    }

    /// Whether the CA is available (initialized + unlocked) to issue.
    pub async fn ca_ready(&self) -> Result<(), CertmeshError> {
        let guard = self.certmesh.ca.lock().await;
        if guard.is_some() {
            Ok(())
        } else if self.certmesh.paths.is_ca_initialized() {
            Err(CertmeshError::CaLocked)
        } else {
            Err(CertmeshError::CaNotInitialized)
        }
    }
}

/// Wrap raw DER CSR bytes as a PEM `CERTIFICATE REQUEST`.
fn der_to_csr_pem(csr_der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der.to_vec()))
}

/// Extract the requested SAN DNS names (+ CN) from a CSR PEM, for the
/// authorization check. Uses x509-parser via rcgen's parse (the same crate the
/// CSR is signed with). Returns the lowercased names.
fn csr_requested_sans(csr_pem: &str) -> Result<Vec<String>, CertmeshError> {
    use x509_parser::prelude::*;

    // Fully-qualify `::pem` — `x509_parser::prelude::*` brings its own `pem` module
    // into scope and would otherwise shadow the `pem` crate.
    let parsed_pem =
        ::pem::parse(csr_pem).map_err(|e| CertmeshError::InvalidPayload(e.to_string()))?;
    let (_, csr) = X509CertificationRequest::from_der(parsed_pem.contents())
        .map_err(|e| CertmeshError::InvalidPayload(format!("CSR parse: {e}")))?;

    let mut names = Vec::new();

    // Subject CN.
    for cn in csr.certification_request_info.subject.iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.push(s.to_lowercase());
        }
    }

    // SAN extension from the requested extensions.
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let GeneralName::DNSName(dns) = gn {
                        names.push(dns.to_lowercase());
                    }
                }
            }
        }
    }

    names.sort();
    names.dedup();
    Ok(names)
}

/// Whether an authorized order name covers a CSR-requested name. A wildcard
/// authorization `*.zone` covers any single-label subdomain `host.zone`; an
/// exact authorization matches the same name.
fn names_match(authorized: &str, requested: &str) -> bool {
    let authorized = authorized.trim_end_matches('.').to_lowercase();
    let requested = requested.trim_end_matches('.').to_lowercase();
    if authorized == requested {
        return true;
    }
    if let Some(base) = authorized.strip_prefix("*.") {
        // `*.base` matches exactly one extra label in front of `base`.
        if let Some(prefix) = requested.strip_suffix(&format!(".{base}")) {
            return !prefix.is_empty() && !prefix.contains('.');
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_exact() {
        assert!(names_match("grafana.lan", "grafana.lan"));
        assert!(names_match("grafana.lan", "Grafana.LAN."));
        assert!(!names_match("grafana.lan", "evil.lan"));
    }

    #[test]
    fn names_match_wildcard() {
        assert!(names_match("*.lan", "host.lan"));
        assert!(!names_match("*.lan", "a.b.lan"), "wildcard is single-label");
        assert!(!names_match("*.lan", "lan"));
    }

    #[test]
    fn der_to_csr_pem_round_trips() {
        let der = b"not a real csr";
        let pem_str = der_to_csr_pem(der);
        assert!(pem_str.contains("BEGIN CERTIFICATE REQUEST"));
        let parsed = pem::parse(&pem_str).unwrap();
        assert_eq!(parsed.contents(), der);
    }
}
