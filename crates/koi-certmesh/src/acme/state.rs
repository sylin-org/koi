//! ACME server state: the wiring between the RFC 8555 endpoints and the certmesh
//! CA, plus the account/nonce/order stores and the dns-01 solver.
//!
//! `AcmeState` is constructed in the composition layer (the binary) from a
//! `CertmeshCore`'s shared state, the Koi DNS zone, and the
//! [`AcmeDnsResolver`](koi_common::integration::AcmeDnsResolver) bridge. It is then
//! handed to [`crate::acme::routes`] and mounted under `/acme` on the dedicated
//! server-auth TLS listener.

use std::sync::Arc;

use koi_common::integration::AcmeDnsResolver;

use crate::acme::challenge;
use crate::acme::nonce::NonceStore;
use crate::acme::order::OrderStore;
use crate::error::CertmeshError;
use crate::roster::MemberStatus;
use crate::CertmeshState;

/// Construction parameters for [`AcmeState`].
pub struct AcmeStateConfig {
    /// The base URL clients use to reach this ACME server, e.g.
    /// `https://daemon.lan:5643`. Endpoint URLs in the directory and account/
    /// order objects are built relative to this.
    pub base_url: String,
    /// The Koi DNS zone (e.g. `lan`). It must match the core's immutable
    /// issuance policy; the core remains authoritative on a mismatch.
    pub zone: String,
    /// The in-process dns-01 solver (writes/reads `_acme-challenge.*` TXT).
    pub dns: Arc<dyn AcmeDnsResolver>,
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
    dns: Arc<dyn AcmeDnsResolver>,
    /// In-memory replay-nonce store.
    nonces: NonceStore,
    /// In-memory order/authz/cert store.
    orders: Arc<OrderStore>,
}

impl AcmeState {
    /// Build the ACME state from certmesh's shared state and the ACME config.
    pub(crate) fn new(certmesh: Arc<CertmeshState>, cfg: AcmeStateConfig) -> Arc<Self> {
        let zone = certmesh.issuance_names.zone().to_string();
        let requested_zone = cfg.zone.trim().trim_end_matches('.');
        if !requested_zone.eq_ignore_ascii_case(&zone) {
            tracing::error!(
                requested_zone,
                authoritative_zone = %zone,
                "ACME zone disagrees with Certmesh issuance policy; using the authoritative zone"
            );
        }
        Arc::new(Self {
            certmesh,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            zone,
            dns: cfg.dns,
            nonces: NonceStore::new(),
            orders: Arc::new(OrderStore::new()),
        })
    }

    // ── Accessors ────────────────────────────────────────────────────

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn nonces(&self) -> &NonceStore {
        &self.nonces
    }

    pub fn orders(&self) -> &OrderStore {
        self.orders.as_ref()
    }

    pub fn dns(&self) -> &Arc<dyn AcmeDnsResolver> {
        &self.dns
    }

    /// Read one ACME account under the Certmesh transition boundary.
    pub async fn account(&self, id: &str) -> Option<crate::acme::account::Account> {
        let _transition = self.certmesh.transition.lock().await;
        self.certmesh.acme_accounts.get(id)
    }

    /// Register an ACME account as one Certmesh aggregate transaction.
    /// Persistence is the commit point; the model becomes visible afterwards.
    pub async fn register_account(
        &self,
        jwk: crate::acme::jws::Jwk,
        contacts: Vec<String>,
    ) -> Result<(crate::acme::account::Account, bool), CertmeshError> {
        self.certmesh
            .run_blocking_transition(move |domain| {
                if !domain
                    .status
                    .current()
                    .authority
                    .as_ref()
                    .is_some_and(|authority| authority.enrollment_open)
                {
                    return Err(CertmeshError::EnrollmentClosed);
                }
                let prepared = domain.acme_accounts.prepare_registration(jwk, contacts)?;
                if let Some(bytes) = &prepared.bytes {
                    let mut transaction = crate::repository::ArtifactTransaction::new();
                    transaction.write(domain.paths.acme_accounts_path(), bytes.clone(), true);
                    transaction.append(
                        domain.paths.audit_log_path(),
                        crate::audit::render_entry(
                            "acme_account_registered",
                            &[("account_id", prepared.account.id.as_str())],
                        ),
                        true,
                    )?;
                    let outcome = domain.commit_artifacts_under_transition(transaction)?;
                    domain.acme_accounts.commit_registration(&prepared);
                    domain.finish_commit_under_transition(outcome)?;
                }
                Ok((prepared.account, prepared.created))
            })
            .await?
    }

    /// Build an absolute URL from a path under the ACME base.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Whether the mesh is in open enrollment (free newAccount) or closed
    /// (newAccount requires EAB). Read from the roster's posture boolean.
    pub async fn enrollment_open(&self) -> bool {
        self.certmesh
            .status
            .current()
            .authority
            .as_ref()
            .is_some_and(|authority| authority.enrollment_open)
    }

    /// Whether an identifier is issuable (in-zone). The wildcard `*.<zone>` is
    /// allowed; out-of-zone names are not.
    pub fn is_issuable(&self, identifier: &str) -> bool {
        challenge::is_in_zone(identifier, &self.zone)
    }

    /// Require every requested identifier to be an exact grant owned by this
    /// ACME account. The same check runs again under finalization's transition.
    pub async fn authorize_order_identifiers(
        &self,
        account_id: &str,
        identifiers: &[String],
    ) -> Result<Vec<String>, CertmeshError> {
        let _transition = self.certmesh.transition.lock().await;
        crate::service_names::authorize_acme_names_under_transition(
            &self.certmesh,
            account_id,
            identifiers,
        )
    }

    // ── Issuance ─────────────────────────────────────────────────────

    /// Finalize one order as a single admitted Certmesh operation: enforce the
    /// SAN gate, sign, durably record the issued identity, publish the transient
    /// order/certificate projection, then publish primary status and event.
    ///
    /// `csr_der` is the raw DER CSR from the finalize body.
    ///
    /// Returns the certificate id already attached to the order. Errors map to
    /// ACME problems by the caller. THIS is the issuance enforcement point — the underlying
    /// [`crate::sign_csr`] further guarantees the issued cert carries only
    /// `authorized_names`, never the CSR's embedded SANs.
    pub(crate) async fn finalize_order_certificate(
        &self,
        order_id: &str,
        account_id: &str,
        csr_der: &[u8],
    ) -> Result<String, CertmeshError> {
        let order_id = order_id.to_string();
        let account_id = account_id.to_string();
        let csr_der = csr_der.to_vec();
        let orders = Arc::clone(&self.orders);
        self.certmesh
            .run_blocking_transition(move |domain| {
                let order = orders
                    .get_order(&order_id)
                    .ok_or_else(|| CertmeshError::NotFound(format!("ACME order '{order_id}'")))?;
                if order.account_id != account_id {
                    return Err(CertmeshError::Forbidden(
                        "ACME order belongs to another account".into(),
                    ));
                }
                if let Some(certificate_id) = order.certificate_id {
                    return Ok(certificate_id);
                }
                if order.status != crate::acme::order::OrderStatus::Ready {
                    return Err(CertmeshError::Conflict(
                        "ACME order is not ready for finalization".into(),
                    ));
                }
                let authorized_names = order.authorized_names().to_vec();
                let csr_pem = der_to_csr_pem(&csr_der);
                let csr_sans = crate::csr::requested_sans(&csr_pem)?;
                for san in &csr_sans {
                    if !authorized_names
                        .iter()
                        .any(|name| crate::csr::names_match(name, san))
                    {
                        return Err(CertmeshError::InvalidPayload(format!(
                            "CSR requests unauthorized identifier '{san}' not in the order"
                        )));
                    }
                }

                // A challenge proves DNS control at one moment; the durable
                // service-name grant proves operator authorization. Recheck it
                // here so revocation racing a ready order cannot still sign.
                let authorized_names = crate::service_names::authorize_acme_names_under_transition(
                    domain,
                    &account_id,
                    &authorized_names,
                )?;
                let validity_days = domain.roster.lock().metadata.policy.leaf_lifetime_days;
                let ca_guard = domain.ca.lock();
                let ca = ca_guard.as_ref().ok_or_else(|| {
                    if domain.paths.is_ca_initialized() {
                        CertmeshError::CaLocked
                    } else {
                        CertmeshError::CaNotInitialized
                    }
                })?;
                let leaf_pem = crate::sign_csr(ca, &csr_pem, &authorized_names, validity_days)?;
                let chain_pem = format!("{leaf_pem}{}", ca.cert_pem);
                let fingerprint = pem::parse(&leaf_pem)
                    .map(|parsed| koi_crypto::pinning::fingerprint_sha256(parsed.contents()))
                    .map_err(|error| CertmeshError::Certificate(error.to_string()))?;
                let expires = crate::leaf_not_after_utc(&leaf_pem).ok_or_else(|| {
                    CertmeshError::Certificate("issued ACME leaf has no usable expiry".into())
                })?;
                drop(ca_guard);

                let (published, renewing, outcome) =
                    crate::service_names::record_acme_certificate_under_transition(
                        domain,
                        &account_id,
                        &authorized_names,
                        &fingerprint,
                        expires,
                    )?;
                let cert_id = orders.record_certificate(&order_id, chain_pem);
                domain.finish_commit_under_transition(outcome)?;
                for grant in published {
                    let _ = domain
                        .event_tx
                        .send(crate::CertmeshEvent::ServiceCertificateIssued {
                            service_id: grant.service_id,
                            dns_name: grant.dns_name,
                            expires_at: expires,
                            renewed: renewing,
                        });
                }
                Ok(cert_id)
            })
            .await?
    }

    /// Revoke an ACME-issued certificate by its leaf fingerprint, reflecting the
    /// revocation in the roster. Returns whether a member was revoked.
    pub async fn revoke_by_fingerprint(&self, fingerprint: &str) -> Result<bool, CertmeshError> {
        // Revocation is a membership change → commit_roster bumps `seq` so the
        // revocation propagates + is enforced mesh-wide (F4/F8). Returns Ok(false)
        // (no commit) when no active member matches the fingerprint.
        let fingerprint = fingerprint.to_string();
        self.certmesh
            .run_blocking_transition(move |domain| {
                if let Some((grant, commit)) =
                    crate::service_names::revoke_service_name_by_fingerprint_under_transition(
                        domain,
                        &fingerprint,
                    )?
                {
                    domain.finish_commit_under_transition(commit)?;
                    let _ = domain
                        .event_tx
                        .send(crate::CertmeshEvent::ServiceNameRevoked {
                            service_id: grant.service_id,
                            dns_name: grant.dns_name,
                        });
                    return Ok(true);
                }
                let outcome = domain.commit_roster_under_transition(
                    true,
                    Some(crate::audit::render_entry(
                        "member_revoked",
                        &[("via", "acme")],
                    )),
                    move |roster| {
                        let hostname = roster
                            .members
                            .iter()
                            .find(|member| {
                                member.cert_fingerprint == fingerprint
                                    && member.status == MemberStatus::Active
                            })
                            .map(|member| member.hostname.clone());
                        let Some(hostname) = hostname else {
                            return Err(crate::error::CertmeshError::NotFound(fingerprint.clone()));
                        };
                        let _ = roster.revoke_member(
                            &hostname,
                            Some("acme".into()),
                            Some("revokeCert".into()),
                        );
                        Ok(hostname)
                    },
                );
                match outcome {
                    Ok((hostname, commit)) => {
                        domain.finish_commit_under_transition(commit)?;
                        let _ = domain
                            .event_tx
                            .send(crate::CertmeshEvent::MemberRevoked { hostname });
                        Ok(true)
                    }
                    Err(crate::error::CertmeshError::NotFound(_)) => Ok(false),
                    Err(error) => Err(error),
                }
            })
            .await?
    }

    /// The CA certificate PEM, for the certificate chain and bootstrap.
    pub async fn ca_pem(&self) -> Option<String> {
        let _transition = self.certmesh.transition.lock().await;
        self.certmesh
            .ca
            .lock()
            .as_ref()
            .map(|ca| ca.cert_pem.clone())
    }

    /// Whether the CA is available (initialized + unlocked) to issue.
    pub async fn ca_ready(&self) -> Result<(), CertmeshError> {
        let _transition = self.certmesh.transition.lock().await;
        let guard = self.certmesh.ca.lock();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::MemberRole;
    use chrono::Utc;

    #[derive(Default)]
    struct EmptyDns;

    impl AcmeDnsResolver for EmptyDns {
        fn get_txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn der_to_csr_pem_round_trips() {
        let der = b"not a real csr";
        let pem_str = der_to_csr_pem(der);
        assert!(pem_str.contains("BEGIN CERTIFICATE REQUEST"));
        let parsed = pem::parse(&pem_str).unwrap();
        assert_eq!(parsed.contents(), der);
    }

    #[tokio::test]
    async fn failed_account_commit_changes_no_model_projection_event_or_audit() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("account-test-pass", &[73_u8; 32], &paths)
            .unwrap()
            .0;
        let core = crate::CertmeshCore::new_with_paths(
            ca,
            crate::roster::Roster::new(true, false, None),
            None,
            paths.clone(),
        );
        let state = core.acme_state(AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        });
        let jwk = crate::acme::jws::Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "test-x".into(),
            y: "test-y".into(),
        };
        let account_id = crate::acme::jws::jwk_thumbprint(&jwk);
        let status_before = core.status();
        let roster_before = core.roster_snapshot();
        let tls_before = core.tls_identity();
        let mut events = core.subscribe();
        core.state.repository.fail_next_commit_after(0);

        state
            .register_account(jwk, vec!["mailto:operator@example.test".into()])
            .await
            .expect_err("repository failure must reject registration");

        assert!(state.account(&account_id).await.is_none());
        assert!(!paths.acme_accounts_path().exists());
        assert!(Arc::ptr_eq(&status_before, &core.status()));
        assert!(Arc::ptr_eq(&roster_before, &core.roster_snapshot()));
        assert!(Arc::ptr_eq(&tls_before, &core.tls_identity()));
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(!core
            .read_audit_log()
            .await
            .unwrap()
            .contains("acme_account_registered"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_account_registration_converges_after_durable_commit_without_retry() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("account-cancel-pass", &[75_u8; 32], &paths)
            .unwrap()
            .0;
        let core = crate::CertmeshCore::new_with_paths(
            ca,
            crate::roster::Roster::new(true, false, None),
            None,
            paths.clone(),
        );
        let state = core.acme_state(AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        });
        let jwk = crate::acme::jws::Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "cancel-x".into(),
            y: "cancel-y".into(),
        };
        let account_id = crate::acme::jws::jwk_thumbprint(&jwk);
        let status_before = core.status();
        let mut events = core.subscribe();
        core.state.repository.pause_next_commit_after_durable();

        let command = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.register_account(jwk, Vec::new()).await })
        };
        while !core.state.repository.is_commit_paused() {
            tokio::task::yield_now().await;
        }
        assert!(
            paths.acme_accounts_path().exists(),
            "account persistence must be visible at the cancellation point"
        );
        command.abort();
        core.state.repository.release_commit();
        let _ = command.await;

        let account = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(account) = state.account(&account_id).await {
                    break account;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained registration must publish the account model without a retry");
        assert_eq!(account.id, account_id);
        assert!(
            Arc::ptr_eq(&status_before, &core.status()),
            "an account-only mutation must not invent a primary-status revision"
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(core
            .read_audit_log()
            .await
            .unwrap()
            .contains("acme_account_registered"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_acme_finalize_converges_grant_order_and_event_without_retry() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("finalize-cancel-pass", &[77_u8; 32], &paths)
            .unwrap()
            .0;
        let core = crate::CertmeshCore::new_with_paths(
            ca,
            crate::roster::Roster::new(true, false, None),
            None,
            paths.clone(),
        );
        let state = core.acme_state(AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        });
        let (account, _) = state
            .register_account(
                crate::acme::jws::Jwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: "finalize-x".into(),
                    y: "finalize-y".into(),
                },
                Vec::new(),
            )
            .await
            .unwrap();
        let account_id = account.id.clone();
        let names = vec!["new.internal".to_string()];
        core.grant_service_name(
            koi_common::service::ServiceId::new("svc_cancelled_finalize").unwrap(),
            "new.internal",
            crate::ServiceNameOwner::AcmeAccount {
                account_id: account_id.clone(),
            },
        )
        .await
        .unwrap();
        let order = state.orders().create_order(&account_id, names.clone());
        for authorization_id in &order.authz_ids {
            state.orders().mark_challenge_valid(authorization_id);
        }
        let (_key, csr_pem) =
            crate::csr::generate_keypair_and_csr("new.internal", &names).expect("test CSR");
        let csr_der = pem::parse(csr_pem).unwrap().contents().to_vec();
        let retry_csr_der = csr_der.clone();
        let initial_status = core.status();
        let mut events = core.subscribe();
        core.state.repository.pause_next_commit_after_durable();

        let command = {
            let state = Arc::clone(&state);
            let order_id = order.id.clone();
            let account_id = account_id.clone();
            tokio::spawn(async move {
                state
                    .finalize_order_certificate(&order_id, &account_id, &csr_der)
                    .await
            })
        };
        while !core.state.repository.is_commit_paused() {
            tokio::task::yield_now().await;
        }
        let durable = crate::roster::load_roster(&paths.roster_path()).unwrap();
        assert!(durable
            .service_name_grants
            .iter()
            .any(|grant| grant.dns_name == "new.internal" && grant.certificate.is_some()));
        command.abort();
        core.state.repository.release_commit();
        let _ = command.await;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let published = core
                    .state
                    .roster
                    .lock()
                    .service_name_grants
                    .iter()
                    .any(|grant| grant.dns_name == "new.internal" && grant.certificate.is_some());
                if published
                    && state
                        .orders()
                        .get_order(&order.id)
                        .is_some_and(|order| order.certificate_id.is_some())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained finalize must converge its grant and order without a retry");
        assert!(Arc::ptr_eq(&initial_status, &core.status()));
        let finalized = state.orders().get_order(&order.id).unwrap();
        let certificate_id = finalized
            .certificate_id
            .expect("the retained tail must attach the certificate to its order");
        assert_eq!(finalized.status, crate::acme::order::OrderStatus::Valid);
        assert!(state.orders().get_certificate(&certificate_id).is_some());
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            crate::CertmeshEvent::ServiceCertificateIssued { dns_name, .. }
                if dns_name == "new.internal"
        ));

        let status_after = core.status();
        let roster_seq = core.state.roster.lock().metadata.seq;
        let retried_certificate_id = state
            .finalize_order_certificate(&order.id, &account_id, &retry_csr_der)
            .await
            .unwrap();
        assert_eq!(retried_certificate_id, certificate_id);
        assert_eq!(core.state.roster.lock().metadata.seq, roster_seq);
        assert!(Arc::ptr_eq(&status_after, &core.status()));
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn finalize_rejects_an_order_after_its_exact_grant_is_revoked() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("finalize-revoked-grant", &[75_u8; 32], &paths)
            .unwrap()
            .0;
        let core = crate::CertmeshCore::new_with_paths(
            ca,
            crate::roster::Roster::new(true, false, None),
            None,
            paths,
        );
        let state = core.acme_state(AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        });
        let (account, _) = state
            .register_account(
                crate::acme::jws::Jwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: "revoked-x".into(),
                    y: "revoked-y".into(),
                },
                Vec::new(),
            )
            .await
            .unwrap();
        let service_id = koi_common::service::ServiceId::new("svc_finalize_revoked").unwrap();
        let names = vec!["revoked.internal".to_string()];
        core.grant_service_name(
            service_id.clone(),
            &names[0],
            crate::ServiceNameOwner::AcmeAccount {
                account_id: account.id.clone(),
            },
        )
        .await
        .unwrap();
        let order = state.orders().create_order(&account.id, names.clone());
        for authorization_id in &order.authz_ids {
            state.orders().mark_challenge_valid(authorization_id);
        }
        core.revoke_service_name(&service_id, &names[0])
            .await
            .unwrap();
        let (_key, csr_pem) = crate::csr::generate_keypair_and_csr(&names[0], &names).unwrap();
        let csr_der = pem::parse(csr_pem).unwrap().contents().to_vec();

        assert!(matches!(
            state
                .finalize_order_certificate(&order.id, &account.id, &csr_der)
                .await,
            Err(CertmeshError::Forbidden(_))
        ));
        assert!(state.orders().get_certificate(&order.id).is_none());
        assert!(state
            .orders()
            .get_order(&order.id)
            .is_some_and(|order| order.certificate_id.is_none()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_acme_revocation_converges_status_and_event_without_retry() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("revoke-cancel-pass", &[76_u8; 32], &paths)
            .unwrap()
            .0;
        let mut roster = crate::roster::Roster::new(true, false, None);
        roster.members.push(crate::roster::RosterMember {
            hostname: "acme.internal".into(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: Some("acme:test-account".into()),
            cert_fingerprint: "acme-revoke-fingerprint".into(),
            cert_expires: Utc::now() + chrono::Duration::days(30),
            cert_sans: vec!["acme.internal".into()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: Some(Utc::now()),
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        let core = crate::CertmeshCore::new_with_paths(ca, roster, None, paths.clone());
        let state = core.acme_state(AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        });
        let initial_revision = core.status().revision;
        let mut events = core.subscribe();
        core.state.repository.pause_next_commit_after_durable();

        let command = {
            let state = Arc::clone(&state);
            tokio::spawn(
                async move { state.revoke_by_fingerprint("acme-revoke-fingerprint").await },
            )
        };
        while !core.state.repository.is_commit_paused() {
            tokio::task::yield_now().await;
        }
        let durable = crate::roster::load_roster(&paths.roster_path()).unwrap();
        assert!(durable.is_revoked("acme.internal"));
        command.abort();
        core.state.repository.release_commit();
        let _ = command.await;

        let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = core.status();
                let revoked = status
                    .authority
                    .as_ref()
                    .and_then(|authority| {
                        authority
                            .members
                            .iter()
                            .find(|member| member.hostname == "acme.internal")
                    })
                    .is_some_and(|member| member.status == "revoked");
                if status.revision > initial_revision && revoked {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained ACME revocation must converge status without a retry");
        assert!(status.revision > initial_revision);
        assert!(core.state.roster.lock().is_revoked("acme.internal"));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            crate::CertmeshEvent::MemberRevoked { hostname } if hostname == "acme.internal"
        ));
    }

    #[tokio::test]
    async fn every_acme_adapter_shares_one_account_model_and_destroy_withdraws_it() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let ca = crate::ca::create_ca("shared-account-pass", &[74_u8; 32], &paths)
            .unwrap()
            .0;
        let core = crate::CertmeshCore::new_with_paths(
            ca,
            crate::roster::Roster::new(true, false, None),
            None,
            paths.clone(),
        );
        let config = || AcmeStateConfig {
            base_url: "https://localhost:5643".into(),
            zone: "internal".into(),
            dns: Arc::new(EmptyDns),
        };
        let first = core.acme_state(config());
        let second = core.acme_state(config());
        let jwk = crate::acme::jws::Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "shared-x".into(),
            y: "shared-y".into(),
        };

        let (account, created) = first.register_account(jwk, Vec::new()).await.unwrap();

        assert!(created);
        assert!(second.account(&account.id).await.is_some());
        assert!(paths.acme_accounts_path().exists());

        core.destroy().await.unwrap();

        assert!(first.account(&account.id).await.is_none());
        assert!(second.account(&account.id).await.is_none());
        assert!(!paths.acme_accounts_path().exists());
    }
}
