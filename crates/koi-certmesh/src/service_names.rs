//! Durable authorization and host-custodied leaves for named services.
//!
//! A DNS name being inside Koi's configured zone is necessary but not sufficient
//! for issuance. The authority first binds that exact name to one stable catalog
//! service and one consumer. Issuance and renewal repeat that check inside the
//! Certmesh transition immediately before signing.

use chrono::{DateTime, Utc};
use koi_common::service::ServiceId;
use serde::{Deserialize, Serialize};

use crate::{ca, repository, CertmeshCore, CertmeshDomain, CertmeshError, CertmeshEvent};

const SERVICE_NAME_GRANT_SCHEMA: u32 = 1;

/// The only consumers that may hold an authorized service-name certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceNameOwner {
    /// Koi's in-process Proxy domain terminates TLS on this host.
    HostProxy,
    /// One persisted ACME account, identified by its RFC 7638 key thumbprint.
    AcmeAccount { account_id: String },
}

/// Non-secret facts about the active leaf for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCertificateStatus {
    pub fingerprint: String,
    pub expires_at: DateTime<Utc>,
}

/// One exact, durable service-name authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceNameGrant {
    pub schema: u32,
    pub service_id: ServiceId,
    pub dns_name: String,
    pub owner: ServiceNameOwner,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ServiceCertificateStatus>,
}

#[derive(Deserialize)]
struct ServiceNameGrantWire {
    schema: u32,
    service_id: ServiceId,
    dns_name: String,
    owner: ServiceNameOwner,
    granted_at: DateTime<Utc>,
    #[serde(default)]
    certificate: Option<ServiceCertificateStatus>,
}

impl<'de> Deserialize<'de> for ServiceNameGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ServiceNameGrantWire::deserialize(deserializer)?;
        if wire.schema != SERVICE_NAME_GRANT_SCHEMA {
            return Err(serde::de::Error::custom(format!(
                "unsupported service-name grant schema {}; supported schema is {}",
                wire.schema, SERVICE_NAME_GRANT_SCHEMA
            )));
        }
        Ok(Self {
            schema: wire.schema,
            service_id: wire.service_id,
            dns_name: wire.dns_name,
            owner: wire.owner,
            granted_at: wire.granted_at,
            certificate: wire.certificate,
        })
    }
}

/// Host-only certificate material handed directly to the TLS consumer.
///
/// This type is intentionally not serializable. Its `Debug` implementation
/// redacts every PEM field so keys cannot enter ordinary logs or diagnostics.
#[derive(Clone)]
pub struct ServiceCertificate {
    pub grant: ServiceNameGrant,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
    pub fullchain_pem: String,
    /// True when this call atomically installed replacement material.
    pub changed: bool,
}

impl std::fmt::Debug for ServiceCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceCertificate")
            .field("grant", &self.grant)
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .field("ca_cert_pem", &"<redacted>")
            .field("fullchain_pem", &"<redacted>")
            .field("changed", &self.changed)
            .finish()
    }
}

impl CertmeshCore {
    /// Bind an exact configured-zone name to one stable service and consumer.
    ///
    /// The operation is idempotent for an identical grant. A name already held
    /// by another service or consumer conflicts; names are never transferred by
    /// display-name similarity or silent replacement.
    pub async fn grant_service_name(
        &self,
        service_id: ServiceId,
        dns_name: &str,
        owner: ServiceNameOwner,
    ) -> Result<ServiceNameGrant, CertmeshError> {
        let dns_name = self.state.issuance_names.service_name(dns_name)?;
        validate_owner(&owner)?;
        self.run_blocking_transition(move |domain| {
            if let ServiceNameOwner::AcmeAccount { account_id } = &owner {
                if domain.acme_accounts.get(account_id).is_none() {
                    return Err(CertmeshError::NotFound(format!(
                        "ACME account '{account_id}'"
                    )));
                }
            }
            let existing = domain
                .roster
                .lock()
                .service_name_grants
                .iter()
                .find(|grant| grant.dns_name == dns_name)
                .cloned();
            if let Some(existing) = existing {
                if existing.service_id == service_id && existing.owner == owner {
                    return Ok(existing);
                }
                return Err(CertmeshError::Conflict(format!(
                    "service name '{}' is already granted to another owner",
                    dns_name
                )));
            }

            let grant = ServiceNameGrant {
                schema: SERVICE_NAME_GRANT_SCHEMA,
                service_id,
                dns_name,
                owner,
                granted_at: Utc::now(),
                certificate: None,
            };
            let persisted = grant.clone();
            let service_id_text = grant.service_id.to_string();
            let dns_name_text = grant.dns_name.clone();
            let owner_kind = owner_kind(&grant.owner);
            let ((), outcome) = domain.commit_roster_under_transition(
                false,
                Some(crate::audit::render_entry(
                    "service_name_granted",
                    &[
                        ("service_id", service_id_text.as_str()),
                        ("dns_name", dns_name_text.as_str()),
                        ("owner", owner_kind),
                    ],
                )),
                move |roster| {
                    roster.service_name_grants.push(persisted);
                    Ok(())
                },
            )?;
            domain.finish_commit_under_transition(outcome)?;
            Ok(grant)
        })
        .await?
    }

    /// Return the current secret-free grant set.
    pub async fn service_name_grants(&self) -> Vec<ServiceNameGrant> {
        let _transition = self.state.transition.lock().await;
        self.state.roster.lock().service_name_grants.clone()
    }

    /// Obtain the current host-proxy leaf, issuing or renewing atomically when due.
    pub async fn ensure_service_certificate(
        &self,
        service_id: &ServiceId,
        dns_name: &str,
    ) -> Result<ServiceCertificate, CertmeshError> {
        self.service_certificate_inner(service_id, dns_name, false)
            .await
    }

    /// Rotate the host-proxy key and leaf now while preserving the prior usable
    /// material if signing or persistence fails.
    pub async fn renew_service_certificate(
        &self,
        service_id: &ServiceId,
        dns_name: &str,
    ) -> Result<ServiceCertificate, CertmeshError> {
        self.service_certificate_inner(service_id, dns_name, true)
            .await
    }

    async fn service_certificate_inner(
        &self,
        service_id: &ServiceId,
        dns_name: &str,
        force: bool,
    ) -> Result<ServiceCertificate, CertmeshError> {
        let service_id = service_id.clone();
        let dns_name = self.state.issuance_names.service_name(dns_name)?;
        self.run_blocking_transition(move |domain| {
            issue_host_service_certificate_under_transition(domain, &service_id, &dns_name, force)
        })
        .await?
    }

    /// Remove one exact grant and any host-held active material.
    ///
    /// Koi-aware callers reject the name immediately after this commits. A copy
    /// already held by an ordinary TLS client can remain cryptographically valid
    /// until `NotAfter` because Certmesh does not publish CRL/OCSP state.
    pub async fn revoke_service_name(
        &self,
        service_id: &ServiceId,
        dns_name: &str,
    ) -> Result<bool, CertmeshError> {
        let service_id = service_id.clone();
        let dns_name = self.state.issuance_names.service_name(dns_name)?;
        self.run_blocking_transition(move |domain| {
            let Some((revoked, outcome)) = revoke_grant_under_transition(domain, |grant| {
                grant.service_id == service_id && grant.dns_name == dns_name
            })?
            else {
                return Ok(false);
            };
            domain.finish_commit_under_transition(outcome)?;
            let _ = domain.event_tx.send(CertmeshEvent::ServiceNameRevoked {
                service_id: revoked.service_id,
                dns_name: revoked.dns_name,
            });
            Ok(true)
        })
        .await?
    }
}

pub(crate) fn authorize_acme_names_under_transition(
    domain: &CertmeshDomain,
    account_id: &str,
    names: &[String],
) -> Result<Vec<String>, CertmeshError> {
    if names.len() != 1 {
        return Err(CertmeshError::InvalidPayload(
            "ACME service issuance requires exactly one identifier".into(),
        ));
    }
    let roster = domain.roster.lock();
    let mut authorized = Vec::with_capacity(names.len());
    for requested in names {
        let name = domain.issuance_names.service_name(requested)?;
        let permitted = roster.service_name_grants.iter().any(|grant| {
            grant.dns_name == name
                && matches!(
                    &grant.owner,
                    ServiceNameOwner::AcmeAccount { account_id: owner } if owner == account_id
                )
        });
        if !permitted {
            return Err(CertmeshError::Forbidden(format!(
                "ACME account is not granted service name '{name}'"
            )));
        }
        if !authorized.contains(&name) {
            authorized.push(name);
        }
    }
    Ok(authorized)
}

pub(crate) fn record_acme_certificate_under_transition(
    domain: &CertmeshDomain,
    account_id: &str,
    names: &[String],
    fingerprint: &str,
    expires_at: DateTime<Utc>,
) -> Result<
    (
        Vec<ServiceNameGrant>,
        bool,
        koi_common::persist::AtomicCommit,
    ),
    CertmeshError,
> {
    let names = authorize_acme_names_under_transition(domain, account_id, names)?;
    let previous = domain.roster.lock().clone();
    let mut next = previous.clone();
    let renewing = names.iter().all(|name| {
        next.service_name_grants
            .iter()
            .find(|grant| grant.dns_name == *name)
            .is_some_and(|grant| grant.certificate.is_some())
    });
    let mut published = Vec::with_capacity(names.len());
    for name in &names {
        let grant = next
            .service_name_grants
            .iter_mut()
            .find(|grant| {
                grant.dns_name == *name
                    && matches!(
                        &grant.owner,
                        ServiceNameOwner::AcmeAccount { account_id: owner } if owner == account_id
                    )
            })
            .expect("authorization and update share one retained transition");
        grant.certificate = Some(ServiceCertificateStatus {
            fingerprint: fingerprint.to_string(),
            expires_at,
        });
        published.push(grant.clone());
    }
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&next)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
        true,
    );
    let dns_names = names.join(",");
    transaction.append(
        domain.paths.audit_log_path(),
        crate::audit::render_entry(
            if renewing {
                "service_certificate_renewed"
            } else {
                "service_certificate_issued"
            },
            &[
                ("dns_names", dns_names.as_str()),
                ("fingerprint", fingerprint),
                ("owner", "acme_account"),
            ],
        ),
        true,
    )?;
    let outcome = match domain.commit_artifacts_under_transition(transaction) {
        Ok(outcome) => outcome,
        Err(error) => {
            *domain.roster.lock() = previous;
            return Err(error);
        }
    };
    *domain.roster.lock() = next;
    Ok((published, renewing, outcome))
}

pub(crate) fn revoke_service_name_by_fingerprint_under_transition(
    domain: &CertmeshDomain,
    fingerprint: &str,
) -> Result<Option<(ServiceNameGrant, koi_common::persist::AtomicCommit)>, CertmeshError> {
    revoke_grant_under_transition(domain, |grant| {
        grant
            .certificate
            .as_ref()
            .is_some_and(|certificate| certificate.fingerprint == fingerprint)
    })
}

fn issue_host_service_certificate_under_transition(
    domain: &CertmeshDomain,
    service_id: &ServiceId,
    dns_name: &str,
    force: bool,
) -> Result<ServiceCertificate, CertmeshError> {
    domain.require_authority_under_transition()?;
    let grant = find_grant(domain, service_id, dns_name, &ServiceNameOwner::HostProxy)?;
    let policy = domain.roster.lock().metadata.policy.clone();
    let ca_guard = domain.ca.lock();
    let ca = ca_guard.as_ref().ok_or_else(|| {
        if domain.paths.is_ca_initialized() {
            CertmeshError::CaLocked
        } else {
            CertmeshError::CaNotInitialized
        }
    })?;
    let ca_pem = ca.cert_pem.clone();

    if !force {
        if let Some(material) = read_current_material(domain, &grant, &ca_pem, &policy)? {
            return Ok(material);
        }
    }

    let issued = ca::issue_certificate(
        ca,
        dns_name,
        &[dns_name.to_string()],
        policy.leaf_lifetime_days,
    )?;
    let issued_expires = crate::leaf_not_after_utc(&issued.cert_pem).ok_or_else(|| {
        CertmeshError::Certificate("issued service leaf has no usable expiry".into())
    })?;
    drop(ca_guard);

    let previous = domain.roster.lock().clone();
    let mut next = previous.clone();
    let next_grant = next
        .service_name_grants
        .iter_mut()
        .find(|candidate| {
            candidate.service_id == *service_id
                && candidate.dns_name == dns_name
                && candidate.owner == ServiceNameOwner::HostProxy
        })
        .ok_or_else(|| {
            CertmeshError::Forbidden(format!("service name '{dns_name}' is not granted"))
        })?;
    let renewing = next_grant.certificate.is_some();
    next_grant.certificate = Some(ServiceCertificateStatus {
        fingerprint: issued.fingerprint.clone(),
        expires_at: issued_expires,
    });
    let published_grant = next_grant.clone();
    let cert_dir = service_certificate_dir(domain, dns_name);
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        cert_dir.join("cert.pem"),
        issued.cert_pem.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        cert_dir.join("key.pem"),
        issued.key_pem.as_bytes().to_vec(),
        true,
    );
    transaction.write(
        cert_dir.join("ca.pem"),
        issued.ca_pem.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        cert_dir.join("fullchain.pem"),
        issued.fullchain_pem.as_bytes().to_vec(),
        false,
    );
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&next)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
        true,
    );
    let service_id_text = service_id.to_string();
    transaction.append(
        domain.paths.audit_log_path(),
        crate::audit::render_entry(
            if renewing {
                "service_certificate_renewed"
            } else {
                "service_certificate_issued"
            },
            &[
                ("service_id", service_id_text.as_str()),
                ("dns_name", dns_name),
                ("fingerprint", issued.fingerprint.as_str()),
                ("owner", "host_proxy"),
            ],
        ),
        true,
    )?;
    let outcome = match domain.commit_artifacts_under_transition(transaction) {
        Ok(outcome) => outcome,
        Err(error) => {
            *domain.roster.lock() = previous;
            return Err(error);
        }
    };
    *domain.roster.lock() = next;
    domain.finish_commit_under_transition(outcome)?;
    let _ = domain
        .event_tx
        .send(CertmeshEvent::ServiceCertificateIssued {
            service_id: service_id.clone(),
            dns_name: dns_name.to_string(),
            expires_at: issued_expires,
            renewed: renewing,
        });

    Ok(ServiceCertificate {
        grant: published_grant,
        cert_pem: issued.cert_pem,
        key_pem: issued.key_pem,
        ca_cert_pem: issued.ca_pem,
        fullchain_pem: issued.fullchain_pem,
        changed: true,
    })
}

fn read_current_material(
    domain: &CertmeshDomain,
    grant: &ServiceNameGrant,
    ca_pem: &str,
    policy: &crate::roster::CertPolicy,
) -> Result<Option<ServiceCertificate>, CertmeshError> {
    let dir = service_certificate_dir(domain, &grant.dns_name);
    let read = |name: &str| match std::fs::read_to_string(dir.join(name)) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CertmeshError::Io(error)),
    };
    let Some(cert_pem) = read("cert.pem")? else {
        return Ok(None);
    };
    let Some(key_pem) = read("key.pem")? else {
        return Ok(None);
    };
    let Some(stored_ca_pem) = read("ca.pem")? else {
        return Ok(None);
    };
    let Some(stored_fullchain_pem) = read("fullchain.pem")? else {
        return Ok(None);
    };
    let expected_fullchain_pem = format!("{cert_pem}{ca_pem}");
    if !crate::IssuanceNames::certificate_has_exact_sans(
        &cert_pem,
        std::slice::from_ref(&grant.dns_name),
    ) || !crate::diagnosis::identity_material_is_usable(&cert_pem, &key_pem, ca_pem)
        || stored_ca_pem != ca_pem
        || stored_fullchain_pem != expected_fullchain_pem
    {
        return Ok(None);
    }
    let parsed_leaf =
        pem::parse(&cert_pem).map_err(|error| CertmeshError::Certificate(error.to_string()))?;
    let actual_fingerprint = koi_crypto::pinning::fingerprint_sha256(parsed_leaf.contents());
    let actual_expiry = crate::leaf_not_after_utc(&cert_pem)
        .ok_or_else(|| CertmeshError::Certificate("service leaf has no usable expiry".into()))?;
    if !grant.certificate.as_ref().is_some_and(|status| {
        status.fingerprint == actual_fingerprint && status.expires_at == actual_expiry
    }) {
        return Ok(None);
    }
    let Some(renewal) = crate::RenewalHealth::from_leaf(&cert_pem, policy) else {
        return Ok(None);
    };
    if renewal.renew_overdue || renewal.expired {
        return Ok(None);
    }
    Ok(Some(ServiceCertificate {
        grant: grant.clone(),
        cert_pem,
        key_pem,
        ca_cert_pem: ca_pem.to_string(),
        fullchain_pem: expected_fullchain_pem,
        changed: false,
    }))
}

fn find_grant(
    domain: &CertmeshDomain,
    service_id: &ServiceId,
    dns_name: &str,
    owner: &ServiceNameOwner,
) -> Result<ServiceNameGrant, CertmeshError> {
    domain
        .roster
        .lock()
        .service_name_grants
        .iter()
        .find(|grant| {
            grant.service_id == *service_id && grant.dns_name == dns_name && grant.owner == *owner
        })
        .cloned()
        .ok_or_else(|| {
            CertmeshError::Forbidden(format!("service name '{dns_name}' is not granted"))
        })
}

fn revoke_grant_under_transition(
    domain: &CertmeshDomain,
    predicate: impl Fn(&ServiceNameGrant) -> bool,
) -> Result<Option<(ServiceNameGrant, koi_common::persist::AtomicCommit)>, CertmeshError> {
    domain.require_authority_under_transition()?;
    let previous = domain.roster.lock().clone();
    let Some(index) = previous.service_name_grants.iter().position(predicate) else {
        return Ok(None);
    };
    let mut next = previous.clone();
    let revoked = next.service_name_grants.remove(index);
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.write(
        domain.paths.roster_path(),
        serde_json::to_vec_pretty(&next)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?,
        true,
    );
    let cert_dir = service_certificate_dir(domain, &revoked.dns_name);
    if revoked.owner == ServiceNameOwner::HostProxy && cert_dir.exists() {
        transaction.remove_tree(&cert_dir)?;
    }
    let service_id_text = revoked.service_id.to_string();
    transaction.append(
        domain.paths.audit_log_path(),
        crate::audit::render_entry(
            "service_name_revoked",
            &[
                ("service_id", service_id_text.as_str()),
                ("dns_name", revoked.dns_name.as_str()),
                ("owner", owner_kind(&revoked.owner)),
            ],
        ),
        true,
    )?;
    let outcome = domain.commit_artifacts_under_transition(transaction)?;
    *domain.roster.lock() = next;
    Ok(Some((revoked, outcome)))
}

fn service_certificate_dir(domain: &CertmeshDomain, dns_name: &str) -> std::path::PathBuf {
    domain.paths.certs_dir().join("services").join(dns_name)
}

fn validate_owner(owner: &ServiceNameOwner) -> Result<(), CertmeshError> {
    if let ServiceNameOwner::AcmeAccount { account_id } = owner {
        if account_id.is_empty()
            || !account_id.is_ascii()
            || account_id.chars().any(char::is_whitespace)
        {
            return Err(CertmeshError::InvalidPayload(
                "ACME account id must be non-empty ASCII without whitespace".into(),
            ));
        }
    }
    Ok(())
}

fn owner_kind(owner: &ServiceNameOwner) -> &'static str {
    match owner {
        ServiceNameOwner::HostProxy => "host_proxy",
        ServiceNameOwner::AcmeAccount { .. } => "acme_account",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol, CertmeshPaths};

    fn service_id(value: &str) -> ServiceId {
        ServiceId::new(value).unwrap()
    }

    async fn core(name: &str) -> CertmeshCore {
        let paths = CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-service-name-tests").join(name),
        );
        let core = CertmeshCore::uninitialized_with_paths(paths)
            .with_dns_zone("internal")
            .unwrap()
            .with_local_hostname("service-name-test-host")
            .unwrap();
        core.create(protocol::CreateCaRequest {
            passphrase: "service-name-test-pass".into(),
            entropy_hex: koi_common::encoding::hex_encode(&[91_u8; 32]),
            operator: None,
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        })
        .await
        .unwrap();
        core
    }

    #[tokio::test]
    async fn exact_grant_issues_only_the_service_san_and_redacts_keys() {
        let core = core("exact-grant").await;
        let id = service_id("svc_exact");
        core.grant_service_name(id.clone(), "App.Internal.", ServiceNameOwner::HostProxy)
            .await
            .unwrap();
        let material = core
            .ensure_service_certificate(&id, "app.internal")
            .await
            .unwrap();
        assert!(material.changed);
        assert!(crate::IssuanceNames::certificate_has_exact_sans(
            &material.cert_pem,
            &["app.internal".into()]
        ));
        let debug = format!("{material:?}");
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(debug.matches("<redacted>").count() >= 4);
    }

    #[tokio::test]
    async fn name_is_unique_and_wildcard_or_wrong_service_is_rejected() {
        let core = core("name-conflict").await;
        let first = service_id("svc_first");
        let second = service_id("svc_second");
        core.grant_service_name(first.clone(), "app.internal", ServiceNameOwner::HostProxy)
            .await
            .unwrap();
        assert!(core
            .grant_service_name(second.clone(), "app.internal", ServiceNameOwner::HostProxy)
            .await
            .is_err());
        assert!(core
            .grant_service_name(second.clone(), "*.internal", ServiceNameOwner::HostProxy)
            .await
            .is_err());
        assert!(core
            .grant_service_name(second.clone(), "app.example", ServiceNameOwner::HostProxy)
            .await
            .is_err());
        assert!(matches!(
            core.ensure_service_certificate(&second, "app.internal")
                .await,
            Err(CertmeshError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn renewal_rotates_exact_material_and_failed_commit_keeps_previous_bytes() {
        let core = core("renewal-atomic").await;
        let id = service_id("svc_rotate");
        core.grant_service_name(id.clone(), "rotate.internal", ServiceNameOwner::HostProxy)
            .await
            .unwrap();
        let first = core
            .ensure_service_certificate(&id, "rotate.internal")
            .await
            .unwrap();
        let second = core
            .renew_service_certificate(&id, "rotate.internal")
            .await
            .unwrap();
        assert_ne!(first.key_pem, second.key_pem);
        assert_ne!(
            first.grant.certificate.as_ref().unwrap().fingerprint,
            second.grant.certificate.as_ref().unwrap().fingerprint
        );
        assert!(crate::IssuanceNames::certificate_has_exact_sans(
            &second.cert_pem,
            &["rotate.internal".into()]
        ));

        core.state.repository.fail_next_commit_after(0);
        assert!(core
            .renew_service_certificate(&id, "rotate.internal")
            .await
            .is_err());
        let after = core
            .ensure_service_certificate(&id, "rotate.internal")
            .await
            .unwrap();
        assert!(!after.changed);
        assert_eq!(after.cert_pem, second.cert_pem);
        assert_eq!(after.key_pem, second.key_pem);
    }

    #[tokio::test]
    async fn incomplete_host_material_is_replaced_as_one_complete_generation() {
        let core = core("incomplete-material").await;
        let id = service_id("svc_incomplete");
        core.grant_service_name(
            id.clone(),
            "incomplete.internal",
            ServiceNameOwner::HostProxy,
        )
        .await
        .unwrap();
        let first = core
            .ensure_service_certificate(&id, "incomplete.internal")
            .await
            .unwrap();
        std::fs::remove_file(
            core.paths()
                .certs_dir()
                .join("services")
                .join("incomplete.internal")
                .join("fullchain.pem"),
        )
        .unwrap();

        let repaired = core
            .ensure_service_certificate(&id, "incomplete.internal")
            .await
            .unwrap();
        assert!(repaired.changed);
        assert_ne!(repaired.key_pem, first.key_pem);
        assert_eq!(
            repaired.fullchain_pem,
            format!("{}{}", repaired.cert_pem, repaired.ca_cert_pem)
        );
    }

    #[tokio::test]
    async fn grants_persist_and_revocation_removes_only_owned_material() {
        let core = core("persist-revoke").await;
        let id = service_id("svc_persist");
        core.grant_service_name(id.clone(), "persist.internal", ServiceNameOwner::HostProxy)
            .await
            .unwrap();
        core.ensure_service_certificate(&id, "persist.internal")
            .await
            .unwrap();
        let paths = core.paths().clone();
        let loaded =
            CertmeshCore::load_with_paths(paths, "internal", "service-name-test-host").unwrap();
        assert_eq!(loaded.service_name_grants().await.len(), 1);
        assert!(loaded
            .revoke_service_name(&id, "persist.internal")
            .await
            .unwrap());
        assert!(loaded.service_name_grants().await.is_empty());
        assert!(matches!(
            loaded
                .ensure_service_certificate(&id, "persist.internal")
                .await,
            Err(CertmeshError::Forbidden(_))
        ));
    }

    #[test]
    fn grant_schema_round_trips_without_secret_material() {
        let grant = ServiceNameGrant {
            schema: SERVICE_NAME_GRANT_SCHEMA,
            service_id: service_id("svc_roundtrip"),
            dns_name: "roundtrip.internal".into(),
            owner: ServiceNameOwner::AcmeAccount {
                account_id: "account-thumbprint".into(),
            },
            granted_at: DateTime::UNIX_EPOCH,
            certificate: Some(ServiceCertificateStatus {
                fingerprint: "public-fingerprint".into(),
                expires_at: DateTime::UNIX_EPOCH,
            }),
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert!(!json.contains("key_pem"));
        assert_eq!(
            serde_json::from_str::<ServiceNameGrant>(&json).unwrap(),
            grant
        );
        let future = json.replace("\"schema\":1", "\"schema\":2");
        assert!(serde_json::from_str::<ServiceNameGrant>(&future).is_err());
    }
}
