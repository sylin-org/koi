use std::fs;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::lab::{curl_json, Lab};
use crate::model::{output_path, CheckResult, NodeSpec, RunId, TrustRotation};

impl Lab {
    /// Drive the deployed RFC 8555 server with a real client. TXT publication
    /// crosses the authenticated HTTP boundary; observation crosses the DNS
    /// wire boundary from the other physical node; validation returns through
    /// AcmeDnsResolver into the same DnsCore.
    pub(crate) fn acme_mini_act(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
        ca: &NodeSpec,
        observer: &NodeSpec,
    ) -> Result<CheckResult> {
        let ca_run_dir = ca.run_dir(run_id)?;
        let ca_pem_path =
            output_path(run_id.as_str()).join(format!("acme-ca-{}.pem", rotation.as_str()));
        self.copy_from_remote(
            ca,
            &format!("{ca_run_dir}/data/certmesh/ca/ca-cert.pem"),
            &ca_pem_path,
        )?;
        let ca_pem = fs::read_to_string(&ca_pem_path)
            .with_context(|| format!("could not read {}", ca_pem_path.display()))?;

        let port = ca.lab_ports()?.acme;
        let mut listening = false;
        for _ in 0..100 {
            let probe = self.run_remote(ca, &format!("ss -H -lnt | grep -Eq ':{port} '"))?;
            if probe.status.success() {
                listening = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !listening {
            bail!("ACME listener did not bind run-owned port {port}");
        }

        let runtime =
            tokio::runtime::Runtime::new().context("could not start ACME client runtime")?;
        let issued =
            runtime.block_on(self.issue_acme_certificate(run_id, ca, observer, &ca_pem_path))?;
        let fingerprint = verify_issued_chain(&issued.chain_pem, &ca_pem, &issued.name)?;

        let status = curl_json(
            "GET",
            &format!("{}/v1/certmesh/status", self.node_url(ca)?),
            None,
            None,
        )?;
        let recorded = status
            .get("members")
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members.iter().any(|member| {
                    member.get("hostname").and_then(Value::as_str) == Some(issued.name.as_str())
                        && member.get("role").and_then(Value::as_str) == Some("client")
                        && member
                            .get("cert_fingerprint")
                            .and_then(Value::as_str)
                            .is_some_and(|recorded| recorded.eq_ignore_ascii_case(&fingerprint))
                })
            });
        if !recorded {
            bail!("ACME-issued identity was not recorded in the certmesh roster");
        }

        Ok(CheckResult {
            name: "act_7_acme_dns01".into(),
            passed: true,
            detail: format!(
                "instant-acme issued {} through {}, {} observed the DNS TXT value, the chain verified to the run CA (sha256 {}…), and exact cleanup removed the value",
                issued.name,
                ca.id(),
                observer.id(),
                &fingerprint[..16]
            ),
        })
    }

    async fn issue_acme_certificate(
        &self,
        run_id: &RunId,
        ca: &NodeSpec,
        observer: &NodeSpec,
        ca_pem_path: &std::path::Path,
    ) -> Result<IssuedAcmeCertificate> {
        let suffix = run_id
            .as_str()
            .rsplit('-')
            .next()
            .unwrap_or("story")
            .to_ascii_lowercase();
        let name = format!("acme-{suffix}.internal");
        let directory = format!(
            "https://{}:{}/acme/directory",
            ca.hostname(),
            ca.lab_ports()?.acme
        );
        let (account, _credentials): (Account, _) = Account::builder_with_root(ca_pem_path)
            .context("could not configure instant-acme with the run CA")?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory,
                None,
            )
            .await
            .context("instant-acme newAccount failed")?;

        let identifiers = [Identifier::Dns(name.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("instant-acme newOrder failed")?;
        let ca_url = self.node_url(ca)?;
        let ca_token = self.daemon_token(ca, run_id)?;

        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result.context("instant-acme authorization failed")?;
                let mut challenge = authorization
                    .challenge(ChallengeType::Dns01)
                    .context("ACME server did not offer dns-01")?;
                let identifier = challenge.identifier().to_string();
                let dns_name = format!("_acme-challenge.{identifier}");
                let value = challenge.key_authorization().dns_value();

                curl_json(
                    "PUT",
                    &format!("{ca_url}/v1/dns/txt"),
                    Some(&ca_token),
                    Some(&serde_json::json!({ "name": dns_name, "value": value })),
                )?;

                let observed = self.remote_line(
                    observer,
                    &format!(
                        "dig @{} -p {} {} TXT +short",
                        ca.address(),
                        ca.lab_ports()?.dns,
                        dns_name
                    ),
                )?;
                if !observed.lines().any(|line| line.trim_matches('"') == value) {
                    let _ = clear_txt(&ca_url, &ca_token, &dns_name, &value);
                    bail!(
                        "{} did not observe the ACME TXT value through real DNS: {observed:?}",
                        observer.id()
                    );
                }

                let validation = challenge
                    .set_ready()
                    .await
                    .context("instant-acme challenge validation failed");
                let cleanup = clear_txt(&ca_url, &ca_token, &dns_name, &value);
                validation?;
                cleanup?;

                let after = self.remote_line(
                    observer,
                    &format!(
                        "dig @{} -p {} {} TXT +short",
                        ca.address(),
                        ca.lab_ports()?.dns,
                        dns_name
                    ),
                )?;
                if !after.is_empty() {
                    bail!("ACME TXT value remained after exact provider cleanup: {after:?}");
                }
            }
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("instant-acme order did not become ready")?;
        if status != OrderStatus::Ready {
            bail!("instant-acme order reached unexpected state {status:?}");
        }
        let _private_key_pem = order
            .finalize()
            .await
            .context("instant-acme finalize failed")?;
        let chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("instant-acme certificate download failed")?;

        Ok(IssuedAcmeCertificate { name, chain_pem })
    }
}

struct IssuedAcmeCertificate {
    name: String,
    chain_pem: String,
}

fn clear_txt(base: &str, token: &str, name: &str, value: &str) -> Result<Value> {
    curl_json(
        "DELETE",
        &format!("{base}/v1/dns/txt"),
        Some(token),
        Some(&serde_json::json!({ "name": name, "value": value })),
    )
}

fn verify_issued_chain(chain_pem: &str, ca_pem: &str, expected_san: &str) -> Result<String> {
    let chain = pem::parse_many(chain_pem).context("ACME response was not a PEM chain")?;
    if chain.len() < 2 {
        bail!("ACME response did not include leaf plus CA certificates");
    }
    let ca_der = pem::parse(ca_pem).context("run CA was not valid PEM")?;
    let (_, leaf) = X509Certificate::from_der(chain[0].contents())
        .map_err(|error| anyhow::anyhow!("ACME leaf was invalid DER: {error}"))?;
    let (_, ca) = X509Certificate::from_der(ca_der.contents())
        .map_err(|error| anyhow::anyhow!("run CA was invalid DER: {error}"))?;
    if leaf.issuer() != ca.subject() || leaf.verify_signature(Some(ca.public_key())).is_err() {
        bail!("ACME leaf did not verify to the run CA");
    }
    let covers_name = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|extension| {
            extension
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(dns) if *dns == expected_san))
        });
    if !covers_name {
        bail!("ACME leaf did not cover authorized name {expected_san}");
    }
    Ok(format!("{:x}", Sha256::digest(chain[0].contents())))
}
