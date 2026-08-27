//! W12 (ADR-032): ACME dns-01 with the Windows-side daemon as the RFC 8555
//! server, serving the dns-01 TXT through its own DNS runtime (the W6
//! machinery), cross-host observed by the Linux member.
//!
//! Flow: the Windows daemon's posture-reactive trust plane comes up once a
//! CA exists (certmesh create on Windows) — mounting the ACME server-auth
//! listener on the catalog ACME port. A real instant-acme client drives the
//! full RFC 8555 flow: newAccount → newOrder → dns-01 challenge → TXT
//! published through the Windows daemon's authenticated API → cross-host
//! observation by dig from the Linux member → challenge ready → finalize →
//! issued chain verified to the run CA → the identity recorded in the
//! certmesh roster as a client member.
//!
//! Built on [`crate::windows_daemon::WindowsLabDaemon`] (evidence doctrine:
//! the daemon's own log rides any failure). Gated on elevation,
//! `--allow-system-mutation`, and the catalog firewall grant.

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsAcmeReport};
use crate::windows_daemon::{WindowsDaemonCapabilities, WindowsLabDaemon};

#[derive(Default)]
struct AcmeResources {
    daemon: Option<WindowsLabDaemon>,
    member_daemon: bool,
    firewall_rules: Vec<String>,
    ca_created: bool,
    token: Option<String>,
    txt_name: Option<String>,
}

impl Lab {
    pub fn windows_acme(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsAcmeReport> {
        crate::lab::require_system_mutation(allow_system_mutation)?;
        crate::lab::ensure_windows_elevated()?;

        let windows = crate::planner::machine_by_id(self.config(), "windows")
            .context("catalog has no windows machine")?;
        if !windows.allows_mutation("firewall") {
            bail!(
                "the catalog does not grant firewall mutations to {}",
                windows.id()
            );
        }
        let member = crate::planner::machine_by_id(self.config(), member_id.unwrap_or("brook"))
            .context("catalog has no such member machine")?;
        if !matches!(member, crate::model::NodeSpec::PuttyLinux { .. }) {
            bail!("the W12 observer must be a physical Linux node");
        }

        let mut resources = AcmeResources::default();
        let result = self.run_windows_acme(run_id, windows, member, &mut resources);
        let cleanup = self.cleanup_windows_acme(run_id, member, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, both daemons, the CA, and the TXT record were removed",
                ));
                let path = output_path(run_id.as_str()).join("windows-acme.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(cleanup_error)) => {
                bail!("checks passed but exact cleanup failed: {cleanup_error:#}")
            }
            (Err(e), Err(cleanup_error)) => {
                bail!("{e:#}; compensating cleanup also failed: {cleanup_error:#}")
            }
        }
    }

    fn run_windows_acme(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut AcmeResources,
    ) -> Result<WindowsAcmeReport> {
        let artifact_sha256 = self
            .remote_line(
                member,
                &format!("cat {}/artifact.sha256", member.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the member")?;

        let ports = windows.lab_ports()?;
        let member_ports = member.lab_ports()?;

        // ── Firewall: the ACME listener is LAN-reachable (the client dials it) ──
        let mut daemon = WindowsLabDaemon::stage(self, run_id, ports)?;
        let exe = daemon.exe().to_path_buf();
        let acme_rule = format!("koi-lab w12 acme (tcp {})", ports.acme);
        let dns_rule = format!("koi-lab w12 dns (udp {})", 18653);
        crate::lab::firewall_rule(&acme_rule, "tcp", &ports.acme.to_string(), &exe)
            .with_context(|| format!("firewall rule {acme_rule}"))?;
        resources.firewall_rules.push(acme_rule);
        crate::lab::firewall_rule(&dns_rule, "udp", "18653", &exe)
            .with_context(|| format!("firewall rule {dns_rule}"))?;
        resources.firewall_rules.push(dns_rule);

        // ── Windows CA daemon (trust plane on: ACME listener is posture-reactive) ──
        let capabilities = WindowsDaemonCapabilities {
            dns_public_port: Some(18653),
            trust_plane: true,
            ..Default::default()
        };
        daemon
            .spawn(&capabilities)
            .context("start the Windows CA daemon")?;
        resources.daemon = Some(daemon);
        let windows_url = {
            let d = resources.daemon.as_ref().expect("daemon staged");
            d.http_url()
        };
        let windows_token = {
            let d = resources.daemon.as_ref().expect("daemon staged");
            self.require_windows_breadcrumb(d.root(), &windows_url)
                .context("read the Windows daemon breadcrumb")?
        };

        // ── Create the CA (posture flips; the trust plane mounts) ──
        let entropy = format!("{:x}", sha2::Sha256::digest(run_id.as_str().as_bytes()));
        curl_json(
            "POST",
            &format!("{windows_url}/v1/certmesh/create"),
            Some(&windows_token),
            Some(&serde_json::json!({
                "passphrase": format!("koi-lab-{}", run_id.as_str()),
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": true
            })),
        )
        .context("CA create on the Windows daemon")?;
        resources.ca_created = true;
        resources.token = Some(windows_token.clone());

        // ── Wait for the ACME listener (posture-reactive mount) ──
        let mut acme_listening = false;
        for _ in 0..60 {
            let probe = acme_listener_probe(ports.acme);
            if probe {
                acme_listening = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if !acme_listening {
            bail!(
                "ACME listener did not bind catalog port {} on Windows",
                ports.acme
            );
        }

        // ── Cross-host observer daemon (for the dig observation) ──
        self.start_story_daemon(member, run_id)
            .context("start the Linux member run daemon")?;
        resources.member_daemon = true;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{member_url}/healthz"))
            .context("Linux member daemon did not become healthy")?;

        // ── The real RFC 8555 flow ──
        let suffix = run_id
            .as_str()
            .rsplit('-')
            .next()
            .unwrap_or("w12")
            .to_ascii_lowercase();
        let name = format!("acme-w12-{suffix}.internal");
        let ca_pem_path = {
            let d = resources.daemon.as_ref().expect("daemon staged");
            d.root()
                .join("program-data")
                .join("koi")
                .join("ca-cert.pem")
        };
        // Fetch the Windows CA root for the ACME client's TLS trust.
        curl_json(
            "GET",
            &format!("{windows_url}/v1/certmesh/status"),
            Some(&windows_token),
            None,
        )
        .context("certmesh status")?;
        let ca_pem = self.windows_ca_pem(resources, run_id, &windows_token)?;
        // instant-acme's builder opens a PATH: persist the fetched root there.
        std::fs::write(&ca_pem_path, &ca_pem)
            .with_context(|| format!("could not persist {}", ca_pem_path.display()))?;

        // The koi-lab graph links both aws-lc-rs and ring; rustls 0.23 refuses
        // to guess, and instant-acme's client panics without a provider. The
        // daemon installs its own; the lab client installs the one actually
        // compiled into its rustls (aws-lc-rs, via instant-acme's features).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let runtime =
            tokio::runtime::Runtime::new().context("could not start the ACME client runtime")?;
        let directory = format!("https://{}:{}", windows.hostname(), ports.acme);
        let mut txt_published: Vec<String> = Vec::new();
        let issued = runtime.block_on(self.issue_windows_acme(
            &name,
            &directory,
            &ca_pem_path,
            &windows_url,
            &windows_token,
            member,
            member_ports.dns,
            windows.address(),
            &mut txt_published,
        ))?;
        resources.txt_name = txt_published.first().cloned();
        let fingerprint = verify_issued_chain(&issued.chain_pem, &ca_pem, &issued.name)?;

        // ── The identity must be recorded in the certmesh roster ──
        let status = curl_json(
            "GET",
            &format!("{windows_url}/v1/certmesh/status"),
            Some(&windows_token),
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
            bail!("the ACME-issued identity was not recorded in the Windows CA roster");
        }

        let w12_check = passed(
            "w12_acme_dns01_via_windows_dns",
            format!(
                "instant-acme issued {} through the Windows RFC 8555 server; the dns-01 \
                 TXT was served by the Windows DNS runtime and observed cross-host by \
                 dig from {}; the chain verified to the run CA and the identity landed \
                 in the roster",
                issued.name,
                member.id()
            ),
        );

        Ok(WindowsAcmeReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: "windows".into(),
            member_node: member.id().to_owned(),
            artifact_sha256,
            checks: vec![w12_check],
            secrets_redacted: true,
        })
    }

    fn windows_ca_pem(
        &self,
        resources: &mut AcmeResources,
        _run_id: &RunId,
        _token: &str,
    ) -> Result<String> {
        // The CA cert lives under the staged data dir (the daemon wrote it on
        // create); read it directly — same file the trust lanes use. Bounded
        // retry: the daemon may still be flushing the brand-new CA files.
        let path = resources
            .daemon
            .as_ref()
            .expect("daemon staged")
            .root()
            .join("data")
            .join("certmesh")
            .join("ca")
            .join("ca-cert.pem");
        let mut last = String::new();
        for _ in 0..20 {
            match std::fs::read_to_string(&path) {
                Ok(content) if !content.trim().is_empty() => return Ok(content),
                Ok(content) => last = format!("empty ca-cert.pem ({content})"),
                Err(e) => last = format!("{e}"),
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        bail!("could not read {}: {last}", path.display())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn issue_windows_acme(
        &self,
        name: &str,
        directory: &str,
        ca_pem_path: &std::path::Path,
        windows_url: &str,
        windows_token: &str,
        member: &crate::model::NodeSpec,
        member_dns_port: u16,
        windows_address: &str,
        txt_published: &mut Vec<String>,
    ) -> Result<IssuedAcmeCertificate> {
        let (account, _credentials): (Account, _) = Account::builder_with_root(ca_pem_path)
            .context("could not configure instant-acme with the Windows run CA")?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_owned(),
                None,
            )
            .await
            .context("instant-acme newAccount failed")?;

        let identifiers = [Identifier::Dns(name.to_owned())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("instant-acme newOrder failed")?;

        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result.context("instant-acme authorization failed")?;
                let mut challenge = authorization
                    .challenge(ChallengeType::Dns01)
                    .context("the ACME server did not offer dns-01")?;
                let identifier = challenge.identifier().to_string();
                let dns_name = format!("_acme-challenge.{identifier}");
                let value = challenge.key_authorization().dns_value();

                // TXT publication crosses the Windows daemon's authenticated API;
                // the daemon's own DNS runtime serves it (W6 machinery).
                curl_json(
                    "PUT",
                    &format!("{windows_url}/v1/dns/txt"),
                    Some(windows_token),
                    Some(&serde_json::json!({ "name": dns_name, "value": value })),
                )?;
                txt_published.push(dns_name.clone());

                // Cross-host observation: the member digs the Windows DNS server.
                let observed = self.remote_line(
                    member,
                    &format!(
                        "dig @{} -p {} {} TXT +short",
                        windows_address, member_dns_port, dns_name
                    ),
                )?;
                if !observed.lines().any(|line| line.trim_matches('"') == value) {
                    let _ = clear_txt(windows_url, windows_token, &dns_name, &value);
                    bail!(
                        "{} did not observe the ACME TXT value through the Windows DNS \
                         server: {observed:?}",
                        member.id()
                    );
                }

                let validation = challenge
                    .set_ready()
                    .await
                    .context("instant-acme challenge validation failed");
                let cleanup = clear_txt(windows_url, windows_token, &dns_name, &value);
                validation?;
                cleanup?;

                let after = self.remote_line(
                    member,
                    &format!(
                        "dig @{} -p {} {} TXT +short",
                        windows_address, member_dns_port, dns_name
                    ),
                )?;
                if !after.is_empty() {
                    bail!("the ACME TXT value remained after exact provider cleanup: {after:?}");
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

        Ok(IssuedAcmeCertificate {
            name: name.to_owned(),
            chain_pem,
        })
    }

    fn cleanup_windows_acme(
        &self,
        run_id: &RunId,
        member: &crate::model::NodeSpec,
        resources: &mut AcmeResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if let Some(name) = &resources.txt_name {
            // TXT cleanup is driven inline by the ACME flow; a leftover means
            // a mid-challenge abort — best-effort remove via the API.
            if let Some(daemon) = &resources.daemon {
                let _ = curl_json(
                    "DELETE",
                    &format!("{}/v1/dns/txt", daemon.http_url()),
                    Some(&resources.token.clone().unwrap_or_default()),
                    Some(&serde_json::json!({ "name": name, "value": "" })),
                );
            }
        }
        if resources.member_daemon {
            if let Err(e) = self.stop_webhook_daemon(member, run_id) {
                errors.push(format!("stop member daemon: {e:#}"));
            }
            if let Err(e) = self.remove_webhook_sink_files(member, run_id) {
                errors.push(format!("remove member run files: {e:#}"));
            }
        }
        if let Some(mut daemon) = resources.daemon.take() {
            let evidence = daemon.evidence();
            if let Err(e) = daemon.stop() {
                errors.push(format!("stop Windows daemon: {e:#}"));
            }
            if let Err(e) = daemon.teardown(self, run_id) {
                errors.push(format!("{e:#}; daemon log: {evidence}"));
            }
        }
        if !resources.firewall_rules.is_empty() {
            if let Err(e) = crate::lab::firewall_rules_remove(&resources.firewall_rules) {
                errors.push(format!("{e:#}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleanup errors: {}", errors.join("; "))
        }
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
fn acme_listener_probe(port: u16) -> bool {
    // TCP connect probe for the ACME listener.
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(500),
    )
    .is_ok()
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}
