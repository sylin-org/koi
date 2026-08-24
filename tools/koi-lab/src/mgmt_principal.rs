//! Physical principal-identity scenario (ADR-026 / V1-08).
//!
//! The controller plays the **foreign caller**: it generates the principal's
//! keypair locally (rcgen, in-process), sends only the CSR to the CA node over
//! raw cross-host HTTP (the DAT-exempt join), and receives a clientAuth-only
//! leaf with an empty `service_key` — custody proved physically. The identity
//! is then staged run-owned onto the probe node, whose OpenSSL curl presents it
//! to the primary's mTLS management plane: a healthy principal completes an MCP
//! initialize over the real LAN; after revocation the same probe is refused 403
//! with the named reason. Non-privileged; exact cleanup on every path.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::Digest;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, MgmtPrincipalReport, NodeSpec, RunId, TrustRotation};

#[derive(Default)]
struct MgmtPrincipalResources {
    primary_daemon: bool,
    ca_created: bool,
    identity_staged: bool,
}

impl Lab {
    pub fn mgmt_principal(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<MgmtPrincipalReport> {
        if rotation == TrustRotation::WindowsClient {
            bail!("mgmt-principal requires one of the two physical Linux rotations");
        }
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("mgmt-principal refused: run does not own both staged node directories");
        }

        let roles = rotation.roles();
        let primary = self.remote_by_id(roles.ca)?;
        let probe_node = self.remote_by_id(roles.service)?;
        let mut resources = MgmtPrincipalResources::default();
        let result = self.run_mgmt_principal(run_id, rotation, primary, probe_node, &mut resources);
        let cleanup = self.cleanup_mgmt_principal(run_id, primary, probe_node, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "daemon and staged identity were removed by exact owned identity",
                ));
                let path = output_path(run_id.as_str())
                    .join(format!("mgmt-principal-{}.json", rotation.as_str()));
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("mgmt-principal checks passed but cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "mgmt-principal failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_mgmt_principal(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
        primary: &NodeSpec,
        probe_node: &NodeSpec,
        resources: &mut MgmtPrincipalResources,
    ) -> Result<MgmtPrincipalReport> {
        let artifact_sha256 = self.remote_line(
            primary,
            &format!("cat {}/artifact.sha256", primary.run_dir(run_id)?),
        )?;

        // ── Primary daemon + CA ──
        self.start_run_daemon(primary, run_id)?;
        resources.primary_daemon = true;
        let primary_url = self.node_url(primary)?;
        wait_for_http(&format!("{primary_url}/healthz"))
            .context("primary daemon did not become healthy")?;
        let token = self.daemon_token(primary, run_id)?;

        let entropy = format!("{:x}", sha2::Sha256::digest(run_id.as_str().as_bytes()));
        curl_json(
            "POST",
            &format!("{primary_url}/v1/certmesh/create"),
            Some(&token),
            Some(&serde_json::json!({
                "passphrase": format!("koi-lab-{}", run_id.as_str()),
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": true
            })),
        )
        .context("CA create failed")?;
        resources.ca_created = true;

        // ── Foreign-caller enrollment: local keygen, CSR-only wire ──
        let suffix: String = run_id
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(12)
            .collect();
        let principal = format!("agent-{suffix}");
        let invite = curl_json(
            "POST",
            &format!("{primary_url}/v1/certmesh/invite"),
            Some(&token),
            Some(&serde_json::json!({
                "hostname": principal,
                "ttl_mins": 30,
                "role": "client"
            })),
        )
        .context("client-bound invite mint failed")?;
        let invite_token = required_str(&invite, "token")?;

        let (key_pem, csr_pem) = generate_keypair_and_csr(&principal)
            .context("controller-local keypair/CSR generation failed")?;

        // Join over raw cross-host HTTP WITHOUT any token header — /join is the
        // one DAT-exempt mutation, and a foreign caller holds nothing else.
        let joined_raw = curl_json(
            "POST",
            &format!("{primary_url}/v1/certmesh/join"),
            None,
            Some(&serde_json::json!({
                "hostname": principal,
                "invite_token": invite_token,
                "csr": csr_pem,
                "sans": [principal],
                "role": "client"
            })),
        )
        .context("principal join over raw HTTP failed")?;
        let leaf_pem = required_str(&joined_raw, "service_cert")?;
        let ca_pem = required_str(&joined_raw, "ca_cert")?;
        let shipped_key = joined_raw
            .get("service_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let roster_role_ok = joined_raw
            .get("hostname")
            .and_then(Value::as_str)
            .map(|h| h == principal)
            .unwrap_or(false)
            && {
                let status = curl_json(
                    "GET",
                    &format!("{primary_url}/v1/certmesh/status"),
                    Some(&token),
                    None,
                )?;
                status["members"]
                    .as_array()
                    .and_then(|members| {
                        members.iter().find(|m| {
                            m.get("hostname").and_then(Value::as_str) == Some(principal.as_str())
                        })
                    })
                    .and_then(|m| m.get("role").and_then(Value::as_str))
                    .map(|role| role.eq_ignore_ascii_case("client"))
                    .unwrap_or(false)
            };

        // ── Healthy principal reaches the management plane across the LAN ──
        self.stage_principal_identity(probe_node, run_id, &leaf_pem, &key_pem, &ca_pem)?;
        resources.identity_staged = true;
        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "koi-lab-principal", "version": "0.0.0" }
            }
        });
        let probe_run_dir = probe_node.run_dir(run_id)?;
        let (healthy_status, healthy_body) = self.mtls_probe(
            probe_node,
            run_id,
            &mtls_probe_command(
                primary,
                &probe_run_dir,
                "POST",
                Some(&initialize.to_string()),
            ),
        )?;

        // ── Revocation closes the door immediately, with its name ──
        curl_json(
            "POST",
            &format!("{primary_url}/v1/certmesh/revoke"),
            Some(&token),
            Some(&serde_json::json!({
                "hostname": principal,
                "reason": "physical principal lifecycle proof",
                "operator": "koi-lab"
            })),
        )
        .context("principal revoke failed")?;
        let (revoked_status, revoked_body) = self.mtls_probe(
            probe_node,
            run_id,
            &mtls_probe_command(primary, &probe_run_dir, "GET", None),
        )?;

        wait_for_http(&format!("{primary_url}/healthz")).context("post-scenario health check")?;

        let mut checks = Vec::new();
        checks.push(check(
            shipped_key.is_empty(),
            "custody_key_never_shipped_by_ca",
            "the join response carried no private key; only the CSR ever left the controller"
                .to_string(),
        ));
        checks.push(check(
            roster_role_ok,
            "roster_records_client_role",
            format!("CA roster lists {principal} with role client"),
        ));
        checks.push(check(
            healthy_status == 200 && !healthy_body.contains("scope_violation"),
            "healthy_principal_reaches_mgmt_plane",
            format!(
                "cross-host MCP initialize over mTLS returned {healthy_status} from the MCP layer"
            ),
        ));
        checks.push(check(
            revoked_status == 403 && revoked_body.contains("revoked"),
            "revocation_closes_mgmt_plane_named_reason",
            format!("after revocation the same identity drew {revoked_status} naming its reason"),
        ));

        Ok(MgmtPrincipalReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            rotation,
            primary_node: primary.id().to_string(),
            probe_node: probe_node.id().to_string(),
            artifact_sha256,
            checks,
            secrets_redacted: true,
        })
    }

    fn cleanup_mgmt_principal(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        probe_node: &NodeSpec,
        resources: &mut MgmtPrincipalResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if resources.primary_daemon {
            if let Err(e) = self.stop_webhook_daemon(primary, run_id) {
                errors.push(format!("stop primary daemon: {e:#}"));
            }
        }
        if resources.identity_staged || resources.ca_created || resources.primary_daemon {
            if let Err(e) = self.remove_principal_identity_files(probe_node, run_id) {
                errors.push(format!("remove staged identity: {e:#}"));
            }
            if let Err(e) = self.remove_webhook_sink_files(primary, run_id) {
                errors.push(format!("remove primary run files: {e:#}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleanup errors: {}", errors.join("; "))
        }
    }
}

/// Build the remote OpenSSL-curl probe command. The JSON payload travels inside
/// single quotes (JSON never contains one); response body lands in the run dir.
///
/// The dial uses `--resolve` to map the leaf's **actual SAN** (`<host>.internal`)
/// onto the node's real LAN address: generic OpenSSL curl enforces hostname
/// verification (unlike Koi's own pinned-CA client, which deliberately relaxes
/// the name check), so the probe must present a name the certificate carries —
/// while still crossing the physical network to the pinned address.
fn mtls_probe_command(
    ca_node: &NodeSpec,
    run_dir: &str,
    method: &str,
    json_body: Option<&str>,
) -> String {
    let port = ca_node.lab_ports().expect("node lab ports").mtls;
    let fqdn = format!("{}.internal", ca_node.hostname());
    let mut cmd = format!(
        "set -eu; test -f {run_dir}/principal-key.pem; curl -sS --max-time 20 \
         --cert {run_dir}/principal-leaf.pem --key {run_dir}/principal-key.pem \
         --cacert {run_dir}/principal-ca.pem \
         --resolve {fqdn}:{port}:{addr} \
         -X {method} \
         -H 'content-type: application/json' \
         -H 'accept: application/json, text/event-stream' ",
        fqdn = fqdn,
        port = port,
        addr = ca_node.address(),
        method = method,
    );
    if let Some(body) = json_body {
        cmd.push_str(&format!("-d '{body}' "));
    }
    cmd.push_str(&format!(
        "-o {run_dir}/principal-probe.json -w '%{{http_code}}' https://{fqdn}:{port}/v1/mcp"
    ));
    cmd
}

/// Controller-local keypair + CSR generation (rcgen). Mirrors
/// `koi_certmesh::csr::generate_keypair_and_csr` without pulling certmesh into
/// the controller: the private key exists here first and crosses the wire to
/// the CA only as a signed CSR.
fn generate_keypair_and_csr(hostname: &str) -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

fn required_str(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("response omitted {key}"))
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}

fn check(condition: bool, name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    if condition {
        passed(name, detail)
    } else {
        CheckResult {
            name: name.into(),
            passed: false,
            detail: detail.into(),
        }
    }
}
