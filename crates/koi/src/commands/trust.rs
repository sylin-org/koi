//! `koi trust` — thin presentation/composition over the Trust domain.
//!
//! Platform effects, ownership state, journaling, recovery, status, and events
//! live in `koi-trust`. This module only reads CLI inputs, composes Certmesh's
//! CA query where requested, and renders stable output DTOs.

use std::path::Path;

use anyhow::Context;
use koi_common::diagnosis::{DiagnosisCheck, TrustDiagnosis};
use koi_trust::{InstallRoot, TrustCore, TrustMutation, TrustPresence, TrustRecovery, TrustStatus};

use crate::commands::{decode_response, print_json, with_mode, Mode};

const CERTMESH_ROOT_NAME: &str = "koi-certmesh-ca";
const CERTMESH_ROOT_SOURCE: &str = "certmesh";

#[derive(serde::Serialize)]
struct TrustEntryOutput<'a> {
    name: &'a str,
    installed_at: &'a str,
    fingerprint: &'a str,
    source: &'a str,
    presence: &'a TrustPresence,
}

/// Open an isolated Trust owner only after the top-level mode selector has
/// positively established explicit standalone ownership.
async fn standalone_trust_core(data_dir: &Path) -> anyhow::Result<TrustCore> {
    TrustCore::open(data_dir.to_path_buf())
        .await
        .context("opening the standalone Trust domain")
}

pub async fn install(
    pem_path: &Path,
    json: bool,
    data_dir: &Path,
    mode: Mode,
) -> anyhow::Result<()> {
    let pem = std::fs::read_to_string(pem_path)
        .with_context(|| format!("reading certificate file {}", pem_path.display()))?;
    let name = derive_name(pem_path);
    let source = pem_path.display().to_string();
    let local_request = InstallRoot {
        name: name.clone(),
        source: source.clone(),
        certificate_pem: pem.clone(),
    };
    let client_name = name.clone();
    let client_source = source.clone();
    let client_pem = pem.clone();
    let mutation: TrustMutation = with_mode(
        mode,
        || async move {
            Ok(standalone_trust_core(data_dir)
                .await?
                .install(local_request)
                .await?)
        },
        |client| async move {
            decode_response(
                client.trust_install(&client_name, &client_source, &client_pem)?,
                "Trust install",
            )
        },
    )
    .await?;
    let fingerprint = mutation
        .fingerprint
        .as_deref()
        .context("the Trust domain returned an install result without a certificate fingerprint")?;

    if json {
        print_json(&serde_json::json!({
            "installed": {
                "name": name,
                "fingerprint": fingerprint,
                "changed": mutation.changed,
                "warning": mutation.warning,
            }
        }))?;
    } else if mutation.changed {
        println!("Installed CA \"{name}\" (sha256: {fingerprint})");
        eprintln!("The CA is present in the OS trust store.");
        if let Some(warning) = mutation.warning {
            eprintln!("Warning: {warning}");
        }
    } else {
        println!("CA \"{name}\" is already present (sha256: {fingerprint}).");
    }
    Ok(())
}

pub async fn list(json: bool, data_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    let status: TrustStatus = with_mode(
        mode,
        || async move {
            let core = standalone_trust_core(data_dir).await?;
            Ok(core.status().as_ref().clone())
        },
        |client| async move { decode_response(client.trust_status()?, "Trust status") },
    )
    .await?;

    if json {
        let roots = status
            .roots
            .iter()
            .map(|root| TrustEntryOutput {
                name: &root.name,
                installed_at: &root.installed_at,
                fingerprint: &root.fingerprint,
                source: &root.source,
                presence: &root.presence,
            })
            .collect::<Vec<_>>();
        print_json(&serde_json::json!({ "roots": roots }))?;
        return Ok(());
    }

    if status.roots.is_empty() {
        println!("No Koi-installed CA roots.");
        return Ok(());
    }
    println!(
        "{:<28}  {:<20}  {:<12}  FINGERPRINT (sha256)",
        "NAME", "INSTALLED", "PRESENCE"
    );
    for root in &status.roots {
        let fingerprint = format!(
            "{}...",
            root.fingerprint.chars().take(16).collect::<String>()
        );
        let presence = match root.presence {
            TrustPresence::Present => "present",
            TrustPresence::Missing => "missing",
            TrustPresence::Unavailable { .. } => "unavailable",
        };
        println!(
            "{:<28}  {:<20}  {:<12}  {fingerprint}",
            root.name, root.installed_at, presence
        );
    }
    Ok(())
}

pub async fn remove(name: &str, json: bool, data_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    let mutation: TrustMutation = with_mode(
        mode,
        || async move { Ok(standalone_trust_core(data_dir).await?.remove(name).await?) },
        |client| async move { decode_response(client.trust_remove(name)?, "Trust remove") },
    )
    .await?;
    if json {
        print_json(&serde_json::json!({
            "removed": name,
            "fingerprint": mutation.fingerprint,
            "changed": mutation.changed,
        }))?;
    } else {
        println!("Removed CA \"{name}\" from the OS trust store.");
    }
    Ok(())
}

/// Export stays a Certmesh query. One selected mode owns the whole command;
/// client failure is never permission to inspect local persistence instead.
pub async fn export(ca: bool, _json: bool, data_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    if !ca {
        anyhow::bail!(
            "specify what to export: `koi trust export --ca` prints the certmesh root CA"
        );
    }
    let pem = certmesh_ca_pem(mode, data_dir)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no Certmesh CA exists; run `koi certmesh create` first"))?;
    print!("{pem}");
    Ok(())
}

pub async fn diagnose(fix: bool, json: bool, data_dir: &Path, mode: Mode) -> anyhow::Result<()> {
    let mut owner = with_mode(
        mode,
        || diagnose_standalone(fix, data_dir),
        |client| async move { diagnose_client(fix, &client).await },
    )
    .await?;

    // Diagnosis is a read unless the operator explicitly supplies `--fix`.
    // Only that selected-owner command path may replay or install Trust state.
    if fix {
        if owner.ca_pem.is_some() {
            let ensured = owner
                .ensured
                .take()
                .context("the selected Trust owner did not return a CA repair result")?;
            match ensured {
                Ok(result) => {
                    let fingerprint = result.fingerprint.as_deref().context(
                        "the Trust domain returned an ensure result without a certificate fingerprint",
                    )?;
                    eprintln!(
                        "Fixed: mesh CA is present in the OS trust store (sha256: {fingerprint})."
                    );
                    if let Some(warning) = result.warning {
                        eprintln!("Warning: {warning}");
                    }
                }
                Err(error) => eprintln!("--fix: could not install the mesh CA: {error}"),
            }
        } else {
            eprintln!("--fix: no Certmesh CA anchor exists on this node.");
        }
    }

    owner
        .diagnosis
        .checks
        .push(transition_check(&owner.trust_status, owner.recovery));
    owner
        .diagnosis
        .checks
        .push(ca_presence_check(owner.ca_pem.is_some(), owner.presence));
    owner.diagnosis = TrustDiagnosis::from_checks(owner.diagnosis.posture, owner.diagnosis.checks);

    if json {
        print_json(&owner.diagnosis)?;
    } else {
        print!("{}", crate::format::trust_diagnosis(&owner.diagnosis));
    }
    if owner.diagnosis.is_red() {
        std::process::exit(owner.diagnosis.exit_code());
    }
    Ok(())
}

fn transition_check(
    status: &TrustStatus,
    recovery: Option<Result<TrustRecovery, String>>,
) -> DiagnosisCheck {
    match recovery {
        Some(Ok(TrustRecovery::Clean)) => DiagnosisCheck::ok(
            "os_trust_transition",
            "no pending OS trust-store transition",
        ),
        Some(Ok(TrustRecovery::Recovered {
            operation, name, ..
        })) => DiagnosisCheck::ok(
            "os_trust_transition",
            format!("recovered pending {operation:?} for {name}"),
        ),
        Some(Err(error)) => DiagnosisCheck::red(
            "os_trust_transition",
            status.last_error.clone().unwrap_or(error),
        )
        .with_remedy("rerun `koi trust diagnose --fix` from an elevated shell"),
        None => {
            if let Some(pending) = &status.pending {
                DiagnosisCheck::red(
                    "os_trust_transition",
                    format!(
                        "pending {:?} for {} has not been replayed",
                        pending.operation, pending.name
                    ),
                )
                .with_remedy("run `koi trust diagnose --fix` from an elevated shell")
            } else {
                DiagnosisCheck::ok(
                    "os_trust_transition",
                    "no pending OS trust-store transition",
                )
            }
        }
    }
}

fn ca_presence_check(
    ca_exists: bool,
    presence: Option<Result<TrustPresence, String>>,
) -> DiagnosisCheck {
    if !ca_exists {
        return DiagnosisCheck::not_applicable(
            "ca_trust_presence",
            "no Certmesh CA anchor exists on this node",
        );
    }
    let Some(presence) = presence else {
        return DiagnosisCheck::red(
            "ca_trust_presence",
            "the selected Trust owner returned no CA presence result",
        );
    };
    match presence {
        Ok(TrustPresence::Present) => DiagnosisCheck::ok(
            "ca_trust_presence",
            "the Certmesh CA is present in the OS trust store",
        ),
        Ok(TrustPresence::Missing) => DiagnosisCheck::warn(
            "ca_trust_presence",
            "the Certmesh CA is not present in the OS trust store",
        )
        .with_remedy("install it: `koi trust diagnose --fix`"),
        Ok(TrustPresence::Unavailable { reason }) => DiagnosisCheck::warn(
            "ca_trust_presence",
            format!("OS trust-store presence could not be inspected: {reason}"),
        )
        .with_remedy("retry from an elevated shell: `koi trust diagnose --fix`"),
        Err(reason) => DiagnosisCheck::red(
            "ca_trust_presence",
            format!("the Certmesh CA presence query failed: {reason}"),
        ),
    }
}

struct DiagnosisOwnerState {
    diagnosis: TrustDiagnosis,
    ca_pem: Option<String>,
    trust_status: TrustStatus,
    recovery: Option<Result<TrustRecovery, String>>,
    ensured: Option<Result<TrustMutation, String>>,
    presence: Option<Result<TrustPresence, String>>,
}

async fn diagnose_standalone(fix: bool, data_dir: &Path) -> anyhow::Result<DiagnosisOwnerState> {
    let trust = standalone_trust_core(data_dir).await?;
    let observation = standalone_certmesh_observation(data_dir).await?;
    let diagnosis = observation.diagnosis().clone();
    let ca_pem = observation.ca_certificate_pem().map(str::to_string);
    let recovery = if fix {
        Some(trust.reconcile().await.map_err(|error| error.to_string()))
    } else {
        None
    };
    let ensured = if fix {
        match ca_pem.as_ref() {
            Some(certificate_pem) => Some(
                trust
                    .ensure_installed(InstallRoot {
                        name: CERTMESH_ROOT_NAME.to_string(),
                        source: CERTMESH_ROOT_SOURCE.to_string(),
                        certificate_pem: certificate_pem.clone(),
                    })
                    .await
                    .map_err(|error| error.to_string()),
            ),
            None => None,
        }
    } else {
        None
    };
    let presence = match ca_pem.as_deref() {
        Some(certificate_pem) => Some(
            trust
                .inspect(certificate_pem)
                .await
                .map_err(|error| error.to_string()),
        ),
        None => None,
    };
    Ok(DiagnosisOwnerState {
        diagnosis,
        ca_pem,
        trust_status: trust.status().as_ref().clone(),
        recovery,
        ensured,
        presence,
    })
}

async fn diagnose_client(
    fix: bool,
    client: &koi_client::KoiClient,
) -> anyhow::Result<DiagnosisOwnerState> {
    let diagnosis = decode_response(client.certmesh_diagnosis()?, "Certmesh diagnosis")?;
    let ca_pem = remote_certmesh_ca_pem(client)?;
    let recovery = fix.then(|| {
        client
            .trust_reconcile()
            .map_err(|error| error.to_string())
            .and_then(|response| {
                decode_response(response, "Trust recovery").map_err(|error| error.to_string())
            })
    });
    let ensured = if fix {
        ca_pem.as_deref().map(|certificate_pem| {
            client
                .trust_ensure_installed(CERTMESH_ROOT_NAME, CERTMESH_ROOT_SOURCE, certificate_pem)
                .map_err(|error| error.to_string())
                .and_then(|response| {
                    decode_response(response, "Trust ensure").map_err(|error| error.to_string())
                })
        })
    } else {
        None
    };
    let trust_status = decode_response(client.trust_status()?, "Trust status")?;
    let presence = ca_pem.as_deref().map(|certificate_pem| {
        client
            .trust_inspect(certificate_pem)
            .map_err(|error| error.to_string())
            .and_then(|response| {
                decode_response(response, "Trust presence").map_err(|error| error.to_string())
            })
    });
    Ok(DiagnosisOwnerState {
        diagnosis,
        ca_pem,
        trust_status,
        recovery,
        ensured,
        presence,
    })
}

async fn certmesh_ca_pem(mode: Mode, data_dir: &Path) -> anyhow::Result<Option<String>> {
    with_mode(
        mode,
        || async move {
            Ok(standalone_certmesh_observation(data_dir)
                .await?
                .ca_certificate_pem()
                .map(str::to_string))
        },
        |client| async move { remote_certmesh_ca_pem(&client) },
    )
    .await
}

fn remote_certmesh_ca_pem(client: &koi_client::KoiClient) -> anyhow::Result<Option<String>> {
    let Some(response) = client.certmesh_ca_certificate()? else {
        return Ok(None);
    };
    let response: koi_certmesh::protocol::CaCertificateResponse =
        decode_response(response, "Certmesh CA")?;
    if response.ca_cert_pem.trim().is_empty() {
        anyhow::bail!("the selected daemon returned an empty Certmesh CA certificate");
    }
    Ok(Some(response.ca_cert_pem))
}

async fn standalone_certmesh_observation(
    data_dir: &Path,
) -> anyhow::Result<koi_certmesh::CertmeshObservation> {
    let host = koi_compose::host::HostIdentity::observe()
        .context("observing the machine identity for local Certmesh state")?;
    let local_hostname = host.hostname().to_string();
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(data_dir.to_path_buf());
    tokio::task::spawn_blocking(move || {
        koi_certmesh::CertmeshObservation::read(&paths, &local_hostname)
    })
    .await
    .map_err(|error| anyhow::anyhow!("certmesh observation task: {error}"))?
    .context("observing local Certmesh state")
}

fn derive_name(pem_path: &Path) -> String {
    let stem = pem_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("koi-root");
    let sanitized = stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .replace("..", "-");
    let safe_stem = sanitized.trim_matches(|character: char| matches!(character, '-' | '_' | '.'));
    let name = format!("koi-{safe_stem}");
    if name.len() <= 4 {
        "koi-root".to_string()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    fn json_server_once(status: u16, body: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), server)
    }

    #[test]
    fn derives_safe_stable_names() {
        assert_eq!(derive_name(Path::new("./My Root:CA.pem")), "koi-My-Root-CA");
        assert_eq!(derive_name(Path::new("....pem")), "koi-root");
        assert!(!derive_name(Path::new("../root.pem")).contains(".."));
    }

    #[test]
    fn public_list_dto_cannot_gain_pem_by_aggregate_expansion() {
        let root = koi_trust::TrustRootStatus {
            name: "root".into(),
            installed_at: "now".into(),
            fingerprint: "abc".into(),
            source: "test".into(),
            presence: TrustPresence::Present,
            warning: None,
        };
        let json = serde_json::to_string(&TrustEntryOutput {
            name: &root.name,
            installed_at: &root.installed_at,
            fingerprint: &root.fingerprint,
            source: &root.source,
            presence: &root.presence,
        })
        .unwrap();
        assert!(!json.contains("certificate"));
        assert!(!json.contains("pem"));
    }

    #[tokio::test]
    async fn list_does_not_create_or_reconcile_trust_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "koi-cli-trust-list-{}",
            koi_common::id::generate_short_id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);

        list(true, &data_dir, Mode::Standalone).await.unwrap();

        assert!(
            !data_dir.exists(),
            "a read-only list must not create a lock or state directory"
        );
    }

    #[tokio::test]
    async fn standalone_certmesh_query_does_not_create_runtime_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "koi-cli-certmesh-observation-{}",
            koi_common::id::generate_short_id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);

        let observation = standalone_certmesh_observation(&data_dir).await.unwrap();

        assert_eq!(observation.status().role, koi_certmesh::CertmeshRole::Open);
        assert!(
            !data_dir.exists(),
            "an offline query must not initialize Certmesh or its credential vault"
        );
    }

    #[tokio::test]
    async fn client_list_uses_only_the_selected_daemon_and_strictly_decodes_status() {
        let data_dir = std::env::temp_dir().join(format!(
            "koi-cli-trust-client-list-{}",
            koi_common::id::generate_short_id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let body = serde_json::to_string(&TrustStatus::default()).unwrap();
        let (endpoint, request) = json_server_once(200, body);

        list(
            true,
            &data_dir,
            Mode::Client {
                endpoint,
                token: "owner-token".into(),
            },
        )
        .await
        .unwrap();

        let request = request.join().unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /v1/trust/status "));
        assert!(request.contains("x-koi-token: owner-token\r\n"));
        assert!(
            !data_dir.exists(),
            "client mode must not open a second local Trust owner"
        );

        let (endpoint, request) = json_server_once(200, "{}".into());
        let error = list(
            true,
            &data_dir,
            Mode::Client {
                endpoint,
                token: "owner-token".into(),
            },
        )
        .await
        .expect_err("missing Trust status fields must be rejected");
        assert!(error.to_string().contains("invalid Trust status response"));
        request.join().unwrap();
        assert!(!data_dir.exists());
    }

    #[tokio::test]
    async fn client_ca_query_never_falls_back_to_local_storage_on_owner_uncertainty() {
        let data_dir = std::env::temp_dir().join(format!(
            "koi-cli-trust-client-ca-{}",
            koi_common::id::generate_short_id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let (endpoint, request) = json_server_once(
            503,
            r#"{"error":"provider_unavailable","message":"owner uncertain"}"#.into(),
        );

        let error = certmesh_ca_pem(
            Mode::Client {
                endpoint,
                token: "owner-token".into(),
            },
            &data_dir,
        )
        .await
        .expect_err("selected-owner uncertainty must propagate");

        assert!(error.to_string().contains("owner uncertain"));
        let request = request.join().unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /v1/certmesh/ca-cert "));
        assert!(request.contains("x-koi-token: owner-token\r\n"));
        assert!(
            !data_dir.exists(),
            "client failure must not authorize an offline observation"
        );
    }
}
