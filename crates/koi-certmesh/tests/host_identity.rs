//! Composition-owned host identity contract for the Certmesh boundary.

use koi_certmesh::{protocol::CreateCaRequest, CertmeshCore, CertmeshPaths};

fn request() -> CreateCaRequest {
    CreateCaRequest {
        passphrase: "host-identity-test-passphrase".into(),
        entropy_hex: "17".repeat(32),
        operator: None,
        enrollment_open: false,
        requires_approval: true,
        auto_unlock: false,
        totp_secret_hex: Some("23".repeat(20)),
    }
}

#[tokio::test]
async fn identity_creation_refuses_to_invent_an_ambient_hostname() {
    let root = tempfile::tempdir().expect("temporary Certmesh root");
    let paths = CertmeshPaths::with_data_dir(root.path().to_path_buf());
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());

    assert_eq!(core.configured_local_hostname(), None);
    let error = core.create(request()).await.expect_err("host is required");
    assert!(
        error
            .to_string()
            .contains("local hostname was not supplied"),
        "unexpected error: {error}"
    );
    assert!(
        !paths.is_ca_initialized(),
        "a rejected launch identity must have no durable side effects"
    );
}

#[test]
fn accepted_identity_is_normalized_once_and_cannot_change_after_sharing() {
    let root = tempfile::tempdir().expect("temporary Certmesh root");
    let core = CertmeshCore::uninitialized_with_paths(CertmeshPaths::with_data_dir(
        root.path().to_path_buf(),
    ))
    .with_local_hostname("accepted-host.")
    .expect("configure host identity");

    assert_eq!(
        core.configured_local_hostname().as_deref(),
        Some("accepted-host")
    );
    let shared = core.clone();
    let error = match core.with_local_hostname("different-host") {
        Ok(_) => panic!("shared identity must be immutable"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("cannot change"));
    assert_eq!(
        shared.configured_local_hostname().as_deref(),
        Some("accepted-host")
    );
}

#[test]
fn invalid_boot_identity_is_rejected_before_repository_recovery() {
    let root = tempfile::tempdir().expect("temporary Certmesh root");
    let data_dir = root.path().join("not-created");
    let paths = CertmeshPaths::with_data_dir(data_dir.clone());

    let error = match CertmeshCore::load_with_paths(paths, "internal", "invalid/host") {
        Ok(_) => panic!("invalid host identity must fail bootstrap"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("invalid characters"));
    assert!(
        !data_dir.exists(),
        "validation must precede durable repository work"
    );
}
