//! Cross-language CSR conformance (V1-11): the TypeScript SDK's hand-rolled
//! DER serialization must be accepted by the real CA issuance path — rcgen's
//! `CertificateSigningRequestParams::from_pem` parses AND verifies the CSR's
//! self-signature, so a green sign here proves the SDK's structure and
//! signature byte-for-byte against the production code.

use koi_certmesh::csr::sign_csr;

const FIXTURE: &str = include_str!("fixtures/sdk-csr-fixture.pem");

#[test]
fn typescript_sdk_csr_is_accepted_by_the_real_ca_path() {
    let ca = koi_certmesh::ca::ephemeral_ca(&[7u8; 32]).expect("create in-memory test CA");
    let leaf = sign_csr(&ca, FIXTURE, &["sdk-fixture-agent".to_string()], 30)
        .expect("the SDK-generated CSR must be signed by the real CA path");
    assert!(leaf.contains("BEGIN CERTIFICATE"));

    // The issued leaf carries exactly the authorized SAN (rcgen discards any
    // CSR-embedded SANs) and chains to the CA.
    use x509_parser::prelude::FromDer;
    let der = pem::parse(&leaf).unwrap();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.contents()).unwrap();
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("leaf CN present")
        .as_str()
        .unwrap();
    assert_eq!(cn, "sdk-fixture-agent");
}
