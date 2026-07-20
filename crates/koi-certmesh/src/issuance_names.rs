//! Certificate-name policy for certmesh-issued identities.
//!
//! The configured Koi DNS zone enters certmesh once, at construction. Every
//! issuance path then asks this value object for the names it may place in a
//! certificate. Callers supply only genuine extras; they never synthesize the
//! hostname or its configured-zone FQDN themselves.

use std::net::IpAddr;

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{validate_hostname, CertmeshError};

const DEFAULT_ZONE: &str = "internal";
const MAX_EXTRA_SANS: usize = 16;

/// Immutable naming policy for certmesh-issued certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceNames {
    zone: String,
}

impl IssuanceNames {
    /// Validate and normalize a configured DNS zone.
    pub fn new(zone: &str) -> Result<Self, CertmeshError> {
        let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
        validate_hostname(&zone)?;
        Ok(Self { zone })
    }

    /// The normalized DNS zone used for issued FQDNs.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Authorize the standard member names plus bounded caller-provided extras.
    pub(crate) fn member_sans(
        &self,
        hostname: &str,
        extras: &[String],
    ) -> Result<Vec<String>, CertmeshError> {
        self.sans(hostname, extras, false)
    }

    /// Authorize the standard member names plus listener loopback identities.
    pub(crate) fn self_sans(
        &self,
        hostname: &str,
        extras: &[String],
    ) -> Result<Vec<String>, CertmeshError> {
        self.sans(hostname, extras, true)
    }

    fn sans(
        &self,
        hostname: &str,
        extras: &[String],
        include_loopback: bool,
    ) -> Result<Vec<String>, CertmeshError> {
        validate_hostname(hostname)?;
        let hostname = hostname.to_ascii_lowercase();
        let mut names = vec![hostname.clone(), format!("{hostname}.{}", self.zone)];

        let mut accepted_extras = 0;
        for extra in extras {
            let normalized = match extra.parse::<IpAddr>() {
                Ok(ip) => ip.to_string(),
                Err(_) => {
                    let dns = extra.to_ascii_lowercase();
                    validate_hostname(&dns)?;
                    dns
                }
            };
            if names.iter().any(|existing| existing == &normalized) {
                continue;
            }
            if accepted_extras == MAX_EXTRA_SANS {
                break;
            }
            names.push(normalized);
            accepted_extras += 1;
        }

        if include_loopback {
            push_unique(&mut names, "localhost".to_string());
            push_unique(&mut names, "127.0.0.1".to_string());
        }
        Ok(names)
    }

    /// Whether a PEM leaf contains every required DNS/IP SAN.
    pub(crate) fn certificate_covers(cert_pem: &str, required: &[String]) -> bool {
        let Ok(pem) = pem::parse(cert_pem) else {
            return false;
        };
        let Ok((_, cert)) = X509Certificate::from_der(pem.contents()) else {
            return false;
        };
        let Ok(Some(san)) = cert.subject_alternative_name() else {
            return false;
        };

        required.iter().all(|required_name| {
            san.value.general_names.iter().any(|actual| match actual {
                GeneralName::DNSName(dns) => dns.eq_ignore_ascii_case(required_name),
                GeneralName::IPAddress(bytes) => required_name
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip_bytes(ip).as_slice() == *bytes),
                _ => false,
            })
        })
    }
}

impl Default for IssuanceNames {
    fn default() -> Self {
        Self {
            zone: DEFAULT_ZONE.to_string(),
        }
    }
}

fn push_unique(names: &mut Vec<String>, name: String) {
    if !names.iter().any(|existing| existing == &name) {
        names.push(name);
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_zone_is_normalized_once() {
        let names = IssuanceNames::new(" Lab.Internal. ").unwrap();
        assert_eq!(names.zone(), "lab.internal");
        assert_eq!(
            names.member_sans("Node-A", &[]).unwrap(),
            ["node-a", "node-a.lab.internal"]
        );
    }

    #[test]
    fn extras_are_validated_deduplicated_and_bounded() {
        let names = IssuanceNames::default();
        let mut extras = vec![
            "NODE-A.INTERNAL".to_string(),
            "10.0.0.7".to_string(),
            "alias.internal".to_string(),
        ];
        extras.extend((0..20).map(|index| format!("extra-{index}.internal")));
        let sans = names.member_sans("node-a", &extras).unwrap();
        assert_eq!(
            sans[0..4],
            ["node-a", "node-a.internal", "10.0.0.7", "alias.internal"]
        );
        assert_eq!(sans.len(), 18); // two base names + sixteen bounded extras
        assert!(names.member_sans("node-a", &["*.internal".into()]).is_err());
    }

    #[test]
    fn self_names_add_loopback_at_the_policy_boundary() {
        let sans = IssuanceNames::new("internal")
            .unwrap()
            .self_sans("node-a", &[])
            .unwrap();
        assert_eq!(
            sans,
            ["node-a", "node-a.internal", "localhost", "127.0.0.1"]
        );
    }
}
