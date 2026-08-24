//! Catalog-driven assignment planning (the role-matrix testbed core).
//!
//! Machines declare what they can run (`roles`) and what may be mutated on
//! them (`mutations`) in `lab.json`; scenarios declare what they need. The
//! planner enumerates every valid assignment — no host names in code, so
//! adding a machine is a data change.

use serde::Serialize;

use crate::model::{LabConfig, NodeSpec};

/// One generated two-role assignment (e.g. primary/probe, ca/member).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Pairing {
    pub primary: String,
    pub secondary: String,
}

/// Enumerate every ordered pairing of machines supporting `primary_role` and
/// `secondary_role` respectively. Deterministic: catalog order for the
/// primary, catalog order for the secondary. Self-pairings are excluded.
pub fn pairings(config: &LabConfig, primary_role: &str, secondary_role: &str) -> Vec<Pairing> {
    let mut out = Vec::new();
    for primary in &config.nodes {
        if !primary.supports_role(primary_role) {
            continue;
        }
        for secondary in &config.nodes {
            if std::ptr::eq(primary, secondary) || !secondary.supports_role(secondary_role) {
                continue;
            }
            out.push(Pairing {
                primary: primary.id().to_string(),
                secondary: secondary.id().to_string(),
            });
        }
    }
    out
}

/// Look up a machine by id (planner consumers resolve assignments this way).
pub fn machine_by_id<'a>(config: &'a LabConfig, id: &str) -> Option<&'a NodeSpec> {
    config.nodes.iter().find(|node| node.id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_config() -> LabConfig {
        let parsed: LabConfig = serde_json::from_value(json!({
            "schema": 2,
            "artifact": { "target": "t", "package": "p", "relative_path": "x" },
            "nodes": [
                { "kind": "putty_linux", "id": "brook", "hostname": "b", "address": "10.0.0.1",
                  "user": "u", "host_key": "SHA256:k", "architecture": "x86_64",
                  "remote_root": "/home/u/koi-test",
                  "http_port": 16541, "mtls_port": 16542, "acme_port": 16543,
                  "proxy_port": 16544, "dns_port": 16553, "fixture_port": 16554,
                  "container_port": 16555,
                  "roles": ["ca", "member", "observer", "sink"],
                  "mutations": ["trust-store", "systemd"],
                  "privilege": "dedicated-box" },
                { "kind": "putty_linux", "id": "granite", "hostname": "g", "address": "10.0.0.2",
                  "user": "u", "host_key": "SHA256:k", "architecture": "x86_64",
                  "remote_root": "/home/u/koi-test",
                  "http_port": 17541, "mtls_port": 17542, "acme_port": 17543,
                  "proxy_port": 17544, "dns_port": 17553, "fixture_port": 17554,
                  "container_port": 17555,
                  "roles": ["ca", "member", "observer", "sink"],
                  "mutations": ["trust-store", "systemd"],
                  "privilege": "dedicated-box" },
                { "kind": "putty_linux", "id": "test01", "hostname": "t", "address": "10.0.0.3",
                  "user": "u", "host_key": "SHA256:k", "architecture": "x86_64",
                  "remote_root": "/home/u/koi-test",
                  "http_port": 19441, "mtls_port": 19442, "acme_port": 19443,
                  "proxy_port": 19444, "dns_port": 19453, "fixture_port": 19454,
                  "container_port": 19455,
                  "roles": ["ca", "member", "observer", "sink"],
                  "mutations": [],
                  "privilege": "workstation",
                  "password_env": "KOI_TEST01_PASSWORD" },
                { "kind": "local_windows", "id": "windows", "hostname": "w",
                  "address": "10.0.0.4",
                  "http_port": 18541, "mtls_port": 18542, "acme_port": 18543,
                  "proxy_port": 18544, "dns_port": 18553, "fixture_port": 18554,
                  "container_port": 18555,
                  "roles": ["principal", "sdk-caller"],
                  "mutations": [],
                  "privilege": "workstation" }
            ]
        }))
        .expect("fixture catalog parses");
        parsed
    }

    #[test]
    fn pairings_enumerate_all_valid_ordered_combinations() {
        let config = fixture_config();
        // Three Linux hosts may play either side; the windows machine opts
        // into neither role.
        let pairs = pairings(&config, "ca", "member");
        assert_eq!(pairs.len(), 6, "3 hosts x 2 orderings");
        assert!(pairs.contains(&Pairing {
            primary: "brook".into(),
            secondary: "test01".into()
        }));
        assert!(pairs.contains(&Pairing {
            primary: "test01".into(),
            secondary: "brook".into()
        }));
        assert!(
            !pairs.iter().any(|p| p.primary == p.secondary),
            "a machine never pairs with itself"
        );
        assert!(
            !pairs
                .iter()
                .any(|p| p.primary == "windows" || p.secondary == "windows"),
            "windows declares no daemon roles yet"
        );
    }

    #[test]
    fn role_lists_gate_participation() {
        let config = fixture_config();
        // The windows machine declares only the caller-side principal role, so
        // principal×ca yields exactly the future SDK pairing shape: the
        // workstation calls, any Linux box plays CA.
        let pairs = pairings(&config, "principal", "ca");
        assert_eq!(pairs.len(), 3);
        assert!(pairs.iter().all(|p| p.primary == "windows"));
    }

    #[test]
    fn mutation_grants_are_per_machine() {
        let config = fixture_config();
        let brook = machine_by_id(&config, "brook").unwrap();
        let test01 = machine_by_id(&config, "test01").unwrap();
        assert!(brook.allows_mutation("trust-store"));
        assert!(
            !test01.allows_mutation("trust-store"),
            "workstation opts out"
        );
        assert_eq!(brook.privilege(), "dedicated-box");
        assert_eq!(test01.privilege(), "workstation");
        assert_eq!(test01.password_env(), Some("KOI_TEST01_PASSWORD"));
    }
}
