//! Architecture guard — mechanizes the crate dependency rules from CLAUDE.md §3 /
//! `.agentic/CONTEXT.md` ("Crate Dependency Graph" + "Domain Boundary Model").
//!
//! It parses every workspace member's `Cargo.toml` and asserts the layering:
//!
//! - **kernel** (`koi-common`) depends on no `koi-*` crate;
//! - **foundation** (`koi-config`, `koi-crypto`, `koi-truststore`) depends only on the
//!   kernel;
//! - **domain** crates (and the lean `koi-client`) depend only on the kernel +
//!   foundation — **never on another domain** (the boundary model);
//! - **composition** crates (`koi-dashboard`, `koi-embedded`, the `koi-net` binary) may
//!   depend on anything — they are the wiring layer.
//!
//! This locks in P06's kernel restoration (koi-common stays clean) and P0x's
//! koi-client decoupling, and turns "a domain accidentally depends on another domain"
//! from a discovered fiction into a failing test. Only the mdns-sd boundary was guarded
//! before. Adding a genuinely-new edge is intentional friction: update the class below.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Kernel,
    Foundation,
    Domain,
    Composition,
}

fn classify(pkg: &str) -> Option<Class> {
    Some(match pkg {
        "koi-common" => Class::Kernel,
        "koi-config" | "koi-crypto" | "koi-truststore" => Class::Foundation,
        // Domains + the lean blocking client (must not re-acquire a domain dependency).
        "koi-mdns" | "koi-dns" | "koi-health" | "koi-proxy" | "koi-udp" | "koi-runtime"
        | "koi-certmesh" | "koi-client" => Class::Domain,
        // Wiring layer.
        "koi-dashboard" | "koi-embedded" | "koi-net" => Class::Composition,
        _ => return None, // non-koi crates (e.g. command-surface) are out of scope
    })
}

const FOUNDATION: &[&str] = &["koi-config", "koi-crypto", "koi-truststore"];

/// `koi-*` dependency names declared in `[dependencies]` / `[target.*.dependencies]`
/// (NOT dev/build-dependencies, NOT `[features]`).
fn koi_deps(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            // A normal-dependency table is exactly `[dependencies]` or a target one
            // ending in `.dependencies]`. `[dev-dependencies]` / `[build-dependencies]`
            // end in `-dependencies]`, so they are excluded; `[features]` etc. too.
            in_deps = line == "[dependencies]" || line.ends_with(".dependencies]");
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The dependency key is the token before `=`, `.`, or whitespace.
        let key = line
            .split(|c: char| c == '=' || c == '.' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if key.starts_with("koi-") {
            deps.insert(key.to_string());
        }
    }
    deps
}

fn package_name(manifest: &str) -> Option<String> {
    let mut in_pkg = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_pkg = line == "[package]";
            continue;
        }
        if in_pkg {
            if let Some(rest) = line.strip_prefix("name") {
                if let Some(v) = rest.split('"').nth(1) {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

#[test]
fn dependency_graph_respects_the_layering_rules() {
    // crates/koi-common -> crates/
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-mdns").exists() {
        // Not in the workspace layout (e.g. a vendored single-crate build) — skip.
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let dir = entry.expect("dir entry").path();
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");
        let pkg = match package_name(&manifest) {
            Some(p) => p,
            None => continue,
        };
        let class = match classify(&pkg) {
            Some(c) => c,
            None => {
                // A new koi-* crate with no class would silently escape the guard.
                if pkg.starts_with("koi-") {
                    violations.push(format!(
                        "crate `{pkg}` is unclassified — add it to `classify()` in the architecture guard"
                    ));
                }
                continue;
            }
        };
        checked += 1;

        let deps = koi_deps(&manifest);
        for dep in &deps {
            let allowed = match class {
                Class::Kernel => false, // the kernel depends on no koi-* crate
                Class::Foundation => dep == "koi-common",
                Class::Domain => dep == "koi-common" || FOUNDATION.contains(&dep.as_str()),
                Class::Composition => true,
            };
            if !allowed {
                violations.push(format!(
                    "`{pkg}` ({class:?}) depends on `{dep}` — not allowed for its layer"
                ));
            }
        }
    }

    assert!(
        checked >= 14,
        "expected to check the full workspace, only saw {checked} koi crates"
    );
    assert!(
        violations.is_empty(),
        "crate dependency-graph violations (see CLAUDE.md §3):\n  - {}",
        violations.join("\n  - ")
    );
}
