//! Architecture guard — mechanizes the crate dependency rules from CLAUDE.md §3 /
//! `.agentic/CONTEXT.md` ("Crate Dependency Graph" + "Domain Boundary Model").
//!
//! It parses every workspace member's `Cargo.toml` and asserts the layering:
//!
//! - **kernel** (`koi-common`) depends on no `koi-*` crate;
//! - **foundation** (`koi-config`, `koi-crypto`) depends only on the kernel;
//! - **domain** crates (and the lean `koi-client`) depend only on the kernel +
//!   foundation — **never on another domain** (the boundary model);
//! - **composition** crates (`koi-dashboard`, `koi-compose`, `koi-serve`, `koi-mcp`,
//!   `koi-embedded`, the `koi-net` binary) may depend on anything — the wiring/serving layer.
//!
//! This locks in P06's kernel restoration (koi-common stays clean) and P0x's
//! koi-client decoupling, and turns "a domain accidentally depends on another domain"
//! from a discovered fiction into a failing test. Only the mdns-sd boundary was guarded
//! before. Adding a genuinely-new edge is intentional friction: update the class below.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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
        "koi-config" | "koi-crypto" => Class::Foundation,
        // Domains + the lean blocking client (must not re-acquire a domain dependency).
        "koi-mdns" | "koi-dns" | "koi-health" | "koi-proxy" | "koi-udp" | "koi-runtime"
        | "koi-certmesh" | "koi-trust" | "koi-client" => Class::Domain,
        // Wiring layer. `koi-mcp` composes the koi-client surface into an MCP adapter,
        // so it is composition (it depends on koi-client, a domain-class crate).
        // `koi-serve` is the serving layer (transports + trust plane); it depends on
        // koi-compose + every domain it mounts, so it is composition too.
        "koi-dashboard" | "koi-compose" | "koi-serve" | "koi-embedded" | "koi-net" | "koi-mcp" => {
            Class::Composition
        }
        _ => return None, // non-koi crates are out of scope
    })
}

const FOUNDATION: &[&str] = &["koi-config", "koi-crypto"];

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

/// Walk a crate's production source tree. Integration tests, examples, and benches live
/// outside `src/`, while inline test modules are removed by [`production_rust_source`].
fn rust_sources(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, files);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();
    files
}

fn blank(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

/// Preserve Rust tokens and line positions while erasing comments and string literals.
/// This keeps architecture rules about API references from firing on prose or fixtures.
fn rust_code_mask(source: &str) -> String {
    let input = source.as_bytes();
    let mut output = input.to_vec();
    let mut index = 0;

    while index < input.len() {
        if input[index..].starts_with(b"//") {
            let end = input[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(input.len(), |offset| index + offset);
            blank(&mut output, index, end);
            index = end;
            continue;
        }

        if input[index..].starts_with(b"/*") {
            let start = index;
            index += 2;
            let mut depth = 1usize;
            while index < input.len() && depth > 0 {
                if input[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if input[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            blank(&mut output, start, index);
            continue;
        }

        // Raw strings (`r"..."`, `r#"..."#`) are recognized from their `r`; this
        // also handles byte/raw-C prefixes because the preceding `b`/`c` is harmless.
        if input[index] == b'r' {
            let mut quote = index + 1;
            while quote < input.len() && input[quote] == b'#' {
                quote += 1;
            }
            if quote < input.len() && input[quote] == b'"' {
                let hashes = quote - index - 1;
                let start = index;
                index = quote + 1;
                while index < input.len() {
                    if input[index] == b'"'
                        && index + 1 + hashes <= input.len()
                        && input[index + 1..index + 1 + hashes]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        index += hashes + 1;
                        break;
                    }
                    index += 1;
                }
                blank(&mut output, start, index);
                continue;
            }
        }

        if input[index] == b'"' {
            let start = index;
            index += 1;
            while index < input.len() {
                if input[index] == b'\\' {
                    index = (index + 2).min(input.len());
                } else if input[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            blank(&mut output, start, index);
            continue;
        }

        index += 1;
    }

    String::from_utf8(output).expect("mask preserves UTF-8")
}

fn cfg_possibilities(expression: &str) -> (bool, bool) {
    let compact = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();

    fn call_body<'a>(expression: &'a str, name: &str) -> Option<&'a str> {
        expression
            .strip_prefix(name)?
            .strip_prefix('(')?
            .strip_suffix(')')
    }

    fn arguments(body: &str) -> Vec<&str> {
        let mut depth = 0usize;
        let mut start = 0usize;
        let mut result = Vec::new();
        for (index, byte) in body.bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => {
                    result.push(&body[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        result.push(&body[start..]);
        result
    }

    if compact == "test" {
        // This scanner models a production build, where `cfg(test)` is false.
        return (true, false);
    }
    if let Some(body) = call_body(&compact, "all") {
        let values = arguments(body)
            .into_iter()
            .map(cfg_possibilities)
            .collect::<Vec<_>>();
        return (
            values.iter().any(|(can_be_false, _)| *can_be_false),
            values.iter().all(|(_, can_be_true)| *can_be_true),
        );
    }
    if let Some(body) = call_body(&compact, "any") {
        let values = arguments(body)
            .into_iter()
            .map(cfg_possibilities)
            .collect::<Vec<_>>();
        return (
            values.iter().all(|(can_be_false, _)| *can_be_false),
            values.iter().any(|(_, can_be_true)| *can_be_true),
        );
    }
    if let Some(body) = call_body(&compact, "not") {
        let (can_be_false, can_be_true) = cfg_possibilities(body);
        return (can_be_true, can_be_false);
    }

    // Target, feature, and platform predicates are unknown to this host-side scan.
    (true, true)
}

fn matching_delimiter(bytes: &[u8], open: usize, left: u8, right: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        if *byte == left {
            depth += 1;
        } else if *byte == right {
            depth -= 1;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

/// Erase items whose `cfg` cannot be true in a non-test build. The lexical mask lets us
/// balance delimiters without comments or literal braces interfering.
fn production_rust_source(source: &str) -> String {
    let mut code = rust_code_mask(source).into_bytes();
    let snapshot = code.clone();
    let mut index = 0usize;

    while index < snapshot.len() {
        if snapshot[index] != b'#' {
            index += 1;
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&snapshot, index + 1);
        if snapshot.get(cursor) != Some(&b'[') {
            index += 1;
            continue;
        }
        cursor = skip_ascii_whitespace(&snapshot, cursor + 1);
        if !snapshot[cursor..].starts_with(b"cfg") {
            index += 1;
            continue;
        }
        cursor = skip_ascii_whitespace(&snapshot, cursor + 3);
        if snapshot.get(cursor) != Some(&b'(') {
            index += 1;
            continue;
        }
        let Some(close_paren) = matching_delimiter(&snapshot, cursor, b'(', b')') else {
            break;
        };
        let close_bracket = skip_ascii_whitespace(&snapshot, close_paren + 1);
        if snapshot.get(close_bracket) != Some(&b']') {
            index += 1;
            continue;
        }
        let expression =
            std::str::from_utf8(&snapshot[cursor + 1..close_paren]).expect("Rust source is UTF-8");
        if cfg_possibilities(expression).1 {
            index = close_bracket + 1;
            continue;
        }

        let mut item_cursor = close_bracket + 1;
        let mut parentheses = 0usize;
        let mut brackets = 0usize;
        let item_end = loop {
            if item_cursor >= snapshot.len() {
                break snapshot.len();
            }
            match snapshot[item_cursor] {
                b'(' => parentheses += 1,
                b')' => parentheses = parentheses.saturating_sub(1),
                b'[' => brackets += 1,
                b']' => brackets = brackets.saturating_sub(1),
                b';' if parentheses == 0 && brackets == 0 => break item_cursor + 1,
                b'{' if parentheses == 0 && brackets == 0 => {
                    break matching_delimiter(&snapshot, item_cursor, b'{', b'}')
                        .map_or(snapshot.len(), |close| close + 1);
                }
                _ => {}
            }
            item_cursor += 1;
        };
        blank(&mut code, index, item_end);
        index = item_end;
    }

    String::from_utf8(code).expect("mask preserves UTF-8")
}

#[derive(Clone, Copy)]
struct RustToken<'a> {
    text: &'a str,
    offset: usize,
}

fn rust_tokens(source: &str) -> Vec<RustToken<'_>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(RustToken {
                text: &source[start..index],
                offset: start,
            });
        } else if bytes[index..].starts_with(b"::") {
            tokens.push(RustToken {
                text: "::",
                offset: index,
            });
            index += 2;
        } else if matches!(bytes[index], b'{' | b'}' | b';') {
            tokens.push(RustToken {
                text: &source[index..index + 1],
                offset: index,
            });
            index += 1;
        } else if bytes[index].is_ascii() {
            index += 1;
        } else {
            index += source[index..]
                .chars()
                .next()
                .expect("valid UTF-8")
                .len_utf8();
        }
    }
    tokens
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn braced_item<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing guarded item `{marker}`"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("guarded item `{marker}` has no body"));
    let close = matching_delimiter(source.as_bytes(), open, b'{', b'}')
        .unwrap_or_else(|| panic!("guarded item `{marker}` has an unclosed body"));
    &source[start..=close]
}

fn forbidden_root_modules(source: &str, root: &str, modules: &[&str]) -> Vec<(usize, String)> {
    let tokens = rust_tokens(source);
    let mut roots = BTreeSet::from([root.to_string()]);

    for window in tokens.windows(4) {
        if (window[0].text == "use" && window[1].text == root && window[2].text == "as")
            || (window[0].text == "extern"
                && window[1].text == "crate"
                && window[2].text == root
                && window.get(3).is_some_and(|token| token.text == "as"))
        {
            let alias = if window[0].text == "use" {
                window[3].text
            } else {
                // The four-token window only reaches `as`; the alias is handled below.
                continue;
            };
            roots.insert(alias.to_string());
        }
    }
    for window in tokens.windows(5) {
        if window[0].text == "extern"
            && window[1].text == "crate"
            && window[2].text == root
            && window[3].text == "as"
        {
            roots.insert(window[4].text.to_string());
        }
    }

    let mut found = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !roots.contains(token.text)
            || tokens.get(index + 1).map(|token| token.text) != Some("::")
        {
            continue;
        }
        let Some(next) = tokens.get(index + 2) else {
            continue;
        };
        if modules.contains(&next.text) {
            found.insert((
                line_at(source, next.offset),
                format!("{root}::{}", next.text),
            ));
            continue;
        }
        if next.text != "{" {
            continue;
        }

        let mut depth = 1usize;
        for grouped in &tokens[index + 3..] {
            match grouped.text {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                module if depth == 1 && modules.contains(&module) => {
                    found.insert((line_at(source, grouped.offset), format!("{root}::{module}")));
                }
                _ => {}
            }
        }
    }
    found.into_iter().collect()
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

#[test]
fn mdns_sd_rust_api_is_isolated_to_the_native_adapter() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let native_adapter = crates_dir.join("koi-mdns/src/native.rs");
    if !native_adapter.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut violations = Vec::new();
    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let src = entry.expect("dir entry").path().join("src");
        for path in rust_sources(&src) {
            if path == native_adapter {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read Rust source");
            let production = production_rust_source(&source);
            for token in rust_tokens(&production)
                .into_iter()
                .filter(|token| token.text == "mdns_sd")
            {
                violations.push(format!(
                    "{}:{} references `mdns_sd` outside koi-mdns's native adapter",
                    path.strip_prefix(crates_dir).unwrap_or(&path).display(),
                    line_at(&production, token.offset)
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "mDNS native-adapter boundary violations (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn os_hostname_observation_stays_at_explicit_adapter_boundaries() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let host_boundary = crates_dir.join("koi-compose/src/host.rs");
    let native_provider = crates_dir.join("koi-mdns/src/native.rs");
    if !host_boundary.exists() || !native_provider.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut violations = Vec::new();
    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let src = entry.expect("dir entry").path().join("src");
        for path in rust_sources(&src) {
            if path == host_boundary || path == native_provider {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read Rust source");
            let production = production_rust_source(&source);
            for window in rust_tokens(&production).windows(3) {
                if window[0].text == "hostname" && window[1].text == "::" && window[2].text == "get"
                {
                    violations.push(format!(
                        "{}:{} observes the OS hostname outside HostIdentity/provider assessment",
                        path.strip_prefix(crates_dir).unwrap_or(&path).display(),
                        line_at(&production, window[0].offset)
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "machine identity escaped its explicit boundaries (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn os_truststore_api_is_isolated_to_the_trust_domain() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-trust").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut violations = Vec::new();
    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let dir = entry.expect("dir entry").path();
        if dir.file_name().and_then(|name| name.to_str()) == Some("koi-trust") {
            continue;
        }
        for path in rust_sources(&dir.join("src")) {
            let source = fs::read_to_string(&path).expect("read Rust source");
            let production = production_rust_source(&source);
            for token in rust_tokens(&production)
                .into_iter()
                .filter(|token| token.text == "os_truststore")
            {
                violations.push(format!(
                    "{}:{} references `os_truststore` outside the Trust domain",
                    path.strip_prefix(crates_dir).unwrap_or(&path).display(),
                    line_at(&production, token.offset)
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OS trust-store adapter boundary violations (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn composition_does_not_read_domain_private_persistence() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-compose").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let forbidden = [
        (
            "koi_certmesh",
            &["roster", "ca", "vault", "audit", "repository"][..],
        ),
        ("koi_proxy", &["config"][..]),
    ];
    let mut violations = Vec::new();

    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let dir = entry.expect("dir entry").path();
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");
        let Some(package) = package_name(&manifest) else {
            continue;
        };
        if classify(&package) != Some(Class::Composition) {
            continue;
        }

        for path in rust_sources(&dir.join("src")) {
            let source = fs::read_to_string(&path).expect("read Rust source");
            let production = production_rust_source(&source);
            for (root, modules) in forbidden {
                for (line, reference) in forbidden_root_modules(&production, root, modules) {
                    violations.push(format!(
                        "{}:{line} imports domain-private `{reference}`",
                        path.strip_prefix(crates_dir).unwrap_or(&path).display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "domain persistence escaped into composition/presentation (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn certmesh_storage_root_does_not_escape_its_domain() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-certmesh").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut violations = Vec::new();
    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let dir = entry.expect("dir entry").path();
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");
        let Some(package) = package_name(&manifest) else {
            continue;
        };
        // Certmesh is the only domain allowed to own the storage this retired
        // helper named. Scanning koi-common prevents the broad helper from
        // being recreated at the kernel boundary.
        if package == "koi-certmesh" {
            continue;
        }

        for path in rust_sources(&dir.join("src")) {
            let source = fs::read_to_string(&path).expect("read Rust source");
            let production = production_rust_source(&source);
            for token in rust_tokens(&production)
                .into_iter()
                .filter(|token| token.text == "koi_certs_dir")
            {
                violations.push(format!(
                    "{}:{} references Certmesh's storage root",
                    path.strip_prefix(crates_dir).unwrap_or(&path).display(),
                    line_at(&production, token.offset)
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Certmesh persistence escaped its domain; use a typed integration port (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn runtime_orchestration_consumes_authoritative_status_not_events() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let path = crates_dir.join("koi-compose/src/orchestrator.rs");
    if !path.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }
    let source = fs::read_to_string(&path).expect("read runtime orchestrator");
    let production = production_rust_source(&source);
    let tokens = rust_tokens(&production);

    assert!(
        tokens.iter().all(|token| token.text != "RuntimeEvent"),
        "runtime orchestrator must reconcile RuntimeStatus; RuntimeEvent is best-effort history"
    );
    assert!(
        tokens.iter().any(|token| token.text == "watch_status"),
        "runtime orchestrator must subscribe to the authoritative RuntimeStatus feed"
    );
}

#[test]
fn cli_status_cannot_reconstruct_or_repair_domain_truth() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let path = crates_dir.join("koi/src/commands/status.rs");
    if !path.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }
    let source = fs::read_to_string(&path).expect("read CLI status handler");
    let production = production_rust_source(&source);
    let forbidden = [
        "TrustCore",
        "reconcile",
        "recover_pending",
        "Config",
        "data_dir",
        "fs",
        "File",
        "OpenOptions",
    ];
    let violations = rust_tokens(&production)
        .into_iter()
        .filter(|token| forbidden.contains(&token.text))
        .map(|token| {
            format!(
                "{}:{} references `{}`",
                path.strip_prefix(crates_dir).unwrap_or(&path).display(),
                line_at(&production, token.offset),
                token.text
            )
        })
        .collect::<Vec<_>>();

    assert!(
        production.contains("koi_compose::status::CAPABILITY_LADDER"),
        "offline CLI status must preserve the composition-owned product ladder"
    );
    assert!(
        violations.is_empty(),
        "CLI status reconstructed or repaired domain state (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn cli_trust_uses_one_selected_owner_and_observation_only_in_standalone() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let cli_path = crates_dir.join("koi/src/commands/trust.rs");
    if !cli_path.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let cli = production_rust_source(&fs::read_to_string(&cli_path).expect("read Trust CLI"));
    let mut violations = Vec::new();
    for marker in [
        "pub async fn export",
        "pub async fn diagnose",
        "async fn diagnose_standalone",
        "async fn certmesh_ca_pem",
        "async fn standalone_certmesh_observation",
    ] {
        let body = braced_item(&cli, marker);
        for token in rust_tokens(body).into_iter().filter(|token| {
            let forbidden = [
                "CertmeshCore",
                "init_certmesh_core",
                "load_with_paths",
                "recover",
                "retry_credential_cleanups",
                "read_auto_unlock_key",
                "Vault",
                "koi_compose",
                "fs",
                "File",
                "OpenOptions",
            ];
            forbidden.contains(&token.text)
                && !(marker == "async fn standalone_certmesh_observation"
                    && token.text == "koi_compose")
        }) {
            violations.push(format!(
                "CLI `{marker}`:{} references `{}`",
                line_at(body, token.offset),
                token.text
            ));
        }
    }

    let offline = braced_item(&cli, "async fn standalone_certmesh_observation");
    assert!(
        offline.contains("CertmeshObservation::read")
            && offline.contains("koi_compose::host::HostIdentity::observe"),
        "offline Trust queries must cross Certmesh's typed observation boundary with one explicitly observed host identity"
    );
    assert!(
        braced_item(&cli, "async fn diagnose_standalone")
            .contains("standalone_certmesh_observation")
            && braced_item(&cli, "async fn certmesh_ca_pem")
                .contains("standalone_certmesh_observation"),
        "standalone diagnose and export must share the Certmesh observation boundary"
    );

    let standalone_core = braced_item(&cli, "async fn standalone_trust_core");
    assert!(
        standalone_core.contains("TrustCore::open") && cli.matches("TrustCore::open").count() == 1,
        "the CLI may open Trust only inside its explicit standalone owner"
    );
    assert!(
        !cli.contains("KoiClient::from_local") && !cli.contains(".health()"),
        "Trust commands must use the already-selected Mode, never probe and fall back per call"
    );
    assert!(
        braced_item(&cli, "pub async fn diagnose").contains("with_mode")
            && braced_item(&cli, "async fn diagnose_client").contains("certmesh_diagnosis")
            && braced_item(&cli, "async fn diagnose_client").contains("trust_status"),
        "Trust diagnosis must keep Certmesh and Trust queries on one selected owner"
    );

    let dispatch_path = crates_dir.join("koi/src/dispatch.rs");
    let dispatch = production_rust_source(
        &fs::read_to_string(dispatch_path).expect("read command dispatch boundary"),
    );
    let trust_dispatch = braced_item(&dispatch, "Command::Trust(trust_cmd)");
    assert!(
        trust_dispatch.contains("detect_mode")
            && trust_dispatch.contains("commands::trust::install")
            && trust_dispatch.contains("commands::trust::diagnose"),
        "Trust dispatch must select Mode before entering every command"
    );

    let observation_path = crates_dir.join("koi-certmesh/src/observation.rs");
    let observation = production_rust_source(
        &fs::read_to_string(&observation_path).expect("read Certmesh observation boundary"),
    );
    let observation_read = braced_item(&observation, "pub fn read(paths");
    let observation_project = braced_item(&observation, "fn project(paths");
    assert!(
        observation_project.contains("status::build")
            && observation_project.contains("status::observe_ca_anchor"),
        "offline observation must reuse Certmesh's canonical status and CA projections"
    );
    for token in rust_tokens(observation_read)
        .into_iter()
        .chain(rust_tokens(observation_project))
        .filter(|token| {
            [
                "recover",
                "commit",
                "retry_credential_cleanups",
                "read_auto_unlock_key",
                "machine_binding_ok",
                "Vault",
                "write",
                "create_dir",
                "create_dir_all",
                "remove_file",
                "remove_dir",
                "remove_dir_all",
            ]
            .contains(&token.text)
        })
    {
        violations.push(format!(
            "Certmesh observation:{} references mutating bootstrap `{}`",
            line_at(&observation, token.offset),
            token.text
        ));
    }

    let repository_path = crates_dir.join("koi-certmesh/src/repository.rs");
    let repository =
        rust_code_mask(&fs::read_to_string(&repository_path).expect("read Certmesh repository"));
    let fence = braced_item(&repository, "pub(crate) fn observe<R>");
    for token in rust_tokens(fence).into_iter().filter(|token| {
        [
            "recover",
            "commit",
            "write",
            "create_dir",
            "create_dir_all",
            "remove_file",
            "remove_dir",
            "remove_dir_all",
        ]
        .contains(&token.text)
    }) {
        violations.push(format!(
            "Certmesh observation fence:{} references mutation `{}`",
            line_at(fence, token.offset),
            token.text
        ));
    }

    assert!(
        violations.is_empty(),
        "offline Trust query crossed a mutating Certmesh boundary (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn prometheus_and_dashboard_presentations_cannot_reread_domain_cores() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-serve").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let read_production = |relative: &str| {
        let path = crates_dir.join(relative);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        production_rust_source(&source)
    };

    let prometheus_projector = read_production("koi-serve/src/prometheus_sd.rs");
    let dashboard_projector = read_production("koi-compose/src/snapshot.rs");
    let dashboard_wiring = read_production("koi-serve/src/dashboard.rs");
    let http = read_production("koi-serve/src/http.rs");
    let prometheus_handler = braced_item(&http, "async fn prometheus_sd_handler");

    // These adapters may import domain-owned data-only status types, but must not
    // acquire a live domain facade or call a domain query/snapshot method. Their
    // complete input is one already-accepted KoiStatus revision (ADR-043).
    let forbidden_identifiers = [
        "MdnsCore",
        "DnsCore",
        "DnsRuntime",
        "HealthCore",
        "HealthRuntime",
        "CertmeshCore",
        "ProxyCore",
        "ProxyRuntime",
        "RuntimeCore",
        "UdpRuntime",
        "CertmeshBridge",
        "list_instances",
        "discovery_snapshot",
        "roster_snapshot",
        "mdns_snapshot",
        "watch_status",
        "watch_snapshot",
        "local_identity",
    ];
    let mut violations = Vec::new();
    for (label, source) in [
        ("Prometheus projector", prometheus_projector.as_str()),
        ("Prometheus handler", prometheus_handler),
        ("dashboard projector", dashboard_projector.as_str()),
        ("dashboard wiring", dashboard_wiring.as_str()),
    ] {
        for token in rust_tokens(source)
            .into_iter()
            .filter(|token| forbidden_identifiers.contains(&token.text))
        {
            violations.push(format!(
                "{label}:{} directly references `{}`",
                line_at(source, token.offset),
                token.text
            ));
        }
    }

    // The wiring structs legitimately contain other domain fields for unrelated
    // routes. Pin only these presentation bodies against reaching through them.
    for (label, source, owner) in [
        ("Prometheus handler", prometheus_handler, "state"),
        ("dashboard wiring", dashboard_wiring.as_str(), "cores"),
    ] {
        for field in [
            "mdns", "dns", "health", "certmesh", "proxy", "runtime", "udp",
        ] {
            let direct = format!("{owner}.{field}");
            if let Some(offset) = source.find(&direct) {
                violations.push(format!(
                    "{label}:{} reaches through `{direct}` instead of system_status",
                    line_at(source, offset)
                ));
            }
        }
    }

    assert!(
        prometheus_projector.contains("KoiStatus") && dashboard_projector.contains("KoiStatus"),
        "pure presentation projectors must accept the typed KoiStatus aggregate"
    );
    assert!(
        prometheus_handler.contains("state.system_status.status()")
            && dashboard_wiring.contains("system_status.status()"),
        "presentation wiring must capture the cheap aggregate status"
    );
    assert!(
        violations.is_empty(),
        "presentation reconstructed product state outside KoiStatus (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn embedded_status_boundary_consumes_the_composition_runtime_directly() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let path = crates_dir.join("koi-embedded/src/handle.rs");
    if !path.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let source = production_rust_source(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    );
    let backend = braced_item(&source, "enum HandleBackend");
    assert!(
        backend.contains("system_status") && backend.contains("KoiStatusRuntime"),
        "embedded mode must retain the composition-owned KoiStatus runtime"
    );

    for (marker, expected_call) in [
        ("pub fn status(", "system_status.status()"),
        ("pub fn watch_status(", "system_status.watch_status()"),
    ] {
        let boundary = braced_item(&source, marker);
        assert_eq!(
            boundary.matches(expected_call).count(),
            1,
            "embedded `{marker}` must delegate exactly once to KoiStatusRuntime"
        );
        for field in [
            "mdns.",
            "dns.",
            "health.",
            "certmesh.",
            "proxy.",
            "runtime.",
            "udp.",
        ] {
            assert!(
                !boundary.contains(field),
                "embedded `{marker}` reconstructed product status through `{field}`"
            );
        }
        assert!(
            !boundary.contains("KoiStatus {") && !boundary.contains("KoiStatus::"),
            "embedded `{marker}` constructed a competing product snapshot"
        );
    }
}

#[test]
fn service_catalog_has_one_composition_owner_and_pure_presentations() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    let compose_dir = crates_dir.join("koi-compose/src");
    if !compose_dir.exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let mut owners = Vec::new();
    for entry in fs::read_dir(crates_dir).expect("read crates/") {
        let src = entry.expect("crate entry").path().join("src");
        for file in rust_sources(&src) {
            let source = fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
            if production_rust_source(&source).contains("pub struct ServiceCatalogRuntime") {
                owners.push(file);
            }
        }
    }
    assert_eq!(
        owners,
        vec![compose_dir.join("catalog.rs")],
        "the authoritative catalog must have exactly one composition owner"
    );

    let cores = production_rust_source(
        &fs::read_to_string(compose_dir.join("cores.rs")).expect("read cores"),
    );
    let status = production_rust_source(
        &fs::read_to_string(compose_dir.join("status.rs")).expect("read status"),
    );
    let dashboard = production_rust_source(
        &fs::read_to_string(compose_dir.join("snapshot.rs")).expect("read snapshot"),
    );
    let inventory = production_rust_source(
        &fs::read_to_string(crates_dir.join("koi-serve/src/inventory.rs")).expect("read inventory"),
    );
    let forwarder = production_rust_source(
        &fs::read_to_string(crates_dir.join("koi-dashboard/src/forward.rs"))
            .expect("read dashboard forwarder"),
    );
    assert!(
        cores.contains("spawn_catalog_observer") && status.contains("CatalogSnapshot"),
        "composition must own the watcher and carry its snapshot through KoiStatus"
    );
    assert!(
        dashboard.contains("status.catalog") && inventory.contains("status.catalog"),
        "dashboard and automation must project the captured catalog"
    );
    for forbidden in ["ServiceCatalogRuntime", "CatalogModel", "ObservationId"] {
        assert!(
            !forwarder.contains(forbidden),
            "lossy dashboard events must not rebuild catalog truth through `{forbidden}`"
        );
    }
}

#[test]
fn mcp_and_pond_status_presentations_consume_one_product_snapshot() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-serve").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let read_production = |relative: &str| {
        let path = crates_dir.join(relative);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        production_rust_source(&source)
    };
    let mcp = read_production("koi-serve/src/mcp_http.rs");
    let inventory = read_production("koi-serve/src/inventory.rs");
    let pond = read_production("koi-serve/src/pond.rs");
    let mut violations = Vec::new();

    // Explicit MCP commands and bounded queries legitimately use their domain facade.
    // Only these status/resource projections are product views, and each must capture
    // the already-accepted aggregate exactly once rather than assembling another model.
    for marker in [
        "async fn health_status",
        "async fn dns_list",
        "async fn inventory_snapshot",
        "async fn runtime_instances",
        "async fn mdns_snapshot",
    ] {
        let body = braced_item(&mcp, marker);
        if !body.contains("self.cores.system_status.status()") {
            violations.push(format!("MCP `{marker}` does not capture KoiStatus"));
        }
        for field in [
            "mdns", "dns", "health", "certmesh", "proxy", "runtime", "udp",
        ] {
            let direct = format!("self.cores.{field}");
            if let Some(offset) = body.find(&direct) {
                violations.push(format!(
                    "MCP `{marker}`:{} reaches through `{direct}`",
                    line_at(body, offset)
                ));
            }
        }
    }

    for (source, marker) in [
        (inventory.as_str(), "fn project_status"),
        (inventory.as_str(), "pub(crate) fn project("),
        (mcp.as_str(), "fn resource_changes"),
    ] {
        let body = braced_item(source, marker);
        if !body.contains("KoiStatus") {
            violations.push(format!(
                "MCP projector `{marker}` is not typed by KoiStatus"
            ));
        }
        for identifier in [
            "MdnsCore",
            "DnsCore",
            "HealthCore",
            "CertmeshCore",
            "ProxyCore",
            "RuntimeCore",
            "UdpRuntime",
            "discovery_snapshot",
            "roster_snapshot",
            "list_instances",
        ] {
            if let Some(offset) = body.find(identifier) {
                violations.push(format!(
                    "MCP projector `{marker}`:{} directly references `{identifier}`",
                    line_at(body, offset)
                ));
            }
        }
    }

    for marker in [
        "async fn pond_status_projection_handler",
        "async fn pond_dns_entries_handler",
    ] {
        let body = braced_item(&pond, marker);
        if !body.contains("system_status.status()") {
            violations.push(format!("Pond `{marker}` does not capture KoiStatus"));
        }
        for direct in [
            "config.dns",
            "config.health",
            "config.certmesh",
            "config.runtime",
        ] {
            if let Some(offset) = body.find(direct) {
                violations.push(format!(
                    "Pond `{marker}`:{} reaches through `{direct}`",
                    line_at(body, offset)
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "MCP/Pond reconstructed product state outside KoiStatus (ADR-043):\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn source_guard_ignores_prose_literals_and_test_only_items() {
    let source = r###"
        // mdns_sd and koi_proxy::config are prose.
        const EXAMPLE: &str = "koi_certmesh::roster";
        const RAW: &str = r#"mdns_sd"#;

        #[cfg(test)]
        mod tests {
            use koi_proxy::config;
            fn fixture() { let _ = mdns_sd::ServiceDaemon::new(); }
        }

        #[cfg(all(not(unix), test))]
        use koi_certmesh::ca;

        use mdns_sd::ServiceDaemon;
    "###;
    let production = production_rust_source(source);

    assert_eq!(
        rust_tokens(&production)
            .into_iter()
            .filter(|token| token.text == "mdns_sd")
            .count(),
        1
    );
    assert!(forbidden_root_modules(&production, "koi_proxy", &["config"]).is_empty());
    assert!(forbidden_root_modules(&production, "koi_certmesh", &["ca"]).is_empty());
}

#[test]
fn source_guard_recognizes_grouped_and_aliased_private_imports() {
    let source = production_rust_source(
        "use koi_certmesh::{CertmeshCore, roster::Roster};\n\
         use koi_proxy as proxy_domain;\n\
         use proxy_domain::config::ProxyConfig;\n",
    );

    assert_eq!(
        forbidden_root_modules(&source, "koi_certmesh", &["roster"]),
        vec![(1, "koi_certmesh::roster".to_string())]
    );
    assert_eq!(
        forbidden_root_modules(&source, "koi_proxy", &["config"]),
        vec![(3, "koi_proxy::config".to_string())]
    );
}

#[test]
fn transport_backed_mcp_inventory_reads_one_aggregate_revision() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("koi-common has a parent dir");
    if !crates_dir.join("koi-mcp").exists() {
        eprintln!("workspace crates/ layout not found; skipping architecture guard");
        return;
    }

    let source = production_rust_source(
        &fs::read_to_string(crates_dir.join("koi-mcp/src/source.rs"))
            .expect("read MCP source boundary"),
    );
    let source_port = braced_item(&source, "pub trait KoiSource");
    assert!(
        !rust_tokens(source_port)
            .into_iter()
            .any(|token| token.text == "unified_status"),
        "MCP must not retain a second, unused unified-status facade beside aggregate inventory"
    );
    let client_impl = braced_item(&source, "impl KoiSource for ClientSource");
    let inventory = braced_item(client_impl, "async fn inventory_snapshot");
    assert!(
        inventory.contains("client.inventory_snapshot()"),
        "transport-backed MCP inventory must use the daemon's aggregate endpoint"
    );
    assert_eq!(
        rust_tokens(inventory)
            .into_iter()
            .filter(|token| token.text == "call")
            .count(),
        1,
        "transport-backed MCP inventory must make exactly one daemon call"
    );
    for forbidden in ["unified_status", "health_status", "dns_list"] {
        assert!(
            !rust_tokens(inventory)
                .into_iter()
                .any(|token| token.text == forbidden),
            "transport-backed MCP inventory must not fall back to `{forbidden}`"
        );
    }

    let http = production_rust_source(
        &fs::read_to_string(crates_dir.join("koi-serve/src/http.rs"))
            .expect("read HTTP aggregate endpoint"),
    );
    let handler = braced_item(&http, "async fn inventory_handler");
    assert_eq!(
        handler.matches("system_status.status()").count(),
        1,
        "aggregate inventory endpoint must capture exactly one KoiStatus"
    );
    assert!(
        handler.contains("inventory::project"),
        "HTTP and in-process MCP inventory must share one pure projector"
    );
}
