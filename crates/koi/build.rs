//! Build identity and Windows resources.
//!
//! Every build reports `MAJOR.MINOR.PATCH.N` (see koi_common::build), where `N`
//! is the number of commits in the build's history. The identity reaches the
//! binary as compile-time environment variables; main() hands it to
//! koi_common::build at startup, so libraries never recompile when it changes.

// The VERSIONINFO packer only runs on Windows hosts.
#[cfg_attr(not(windows), allow(dead_code))]
#[path = "src/build_version.rs"]
mod build_version;

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

/// Ask Cargo to re-run this script only when the identity could change: a new
/// commit or branch, a staging change, or any edit to workspace sources (for
/// the dirty flag). Paths that don't exist are skipped, because Cargo treats a
/// missing path as always changed.
fn rerun_triggers() {
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let mut paths = vec![
            format!("{git_dir}/HEAD"),
            format!("{git_dir}/index"),
            format!("{git_dir}/packed-refs"),
        ];
        if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
            paths.push(format!("{git_dir}/{branch}"));
        }
        for path in paths.iter().filter(|p| Path::new(p).exists()) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    // The whole crates/ tree, so an uncommitted edit anywhere marks the build dirty.
    println!("cargo:rerun-if-changed=..");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn main() {
    let core = build_version::core_version(env!("CARGO_PKG_VERSION"));
    let commits = git(&["rev-list", "--count", "HEAD"])
        .and_then(|count| count.parse::<u64>().ok())
        .unwrap_or(0);
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    let built_at = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|epoch| epoch.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    let version = build_version::product_version(core, commits);

    println!("cargo:rustc-env=KOI_VERSION={version}");
    println!("cargo:rustc-env=KOI_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=KOI_BUILD_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=KOI_BUILT_AT={}",
        build_version::utc_rfc3339(built_at)
    );
    rerun_triggers();

    #[cfg(windows)]
    {
        let packed = build_version::pack_windows_version(&version);
        let mut resource = winresource::WindowsResource::new();
        resource.set("ProductName", "Koi");
        resource.set("ProductVersion", &version);
        resource.set("FileVersion", &version);
        resource.set_version_info(winresource::VersionInfo::FILEVERSION, packed);
        resource.set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);
        resource.set("FileDescription", env!("CARGO_PKG_DESCRIPTION"));
        resource.set("CompanyName", "Sylin.org");
        resource.set("OriginalFilename", "koi.exe");
        resource.set("LegalCopyright", "Copyright (c) Sylin.org contributors");
        resource.compile().expect("compile Koi Windows resources");
    }
}
