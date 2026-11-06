//! The running product's build identity: one version for every surface (CLI,
//! HTTP, mDNS TXT records, MCP, the interface), set once by the binary at
//! startup.
//!
//! The version is `MAJOR.MINOR.PATCH.N`. The first three numbers are the
//! workspace version with any pre-release part removed; `N` is the number of
//! commits in the build's history. `N` grows with every commit and is the
//! same for the same commit on any machine. A build from uncommitted changes
//! keeps the number and sets `dirty`, so the full identity still tells it
//! apart from the clean build.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BuildInfo {
    /// `MAJOR.MINOR.PATCH.N`, e.g. `1.0.0.2147`.
    pub version: String,
    /// The commit the build was made from, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Built from a working tree with uncommitted changes.
    #[serde(default)]
    pub dirty: bool,
    /// When the binary was built (RFC 3339, UTC), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<String>,
}

impl BuildInfo {
    /// Whether two identities describe the same artifact. Clean builds of the
    /// same commit are interchangeable; dirty builds also need the same build
    /// time, since two of them can differ in content.
    pub fn same_build(&self, other: &BuildInfo) -> bool {
        self.version == other.version
            && self.commit == other.commit
            && self.dirty == other.dirty
            && (!self.dirty || self.built_at == other.built_at)
    }

    /// The details after the version, for a second line or a parenthetical:
    /// `commit a1b2c3d4e5f6 · built 2026-11-05T22:10:31Z · uncommitted changes`.
    pub fn details(&self) -> String {
        let mut parts = Vec::new();
        if let Some(commit) = &self.commit {
            parts.push(format!("commit {commit}"));
        }
        if let Some(built_at) = &self.built_at {
            parts.push(format!("built {built_at}"));
        }
        if self.dirty {
            parts.push("uncommitted changes".to_string());
        }
        parts.join(" · ")
    }
}

static BUILD: OnceLock<BuildInfo> = OnceLock::new();

/// Record the binary's build identity. The first call wins.
pub fn set(info: BuildInfo) {
    let _ = BUILD.set(info);
}

/// The running build's identity. A host that never calls [`set`] (an embedder,
/// a test) reports this crate's version with no commit.
pub fn info() -> &'static BuildInfo {
    BUILD.get_or_init(|| BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
        dirty: false,
        built_at: None,
    })
}

/// The version every surface reports.
pub fn version() -> &'static str {
    &info().version
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(version: &str, commit: &str, dirty: bool, built_at: &str) -> BuildInfo {
        BuildInfo {
            version: version.into(),
            commit: Some(commit.into()),
            dirty,
            built_at: Some(built_at.into()),
        }
    }

    #[test]
    fn clean_builds_of_one_commit_are_the_same_build() {
        let a = build("1.0.0.10", "abc", false, "2026-11-05T10:00:00Z");
        let b = build("1.0.0.10", "abc", false, "2026-11-05T11:00:00Z");
        assert!(a.same_build(&b));
    }

    #[test]
    fn dirty_builds_differ_by_build_time() {
        let a = build("1.0.0.10", "abc", true, "2026-11-05T10:00:00Z");
        let b = build("1.0.0.10", "abc", true, "2026-11-05T11:00:00Z");
        assert!(!a.same_build(&b));
        assert!(a.same_build(&a.clone()));
    }

    #[test]
    fn a_dirty_build_is_not_the_clean_build() {
        let clean = build("1.0.0.10", "abc", false, "2026-11-05T10:00:00Z");
        let dirty = build("1.0.0.10", "abc", true, "2026-11-05T10:00:00Z");
        assert!(!clean.same_build(&dirty));
    }

    #[test]
    fn details_read_naturally() {
        let b = build("1.0.0.10", "abc", true, "2026-11-05T10:00:00Z");
        assert_eq!(
            b.details(),
            "commit abc · built 2026-11-05T10:00:00Z · uncommitted changes"
        );
    }
}
