use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::{CheckResult, EvidenceReport};

pub(crate) fn write_bundle<T: EvidenceReport>(
    repo_root: &Path,
    relative_json_path: &Path,
    report: &T,
) -> Result<PathBuf> {
    anyhow::ensure!(
        report.secrets_redacted(),
        "refusing to publish a scenario report that is not marked secrets_redacted"
    );
    let json_path = if relative_json_path.is_absolute() {
        relative_json_path.to_path_buf()
    } else {
        repo_root.join(relative_json_path)
    };
    let (junit_path, summary_path, suite_name) = companion_paths(&json_path)?;
    let parent = json_path
        .parent()
        .context("evidence path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("could not create evidence directory {}", parent.display()))?;

    // Render every format before writing any of them. A serialization failure
    // therefore cannot leave a misleading partial evidence bundle.
    let json = serde_json::to_vec_pretty(report)?;
    let junit = render_junit(&suite_name, report.checks());
    let summary = render_summary(&suite_name, report.checks());
    write_file(&json_path, &json)?;
    write_file(&junit_path, junit.as_bytes())?;
    write_file(&summary_path, summary.as_bytes())?;
    Ok(json_path)
}

fn companion_paths(json_path: &Path) -> Result<(PathBuf, PathBuf, String)> {
    anyhow::ensure!(
        json_path.extension().and_then(|value| value.to_str()) == Some("json"),
        "canonical evidence path must end in .json"
    );
    let stem = json_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .context("evidence JSON path has no UTF-8 filename stem")?;
    let parent = json_path
        .parent()
        .context("evidence JSON path has no parent directory")?;
    Ok((
        parent.join(format!("{stem}.junit.xml")),
        parent.join(format!("{stem}.txt")),
        stem.to_owned(),
    ))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("could not write evidence {}", path.display()))
}

fn render_junit(suite_name: &str, checks: &[CheckResult]) -> String {
    let failures = checks.iter().filter(|check| !check.passed).count();
    let mut xml = String::new();
    let _ = writeln!(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = writeln!(
        xml,
        "<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\">",
        escape_xml(suite_name),
        checks.len(),
        failures
    );
    for check in checks {
        let _ = writeln!(xml, "  <testcase name=\"{}\">", escape_xml(&check.name));
        if check.passed {
            let _ = writeln!(
                xml,
                "    <system-out>{}</system-out>",
                escape_xml(&check.detail)
            );
        } else {
            let _ = writeln!(
                xml,
                "    <failure message=\"check failed\">{}</failure>",
                escape_xml(&check.detail)
            );
        }
        let _ = writeln!(xml, "  </testcase>");
    }
    let _ = writeln!(xml, "</testsuite>");
    xml
}

fn render_summary(suite_name: &str, checks: &[CheckResult]) -> String {
    let passed = checks.iter().filter(|check| check.passed).count();
    let mut summary = format!(
        "Koi lab evidence: {suite_name}\nResult: {passed}/{} checks passed\n\n",
        checks.len()
    );
    for check in checks {
        let verdict = if check.passed { "PASS" } else { "FAIL" };
        let detail = check.detail.replace('\n', "\n    ");
        let _ = writeln!(summary, "[{verdict}] {}\n    {detail}", check.name);
    }
    summary
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(character),
            value if value >= '\u{20}' => escaped.push(value),
            _ => escaped.push('\u{fffd}'),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct TestReport {
        checks: Vec<CheckResult>,
        secrets_redacted: bool,
    }

    impl EvidenceReport for TestReport {
        fn checks(&self) -> &[CheckResult] {
            &self.checks
        }

        fn secrets_redacted(&self) -> bool {
            self.secrets_redacted
        }
    }

    fn checks() -> Vec<CheckResult> {
        vec![
            CheckResult {
                name: "healthy & ready".into(),
                passed: true,
                detail: "value <expected>\nsecond line".into(),
            },
            CheckResult {
                name: "hostile \"name\"".into(),
                passed: false,
                detail: "bad\u{1}value".into(),
            },
        ]
    }

    #[test]
    fn companion_names_keep_one_canonical_stem() {
        let path = Path::new(".lab-runs/v1-test/capability-story-linux.json");
        let (junit, summary, suite) = companion_paths(path).unwrap();
        assert_eq!(suite, "capability-story-linux");
        assert_eq!(
            junit,
            Path::new(".lab-runs/v1-test/capability-story-linux.junit.xml")
        );
        assert_eq!(
            summary,
            Path::new(".lab-runs/v1-test/capability-story-linux.txt")
        );
    }

    #[test]
    fn junit_counts_failures_and_escapes_untrusted_text() {
        let xml = render_junit("suite & one", &checks());
        assert!(xml.contains("name=\"suite &amp; one\" tests=\"2\" failures=\"1\""));
        assert!(xml.contains("healthy &amp; ready"));
        assert!(xml.contains("value &lt;expected&gt;"));
        assert!(xml.contains("hostile &quot;name&quot;"));
        assert!(xml.contains("bad�value"));
        assert!(!xml.contains('\u{1}'));
    }

    #[test]
    fn readable_summary_is_compact_and_multiline_safe() {
        let summary = render_summary("suite", &checks());
        assert!(summary.contains("Result: 1/2 checks passed"));
        assert!(summary.contains("[PASS] healthy & ready"));
        assert!(summary.contains("second line"));
        assert!(summary.contains("[FAIL] hostile \"name\""));
    }

    #[test]
    fn bundle_writer_creates_all_three_companion_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("koi-evidence-test-{}-{nonce}", std::process::id()));
        let report = TestReport {
            checks: checks(),
            secrets_redacted: true,
        };
        let json = write_bundle(&root, Path::new("run/report.json"), &report).unwrap();
        assert_eq!(json, root.join("run/report.json"));
        assert!(json.is_file());
        assert!(root.join("run/report.junit.xml").is_file());
        assert!(root.join("run/report.txt").is_file());
        assert!(fs::read_to_string(root.join("run/report.junit.xml"))
            .unwrap()
            .contains("failures=\"1\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writer_refuses_reports_not_marked_redacted() {
        let report = TestReport {
            checks: checks(),
            secrets_redacted: false,
        };
        let error = write_bundle(
            Path::new("unused-root"),
            Path::new("run/report.json"),
            &report,
        )
        .unwrap_err();
        assert!(error.to_string().contains("secrets_redacted"));
    }
}
