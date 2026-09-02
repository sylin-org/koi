//! Typed Windows Firewall adapter shared by platform lifecycle operations and Pond.
//!
//! NetSecurity owns locale-independent inspection and deletion. `netsh` remains the
//! mutation vocabulary because it can recreate the exact snapshot fields, but every
//! command result is checked and deletion distinguishes `Removed` from `Absent`.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const MANAGED_RULE_PREFIX: &str = "Koi ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSnapshot {
    pub name: String,
    pub enabled: bool,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub local_port: String,
    pub program: String,
    /// Version-1 installer manifests predate profile capture. Missing is not `Any`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    Removed,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    MissingOrMismatchedRule,
    ActiveProfileNotCovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    Open,
    Inactive,
    Blocked(BlockReason),
}

#[derive(Debug)]
struct ProcessResult {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

trait CommandRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessResult>;
}

struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessResult> {
        let output = Command::new(program).args(args).output()?;
        Ok(ProcessResult {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn snapshot_managed() -> anyhow::Result<Vec<RuleSnapshot>> {
    snapshot_managed_with(&SystemRunner)
}

pub fn remove(name: &str) -> anyhow::Result<Removal> {
    remove_with(&SystemRunner, name)
}

/// Replace every same-name rule with one intentional application-scoped allow rule.
/// A failed deletion stops before the add, so duplicates cannot accumulate.
pub fn replace_managed(
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Removal> {
    replace_managed_with(&SystemRunner, name, protocol, port, executable)
}

/// Restore a complete prior set. All snapshots are validated and all target names are
/// removed before the first add, making retries converge without duplicates.
pub fn restore_snapshot_set(
    added_names: &[String],
    snapshots: &[RuleSnapshot],
) -> anyhow::Result<()> {
    restore_snapshot_set_with(&SystemRunner, added_names, snapshots)
}

pub fn validate_snapshots(snapshots: &[RuleSnapshot]) -> anyhow::Result<()> {
    for rule in snapshots {
        restore_args(rule)?;
    }
    Ok(())
}

pub fn assess_managed(
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Assessment> {
    assess_managed_with(&SystemRunner, name, protocol, port, executable)
}

fn snapshot_managed_with(runner: &impl CommandRunner) -> anyhow::Result<Vec<RuleSnapshot>> {
    let pattern = powershell_quote(&format!("{MANAGED_RULE_PREFIX}*"));
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
Get-NetFirewallRule -ErrorAction Stop |
  Where-Object {{ $_.DisplayName -like {pattern} }} |
  ForEach-Object {{
    $rule = $_
    $app = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    [pscustomobject]@{{
      name = [string]$rule.DisplayName
      enabled = [bool]($rule.Enabled -eq 'True')
      direction = [string]$rule.Direction
      action = [string]$rule.Action
      protocol = [string](@($port.Protocol) -join ',')
      local_port = [string](@($port.LocalPort) -join ',')
      program = [string](@($app.Program) -join ',')
      profile = [string]$rule.Profile
    }}
  }} | ConvertTo-Json -Compress
"#
    );
    let output = powershell(runner, &script).context("could not enumerate firewall rules")?;
    require_success("enumerate firewall rules", &output)?;
    parse_snapshot_json(&output.stdout)
}

fn remove_with(runner: &impl CommandRunner, name: &str) -> anyhow::Result<Removal> {
    let name = powershell_quote(name);
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq {name} }})
if ($rules.Count -eq 0) {{ Write-Output 'KOI_ABSENT'; exit 0 }}
$rules | Remove-NetFirewallRule -ErrorAction Stop
Write-Output 'KOI_REMOVED'
"#
    );
    let output = powershell(runner, &script)
        .with_context(|| format!("could not remove firewall rule {name}"))?;
    require_success("remove firewall rule", &output)?;
    match output.stdout.trim() {
        "KOI_REMOVED" => Ok(Removal::Removed),
        "KOI_ABSENT" => Ok(Removal::Absent),
        other => anyhow::bail!(
            "remove firewall rule returned an unknown result: {:?}",
            other
        ),
    }
}

fn replace_managed_with(
    runner: &impl CommandRunner,
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Removal> {
    let removal = remove_with(runner, name)?;
    let args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={name}"),
        "dir=in".to_string(),
        "action=allow".to_string(),
        format!("protocol={protocol}"),
        format!("localport={port}"),
        format!("program={}", executable.display()),
    ];
    let output = runner
        .run("netsh", &args)
        .with_context(|| format!("could not create firewall rule {name}"))?;
    require_success("create firewall rule", &output)?;
    Ok(removal)
}

fn restore_snapshot_set_with(
    runner: &impl CommandRunner,
    added_names: &[String],
    snapshots: &[RuleSnapshot],
) -> anyhow::Result<()> {
    validate_snapshots(snapshots)?;

    let mut seen = HashSet::new();
    for name in added_names
        .iter()
        .map(String::as_str)
        .chain(snapshots.iter().map(|rule| rule.name.as_str()))
    {
        if seen.insert(name) {
            remove_with(runner, name)?;
        }
    }
    for rule in snapshots {
        let args = restore_args(rule)?;
        let output = runner
            .run("netsh", &args)
            .with_context(|| format!("could not restore firewall rule {}", rule.name))?;
        require_success("restore firewall rule", &output)?;
    }
    Ok(())
}

fn restore_args(rule: &RuleSnapshot) -> anyhow::Result<Vec<String>> {
    let direction = match rule.direction.to_ascii_lowercase().as_str() {
        "inbound" | "in" => "in",
        "outbound" | "out" => "out",
        other => anyhow::bail!("unsupported firewall direction '{other}'"),
    };
    let action = match rule.action.to_ascii_lowercase().as_str() {
        "allow" => "allow",
        "block" => "block",
        other => anyhow::bail!("unsupported firewall action '{other}'"),
    };
    let profile = rule
        .profile
        .as_deref()
        .map(str::trim)
        .filter(|profile| !profile.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "firewall snapshot for '{}' has no captured profile; refusing to guess Any",
                rule.name
            )
        })?;
    let mut args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", rule.name),
        format!("dir={direction}"),
        format!("action={action}"),
        format!("enable={}", if rule.enabled { "yes" } else { "no" }),
        format!("profile={}", profile.replace(' ', "")),
    ];
    if !rule.protocol.is_empty() && !rule.protocol.eq_ignore_ascii_case("any") {
        args.push(format!("protocol={}", rule.protocol));
    }
    if !rule.local_port.is_empty() && !rule.local_port.eq_ignore_ascii_case("any") {
        args.push(format!("localport={}", rule.local_port));
    }
    if !rule.program.is_empty() && !rule.program.eq_ignore_ascii_case("any") {
        args.push(format!("program={}", rule.program));
    }
    Ok(args)
}

#[derive(Debug, Deserialize)]
struct AssessmentSnapshot {
    enabled_profiles: Vec<String>,
    active_profiles: Vec<String>,
    rules: Vec<RuleSnapshot>,
}

fn assess_managed_with(
    runner: &impl CommandRunner,
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Assessment> {
    let name = powershell_quote(name);
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
$enabled = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object {{ $_.Enabled -eq 'True' }} | ForEach-Object {{ [string]$_.Name }})
$active = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {{ [string]$_.NetworkCategory }} | Sort-Object -Unique)
$rules = @(Get-NetFirewallRule -ErrorAction Stop |
  Where-Object {{ $_.DisplayName -eq {name} }} |
  ForEach-Object {{
    $rule = $_
    $app = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    [pscustomobject]@{{
      name = [string]$rule.DisplayName
      enabled = [bool]($rule.Enabled -eq 'True')
      direction = [string]$rule.Direction
      action = [string]$rule.Action
      protocol = [string](@($port.Protocol) -join ',')
      local_port = [string](@($port.LocalPort) -join ',')
      program = [string](@($app.Program) -join ',')
      profile = [string]$rule.Profile
    }}
  }})
[pscustomobject]@{{ enabled_profiles = $enabled; active_profiles = $active; rules = $rules }} | ConvertTo-Json -Depth 4 -Compress
"#
    );
    let output = powershell(runner, &script).context("could not query Windows Firewall")?;
    require_success("assess firewall rule", &output)?;
    let snapshot: AssessmentSnapshot = serde_json::from_str(output.stdout.trim())
        .context("Windows Firewall assessment returned unparseable JSON")?;
    assess_snapshot(snapshot, protocol, port, executable)
}

fn assess_snapshot(
    snapshot: AssessmentSnapshot,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Assessment> {
    let enabled = snapshot
        .enabled_profiles
        .iter()
        .map(|profile| profile.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if enabled.is_empty() {
        return Ok(Assessment::Inactive);
    }
    let active = snapshot
        .active_profiles
        .iter()
        .map(|profile| profile.to_ascii_lowercase())
        .filter(|profile| enabled.contains(profile))
        .collect::<Vec<_>>();
    if active.is_empty() {
        anyhow::bail!("no active network connection uses an enabled Windows Firewall profile");
    }

    let port = port.to_string();
    let executable = executable.to_string_lossy();
    let candidates = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && matches!(
                    rule.direction.to_ascii_lowercase().as_str(),
                    "inbound" | "in"
                )
                && rule.action.eq_ignore_ascii_case("allow")
                && comma_values(&rule.protocol).any(|value| value.eq_ignore_ascii_case(protocol))
                && comma_values(&rule.local_port).any(|value| value == port)
                && comma_values(&rule.program)
                    .any(|value| value.eq_ignore_ascii_case(executable.as_ref()))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(Assessment::Blocked(BlockReason::MissingOrMismatchedRule));
    }
    let covered = active.iter().all(|active_profile| {
        candidates.iter().any(|rule| {
            rule.profile.as_deref().is_some_and(|profiles| {
                comma_values(profiles).any(|profile| {
                    profile.eq_ignore_ascii_case("any")
                        || profile.eq_ignore_ascii_case(active_profile)
                })
            })
        })
    });
    Ok(if covered {
        Assessment::Open
    } else {
        Assessment::Blocked(BlockReason::ActiveProfileNotCovered)
    })
}

fn comma_values(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_snapshot_json(text: &str) -> anyhow::Result<Vec<RuleSnapshot>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: serde_json::Value =
        serde_json::from_str(text).context("firewall enumeration returned unparseable JSON")?;
    let values = match parsed {
        serde_json::Value::Array(values) => values,
        one @ serde_json::Value::Object(_) => vec![one],
        other => anyhow::bail!("firewall enumeration returned unexpected JSON: {other}"),
    };
    values
        .into_iter()
        .map(|value| {
            let rule: RuleSnapshot = serde_json::from_value(value).context(
                "firewall rule snapshot is missing fields needed for rollback restoration",
            )?;
            Ok(RuleSnapshot {
                direction: rule.direction.to_ascii_lowercase(),
                action: rule.action.to_ascii_lowercase(),
                protocol: rule.protocol.to_ascii_lowercase(),
                profile: rule.profile.map(|profile| profile.to_ascii_lowercase()),
                ..rule
            })
        })
        .collect()
}

fn powershell(runner: &impl CommandRunner, script: &str) -> std::io::Result<ProcessResult> {
    runner.run(
        "powershell.exe",
        &[
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            script.to_string(),
        ],
    )
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn require_success(operation: &str, output: &ProcessResult) -> anyhow::Result<()> {
    if output.success {
        return Ok(());
    }
    anyhow::bail!(
        "{operation} failed (exit {:?}): {}",
        output.code,
        output.stderr.trim()
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    struct FakeRunner {
        results: RefCell<VecDeque<std::io::Result<ProcessResult>>>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl FakeRunner {
        fn new(results: Vec<std::io::Result<ProcessResult>>) -> Self {
            Self {
                results: RefCell::new(results.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessResult> {
            self.calls
                .borrow_mut()
                .push((program.to_string(), args.to_vec()));
            self.results.borrow_mut().pop_front().unwrap()
        }
    }

    fn ok(stdout: &str) -> std::io::Result<ProcessResult> {
        Ok(ProcessResult {
            success: true,
            code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
        })
    }

    fn failed(stderr: &str) -> std::io::Result<ProcessResult> {
        Ok(ProcessResult {
            success: false,
            code: Some(1),
            stdout: String::new(),
            stderr: stderr.to_string(),
        })
    }

    fn snapshot(name: &str, profile: Option<&str>) -> RuleSnapshot {
        RuleSnapshot {
            name: name.to_string(),
            enabled: true,
            direction: "inbound".to_string(),
            action: "allow".to_string(),
            protocol: "tcp".to_string(),
            local_port: "5644".to_string(),
            program: r"C:\Program Files\Koi\koi.exe".to_string(),
            profile: profile.map(str::to_string),
        }
    }

    #[test]
    fn deletion_distinguishes_removed_and_absent() {
        let removed = FakeRunner::new(vec![ok("KOI_REMOVED\r\n")]);
        assert_eq!(remove_with(&removed, "Koi rule").unwrap(), Removal::Removed);
        let absent = FakeRunner::new(vec![ok("KOI_ABSENT\r\n")]);
        assert_eq!(remove_with(&absent, "Koi rule").unwrap(), Removal::Absent);
    }

    #[test]
    fn failed_delete_stops_replacement_before_add() {
        let runner = FakeRunner::new(vec![failed("access denied")]);
        let error = replace_managed_with(
            &runner,
            "Koi Pond (TCP 5644)",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("remove firewall rule"));
        assert_eq!(runner.calls.borrow().len(), 1, "add must not run");
    }

    #[test]
    fn command_spawn_failure_is_an_error_not_absence() {
        let runner = FakeRunner::new(vec![Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "powershell missing",
        ))]);
        let error = remove_with(&runner, "Koi rule").unwrap_err();
        assert!(error.to_string().contains("could not remove firewall rule"));
    }

    #[test]
    fn missing_profile_stops_restore_before_any_command() {
        let runner = FakeRunner::new(Vec::new());
        let error =
            restore_snapshot_set_with(&runner, &[], &[snapshot("Koi old", None)]).unwrap_err();
        assert!(error.to_string().contains("refusing to guess Any"));
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn restore_removes_each_name_once_before_recreating_duplicates() {
        let runner = FakeRunner::new(vec![ok("KOI_REMOVED"), ok(""), ok("")]);
        let rules = vec![
            snapshot("Koi same", Some("private")),
            snapshot("Koi same", Some("public")),
        ];
        restore_snapshot_set_with(&runner, &[], &rules).unwrap();
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "powershell.exe");
        assert_eq!(calls[1].0, "netsh");
        assert_eq!(calls[2].0, "netsh");
        assert!(calls[1].1.iter().any(|arg| arg == "profile=private"));
        assert!(calls[2].1.iter().any(|arg| arg == "profile=public"));
    }

    #[test]
    fn assessment_keeps_each_rules_filters_correlated() {
        let mut wrong_program = snapshot("Koi Pond", Some("private"));
        wrong_program.program = r"C:\other.exe".to_string();
        let mut wrong_profile = snapshot("Koi Pond", Some("public"));
        wrong_profile.program = r"C:\Program Files\Koi\koi.exe".to_string();
        let assessment = assess_snapshot(
            AssessmentSnapshot {
                enabled_profiles: vec!["Private".to_string()],
                active_profiles: vec!["Private".to_string()],
                rules: vec![wrong_program, wrong_profile],
            },
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap();
        assert_eq!(
            assessment,
            Assessment::Blocked(BlockReason::ActiveProfileNotCovered)
        );
    }

    #[test]
    fn netsecurity_json_accepts_real_v1_missing_profile_without_inventing_it() {
        let json = r#"{"name":"Koi old","enabled":true,"direction":"Inbound","action":"Allow","protocol":"TCP","local_port":"5644","program":"Any"}"#;
        let rules = parse_snapshot_json(json).unwrap();
        assert_eq!(rules[0].profile, None);
        assert!(validate_snapshots(&rules).is_err());
    }

    #[test]
    fn netsecurity_json_normalizes_complete_v2_snapshots() {
        let json = r#"{"name":"Koi Pond (TCP 5644)","enabled":true,"direction":"Inbound","action":"Allow","protocol":"TCP","local_port":"5644","program":"C:\\Program Files\\Koi\\koi.exe","profile":"Domain, Private"}"#;
        let rules = parse_snapshot_json(json).unwrap();
        assert_eq!(rules[0].direction, "inbound");
        assert_eq!(rules[0].protocol, "tcp");
        assert_eq!(rules[0].profile.as_deref(), Some("domain, private"));
        validate_snapshots(&rules).unwrap();
    }

    #[test]
    #[ignore = "queries the live Windows Firewall through NetSecurity"]
    fn live_snapshot_enumerates_complete_managed_rules() {
        for rule in snapshot_managed().unwrap() {
            assert!(rule.name.starts_with(MANAGED_RULE_PREFIX));
            assert!(!rule.direction.is_empty());
            assert!(!rule.action.is_empty());
            assert!(rule
                .profile
                .as_deref()
                .is_some_and(|value| !value.is_empty()));
        }
    }
}
