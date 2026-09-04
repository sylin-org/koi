//! Typed Windows Firewall adapter shared by platform lifecycle operations and Pond.
//!
//! NetSecurity owns locale-independent inspection and deletion. Applicability reads the
//! effective `ActiveStore`; lifecycle snapshot and deletion stay in Koi's local
//! `PersistentStore`. `netsh` remains the mutation vocabulary because it can recreate the
//! exact snapshot fields, but every command result is checked and deletion distinguishes
//! `Removed` from `Absent`.

use std::collections::HashSet;
use std::io::Read as _;
use std::os::windows::io::AsRawHandle as _;
use std::os::windows::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_TIMEOUT, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

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

#[derive(Debug, Clone, Copy, Default)]
struct SystemRunner {
    deadline: Option<Instant>,
}

impl SystemRunner {
    fn until(deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
        }
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<ProcessResult> {
        if let Some(deadline) = self.deadline {
            return run_owned_until(program, args, deadline);
        }
        let output = Command::new(program).args(args).output()?;
        Ok(ProcessResult {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// A private Windows Job Object is the process-tree ownership boundary for a bounded
/// firewall query. Closing the last handle kills every associated process, so no
/// PowerShell helper can outlive either its deadline or an error path.
struct ProcessJob {
    handle: HANDLE,
}

impl ProcessJob {
    fn new() -> std::io::Result<Self> {
        // SAFETY: null security attributes and name request a private, non-inheritable job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` has the exact layout and size required by this information class;
        // `handle` remains owned by `job` until Drop.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `handle` was returned by CreateJobObjectW and has not been closed.
            unsafe {
                CloseHandle(handle);
            }
            return Err(error);
        }
        Ok(Self { handle })
    }

    fn assign(&self, child: &Child) -> std::io::Result<()> {
        let child_handle = child.as_raw_handle() as HANDLE;
        // SAFETY: both handles are live. `std::process::Child` grants the process rights
        // required by AssignProcessToJobObject for a process it created.
        if unsafe { AssignProcessToJobObject(self.handle, child_handle) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&self) -> std::io::Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        // SAFETY: the owned job handle is live; ERROR_TIMEOUT becomes the process-tree exit
        // code and cannot be handled or postponed by members of the job.
        if unsafe { TerminateJobObject(self.handle, ERROR_TIMEOUT) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        // SAFETY: this is the only owned handle. KILL_ON_JOB_CLOSE is a second independent
        // process-tree termination route, including for a parent that exited normally.
        if unsafe { CloseHandle(self.handle) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.handle = std::ptr::null_mut();
        Ok(())
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        let _ = self.terminate();
        let _ = self.close();
    }
}

struct OwnedJobChild {
    child: Child,
    job: ProcessJob,
    reaped: bool,
}

impl OwnedJobChild {
    fn spawn(program: &str, args: &[String]) -> std::io::Result<Self> {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let job = ProcessJob::new()?;
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);
        let child = command.spawn()?;
        let owned = Self {
            child,
            job,
            reaped: false,
        };
        owned.job.assign(&owned.child)?;
        Ok(owned)
    }

    fn wait_until(&mut self, deadline: Instant, program: &str) -> std::io::Result<ExitStatus> {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    // A query must not intentionally leave helpers behind. Terminating the job
                    // after the direct child exits also closes inherited pipe writers promptly.
                    let terminated = self.job.terminate();
                    let closed = self.job.close();
                    if let (Err(terminate_error), Err(close_error)) = (terminated, closed) {
                        return Err(std::io::Error::other(format!(
                            "could not close completed {program} process tree: {}; {}",
                            terminate_error, close_error
                        )));
                    }
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = self.terminate_and_reap();
                    return Err(error);
                }
            }

            let now = Instant::now();
            if now >= deadline {
                self.terminate_and_reap()?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("{program} exceeded its firewall assessment deadline"),
                ));
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(20)),
            );
        }
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<()> {
        let tree_result = self.job.terminate();
        let close_result = self.job.close();
        let tree_failure = match (tree_result, close_result) {
            (Err(terminate_error), Err(close_error)) => Some((terminate_error, close_error)),
            _ => None,
        };
        if tree_failure.is_some() {
            // The Child handle is an independent last-resort termination route. Job Drop still
            // retries tree termination through KILL_ON_JOB_CLOSE on every return path.
            self.child.kill()?;
        }
        self.child.wait()?;
        self.reaped = true;
        if let Some((terminate_error, close_error)) = tree_failure {
            return Err(std::io::Error::other(format!(
                "could not terminate firewall command process tree: {}; {}",
                terminate_error, close_error
            )));
        }
        Ok(())
    }
}

impl Drop for OwnedJobChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.job.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

fn run_owned_until(
    program: &str,
    args: &[String],
    deadline: Instant,
) -> std::io::Result<ProcessResult> {
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("firewall assessment deadline elapsed before {program}"),
        ));
    }

    let mut owned = OwnedJobChild::spawn(program, args)?;
    let mut stdout = owned
        .child
        .stdout
        .take()
        .expect("bounded command configured stdout as piped");
    let mut stderr = owned
        .child
        .stderr
        .take()
        .expect("bounded command configured stderr as piped");

    std::thread::scope(|scope| {
        // Pipes are drained while the process runs so a large firewall ruleset cannot fill a
        // kernel pipe buffer and turn an otherwise healthy query into a false timeout.
        let stdout_reader = scope.spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr_reader = scope.spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });

        let status = owned.wait_until(deadline, program);
        // Release the kill-on-close job boundary before joining readers. This guarantees EOF
        // even if an unexpected descendant inherited one of the output pipe writers.
        drop(owned);
        let stdout = join_output_reader(stdout_reader, "stdout")?;
        let stderr = join_output_reader(stderr_reader, "stderr")?;
        let status = status?;
        Ok(ProcessResult {
            success: status.success(),
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    })
}

fn join_output_reader(
    reader: std::thread::ScopedJoinHandle<'_, std::io::Result<Vec<u8>>>,
    stream: &str,
) -> std::io::Result<Vec<u8>> {
    reader.join().map_err(|_| {
        std::io::Error::other(format!("{stream} reader for firewall command panicked"))
    })?
}

pub fn snapshot_managed() -> anyhow::Result<Vec<RuleSnapshot>> {
    snapshot_managed_with(&SystemRunner::default())
}

pub fn remove(name: &str) -> anyhow::Result<Removal> {
    remove_with(&SystemRunner::default(), name)
}

/// Replace every same-name rule with one intentional application-scoped allow rule.
/// A failed deletion stops before the add, so duplicates cannot accumulate.
pub fn replace_managed(
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Removal> {
    replace_managed_with(&SystemRunner::default(), name, protocol, port, executable)
}

/// Restore a complete prior set. All snapshots are validated and all target names are
/// removed before the first add, making retries converge without duplicates.
pub fn restore_snapshot_set(
    added_names: &[String],
    snapshots: &[RuleSnapshot],
) -> anyhow::Result<()> {
    restore_snapshot_set_with(&SystemRunner::default(), added_names, snapshots)
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
    assess_managed_with(&SystemRunner::default(), name, protocol, port, executable)
}

/// Assess one managed rule under an adapter-owned wall-clock deadline.
///
/// The call returns only after the PowerShell process tree has exited and its direct child
/// has been reaped. Callers therefore do not need a cancellable outer timeout that can detach
/// blocking process work.
pub fn assess_managed_until(
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
    deadline: Instant,
) -> anyhow::Result<Assessment> {
    assess_managed_with(
        &SystemRunner::until(deadline),
        name,
        protocol,
        port,
        executable,
    )
}

/// Assess several managed rules from one Windows Firewall query.
///
/// Each tuple is `(rule name, protocol, local port)`. Verdicts retain input order.
pub fn assess_managed_rules(
    rules: &[(&str, &str, u16)],
    executable: &Path,
) -> anyhow::Result<Vec<Assessment>> {
    assess_managed_rules_with(&SystemRunner::default(), rules, executable)
}

fn snapshot_managed_with(runner: &impl CommandRunner) -> anyhow::Result<Vec<RuleSnapshot>> {
    let pattern = powershell_quote(&format!("{MANAGED_RULE_PREFIX}*"));
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
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
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq {name} }})
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
    assess_managed_rules_with(runner, &[(name, protocol, port)], executable)?
        .pop()
        .context("Windows Firewall assessment returned no verdict")
}

fn assess_managed_rules_with(
    runner: &impl CommandRunner,
    rules: &[(&str, &str, u16)],
    executable: &Path,
) -> anyhow::Result<Vec<Assessment>> {
    if rules.is_empty() {
        return Ok(Vec::new());
    }
    let names = rules
        .iter()
        .map(|(name, _, _)| powershell_quote(name))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
$names = @({names})
$enabled = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.Enabled -eq 'True' }} | ForEach-Object {{ [string]$_.Name }})
$active = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {{ [string]$_.NetworkCategory }} | Sort-Object -Unique)
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
  Where-Object {{ $names -contains [string]$_.DisplayName }} |
  ForEach-Object {{
    $rule = $_
    $app = @($rule | Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop)
    $port = @($rule | Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop)
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
    rules
        .iter()
        .map(|(name, protocol, port)| assess_snapshot(&snapshot, name, protocol, *port, executable))
        .collect()
}

fn assess_snapshot(
    snapshot: &AssessmentSnapshot,
    name: &str,
    protocol: &str,
    port: u16,
    executable: &Path,
) -> anyhow::Result<Assessment> {
    let active = snapshot
        .active_profiles
        .iter()
        .map(|category| canonical_firewall_profile(category))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let enabled = snapshot
        .enabled_profiles
        .iter()
        .map(|profile| profile.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let active = active
        .into_iter()
        .filter(|profile| enabled.contains(profile))
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(Assessment::Inactive);
    }

    let port = port.to_string();
    let executable = executable.to_string_lossy();
    let candidates = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.name == name
                && rule.enabled
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

fn canonical_firewall_profile(network_category: &str) -> anyhow::Result<String> {
    match network_category.trim() {
        "DomainAuthenticated" => Ok("domain".to_string()),
        "Private" => Ok("private".to_string()),
        "Public" => Ok("public".to_string()),
        unknown => anyhow::bail!(
            "unknown active Windows network category '{unknown}'; refusing to infer a firewall profile"
        ),
    }
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

    #[test]
    fn expired_deadline_refuses_to_spawn_a_process() {
        let error = run_owned_until(
            "koi-command-that-must-not-exist.exe",
            &[],
            Instant::now() - Duration::from_millis(1),
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("deadline elapsed before koi-command-that-must-not-exist.exe"));
    }

    #[test]
    fn bounded_process_owner_terminates_and_reaps_at_deadline() {
        let args = vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 30".to_string(),
        ];
        let mut owned = OwnedJobChild::spawn("powershell.exe", &args).unwrap();
        let started = Instant::now();
        let error = owned
            .wait_until(
                Instant::now() + Duration::from_millis(100),
                "powershell.exe",
            )
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(owned.reaped, "deadline return must acknowledge child reap");
        assert!(owned.child.try_wait().unwrap().is_some());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "terminated child was not reaped promptly"
        );
    }

    #[test]
    fn powershell_query_is_headless_and_noninteractive() {
        let runner = FakeRunner::new(vec![ok("")]);
        powershell(&runner, "Write-Output 'ok'").unwrap();

        let calls = runner.calls.borrow();
        assert_eq!(calls[0].0, "powershell.exe");
        assert_eq!(
            &calls[0].1[..3],
            &["-NoProfile", "-NonInteractive", "-Command"]
        );
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
            &AssessmentSnapshot {
                enabled_profiles: vec!["Private".to_string()],
                active_profiles: vec!["Private".to_string()],
                rules: vec![wrong_program, wrong_profile],
            },
            "Koi Pond",
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
    fn assessment_maps_domain_authenticated_network_to_domain_firewall_profile() {
        let assessment = assess_snapshot(
            &AssessmentSnapshot {
                enabled_profiles: vec!["Domain".to_string()],
                active_profiles: vec!["DomainAuthenticated".to_string()],
                rules: vec![snapshot("Koi Pond", Some("Domain"))],
            },
            "Koi Pond",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap();

        assert_eq!(assessment, Assessment::Open);
    }

    #[test]
    fn assessment_is_inactive_when_only_an_inactive_network_profile_is_enabled() {
        let assessment = assess_snapshot(
            &AssessmentSnapshot {
                enabled_profiles: vec!["Private".to_string()],
                active_profiles: vec!["Public".to_string()],
                rules: vec![snapshot("Koi Pond", Some("Public"))],
            },
            "Koi Pond",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap();

        assert_eq!(assessment, Assessment::Inactive);
    }

    #[test]
    fn assessment_requires_rule_coverage_for_every_active_firewall_profile() {
        let assessment = assess_snapshot(
            &AssessmentSnapshot {
                enabled_profiles: vec!["Private".to_string(), "Public".to_string()],
                active_profiles: vec!["Private".to_string(), "Public".to_string()],
                rules: vec![snapshot("Koi Pond", Some("Private"))],
            },
            "Koi Pond",
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
    fn assessment_fails_closed_on_unknown_active_network_category() {
        let error = assess_snapshot(
            &AssessmentSnapshot {
                enabled_profiles: Vec::new(),
                active_profiles: vec!["Unidentified".to_string()],
                rules: Vec::new(),
            },
            "Koi Pond",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("unknown active Windows network category 'Unidentified'"));
    }

    #[test]
    fn batch_assessment_queries_once_and_keeps_rule_names_correlated() {
        let json = r#"{"enabled_profiles":["Private"],"active_profiles":["Private"],"rules":[{"name":"Koi first","enabled":true,"direction":"Inbound","action":"Allow","protocol":"TCP","local_port":"5644","program":"C:\\Program Files\\Koi\\koi.exe","profile":"Private"}]}"#;
        let runner = FakeRunner::new(vec![ok(json)]);

        let assessments = assess_managed_rules_with(
            &runner,
            &[("Koi first", "TCP", 5644), ("Koi second", "TCP", 5644)],
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap();

        assert_eq!(
            assessments,
            vec![
                Assessment::Open,
                Assessment::Blocked(BlockReason::MissingOrMismatchedRule)
            ]
        );
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn assessment_queries_only_the_effective_active_store() {
        let json = r#"{"enabled_profiles":[],"active_profiles":[],"rules":[]}"#;
        let runner = FakeRunner::new(vec![ok(json)]);

        assess_managed_with(
            &runner,
            "Koi Pond",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap();

        let calls = runner.calls.borrow();
        let script = calls[0].1.last().unwrap();
        for cmdlet in [
            "Get-NetFirewallProfile",
            "Get-NetFirewallRule",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallPortFilter",
        ] {
            let line = script
                .lines()
                .find(|line| line.contains(cmdlet))
                .unwrap_or_else(|| panic!("assessment script omitted {cmdlet}"));
            assert!(
                line.contains("-PolicyStore ActiveStore"),
                "assessment {cmdlet} must query effective policy: {line}"
            );
            assert!(!line.contains("PersistentStore"));
        }
    }

    #[test]
    fn lifecycle_queries_remain_scoped_to_the_local_persistent_store() {
        let snapshot_runner = FakeRunner::new(vec![ok("")]);
        snapshot_managed_with(&snapshot_runner).unwrap();
        let snapshot_calls = snapshot_runner.calls.borrow();
        let snapshot_script = snapshot_calls[0].1.last().unwrap();
        let snapshot_query = snapshot_script
            .lines()
            .find(|line| line.contains("Get-NetFirewallRule"))
            .unwrap();
        assert!(snapshot_query.contains("-PolicyStore PersistentStore"));
        assert!(!snapshot_query.contains("ActiveStore"));

        let remove_runner = FakeRunner::new(vec![ok("KOI_ABSENT")]);
        remove_with(&remove_runner, "Koi Pond").unwrap();
        let remove_calls = remove_runner.calls.borrow();
        let remove_script = remove_calls[0].1.last().unwrap();
        let remove_query = remove_script
            .lines()
            .find(|line| line.contains("Get-NetFirewallRule"))
            .unwrap();
        assert!(remove_query.contains("-PolicyStore PersistentStore"));
        assert!(!remove_query.contains("ActiveStore"));
    }

    #[test]
    fn assessment_query_spawn_failure_remains_an_error() {
        let runner = FakeRunner::new(vec![Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "powershell missing",
        ))]);

        let error = assess_managed_with(
            &runner,
            "Koi Pond",
            "TCP",
            5644,
            Path::new(r"C:\Program Files\Koi\koi.exe"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("could not query Windows Firewall"));
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
