use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::installed_service::{NativeServiceSample, ServiceObserver};
use crate::installed_service_process as process;
use crate::model::{InstalledServiceIdentity, ObservedU64};

const OPENRC_INIT_DIR: &str = "/etc/init.d";
const OPENRC_OPTIONS_DIR: &str = "/run/openrc/options";
const OPENRC_STARTED_DIR: &str = "/run/openrc/started";
const OPENRC_TASK_COUNT_UNAVAILABLE: &str =
    "OpenRC exposes no service-cgroup task count for supervise-daemon";

pub(super) struct OpenRcObserver {
    service_name: String,
    expected_binary: PathBuf,
}

impl OpenRcObserver {
    pub(super) fn new(service_name: String, expected_binary: PathBuf) -> Self {
        Self {
            service_name,
            expected_binary,
        }
    }
}

impl ServiceObserver for OpenRcObserver {
    fn name(&self) -> &'static str {
        "openrc"
    }

    fn identity(&self) -> Result<InstalledServiceIdentity> {
        let openrc = openrc_snapshot(&self.service_name)?;
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", openrc.child_pid));
        let process_binary = process::binary_path(openrc.child_pid, &proc_exe)?;
        if openrc.executable != self.expected_binary || process_binary != self.expected_binary {
            bail!(
                "{} child pid {} uses OpenRC executable {} and process image {}, expected {}",
                self.service_name,
                openrc.child_pid,
                openrc.executable.display(),
                process_binary.display(),
                self.expected_binary.display()
            );
        }
        let version = process::checked_output(&self.expected_binary, &["--version"])?;
        Ok(InstalledServiceIdentity {
            observer: self.name().to_owned(),
            service_name: self.service_name.clone(),
            active_state: "started".to_owned(),
            sub_state: "supervised".to_owned(),
            service_definition: openrc.service_definition,
            exec_start: openrc.arguments.join(" "),
            pid: openrc.child_pid,
            restart_count: ObservedU64::available(openrc.restart_count),
            binary: process::artifact(&proc_exe, &process_binary)?,
            version,
        })
    }

    fn sample(&self) -> Result<NativeServiceSample> {
        let openrc = openrc_snapshot(&self.service_name)?;
        let process = process::snapshot(openrc.child_pid)?;
        Ok(NativeServiceSample {
            pid: openrc.child_pid,
            restart_count: ObservedU64::available(openrc.restart_count),
            rss_bytes: ObservedU64::available(process.rss_bytes),
            descriptor_count: ObservedU64::available(process.descriptor_count),
            thread_count: ObservedU64::available(process.thread_count),
            task_count: ObservedU64::unavailable(OPENRC_TASK_COUNT_UNAVAILABLE),
        })
    }
}

#[derive(Debug)]
struct OpenRcSnapshot {
    service_definition: PathBuf,
    executable: PathBuf,
    arguments: Vec<String>,
    child_pid: u32,
    restart_count: u64,
}

fn openrc_snapshot(service_name: &str) -> Result<OpenRcSnapshot> {
    require_started(service_name)?;

    let service_definition = PathBuf::from(OPENRC_INIT_DIR).join(service_name);
    let service_definition = service_definition.canonicalize().with_context(|| {
        format!(
            "could not resolve OpenRC service definition {}",
            service_definition.display()
        )
    })?;
    let started_marker = PathBuf::from(OPENRC_STARTED_DIR).join(service_name);
    let started_definition = started_marker.canonicalize().with_context(|| {
        format!(
            "could not resolve started marker {}",
            started_marker.display()
        )
    })?;
    if started_definition != service_definition {
        bail!(
            "OpenRC started marker {} resolves to {}, expected {}",
            started_marker.display(),
            started_definition.display(),
            service_definition.display()
        );
    }

    let options_dir = PathBuf::from(OPENRC_OPTIONS_DIR).join(service_name);
    let child_pid = read_number::<u32>(&options_dir.join("child_pid"), "child pid")?;
    if child_pid == 0 {
        bail!("OpenRC reported child pid zero for {service_name}");
    }
    let restart_count = read_number(&options_dir.join("start_count"), "start count")?;
    let executable = canonical_option_path(&options_dir.join("exec"), "executable")?;
    let arguments = read_arguments(&options_dir)?;
    if arguments.first().map(String::as_str) != executable.to_str() {
        bail!(
            "OpenRC argv_0 does not match executable {}",
            executable.display()
        );
    }

    let supervisor_pidfile = canonical_option_path(&options_dir.join("pidfile"), "pidfile")?;
    let expected_pidfile = PathBuf::from(format!("/run/supervise-{service_name}.pid"));
    let expected_pidfile = expected_pidfile.canonicalize().with_context(|| {
        format!(
            "could not resolve expected supervise-daemon pidfile {}",
            expected_pidfile.display()
        )
    })?;
    if supervisor_pidfile != expected_pidfile {
        bail!(
            "OpenRC pidfile resolves to {}, expected {}",
            supervisor_pidfile.display(),
            expected_pidfile.display()
        );
    }
    let supervisor_pid = read_number::<u32>(&supervisor_pidfile, "supervisor pid")?;
    let child_status = fs::read_to_string(format!("/proc/{child_pid}/status"))
        .with_context(|| format!("could not read status for OpenRC child pid {child_pid}"))?;
    let parent_pid = parse_parent_pid(&child_status)?;
    if parent_pid != supervisor_pid {
        bail!(
            "OpenRC child pid {child_pid} has parent {parent_pid}, expected supervisor pid {supervisor_pid}"
        );
    }

    Ok(OpenRcSnapshot {
        service_definition,
        executable,
        arguments,
        child_pid,
        restart_count,
    })
}

fn require_started(service_name: &str) -> Result<()> {
    let output = Command::new("rc-service")
        .args([service_name, "status"])
        .output()
        .context("failed to start rc-service")?;
    if !output.status.success() {
        bail!(
            "OpenRC service {service_name} is not started (exit {}): {}{}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn read_arguments(options_dir: &Path) -> Result<Vec<String>> {
    let argument_count = read_number::<usize>(&options_dir.join("argc"), "argument count")?;
    if argument_count == 0 {
        bail!("OpenRC reported zero command arguments");
    }
    let mut arguments = Vec::with_capacity(argument_count);
    for index in 0..argument_count {
        arguments.push(read_required(&options_dir.join(format!("argv_{index}")))?);
    }
    Ok(arguments)
}

fn canonical_option_path(path: &Path, label: &str) -> Result<PathBuf> {
    let value = PathBuf::from(read_required(path)?);
    if !value.is_absolute() {
        bail!(
            "OpenRC {label} is not an absolute path: {}",
            value.display()
        );
    }
    value
        .canonicalize()
        .with_context(|| format!("could not resolve OpenRC {label} {}", value.display()))
}

fn read_number<T>(path: &Path, label: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    read_required(path)?
        .parse()
        .map_err(|error| anyhow::anyhow!("OpenRC {label} is invalid: {error}"))
}

fn read_required(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("could not read OpenRC fact {}", path.display()))?;
    let value = value.trim();
    if value.is_empty() {
        bail!("OpenRC fact {} is empty", path.display());
    }
    Ok(value.to_owned())
}

fn parse_parent_pid(status: &str) -> Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .context("process status omitted PPid")?
        .trim()
        .parse()
        .context("process PPid is not an integer")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn parses_parent_pid_without_process_summary_text() {
        assert_eq!(
            parse_parent_pid("Name:\tkoi\nPPid:\t2022\nThreads:\t14\n").unwrap(),
            2022
        );
        assert!(parse_parent_pid("Name:\tkoi\n").is_err());
        assert!(parse_parent_pid("PPid:\tparent\n").is_err());
    }

    #[test]
    fn task_count_is_explicitly_unavailable() {
        let observed = ObservedU64::unavailable(OPENRC_TASK_COUNT_UNAVAILABLE);
        assert_eq!(observed.value, None);
        assert_eq!(
            observed.unavailable.as_deref(),
            Some(OPENRC_TASK_COUNT_UNAVAILABLE)
        );
    }

    #[test]
    fn openrc_native_states_do_not_claim_systemd_vocabulary() {
        assert_ne!("started", "active");
        assert_ne!("supervised", "running");
    }

    #[test]
    fn argument_files_are_indexed_by_openrc_argc() {
        let files = BTreeMap::from([
            ("argc", "2"),
            ("argv_0", "/usr/bin/koi"),
            ("argv_1", "--daemon"),
        ]);
        let arguments = arguments_from_map(&files).unwrap();
        assert_eq!(arguments, ["/usr/bin/koi", "--daemon"]);
    }

    fn arguments_from_map(files: &BTreeMap<&str, &str>) -> Result<Vec<String>> {
        let argument_count = files
            .get("argc")
            .context("missing argc")?
            .parse::<usize>()?;
        (0..argument_count)
            .map(|index| {
                files
                    .get(format!("argv_{index}").as_str())
                    .map(|value| (*value).to_owned())
                    .with_context(|| format!("missing argv_{index}"))
            })
            .collect()
    }
}
