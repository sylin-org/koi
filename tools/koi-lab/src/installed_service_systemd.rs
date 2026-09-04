use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::installed_service::{NativeServiceSample, ServiceObserver};
use crate::installed_service_process as process;
use crate::model::{InstalledServiceIdentity, ObservedU64};

pub(super) struct SystemdObserver {
    service_name: String,
    expected_binary: PathBuf,
}

impl SystemdObserver {
    pub(super) fn new(service_name: String, expected_binary: PathBuf) -> Self {
        Self {
            service_name,
            expected_binary,
        }
    }
}

impl ServiceObserver for SystemdObserver {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn identity(&self) -> Result<InstalledServiceIdentity> {
        let systemd = systemd_snapshot(&self.service_name)?;
        if systemd.active_state != "active" || systemd.sub_state != "running" {
            bail!(
                "{} is not an active running installed service: {}/{}",
                self.service_name,
                systemd.active_state,
                systemd.sub_state
            );
        }
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", systemd.pid));
        let process_binary = process::binary_path(systemd.pid, &proc_exe)?;
        if process_binary != self.expected_binary {
            bail!(
                "{} pid {} runs {}, expected {}",
                self.service_name,
                systemd.pid,
                process_binary.display(),
                self.expected_binary.display()
            );
        }
        let version = process::checked_output(&self.expected_binary, &["--version"])?;
        Ok(InstalledServiceIdentity {
            observer: self.name().to_owned(),
            service_name: self.service_name.clone(),
            active_state: systemd.active_state,
            sub_state: systemd.sub_state,
            service_definition: systemd.fragment_path,
            exec_start: systemd.exec_start,
            pid: systemd.pid,
            restart_count: ObservedU64::available(systemd.restart_count),
            binary: process::artifact(&proc_exe, &process_binary)?,
            version,
        })
    }

    fn sample(&self) -> Result<NativeServiceSample> {
        let systemd = systemd_snapshot(&self.service_name)?;
        let process = process::snapshot(systemd.pid)?;
        Ok(NativeServiceSample {
            pid: systemd.pid,
            restart_count: ObservedU64::available(systemd.restart_count),
            rss_bytes: ObservedU64::available(process.rss_bytes),
            descriptor_count: ObservedU64::available(process.descriptor_count),
            thread_count: ObservedU64::available(process.thread_count),
            task_count: ObservedU64::available(systemd.task_count),
        })
    }
}

#[derive(Debug)]
struct SystemdSnapshot {
    active_state: String,
    sub_state: String,
    fragment_path: PathBuf,
    exec_start: String,
    pid: u32,
    restart_count: u64,
    task_count: u64,
}

fn systemd_snapshot(service_name: &str) -> Result<SystemdSnapshot> {
    let output = checked_command(
        "systemctl",
        &[
            "show",
            service_name,
            "--no-pager",
            "--property=ActiveState,SubState,FragmentPath,ExecStart,MainPID,NRestarts,TasksCurrent",
        ],
    )?;
    let properties = parse_properties(&output);
    Ok(SystemdSnapshot {
        active_state: required_property(&properties, "ActiveState")?.to_owned(),
        sub_state: required_property(&properties, "SubState")?.to_owned(),
        fragment_path: PathBuf::from(required_property(&properties, "FragmentPath")?),
        exec_start: required_property(&properties, "ExecStart")?.to_owned(),
        pid: parse_property(&properties, "MainPID")?,
        restart_count: parse_property(&properties, "NRestarts")?,
        task_count: parse_property(&properties, "TasksCurrent")?,
    })
}

fn parse_properties(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn required_property<'a>(properties: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    let value = properties
        .get(name)
        .with_context(|| format!("systemctl omitted {name}"))?;
    if value.is_empty() {
        bail!("systemctl reported an empty {name}");
    }
    Ok(value)
}

fn parse_property<T>(properties: &BTreeMap<String, String>, name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    required_property(properties, name)?
        .parse()
        .map_err(|error| anyhow::anyhow!("systemctl {name} is invalid: {error}"))
}

fn checked_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {program}"))?;
    checked_process_output(program, args, output)
}

fn checked_process_output(
    program: &str,
    args: &[&str],
    output: std::process::Output,
) -> Result<String> {
    if !output.status.success() {
        bail!(
            "{} {} failed (exit {}): {}",
            program,
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_shape_without_human_summary_text() {
        let properties =
            parse_properties("MainPID=24507\nNRestarts=2\nActiveState=active\nSubState=running\n");
        assert_eq!(
            parse_property::<u32>(&properties, "MainPID").unwrap(),
            24507
        );
        assert_eq!(parse_property::<u64>(&properties, "NRestarts").unwrap(), 2);
        assert_eq!(
            required_property(&properties, "ActiveState").unwrap(),
            "active"
        );
    }
}
