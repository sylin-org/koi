use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::installed_service::{NativeServiceSample, ServiceObserver};
use crate::model::{ArtifactIdentity, InstalledServiceIdentity, ObservedU64};

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
        let process_binary = process_binary_path(systemd.pid, &proc_exe)?;
        if process_binary != self.expected_binary {
            bail!(
                "{} pid {} runs {}, expected {}",
                self.service_name,
                systemd.pid,
                process_binary.display(),
                self.expected_binary.display()
            );
        }
        let version = checked_output(&self.expected_binary, &["--version"])?;
        Ok(InstalledServiceIdentity {
            observer: self.name().to_owned(),
            service_name: self.service_name.clone(),
            active_state: systemd.active_state,
            sub_state: systemd.sub_state,
            service_definition: systemd.fragment_path,
            exec_start: systemd.exec_start,
            pid: systemd.pid,
            restart_count: ObservedU64::available(systemd.restart_count),
            binary: process_artifact(&proc_exe, &process_binary)?,
            version,
        })
    }

    fn sample(&self) -> Result<NativeServiceSample> {
        let systemd = systemd_snapshot(&self.service_name)?;
        let process = proc_snapshot(systemd.pid)?;
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

#[derive(Debug)]
struct ProcSnapshot {
    rss_bytes: u64,
    descriptor_count: u64,
    thread_count: u64,
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

fn proc_snapshot(pid: u32) -> Result<ProcSnapshot> {
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let status = fs::read_to_string(&status_path)
        .with_context(|| format!("could not read {}", status_path.display()))?;
    let (rss_bytes, thread_count) = parse_proc_status(&status)?;
    Ok(ProcSnapshot {
        rss_bytes,
        descriptor_count: descriptor_count(pid)?,
        thread_count,
    })
}

fn descriptor_count(pid: u32) -> Result<u64> {
    let path = PathBuf::from(format!("/proc/{pid}/fd"));
    match fs::read_dir(&path) {
        Ok(entries) => {
            let mut count = 0_u64;
            for entry in entries {
                entry.with_context(|| format!("could not enumerate {}", path.display()))?;
                count = count.saturating_add(1);
            }
            Ok(count)
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let output = checked_command(
                "sudo",
                &[
                    "-n",
                    "find",
                    path.to_str().context("proc fd path is not UTF-8")?,
                    "-mindepth",
                    "1",
                    "-maxdepth",
                    "1",
                    "-printf",
                    ".\n",
                ],
            )?;
            Ok(usize_to_u64(output.lines().count()))
        }
        Err(error) => Err(error).with_context(|| format!("could not enumerate {}", path.display())),
    }
}

fn process_binary_path(pid: u32, proc_exe: &Path) -> Result<PathBuf> {
    match proc_exe.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let output = checked_command(
                "sudo",
                &[
                    "-n",
                    "readlink",
                    "-f",
                    proc_exe
                        .to_str()
                        .context("proc executable path is not UTF-8")?,
                ],
            )?;
            if output.ends_with(" (deleted)") {
                bail!("pid {pid} is running a deleted executable");
            }
            let path = PathBuf::from(output);
            if !path.is_absolute() {
                bail!("pid {pid} executable did not resolve to an absolute path");
            }
            Ok(path)
        }
        Err(error) => {
            Err(error).with_context(|| format!("could not resolve executable for pid {pid}"))
        }
    }
}

fn process_artifact(proc_exe: &Path, resolved_path: &Path) -> Result<ArtifactIdentity> {
    match ArtifactIdentity::from_path(proc_exe) {
        Ok(mut artifact) => {
            artifact.path = resolved_path.to_path_buf();
            Ok(artifact)
        }
        Err(_) => {
            let proc_exe = proc_exe
                .to_str()
                .context("proc executable path is not UTF-8")?;
            let size_bytes = checked_command("sudo", &["-n", "stat", "-Lc", "%s", proc_exe])?
                .parse()
                .context("process executable size is not an integer")?;
            let sha_output = checked_command("sudo", &["-n", "sha256sum", proc_exe])?;
            let sha256 = sha_output
                .split_whitespace()
                .next()
                .context("sha256sum returned no digest")?;
            if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("sha256sum returned an invalid process executable digest");
            }
            Ok(ArtifactIdentity {
                path: resolved_path.to_path_buf(),
                size_bytes,
                sha256: sha256.to_owned(),
            })
        }
    }
}

fn parse_proc_status(status: &str) -> Result<(u64, u64)> {
    let mut rss_kib = None;
    let mut threads = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss_kib = Some(parse_first_u64(value, "VmRSS")?);
        } else if let Some(value) = line.strip_prefix("Threads:") {
            threads = Some(parse_first_u64(value, "Threads")?);
        }
    }
    Ok((
        rss_kib
            .context("process status omitted VmRSS")?
            .saturating_mul(1024),
        threads.context("process status omitted Threads")?,
    ))
}

fn parse_first_u64(value: &str, label: &str) -> Result<u64> {
    value
        .split_whitespace()
        .next()
        .with_context(|| format!("{label} is empty"))?
        .parse()
        .with_context(|| format!("{label} is not an integer"))
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

fn checked_output(binary: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {}", binary.display()))?;
    checked_process_output(&binary.display().to_string(), args, output)
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

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_and_proc_shapes_without_human_summary_text() {
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

        let (rss, threads) =
            parse_proc_status("Name:\tkoi\nVmRSS:\t  28916 kB\nThreads:\t8\n").unwrap();
        assert_eq!(rss, 28_916 * 1024);
        assert_eq!(threads, 8);
        assert!(parse_proc_status("Threads:\t8\n").is_err());
    }
}
