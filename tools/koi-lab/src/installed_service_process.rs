use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::model::ArtifactIdentity;

#[derive(Debug)]
pub(super) struct ProcessSnapshot {
    pub rss_bytes: u64,
    pub descriptor_count: u64,
    pub thread_count: u64,
}

pub(super) fn snapshot(pid: u32) -> Result<ProcessSnapshot> {
    let status_path = PathBuf::from(format!("/proc/{pid}/status"));
    let status = fs::read_to_string(&status_path)
        .with_context(|| format!("could not read {}", status_path.display()))?;
    let (rss_bytes, thread_count) = parse_proc_status(&status)?;
    Ok(ProcessSnapshot {
        rss_bytes,
        descriptor_count: descriptor_count(pid)?,
        thread_count,
    })
}

pub(super) fn binary_path(pid: u32, proc_exe: &Path) -> Result<PathBuf> {
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

pub(super) fn artifact(proc_exe: &Path, resolved_path: &Path) -> Result<ArtifactIdentity> {
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

pub(super) fn checked_output(binary: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {}", binary.display()))?;
    checked_process_output(&binary.display().to_string(), args, output)
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
    fn parses_proc_shape() {
        let (rss, threads) =
            parse_proc_status("Name:\tkoi\nVmRSS:\t  28916 kB\nThreads:\t8\n").unwrap();
        assert_eq!(rss, 28_916 * 1024);
        assert_eq!(threads, 8);
        assert!(parse_proc_status("Threads:\t8\n").is_err());
    }
}
