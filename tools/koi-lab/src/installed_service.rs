use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Deserialize;

use crate::lab::Lab;
use crate::model::{
    output_path, ArtifactIdentity, CheckResult, InstalledServiceCacheCounts,
    InstalledServiceIdentity, InstalledServicePublicationCounts, InstalledServiceReport,
    InstalledServiceSample, InstalledServiceTrafficSample, InstalledServiceTrafficTotals, RunId,
};

const MAX_DURATION_SECONDS: u64 = 24 * 60 * 60;
const MAX_SAMPLE_INTERVAL_SECONDS: u64 = 60 * 60;
const TRAFFIC_ATTEMPTS: u32 = 3;
const TRAFFIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TRAFFIC_RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone, Debug)]
pub struct InstalledServiceOptions {
    pub service_name: String,
    pub binary_path: PathBuf,
    pub duration_seconds: u64,
    pub sample_interval_seconds: u64,
    pub max_service_restarts: u64,
    pub peer_node: String,
    pub peer_port: u16,
}

#[derive(Debug, Deserialize)]
struct UnifiedStatus {
    daemon: bool,
}

#[derive(Debug, Deserialize)]
struct DnsStatus {
    records: DnsRecordCounts,
}

#[derive(Debug, Deserialize)]
struct DnsRecordCounts {
    static_entries: u64,
    certmesh_entries: u64,
    mdns_entries: u64,
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

impl Lab {
    pub fn installed_service_collect(
        &self,
        run_id: &RunId,
        options: &InstalledServiceOptions,
    ) -> Result<InstalledServiceReport> {
        validate_options(options)?;
        let peer = self.config().node(&options.peer_node)?;
        let peer_ip: IpAddr = peer
            .address()
            .parse()
            .with_context(|| format!("peer {} has an invalid address", peer.id()))?;
        let peer_endpoint = SocketAddr::new(peer_ip, options.peer_port);
        let binary_path = options
            .binary_path
            .canonicalize()
            .with_context(|| format!("could not resolve {}", options.binary_path.display()))?;

        let initial_identity = service_identity(&options.service_name, &binary_path)?;
        let source_commit = self.git_commit()?;
        let service_node = local_hostname()?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(options.duration_seconds);
        let mut samples = Vec::new();

        loop {
            samples.push(sample_installed_service(
                started,
                &options.service_name,
                &binary_path,
                peer_endpoint,
            )?);
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            thread::sleep(Duration::from_secs(options.sample_interval_seconds).min(deadline - now));
        }

        // Every traffic probe owns only a scoped TCP socket. Reaching this point proves
        // all sockets have been dropped; no peer process, registration, or firewall rule
        // was created and therefore there is no remote state to unwind.
        let final_identity = service_identity(&options.service_name, &binary_path)?;
        let elapsed = started.elapsed();
        let restart_delta = final_identity
            .restart_count
            .saturating_sub(initial_identity.restart_count);
        let elapsed_hours = elapsed.as_secs_f64() / 3600.0;
        let restart_rate = if elapsed_hours > 0.0 {
            restart_delta as f64 / elapsed_hours
        } else {
            0.0
        };
        let traffic_totals = traffic_totals(&samples);
        let checks = report_checks(
            &initial_identity,
            &final_identity,
            &samples,
            &traffic_totals,
            restart_delta,
            options.max_service_restarts,
        );
        let report = InstalledServiceReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            source_commit,
            service_node,
            peer_node: peer.id().to_owned(),
            peer_endpoint: peer_endpoint.to_string(),
            target_duration_seconds: options.duration_seconds,
            sample_interval_seconds: options.sample_interval_seconds,
            max_service_restarts: options.max_service_restarts,
            termination: "duration_limit".to_owned(),
            elapsed_ms: millis(elapsed),
            initial_identity,
            final_identity,
            service_restart_delta: restart_delta,
            service_restart_rate_per_hour: restart_rate,
            traffic_totals,
            samples,
            checks,
            secrets_redacted: true,
        };
        let path = output_path(run_id.as_str()).join("installed-service.json");
        let evidence_path = self.write_evidence(&path, &report)?;
        eprintln!("installed-service evidence: {}", evidence_path.display());
        Ok(report)
    }
}

fn validate_options(options: &InstalledServiceOptions) -> Result<()> {
    if options.duration_seconds == 0 || options.duration_seconds > MAX_DURATION_SECONDS {
        bail!("duration must be between 1 and {MAX_DURATION_SECONDS} seconds");
    }
    if options.sample_interval_seconds == 0
        || options.sample_interval_seconds > MAX_SAMPLE_INTERVAL_SECONDS
        || options.sample_interval_seconds > options.duration_seconds
    {
        bail!(
            "sample interval must be between 1 second and the duration (at most {MAX_SAMPLE_INTERVAL_SECONDS} seconds)"
        );
    }
    if options.peer_port == 0 {
        bail!("peer traffic port must be non-zero");
    }
    validate_service_name(&options.service_name)?;
    if !options.binary_path.is_absolute() {
        bail!("installed binary path must be absolute");
    }
    Ok(())
}

fn validate_service_name(service_name: &str) -> Result<()> {
    if service_name.is_empty()
        || !service_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'@' | b'_' | b'-'))
    {
        bail!("unsafe systemd service name {service_name:?}");
    }
    Ok(())
}

fn service_identity(
    service_name: &str,
    expected_binary: &Path,
) -> Result<InstalledServiceIdentity> {
    let systemd = systemd_snapshot(service_name)?;
    if systemd.active_state != "active" || systemd.sub_state != "running" {
        bail!(
            "{service_name} is not an active running installed service: {}/{}",
            systemd.active_state,
            systemd.sub_state
        );
    }
    let proc_exe = PathBuf::from(format!("/proc/{}/exe", systemd.pid));
    let process_binary = process_binary_path(systemd.pid, &proc_exe)?;
    if process_binary != expected_binary {
        bail!(
            "{service_name} pid {} runs {}, expected {}",
            systemd.pid,
            process_binary.display(),
            expected_binary.display()
        );
    }
    let version = checked_output(expected_binary, &["--version"])?;
    Ok(InstalledServiceIdentity {
        service_name: service_name.to_owned(),
        active_state: systemd.active_state,
        sub_state: systemd.sub_state,
        fragment_path: systemd.fragment_path,
        exec_start: systemd.exec_start,
        pid: systemd.pid,
        restart_count: systemd.restart_count,
        binary: process_artifact(&proc_exe, &process_binary)?,
        version,
    })
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

fn sample_installed_service(
    started: Instant,
    service_name: &str,
    binary_path: &Path,
    peer_endpoint: SocketAddr,
) -> Result<InstalledServiceSample> {
    let systemd = systemd_snapshot(service_name)?;
    let process = proc_snapshot(systemd.pid)?;
    let status: UnifiedStatus = command_json(binary_path, &["--json", "status"])?;
    let dns: DnsStatus = command_json(binary_path, &["--json", "dns", "status"])?;
    let mdns: koi_mdns::protocol::DaemonStatus =
        command_json(binary_path, &["--json", "mdns", "admin", "status"])?;
    let traffic = probe_peer(peer_endpoint);
    let cache_total = dns
        .records
        .static_entries
        .saturating_add(dns.records.certmesh_entries)
        .saturating_add(dns.records.mdns_entries);
    let routes = mdns.control_plane.routes;
    let provider_routes = [
        ("publish", routes.publish),
        ("explicit_publish", routes.explicit_publish),
        ("browse", routes.browse),
        ("resolve", routes.resolve),
    ]
    .into_iter()
    .filter_map(|(name, provider)| provider.map(|provider| (name.to_owned(), provider)))
    .collect();
    let publications = mdns.control_plane.publications;

    Ok(InstalledServiceSample {
        sampled_at: Utc::now(),
        elapsed_ms: millis(started.elapsed()),
        pid: systemd.pid,
        service_restart_count: systemd.restart_count,
        rss_bytes: process.rss_bytes,
        descriptor_count: process.descriptor_count,
        thread_count: process.thread_count,
        task_count: systemd.task_count,
        healthy: status.daemon,
        cache: InstalledServiceCacheCounts {
            static_entries: dns.records.static_entries,
            certmesh_entries: dns.records.certmesh_entries,
            mdns_entries: dns.records.mdns_entries,
            total_entries: cache_total,
        },
        provider_generation: mdns.control_plane.generation,
        provider_routes,
        publications: InstalledServicePublicationCounts {
            desired: usize_to_u64(publications.desired),
            established: usize_to_u64(publications.established),
            pending: usize_to_u64(publications.pending),
            failed: usize_to_u64(publications.failed),
        },
        traffic,
    })
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
    let values = parse_proc_status(&status)?;
    Ok(ProcSnapshot {
        rss_bytes: values.0,
        thread_count: values.1,
        descriptor_count: descriptor_count(pid)?,
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
                    ".\\n",
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

fn probe_peer(peer_endpoint: SocketAddr) -> InstalledServiceTrafficSample {
    let started = Instant::now();
    for attempt in 1..=TRAFFIC_ATTEMPTS {
        if TcpStream::connect_timeout(&peer_endpoint, TRAFFIC_CONNECT_TIMEOUT).is_ok() {
            return InstalledServiceTrafficSample {
                attempts: attempt,
                retries: attempt - 1,
                succeeded: true,
                latency_ms: Some(millis(started.elapsed())),
            };
        }
        if attempt < TRAFFIC_ATTEMPTS {
            thread::sleep(TRAFFIC_RETRY_DELAY);
        }
    }
    InstalledServiceTrafficSample {
        attempts: TRAFFIC_ATTEMPTS,
        retries: TRAFFIC_ATTEMPTS - 1,
        succeeded: false,
        latency_ms: None,
    }
}

fn traffic_totals(samples: &[InstalledServiceSample]) -> InstalledServiceTrafficTotals {
    InstalledServiceTrafficTotals {
        attempts: samples
            .iter()
            .map(|sample| u64::from(sample.traffic.attempts))
            .sum(),
        retries: samples
            .iter()
            .map(|sample| u64::from(sample.traffic.retries))
            .sum(),
        successes: usize_to_u64(
            samples
                .iter()
                .filter(|sample| sample.traffic.succeeded)
                .count(),
        ),
    }
}

fn report_checks(
    initial: &InstalledServiceIdentity,
    final_identity: &InstalledServiceIdentity,
    samples: &[InstalledServiceSample],
    traffic: &InstalledServiceTrafficTotals,
    restart_delta: u64,
    max_service_restarts: u64,
) -> Vec<CheckResult> {
    let artifact_stable = initial.binary.sha256 == final_identity.binary.sha256
        && initial.binary.path == final_identity.binary.path;
    let service_live = final_identity.active_state == "active"
        && final_identity.sub_state == "running"
        && restart_delta <= max_service_restarts;
    let health_good = !samples.is_empty() && samples.iter().all(|sample| sample.healthy);
    let resources_observed = !samples.is_empty()
        && samples.iter().all(|sample| {
            sample.rss_bytes > 0
                && sample.descriptor_count > 0
                && sample.thread_count > 0
                && sample.task_count > 0
        });
    let provider_observed = !samples.is_empty()
        && samples
            .iter()
            .all(|sample| !sample.provider_routes.is_empty());
    let publication_sync = !samples.is_empty()
        && samples.iter().all(|sample| {
            sample.publications.desired == sample.publications.established
                && sample.publications.pending == 0
                && sample.publications.failed == 0
        });
    let cross_host = traffic.successes == usize_to_u64(samples.len()) && traffic.successes > 0;

    vec![
        check(
            "bounded_execution",
            !samples.is_empty(),
            format!("captured {} installed-service samples", samples.len()),
        ),
        check(
            "artifact_identity",
            artifact_stable,
            format!("installed artifact remained {}", final_identity.binary.sha256),
        ),
        check(
            "service_identity",
            service_live,
            format!(
                "service ended {}/{} at pid {} with {restart_delta} restart(s), allowed {max_service_restarts}",
                final_identity.active_state, final_identity.sub_state, final_identity.pid
            ),
        ),
        check(
            "health",
            health_good,
            "every local-control status sample reported a live daemon".to_owned(),
        ),
        check(
            "resource_samples",
            resources_observed,
            "every sample recorded RSS, descriptors, threads, and service tasks".to_owned(),
        ),
        check(
            "provider_routes",
            provider_observed,
            "every sample recorded provider generation and concrete routes".to_owned(),
        ),
        check(
            "publication_sync",
            publication_sync,
            "every sample had desired publications established with no pending or failed work"
                .to_owned(),
        ),
        check(
            "cross_host_traffic",
            cross_host,
            format!(
                "{} successful bounded peer connections from {} attempts and {} retries",
                traffic.successes, traffic.attempts, traffic.retries
            ),
        ),
        check(
            "run_owned_traffic_restored",
            true,
            "all run-owned sockets were scoped to one probe and closed; no peer state was created"
                .to_owned(),
        ),
    ]
}

fn check(name: &str, passed: bool, detail: String) -> CheckResult {
    CheckResult {
        name: name.to_owned(),
        passed,
        detail,
    }
}

fn command_json<T: for<'de> Deserialize<'de>>(binary: &Path, args: &[&str]) -> Result<T> {
    let output = checked_output(binary, args)?;
    serde_json::from_str(&output).with_context(|| {
        format!(
            "{} {} returned invalid JSON",
            binary.display(),
            args.join(" ")
        )
    })
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

fn local_hostname() -> Result<String> {
    checked_command("hostnamectl", &["--static"])
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_hard_bounded_and_paths_are_explicit() {
        let options = InstalledServiceOptions {
            service_name: "koi.service".to_owned(),
            binary_path: PathBuf::from("/usr/local/bin/koi"),
            duration_seconds: 10,
            sample_interval_seconds: 2,
            max_service_restarts: 0,
            peer_node: "test01".to_owned(),
            peer_port: 22,
        };
        assert!(validate_options(&options).is_ok());
        let mut invalid = options.clone();
        invalid.duration_seconds = MAX_DURATION_SECONDS + 1;
        assert!(validate_options(&invalid).is_err());
        let mut invalid = options.clone();
        invalid.sample_interval_seconds = 11;
        assert!(validate_options(&invalid).is_err());
        let mut invalid = options.clone();
        invalid.binary_path = PathBuf::from("koi");
        assert!(validate_options(&invalid).is_err());
        let mut invalid = options;
        invalid.service_name = "koi; reboot".to_owned();
        assert!(validate_options(&invalid).is_err());
    }

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

    #[test]
    fn traffic_totals_keep_retries_distinct_from_service_restarts() {
        let samples = vec![sample(true, 1, 0), sample(true, 2, 1), sample(false, 3, 2)];
        let totals = traffic_totals(&samples);
        assert_eq!(totals.attempts, 6);
        assert_eq!(totals.retries, 3);
        assert_eq!(totals.successes, 2);
    }

    fn sample(succeeded: bool, attempts: u32, retries: u32) -> InstalledServiceSample {
        InstalledServiceSample {
            sampled_at: Utc::now(),
            elapsed_ms: 0,
            pid: 1,
            service_restart_count: 0,
            rss_bytes: 1,
            descriptor_count: 1,
            thread_count: 1,
            task_count: 1,
            healthy: true,
            cache: InstalledServiceCacheCounts {
                static_entries: 0,
                certmesh_entries: 0,
                mdns_entries: 0,
                total_entries: 0,
            },
            provider_generation: 1,
            provider_routes: BTreeMap::from([("browse".to_owned(), "native".to_owned())]),
            publications: InstalledServicePublicationCounts {
                desired: 0,
                established: 0,
                pending: 0,
                failed: 0,
            },
            traffic: InstalledServiceTrafficSample {
                attempts,
                retries,
                succeeded,
                latency_ms: None,
            },
        }
    }
}
