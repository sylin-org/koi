use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::ValueEnum;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::installed_service_systemd::SystemdObserver;
use crate::lab::Lab;
use crate::model::{
    output_path, CheckResult, InstalledServiceCacheCounts, InstalledServiceIdentity,
    InstalledServicePublicationCounts, InstalledServiceReport, InstalledServiceResourceGrowth,
    InstalledServiceSample, InstalledServiceTrafficSample, InstalledServiceTrafficTotals,
    InstalledServiceTransitions, ObservedU64, RunId,
};

const MAX_DURATION_SECONDS: u64 = 24 * 60 * 60;
const MAX_SAMPLE_INTERVAL_SECONDS: u64 = 60 * 60;
const TRAFFIC_ATTEMPTS: u32 = 3;
const TRAFFIC_RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ObserverKind {
    Systemd,
}

#[derive(Clone, Debug)]
pub struct InstalledServiceOptions {
    pub observer: ObserverKind,
    pub service_name: String,
    pub binary_path: PathBuf,
    pub duration_seconds: u64,
    pub sample_interval_seconds: u64,
    pub max_service_restarts: u64,
    pub max_unavailable_samples: u64,
    pub max_consecutive_unavailable_samples: u64,
    pub max_rss_growth_bytes: u64,
    pub max_descriptor_growth: u64,
    pub max_thread_growth: u64,
    pub max_task_growth: u64,
    pub peer_label: String,
    pub peer_surface: String,
}

pub(super) trait ServiceObserver {
    fn name(&self) -> &'static str;
    fn identity(&self) -> Result<InstalledServiceIdentity>;
    fn sample(&self) -> Result<NativeServiceSample>;
}

#[derive(Debug)]
pub(super) struct NativeServiceSample {
    pub pid: u32,
    pub restart_count: ObservedU64,
    pub rss_bytes: ObservedU64,
    pub descriptor_count: ObservedU64,
    pub thread_count: ObservedU64,
    pub task_count: ObservedU64,
}

#[derive(Debug, Deserialize)]
struct InventorySnapshot {
    status: InventoryStatus,
}

#[derive(Debug, Deserialize)]
struct InventoryStatus {
    revision: u64,
    daemon: bool,
    #[serde(deserialize_with = "required_nullable")]
    mdns: Option<InventoryMdnsStatus>,
    #[serde(deserialize_with = "required_nullable")]
    dns: Option<InventoryDnsStatus>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Deserialize)]
struct InventoryDnsStatus {
    records: InventoryDnsRecordCounts,
}

#[derive(Debug, Deserialize)]
struct InventoryDnsRecordCounts {
    static_entries: u64,
    certmesh_entries: u64,
    mdns_entries: u64,
}

#[derive(Debug, Deserialize)]
struct InventoryMdnsStatus {
    control_plane: InventoryMdnsControlPlane,
}

#[derive(Debug, Deserialize)]
struct InventoryMdnsControlPlane {
    generation: u64,
    routes: InventoryMdnsRoutes,
    publications: InventoryPublicationCounts,
}

#[derive(Debug, Deserialize)]
struct InventoryMdnsRoutes {
    publish: Option<String>,
    explicit_publish: Option<String>,
    browse: Option<String>,
    resolve: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InventoryPublicationCounts {
    desired: u64,
    established: u64,
    pending: u64,
    failed: u64,
}

#[derive(Debug, Deserialize)]
struct PondPeerStatus {
    version: String,
    platform: String,
    revision: u64,
    daemon: bool,
    surface: String,
    capabilities: Vec<PondPeerCapability>,
}

#[derive(Debug, Deserialize)]
struct PondPeerCapability {
    name: String,
    #[serde(rename = "enabled")]
    _enabled: bool,
    #[serde(rename = "healthy")]
    _healthy: bool,
}

impl Lab {
    pub fn installed_service_collect(
        &self,
        run_id: &RunId,
        options: &InstalledServiceOptions,
    ) -> Result<InstalledServiceReport> {
        validate_options(options)?;
        let binary_path = options
            .binary_path
            .canonicalize()
            .with_context(|| format!("could not resolve {}", options.binary_path.display()))?;
        let observer = observer(options, binary_path.clone())?;
        let peer_surface = canonical_peer_surface(&options.peer_surface)?;

        let initial_identity = observer.identity()?;
        let source_commit = self.git_commit()?;
        let service_node = local_hostname()?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(options.duration_seconds);
        let mut samples = Vec::new();

        loop {
            samples.push(sample_installed_service(
                started,
                observer.as_ref(),
                &peer_surface,
            ));
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            thread::sleep(Duration::from_secs(options.sample_interval_seconds).min(deadline - now));
        }

        let final_identity = observer.identity()?;
        let elapsed = started.elapsed();
        let restart_delta = observed_delta(
            &initial_identity.restart_count,
            &final_identity.restart_count,
        );
        let restart_rate = restart_delta.map(|delta| {
            let elapsed_hours = elapsed.as_secs_f64() / 3600.0;
            if elapsed_hours > 0.0 {
                delta as f64 / elapsed_hours
            } else {
                0.0
            }
        });
        let transitions = transition_summary(&samples);
        let resource_growth = resource_growth(&samples);
        let traffic_totals = traffic_totals(&samples);
        let checks = report_checks(
            &initial_identity,
            &final_identity,
            &samples,
            &traffic_totals,
            restart_delta,
            &transitions,
            &resource_growth,
            options,
        );
        let report = InstalledServiceReport {
            schema: 3,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            source_commit,
            service_node,
            observer: observer.name().to_owned(),
            peer_label: options.peer_label.clone(),
            peer_surface,
            target_duration_seconds: options.duration_seconds,
            sample_interval_seconds: options.sample_interval_seconds,
            max_service_restarts: options.max_service_restarts,
            max_unavailable_samples: options.max_unavailable_samples,
            max_consecutive_unavailable_samples: options.max_consecutive_unavailable_samples,
            max_rss_growth_bytes: options.max_rss_growth_bytes,
            max_descriptor_growth: options.max_descriptor_growth,
            max_thread_growth: options.max_thread_growth,
            max_task_growth: options.max_task_growth,
            termination: "duration_limit".to_owned(),
            elapsed_ms: millis(elapsed),
            initial_identity,
            final_identity,
            service_restart_delta: restart_delta,
            service_restart_rate_per_hour: restart_rate,
            transitions,
            resource_growth,
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

fn observer(
    options: &InstalledServiceOptions,
    binary_path: PathBuf,
) -> Result<Box<dyn ServiceObserver>> {
    match options.observer {
        ObserverKind::Systemd => Ok(Box::new(SystemdObserver::new(
            options.service_name.clone(),
            binary_path,
        ))),
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
    validate_service_name(&options.service_name)?;
    validate_peer_label(&options.peer_label)?;
    if !options.binary_path.is_absolute() {
        bail!("installed binary path must be absolute");
    }
    canonical_peer_surface(&options.peer_surface)?;
    Ok(())
}

fn validate_peer_label(peer_label: &str) -> Result<()> {
    if peer_label.is_empty()
        || peer_label.len() > 128
        || peer_label.trim() != peer_label
        || peer_label.chars().any(char::is_control)
    {
        bail!("unsafe peer provenance label {peer_label:?}");
    }
    Ok(())
}

fn validate_service_name(service_name: &str) -> Result<()> {
    if service_name.is_empty()
        || !service_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'@' | b'_' | b'-'))
    {
        bail!("unsafe service name {service_name:?}");
    }
    Ok(())
}

fn canonical_peer_surface(value: &str) -> Result<String> {
    let parsed = Url::parse(value).context("peer surface must be an absolute HTTP URL")?;
    if parsed.scheme() != "http" {
        bail!("peer surface must use http");
    }
    if parsed.host().is_none() || parsed.port().is_none() {
        bail!("peer surface must include an explicit host and port");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("peer surface must not contain credentials, query parameters, or a fragment");
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        bail!("peer surface must identify the Koi root URL");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn sample_installed_service(
    started: Instant,
    observer: &dyn ServiceObserver,
    peer_surface: &str,
) -> InstalledServiceSample {
    let mut unavailable = BTreeMap::new();
    let native = observer.sample();
    let (pid, service_restart_count, rss_bytes, descriptor_count, thread_count, task_count) =
        match native {
            Ok(sample) => (
                Some(sample.pid),
                sample.restart_count,
                sample.rss_bytes,
                sample.descriptor_count,
                sample.thread_count,
                sample.task_count,
            ),
            Err(error) => {
                let reason = format!("{error:#}");
                unavailable.insert("native_service".to_owned(), reason.clone());
                (
                    None,
                    ObservedU64::unavailable(reason.clone()),
                    ObservedU64::unavailable(reason.clone()),
                    ObservedU64::unavailable(reason.clone()),
                    ObservedU64::unavailable(reason.clone()),
                    ObservedU64::unavailable(reason),
                )
            }
        };

    let (aggregate_revision, healthy, cache, provider_generation, provider_routes, publications) =
        match local_inventory_snapshot() {
            Ok(status) => {
                let cache = status.dns.map(|dns| {
                    let static_entries = dns.records.static_entries;
                    let certmesh_entries = dns.records.certmesh_entries;
                    let mdns_entries = dns.records.mdns_entries;
                    InstalledServiceCacheCounts {
                        static_entries,
                        certmesh_entries,
                        mdns_entries,
                        total_entries: static_entries
                            .saturating_add(certmesh_entries)
                            .saturating_add(mdns_entries),
                    }
                });
                if cache.is_none() {
                    unavailable.insert(
                        "dns_status".to_owned(),
                        "aggregate inventory reported no DNS status".to_owned(),
                    );
                }

                let (provider_generation, provider_routes, publications) = status.mdns.map_or_else(
                    || {
                        unavailable.insert(
                            "mdns_status".to_owned(),
                            "aggregate inventory reported no mDNS status".to_owned(),
                        );
                        (None, BTreeMap::new(), None)
                    },
                    |mdns| {
                        let routes = mdns.control_plane.routes;
                        let provider_routes = [
                            ("publish", routes.publish),
                            ("explicit_publish", routes.explicit_publish),
                            ("browse", routes.browse),
                            ("resolve", routes.resolve),
                        ]
                        .into_iter()
                        .filter_map(|(name, provider)| {
                            provider.map(|provider| (name.to_owned(), provider))
                        })
                        .collect();
                        let counts = mdns.control_plane.publications;
                        (
                            Some(mdns.control_plane.generation),
                            provider_routes,
                            Some(InstalledServicePublicationCounts {
                                desired: counts.desired,
                                established: counts.established,
                                pending: counts.pending,
                                failed: counts.failed,
                            }),
                        )
                    },
                );
                (
                    Some(status.revision),
                    Some(status.daemon),
                    cache,
                    provider_generation,
                    provider_routes,
                    publications,
                )
            }
            Err(error) => {
                unavailable.insert("inventory_snapshot".to_owned(), format!("{error:#}"));
                (None, None, None, None, BTreeMap::new(), None)
            }
        };

    InstalledServiceSample {
        sampled_at: Utc::now(),
        elapsed_ms: millis(started.elapsed()),
        pid,
        service_restart_count,
        rss_bytes,
        descriptor_count,
        thread_count,
        task_count,
        aggregate_revision,
        healthy,
        cache,
        provider_generation,
        provider_routes,
        publications,
        traffic: probe_peer_surface(peer_surface),
        unavailable,
    }
}

fn local_inventory_snapshot() -> Result<InventoryStatus> {
    let client = koi_client::KoiClient::from_local()
        .context("could not authenticate to the installed local Koi service")?;
    let snapshot = client
        .inventory_snapshot()
        .context("could not read the installed service aggregate inventory")?;
    decode_inventory_snapshot(snapshot)
}

fn decode_inventory_snapshot(snapshot: serde_json::Value) -> Result<InventoryStatus> {
    serde_json::from_value::<InventorySnapshot>(snapshot)
        .map(|snapshot| snapshot.status)
        .context("installed service inventory omitted or malformed a required consumed field")
}

fn probe_peer_surface(peer_surface: &str) -> InstalledServiceTrafficSample {
    let started = Instant::now();
    let client = koi_client::KoiClient::new(peer_surface);
    for attempt in 1..=TRAFFIC_ATTEMPTS {
        let peer_revision = client
            .unified_status()
            .map_err(anyhow::Error::from)
            .and_then(decode_pond_peer_status);
        if let Ok(peer_revision) = peer_revision {
            return InstalledServiceTrafficSample {
                attempts: attempt,
                retries: attempt - 1,
                succeeded: true,
                latency_ms: Some(millis(started.elapsed())),
                peer_revision: Some(peer_revision),
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
        peer_revision: None,
    }
}

fn decode_pond_peer_status(value: serde_json::Value) -> Result<u64> {
    let status: PondPeerStatus = serde_json::from_value(value)
        .context("peer /v1/status was not the required Pond status DTO")?;
    if !status.daemon {
        bail!("peer Pond status did not report a live daemon");
    }
    if status.surface != "pond" {
        bail!(
            "peer status surface was {:?}, expected \"pond\"",
            status.surface
        );
    }
    if status.version.trim().is_empty() || status.platform.trim().is_empty() {
        bail!("peer Pond status omitted version or platform provenance");
    }
    if status.capabilities.is_empty() {
        bail!("peer Pond status reported no capability entries");
    }
    let mut names = std::collections::BTreeSet::new();
    for capability in status.capabilities {
        if capability.name.is_empty()
            || capability.name.len() > 128
            || capability.name.trim() != capability.name
            || capability.name.chars().any(char::is_control)
        {
            bail!(
                "peer Pond status contained invalid capability name {:?}",
                capability.name
            );
        }
        if !names.insert(capability.name.clone()) {
            bail!("peer Pond status repeated capability {:?}", capability.name);
        }
    }
    Ok(status.revision)
}

fn observation_available(sample: &InstalledServiceSample) -> bool {
    sample.pid.is_some()
        && sample.aggregate_revision.is_some()
        && sample.healthy == Some(true)
        && sample.cache.is_some()
        && sample.provider_generation.is_some()
        && sample.publications.is_some()
}

fn transition_summary(samples: &[InstalledServiceSample]) -> InstalledServiceTransitions {
    let mut prior_pid = None;
    let mut prior_available = true;
    let mut pid_changes = 0_u64;
    let mut unavailable_samples = 0_u64;
    let mut consecutive = 0_u64;
    let mut max_consecutive = 0_u64;
    let mut recovery_events = 0_u64;

    for sample in samples {
        if let Some(pid) = sample.pid {
            if prior_pid.is_some_and(|prior| prior != pid) {
                pid_changes = pid_changes.saturating_add(1);
            }
            prior_pid = Some(pid);
        }
        let available = observation_available(sample);
        if available {
            if !prior_available {
                recovery_events = recovery_events.saturating_add(1);
            }
            consecutive = 0;
        } else {
            unavailable_samples = unavailable_samples.saturating_add(1);
            consecutive = consecutive.saturating_add(1);
            max_consecutive = max_consecutive.max(consecutive);
        }
        prior_available = available;
    }

    InstalledServiceTransitions {
        pid_changes,
        unavailable_samples,
        max_consecutive_unavailable_samples: max_consecutive,
        recovery_events,
    }
}

fn resource_growth(samples: &[InstalledServiceSample]) -> InstalledServiceResourceGrowth {
    InstalledServiceResourceGrowth {
        rss_bytes: metric_growth(samples, |sample| sample.rss_bytes.value),
        descriptor_count: metric_growth(samples, |sample| sample.descriptor_count.value),
        thread_count: metric_growth(samples, |sample| sample.thread_count.value),
        task_count: metric_growth(samples, |sample| sample.task_count.value),
    }
}

fn metric_growth(
    samples: &[InstalledServiceSample],
    metric: impl Fn(&InstalledServiceSample) -> Option<u64>,
) -> Option<i64> {
    let first = samples.iter().find_map(&metric)?;
    let last = samples.iter().rev().find_map(metric)?;
    Some(signed_difference(last, first))
}

fn signed_difference(final_value: u64, initial_value: u64) -> i64 {
    let difference = i128::from(final_value) - i128::from(initial_value);
    difference.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn observed_delta(initial: &ObservedU64, final_value: &ObservedU64) -> Option<u64> {
    Some(final_value.value?.saturating_sub(initial.value?))
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

#[allow(clippy::too_many_arguments)]
fn report_checks(
    initial: &InstalledServiceIdentity,
    final_identity: &InstalledServiceIdentity,
    samples: &[InstalledServiceSample],
    traffic: &InstalledServiceTrafficTotals,
    restart_delta: Option<u64>,
    transitions: &InstalledServiceTransitions,
    growth: &InstalledServiceResourceGrowth,
    options: &InstalledServiceOptions,
) -> Vec<CheckResult> {
    let artifact_stable = initial.binary.sha256 == final_identity.binary.sha256
        && initial.binary.path == final_identity.binary.path;
    let observed_restarts = restart_delta
        .unwrap_or(transitions.pid_changes)
        .max(transitions.pid_changes);
    let service_live = final_identity.active_state == "active"
        && final_identity.sub_state == "running"
        && observed_restarts <= options.max_service_restarts;
    let health_good = !samples.is_empty()
        && samples
            .iter()
            .filter_map(|sample| sample.healthy)
            .all(|healthy| healthy)
        && samples.iter().any(|sample| sample.healthy.is_some());
    let resource_counters = samples.iter().flat_map(|sample| {
        [
            &sample.rss_bytes,
            &sample.descriptor_count,
            &sample.thread_count,
            &sample.task_count,
        ]
    });
    let resource_shapes_valid = resource_counters.clone().all(observation_shape_valid);
    let resources_observed = !samples.is_empty()
        && resource_shapes_valid
        && resource_counters
            .filter(|counter| counter.value.is_some())
            .count()
            > 0;
    let provider_observed = !samples.is_empty()
        && samples
            .iter()
            .filter(|sample| sample.provider_generation.is_some())
            .all(|sample| !sample.provider_routes.is_empty())
        && samples
            .iter()
            .any(|sample| sample.provider_generation.is_some());
    let publication_sync = !samples.is_empty()
        && samples
            .iter()
            .filter_map(|sample| sample.publications.as_ref())
            .all(|counts| {
                counts.desired == counts.established && counts.pending == 0 && counts.failed == 0
            })
        && samples.iter().any(|sample| sample.publications.is_some());
    let availability_bounded = transitions.unavailable_samples <= options.max_unavailable_samples
        && transitions.max_consecutive_unavailable_samples
            <= options.max_consecutive_unavailable_samples;
    let recovered = samples.last().is_some_and(observation_available);
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
                "service ended {}/{} at pid {} with {observed_restarts} observed restart/PID transition(s), allowed {}",
                final_identity.active_state,
                final_identity.sub_state,
                final_identity.pid,
                options.max_service_restarts
            ),
        ),
        check(
            "health",
            health_good,
            "every available authenticated aggregate snapshot reported a live daemon".to_owned(),
        ),
        check(
            "resource_samples",
            resources_observed,
            "resource counters were observed; unsupported counters remain explicitly unavailable"
                .to_owned(),
        ),
        check(
            "provider_routes",
            provider_observed,
            "every available provider sample recorded a generation and concrete routes".to_owned(),
        ),
        check(
            "publication_sync",
            publication_sync,
            "every available publication sample was converged with no pending or failed work"
                .to_owned(),
        ),
        check(
            "bounded_unavailability",
            availability_bounded,
            format!(
                "{} unavailable sample(s), maximum consecutive {}; allowed {}/{}",
                transitions.unavailable_samples,
                transitions.max_consecutive_unavailable_samples,
                options.max_unavailable_samples,
                options.max_consecutive_unavailable_samples
            ),
        ),
        check(
            "transition_recovery",
            recovered,
            format!(
                "final sample was available after {} PID change(s) and {} recovery event(s)",
                transitions.pid_changes, transitions.recovery_events
            ),
        ),
        growth_check("rss_growth", growth.rss_bytes, options.max_rss_growth_bytes),
        growth_check(
            "descriptor_growth",
            growth.descriptor_count,
            options.max_descriptor_growth,
        ),
        growth_check(
            "thread_growth",
            growth.thread_count,
            options.max_thread_growth,
        ),
        growth_check("task_growth", growth.task_count, options.max_task_growth),
        check(
            "cross_host_pond_status",
            cross_host,
            format!(
                "{} valid peer Pond /v1/status reads from {} attempts and {} retries",
                traffic.successes, traffic.attempts, traffic.retries
            ),
        ),
    ]
}

fn growth_check(name: &str, growth: Option<i64>, allowed: u64) -> CheckResult {
    let passed = growth.is_none_or(|value| value <= allowed.min(i64::MAX as u64) as i64);
    check(
        name,
        passed,
        match growth {
            Some(value) => format!("observed growth {value}, allowed {allowed}"),
            None => "counter unavailable on this observer; no zero value was fabricated".to_owned(),
        },
    )
}

fn observation_shape_valid(counter: &ObservedU64) -> bool {
    counter.value.is_some() != counter.unavailable.is_some()
}

fn check(name: &str, passed: bool, detail: String) -> CheckResult {
    CheckResult {
        name: name.to_owned(),
        passed,
        detail,
    }
}

fn local_hostname() -> Result<String> {
    let output = Command::new("hostname")
        .output()
        .context("failed to start hostname")?;
    if !output.status.success() {
        bail!("hostname failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
    fn options_are_hard_bounded_and_peer_surface_is_secret_free() {
        let options = options();
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
        let mut invalid = options.clone();
        invalid.service_name = "koi; reboot".to_owned();
        assert!(validate_options(&invalid).is_err());
        let mut invalid = options.clone();
        invalid.peer_label = "bad\nlabel".to_owned();
        assert!(validate_options(&invalid).is_err());
        let mut invalid = options;
        invalid.peer_surface = "http://user:secret@192.0.2.1:5644".to_owned();
        assert!(validate_options(&invalid).is_err());
    }

    #[test]
    fn inventory_decode_requires_consumed_fields_and_accepts_extensions() {
        let decoded = decode_inventory_snapshot(inventory_json()).unwrap();
        assert_eq!(decoded.revision, 7);
        assert!(decoded.daemon);
        assert!(decoded.mdns.is_some());
        assert_eq!(decoded.dns.unwrap().records.static_entries, 2);

        for required in ["revision", "daemon", "mdns", "dns"] {
            let mut value = inventory_json();
            value["status"].as_object_mut().unwrap().remove(required);
            assert!(
                decode_inventory_snapshot(value).is_err(),
                "missing {required} must not become a fabricated default"
            );
        }

        for pointer in [
            "/status/mdns/control_plane/generation",
            "/status/mdns/control_plane/publications/desired",
            "/status/dns/records/static_entries",
        ] {
            let mut value = inventory_json();
            remove_json_pointer(&mut value, pointer);
            assert!(
                decode_inventory_snapshot(value).is_err(),
                "missing consumed field {pointer} must fail decoding"
            );
        }

        let mut disabled = inventory_json();
        disabled["status"]["mdns"] = serde_json::Value::Null;
        disabled["status"]["dns"] = serde_json::Value::Null;
        let decoded = decode_inventory_snapshot(disabled).unwrap();
        assert!(decoded.mdns.is_none());
        assert!(decoded.dns.is_none());
    }

    #[test]
    fn peer_probe_accepts_only_a_well_formed_pond_status() {
        assert_eq!(decode_pond_peer_status(pond_status_json()).unwrap(), 11);
        assert!(decode_pond_peer_status(serde_json::json!({"status": "ok"})).is_err());

        for (field, invalid) in [
            ("daemon", serde_json::json!(false)),
            ("surface", serde_json::json!("operator")),
            ("version", serde_json::json!("")),
            ("platform", serde_json::json!(" ")),
            ("capabilities", serde_json::json!([])),
        ] {
            let mut value = pond_status_json();
            value[field] = invalid;
            assert!(decode_pond_peer_status(value).is_err(), "invalid {field}");
        }

        let mut missing_bool = pond_status_json();
        missing_bool["capabilities"][0]
            .as_object_mut()
            .unwrap()
            .remove("healthy");
        assert!(decode_pond_peer_status(missing_bool).is_err());

        let mut duplicate = pond_status_json();
        duplicate["capabilities"] = serde_json::json!([
            {"name": "mdns", "enabled": true, "healthy": true},
            {"name": "mdns", "enabled": false, "healthy": false}
        ]);
        assert!(decode_pond_peer_status(duplicate).is_err());
    }

    #[test]
    fn traffic_totals_keep_retries_distinct_from_service_restarts() {
        let samples = vec![sample(true, 1, 0, Some(1)), sample(true, 2, 1, Some(1))];
        let totals = traffic_totals(&samples);
        assert_eq!(totals.attempts, 3);
        assert_eq!(totals.retries, 1);
        assert_eq!(totals.successes, 2);
    }

    #[test]
    fn transition_and_growth_evidence_are_bounded_and_honest() {
        let samples = vec![
            sample(true, 1, 0, Some(10)),
            sample(false, 3, 2, None),
            sample(true, 1, 0, Some(11)),
        ];
        let transitions = transition_summary(&samples);
        assert_eq!(transitions.pid_changes, 1);
        assert_eq!(transitions.unavailable_samples, 1);
        assert_eq!(transitions.max_consecutive_unavailable_samples, 1);
        assert_eq!(transitions.recovery_events, 1);
        let growth = resource_growth(&samples);
        assert_eq!(growth.rss_bytes, Some(8));
        assert_eq!(growth.descriptor_count, Some(1));
    }

    #[test]
    fn observed_counter_round_trips_available_and_unavailable_shapes() {
        for observed in [
            ObservedU64::available(42),
            ObservedU64::unavailable("SCM exposes no restart counter"),
        ] {
            let json = serde_json::to_string(&observed).unwrap();
            assert_eq!(
                serde_json::from_str::<ObservedU64>(&json).unwrap(),
                observed
            );
        }
    }

    fn inventory_json() -> serde_json::Value {
        serde_json::json!({
            "status": {
                "version": "1.0.0-dev.0",
                "platform": "linux",
                "uptime_secs": 5,
                "revision": 7,
                "daemon": true,
                "http_bind": "127.0.0.1",
                "capabilities": [],
                "mdns": serde_json::to_value(koi_mdns::MdnsStatus::default()).unwrap(),
                "dns": {
                    "revision": 3,
                    "running": true,
                    "desired": true,
                    "state": "running",
                    "endpoints": ["127.0.0.1:53"],
                    "zone": "internal",
                    "port": 53,
                    "records": {
                        "static_entries": 2,
                        "certmesh_entries": 1,
                        "mdns_entries": 3,
                        "txt_names": 0
                    },
                    "future_dns_field": true
                },
                "future_status_field": {"accepted": true}
            },
            "health": null,
            "dns": {"names": []},
            "future_inventory_field": 42
        })
    }

    fn pond_status_json() -> serde_json::Value {
        serde_json::json!({
            "version": "1.0.0-dev.0",
            "platform": "linux",
            "uptime_secs": 8,
            "revision": 11,
            "daemon": true,
            "surface": "pond",
            "capabilities": [
                {"name": "mdns", "enabled": true, "healthy": true},
                {"name": "dns", "enabled": true, "healthy": true}
            ],
            "future_public_field": "accepted"
        })
    }

    fn remove_json_pointer(value: &mut serde_json::Value, pointer: &str) {
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
    }

    fn options() -> InstalledServiceOptions {
        InstalledServiceOptions {
            observer: ObserverKind::Systemd,
            service_name: "koi.service".to_owned(),
            binary_path: std::env::temp_dir().join("koi-installed-service-test"),
            duration_seconds: 10,
            sample_interval_seconds: 2,
            max_service_restarts: 0,
            max_unavailable_samples: 0,
            max_consecutive_unavailable_samples: 0,
            max_rss_growth_bytes: 64 * 1024 * 1024,
            max_descriptor_growth: 16,
            max_thread_growth: 8,
            max_task_growth: 8,
            peer_label: "test-01 installed Koi".to_owned(),
            peer_surface: "http://192.0.2.1:5644".to_owned(),
        }
    }

    fn sample(
        succeeded: bool,
        attempts: u32,
        retries: u32,
        pid: Option<u32>,
    ) -> InstalledServiceSample {
        let available = pid.is_some();
        let observed = |value| {
            if available {
                ObservedU64::available(value)
            } else {
                ObservedU64::unavailable("sample unavailable")
            }
        };
        InstalledServiceSample {
            sampled_at: Utc::now(),
            elapsed_ms: 0,
            pid,
            service_restart_count: observed(0),
            rss_bytes: observed(if pid == Some(11) { 18 } else { 10 }),
            descriptor_count: observed(if pid == Some(11) { 2 } else { 1 }),
            thread_count: observed(1),
            task_count: observed(1),
            aggregate_revision: available.then_some(7),
            healthy: available.then_some(true),
            cache: available.then_some(InstalledServiceCacheCounts {
                static_entries: 0,
                certmesh_entries: 0,
                mdns_entries: 0,
                total_entries: 0,
            }),
            provider_generation: available.then_some(1),
            provider_routes: if available {
                BTreeMap::from([("browse".to_owned(), "native".to_owned())])
            } else {
                BTreeMap::new()
            },
            publications: available.then_some(InstalledServicePublicationCounts {
                desired: 0,
                established: 0,
                pending: 0,
                failed: 0,
            }),
            traffic: InstalledServiceTrafficSample {
                attempts,
                retries,
                succeeded,
                latency_ms: None,
                peer_revision: succeeded.then_some(11),
            },
            unavailable: if available {
                BTreeMap::new()
            } else {
                BTreeMap::from([("native_service".to_owned(), "sample unavailable".to_owned())])
            },
        }
    }
}
