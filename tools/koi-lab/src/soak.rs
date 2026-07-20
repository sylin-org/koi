use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::Utc;

use crate::derived::{wait_for_derived_service, wait_for_derived_service_absence};
use crate::lab::{wait_for_http, Lab};
use crate::model::{
    output_path, BoundedSoakReport, CheckResult, NodeSpec, RunId, SoakIterationReport,
};

const PRIMARY_NODE: &str = "brook";
const OBSERVER_NODE: &str = "granite";
const MAX_ITERATIONS: u32 = 100_000;
const MAX_DURATION_MINUTES: u32 = 24 * 60;

#[derive(Default)]
struct SoakResources {
    primary_daemon: bool,
    observer_daemon: bool,
    image_owned: bool,
    container_owned: bool,
}

impl Lab {
    pub fn bounded_soak(
        &self,
        run_id: &RunId,
        iterations: u32,
        max_minutes: u32,
        restart_every: u32,
    ) -> Result<BoundedSoakReport> {
        validate_soak_bounds(iterations, max_minutes, restart_every)?;
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("bounded soak refused: run does not own both staged node directories");
        }

        let primary = self.remote_by_id(PRIMARY_NODE)?;
        let observer = self.remote_by_id(OBSERVER_NODE)?;
        let mut resources = SoakResources::default();
        let result = self.run_bounded_soak(
            run_id,
            primary,
            observer,
            iterations,
            max_minutes,
            restart_every,
            &mut resources,
        );
        let cleanup = self.cleanup_bounded_soak(run_id, primary, observer, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "container, image, daemons, sockets, and process markers were removed by exact run identity",
                ));
                let path = output_path(run_id.as_str()).join("bounded-soak-linux.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("soak checks passed but cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "bounded soak failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_bounded_soak(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        target_iterations: u32,
        max_minutes: u32,
        restart_every: u32,
        resources: &mut SoakResources,
    ) -> Result<BoundedSoakReport> {
        self.start_story_daemon(primary, run_id)?;
        resources.primary_daemon = true;
        self.start_story_daemon(observer, run_id)?;
        resources.observer_daemon = true;
        let primary_url = self.node_url(primary)?;
        let observer_url = self.node_url(observer)?;
        wait_for_http(&format!("{primary_url}/healthz"))?;
        wait_for_http(&format!("{observer_url}/healthz"))?;

        resources.image_owned = true;
        self.stage_story_container_image(primary, run_id)?;
        let artifact_sha256 = self.remote_line(
            primary,
            &format!("cat {}/artifact.sha256", primary.run_dir(run_id)?),
        )?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(u64::from(max_minutes) * 60);
        let suffix = soak_suffix(run_id);
        let mut reports = Vec::new();

        for iteration in 1..=target_iterations {
            if Instant::now() >= deadline && !reports.is_empty() {
                break;
            }
            let iteration_started = Instant::now();
            let service_name = format!("koi-soak-{suffix}-{iteration}");
            let dns_name = format!("soak-{suffix}-{iteration}.internal");
            let full_service_name = format!("{service_name}._http._tcp.local.");
            let health_name = format!("runtime:{service_name}");

            resources.container_owned = true;
            self.start_story_container(primary, run_id, &service_name, &dns_name)?;
            wait_for_derived_service(
                self,
                primary,
                observer,
                &primary_url,
                &observer_url,
                &service_name,
                &dns_name,
                &full_service_name,
                &health_name,
            )?;

            let mut restarted_from_pid = None;
            let mut restarted_to_pid = None;
            if restart_every != 0 && iteration % restart_every == 0 {
                let before_pid = self.story_daemon_pid(primary, run_id)?;
                let before_token = self.daemon_token(primary, run_id)?;
                self.restart_story_daemon(primary, run_id)?;
                wait_for_http(&format!("{primary_url}/healthz"))?;
                let after_pid = self.story_daemon_pid(primary, run_id)?;
                let after_token = self.daemon_token(primary, run_id)?;
                if after_pid == before_pid {
                    bail!("soak restart retained PID {before_pid}");
                }
                if after_token == before_token {
                    bail!("soak restart retained the daemon access token");
                }
                wait_for_derived_service(
                    self,
                    primary,
                    observer,
                    &primary_url,
                    &observer_url,
                    &service_name,
                    &dns_name,
                    &full_service_name,
                    &health_name,
                )?;
                restarted_from_pid = Some(before_pid);
                restarted_to_pid = Some(after_pid);
            }

            self.stop_story_container(primary, run_id)?;
            resources.container_owned = false;
            wait_for_derived_service_absence(
                &primary_url,
                &observer_url,
                &service_name,
                &dns_name,
                &full_service_name,
                &health_name,
            )?;
            reports.push(SoakIterationReport {
                iteration,
                duration_ms: millis(iteration_started.elapsed()),
                restarted_from_pid,
                restarted_to_pid,
            });
        }

        let completed_iterations = u32::try_from(reports.len()).unwrap_or(u32::MAX);
        let termination = if completed_iterations == target_iterations {
            "iteration_limit"
        } else {
            "duration_limit"
        };
        let restart_count = reports
            .iter()
            .filter(|report| report.restarted_to_pid.is_some())
            .count();
        Ok(BoundedSoakReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            primary_node: primary.id().to_owned(),
            observer_node: observer.id().to_owned(),
            artifact_sha256,
            target_iterations,
            completed_iterations,
            max_minutes,
            restart_every,
            termination: termination.to_owned(),
            elapsed_ms: millis(started.elapsed()),
            iterations: reports,
            checks: vec![
                passed(
                    "bounded_execution",
                    format!(
                        "completed {completed_iterations}/{target_iterations} iterations before the {termination}"
                    ),
                ),
                passed(
                    "complete_iteration_reversal",
                    "every completed iteration converged and disappeared across runtime, DNS, mDNS, health, proxy state, and live proxy traffic",
                ),
                passed(
                    "periodic_restart_reconstruction",
                    format!("{restart_count} selected live-container iterations rotated PID and DAT and fully reconstructed"),
                ),
            ],
            secrets_redacted: true,
        })
    }

    fn cleanup_bounded_soak(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        resources: &mut SoakResources,
    ) -> Result<()> {
        let mut failures = Vec::new();
        if resources.container_owned {
            if let Err(error) = self.cleanup_story_container(primary, run_id) {
                failures.push(format!("container: {error:#}"));
            } else {
                resources.container_owned = false;
            }
        }
        if resources.image_owned {
            if let Err(error) = self.cleanup_story_container_image(primary, run_id) {
                failures.push(format!("image: {error:#}"));
            } else {
                resources.image_owned = false;
            }
        }
        if resources.primary_daemon {
            if let Err(error) = self.stop_story_daemon(primary, run_id) {
                failures.push(format!("primary daemon: {error:#}"));
            } else {
                resources.primary_daemon = false;
            }
        }
        if resources.observer_daemon {
            if let Err(error) = self.stop_story_daemon(observer, run_id) {
                failures.push(format!("observer daemon: {error:#}"));
            } else {
                resources.observer_daemon = false;
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("{}", failures.join("; "))
        }
    }

    fn story_daemon_pid(&self, node: &NodeSpec, run_id: &RunId) -> Result<u32> {
        let run_dir = node.run_dir(run_id)?;
        self.remote_line(node, &format!("cat {run_dir}/daemon.pid"))?
            .parse()
            .context("story daemon PID was not a u32")
    }
}

pub(crate) fn validate_soak_bounds(
    iterations: u32,
    max_minutes: u32,
    restart_every: u32,
) -> Result<()> {
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        bail!("iterations must be between 1 and {MAX_ITERATIONS}");
    }
    if !(1..=MAX_DURATION_MINUTES).contains(&max_minutes) {
        bail!("max-minutes must be between 1 and {MAX_DURATION_MINUTES}");
    }
    if restart_every > iterations {
        bail!("restart-every must be zero or no greater than iterations");
    }
    Ok(())
}

fn soak_suffix(run_id: &RunId) -> &str {
    run_id.as_str().rsplit('-').next().unwrap_or("soak")
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soak_bounds_are_finite_and_restart_zero_is_allowed() {
        assert!(validate_soak_bounds(20, 15, 5).is_ok());
        assert!(validate_soak_bounds(20, 15, 0).is_ok());
        assert!(validate_soak_bounds(0, 15, 0).is_err());
        assert!(validate_soak_bounds(1, 0, 0).is_err());
        assert!(validate_soak_bounds(2, 1, 3).is_err());
    }

    #[test]
    fn soak_suffix_uses_only_run_entropy() {
        let run_id = RunId::parse("v1-20260720T000000Z-deadbeef").unwrap();
        assert_eq!(soak_suffix(&run_id), "deadbeef");
    }
}
