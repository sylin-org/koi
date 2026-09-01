//! Capability-aware mDNS control plane.
//!
//! This application service owns provider policy and real materializations. It
//! never owns registration intent or browse demand: those belong to the
//! registration registry and discovery hub respectively.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use koi_common::mdns_protocol::{
    ControlPlaneState, MdnsCapabilities, MdnsControlPlaneStatus, MdnsProviderReport, MdnsRoutes,
    ProviderAvailability, ProviderSessionState, PublicationSync,
};

use crate::adapter::{failed_assessment, MdnsAdapter};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::native::NativeMdnsAdapter;
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderBrowse, ProviderService, ProviderSession,
    PublicationLease,
};
use crate::registry::RegistrationRegistry;
use crate::Result;

const COMMAND_CAPACITY: usize = 512;
const BROWSE_CAPACITY: usize = 512;
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(6);
const OPEN_TIMEOUT: Duration = Duration::from_secs(8);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(8);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);
const INITIAL_TIMEOUT: Duration = Duration::from_secs(20);
const FAILOVER_OBSERVATIONS: u8 = 2;
const PROMOTION_OBSERVATIONS: u8 = 3;

#[derive(Debug, Clone)]
struct ControlPlaneConfig {
    probe_interval: Duration,
    inspect_timeout: Duration,
    open_timeout: Duration,
    operation_timeout: Duration,
    shutdown_timeout: Duration,
    initial_timeout: Duration,
    failover_observations: u8,
    promotion_observations: u8,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            probe_interval: PROBE_INTERVAL,
            inspect_timeout: INSPECT_TIMEOUT,
            open_timeout: OPEN_TIMEOUT,
            operation_timeout: OPERATION_TIMEOUT,
            shutdown_timeout: SHUTDOWN_TIMEOUT,
            initial_timeout: INITIAL_TIMEOUT,
            failover_observations: FAILOVER_OBSERVATIONS,
            promotion_observations: PROMOTION_OBSERVATIONS,
        }
    }
}

/// Stable application service used by `MdnsCore` and `DiscoveryHub`.
pub(crate) struct MdnsControlPlane {
    command_tx: mpsc::Sender<Command>,
    status: Arc<RwLock<MdnsControlPlaneStatus>>,
    browse_generation_tx: watch::Sender<u64>,
}

impl MdnsControlPlane {
    pub(crate) async fn start(
        mut platform_adapters: Vec<Arc<dyn MdnsAdapter>>,
        registry: Arc<RegistrationRegistry>,
    ) -> Result<Arc<Self>> {
        let native: Arc<dyn MdnsAdapter> = Arc::new(NativeMdnsAdapter);
        if platform_adapters
            .iter()
            .any(|adapter| adapter.descriptor().name == native.descriptor().name)
        {
            return Err(MdnsError::Daemon(
                "the platform catalog cannot replace the reserved native Koi adapter".to_string(),
            ));
        }
        if let Some(adapter) = platform_adapters
            .iter()
            .find(|adapter| adapter.descriptor().priority <= native.descriptor().priority)
        {
            return Err(MdnsError::Daemon(format!(
                "platform adapter {} priority {} must exceed reserved native priority {}",
                adapter.descriptor().name,
                adapter.descriptor().priority,
                native.descriptor().priority
            )));
        }
        platform_adapters.push(native);
        Self::start_catalog(platform_adapters, registry, ControlPlaneConfig::default()).await
    }

    async fn start_catalog(
        mut adapters: Vec<Arc<dyn MdnsAdapter>>,
        registry: Arc<RegistrationRegistry>,
        config: ControlPlaneConfig,
    ) -> Result<Arc<Self>> {
        if adapters.is_empty() {
            return Err(MdnsError::Daemon(
                "mDNS provider catalog cannot be empty".to_string(),
            ));
        }
        adapters.sort_by(|left, right| {
            right
                .descriptor()
                .priority
                .cmp(&left.descriptor().priority)
                .then_with(|| left.descriptor().name.cmp(right.descriptor().name))
        });
        let mut names = HashSet::new();
        for adapter in &adapters {
            if !names.insert(adapter.descriptor().name) {
                return Err(MdnsError::Daemon(format!(
                    "duplicate mDNS adapter name: {}",
                    adapter.descriptor().name
                )));
            }
        }

        let status = Arc::new(RwLock::new(MdnsControlPlaneStatus::default()));
        let (browse_generation_tx, _) = watch::channel(0_u64);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (initial_tx, initial_rx) = oneshot::channel();
        let actor = ControlPlaneActor {
            adapters,
            registry,
            command_tx: command_tx.clone(),
            command_rx,
            status: Arc::clone(&status),
            browse_generation_tx: browse_generation_tx.clone(),
            config: config.clone(),
            plan: None,
            sessions: HashMap::new(),
            publications: HashMap::new(),
            publication_failures: HashMap::new(),
            latest_reports: Vec::new(),
            round: None,
            next_round: 0,
            pending_transition: None,
            transition_note: Some("probing provider catalog".to_string()),
            initial_tx: Some(initial_tx),
        };
        let actor_task = tokio::spawn(actor.run());
        match tokio::time::timeout(config.initial_timeout, initial_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                actor_task.abort();
                return Err(MdnsError::Daemon(
                    "mDNS control plane stopped during initial reconciliation".to_string(),
                ));
            }
            Err(_) => {
                actor_task.abort();
                return Err(provider_error(
                    "control-plane",
                    ProviderOperation::Inspect,
                    ProviderFailure::Timeout,
                    "initial provider assessment timed out",
                ));
            }
        }

        Ok(Arc::new(Self {
            command_tx,
            status,
            browse_generation_tx,
        }))
    }

    pub(crate) fn status(&self) -> MdnsControlPlaneStatus {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) async fn publish(&self, announcement: Announcement) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Publish {
                announcement,
                reply: reply_tx,
            })
            .await
            .map_err(|_| stopped_error(ProviderOperation::Publish))?;
        reply_rx
            .await
            .map_err(|_| stopped_error(ProviderOperation::Publish))?
    }

    pub(crate) async fn withdraw(&self, id: &str) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Withdraw {
                id: id.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| stopped_error(ProviderOperation::Withdraw))?;
        reply_rx
            .await
            .map_err(|_| stopped_error(ProviderOperation::Withdraw))?
    }

    pub(crate) async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Browse {
                service_type: service_type.to_string(),
                is_meta,
                reply: reply_tx,
            })
            .await
            .map_err(|_| stopped_error(ProviderOperation::Browse))?;
        let (mut raw, generation) = reply_rx
            .await
            .map_err(|_| stopped_error(ProviderOperation::Browse))??;

        let mut generation_rx = self.browse_generation_tx.subscribe();
        let (event_tx, event_rx) = mpsc::channel(BROWSE_CAPACITY);
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => break,
                    changed = generation_rx.changed() => {
                        if changed.is_err() || *generation_rx.borrow() != generation {
                            break;
                        }
                    }
                    event = raw.recv() => {
                        let Some(event) = event else { break; };
                        if *generation_rx.borrow() != generation || event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = done_tx.send(raw.close().await);
        });
        Ok(ProviderBrowse::new(
            event_rx,
            Box::new(ControlPlaneBrowseLease {
                cancel_tx: Some(cancel_tx),
                done_rx: Some(done_rx),
            }),
        ))
    }

    pub(crate) async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Resolve {
                name: name.to_string(),
                service_type: service_type.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| stopped_error(ProviderOperation::Resolve))?;
        reply_rx
            .await
            .map_err(|_| stopped_error(ProviderOperation::Resolve))?
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Shutdown(reply_tx))
            .await
            .map_err(|_| stopped_error(ProviderOperation::Shutdown))?;
        reply_rx
            .await
            .map_err(|_| stopped_error(ProviderOperation::Shutdown))?
    }
}

struct ControlPlaneBrowseLease {
    cancel_tx: Option<oneshot::Sender<()>>,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
}

#[async_trait::async_trait]
impl BrowseLease for ControlPlaneBrowseLease {
    fn provider_name(&self) -> &'static str {
        "control-plane"
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.send(());
        }
        match self.done_rx.take() {
            Some(done_rx) => done_rx
                .await
                .map_err(|_| stopped_error(ProviderOperation::Browse))?,
            None => Ok(()),
        }
    }
}

enum Command {
    Assessed {
        round: u64,
        index: usize,
        report: MdnsProviderReport,
    },
    Publish {
        announcement: Announcement,
        reply: oneshot::Sender<Result<()>>,
    },
    Withdraw {
        id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Browse {
        service_type: String,
        is_meta: bool,
        reply: oneshot::Sender<Result<(ProviderBrowse, u64)>>,
    },
    Resolve {
        name: String,
        service_type: String,
        reply: oneshot::Sender<Result<ProviderService>>,
    },
    Shutdown(oneshot::Sender<Result<()>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoutePlan {
    publish: usize,
    explicit_publish: usize,
    browse: usize,
    resolve: Option<usize>,
}

impl RoutePlan {
    fn publication_provider(self, explicit: bool) -> usize {
        if explicit {
            self.explicit_publish
        } else {
            self.publish
        }
    }

    fn indices(self) -> Vec<usize> {
        let mut indices = vec![self.publish, self.explicit_publish, self.browse];
        if let Some(index) = self.resolve {
            indices.push(index);
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    fn required_from(self, index: usize) -> MdnsCapabilities {
        let mut required = MdnsCapabilities::default();
        if self.publish == index {
            required.publish = true;
            required.withdraw = true;
        }
        if self.explicit_publish == index {
            required.publish = true;
            required.withdraw = true;
            required.explicit_address = true;
        }
        if self.browse == index {
            required.continuous_browse = true;
            required.browse_resolves = true;
        }
        if self.resolve == Some(index) {
            required.direct_resolve = true;
        }
        required
    }
}

struct MaterializedPublication {
    announcement: Announcement,
    provider: usize,
    lease: Box<dyn PublicationLease>,
}

struct AssessmentRound {
    id: u64,
    reports: Vec<Option<MdnsProviderReport>>,
    remaining: usize,
    decided: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTransition {
    target: Option<RoutePlan>,
    observations: u8,
}

struct ControlPlaneActor {
    adapters: Vec<Arc<dyn MdnsAdapter>>,
    registry: Arc<RegistrationRegistry>,
    command_tx: mpsc::Sender<Command>,
    command_rx: mpsc::Receiver<Command>,
    status: Arc<RwLock<MdnsControlPlaneStatus>>,
    browse_generation_tx: watch::Sender<u64>,
    config: ControlPlaneConfig,
    plan: Option<RoutePlan>,
    sessions: HashMap<usize, Arc<dyn ProviderSession>>,
    publications: HashMap<String, MaterializedPublication>,
    publication_failures: HashMap<String, String>,
    latest_reports: Vec<Option<MdnsProviderReport>>,
    round: Option<AssessmentRound>,
    next_round: u64,
    pending_transition: Option<PendingTransition>,
    transition_note: Option<String>,
    initial_tx: Option<oneshot::Sender<()>>,
}

impl ControlPlaneActor {
    async fn run(mut self) {
        self.latest_reports = vec![None; self.adapters.len()];
        self.begin_assessment();
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.probe_interval,
            self.config.probe_interval,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    let Some(command) = command else {
                        let _ = self.release_everything().await;
                        break;
                    };
                    if !self.handle(command).await {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if self.round.is_none() {
                        self.begin_assessment();
                    }
                    let _ = self.synchronize_publications().await;
                    self.refresh_status();
                }
            }
        }
        self.set_stopped();
    }

    async fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Assessed {
                round,
                index,
                report,
            } => {
                self.handle_assessment(round, index, report).await;
            }
            Command::Publish {
                announcement,
                reply,
            } => {
                let id = announcement.id.clone();
                let result = self.publish_one(announcement).await;
                self.refresh_status();
                if let Err(Ok(())) = reply.send(result) {
                    let _ = self.withdraw_one(&id).await;
                    let _ = self.synchronize_publications().await;
                    self.refresh_status();
                }
            }
            Command::Withdraw { id, reply } => {
                let result = self.withdraw_one(&id).await;
                self.refresh_status();
                let _ = reply.send(result);
            }
            Command::Browse {
                service_type,
                is_meta,
                reply,
            } => {
                let result = self.open_browse(&service_type, is_meta).await;
                if let Err(Ok((browse, _))) = reply.send(result) {
                    let _ = browse.close().await;
                }
            }
            Command::Resolve {
                name,
                service_type,
                reply,
            } => {
                let result = self.resolve(&name, &service_type).await;
                let _ = reply.send(result);
            }
            Command::Shutdown(reply) => {
                self.advance_browse_generation();
                let result = self.release_everything().await;
                let complete = result.is_ok();
                let _ = reply.send(result);
                if complete {
                    return false;
                }
            }
        }
        true
    }

    fn begin_assessment(&mut self) {
        self.next_round = self.next_round.saturating_add(1);
        let round_id = self.next_round;
        self.round = Some(AssessmentRound {
            id: round_id,
            reports: vec![None; self.adapters.len()],
            remaining: self.adapters.len(),
            decided: false,
        });
        for (index, adapter) in self.adapters.iter().cloned().enumerate() {
            let command_tx = self.command_tx.clone();
            let inspect_timeout = self.config.inspect_timeout;
            tokio::spawn(async move {
                let descriptor = adapter.descriptor();
                let report = match tokio::time::timeout(inspect_timeout, adapter.assess()).await {
                    Ok(report) => report,
                    Err(_) => failed_assessment(
                        descriptor,
                        ProviderAvailability::Unavailable,
                        format!("assessment exceeded {inspect_timeout:?}"),
                    ),
                };
                let _ = command_tx
                    .send(Command::Assessed {
                        round: round_id,
                        index,
                        report,
                    })
                    .await;
            });
        }
    }

    async fn handle_assessment(
        &mut self,
        round_id: u64,
        index: usize,
        mut report: MdnsProviderReport,
    ) {
        let (round_complete, bootstrap_can_decide) = {
            let Some(round) = self.round.as_mut() else {
                return;
            };
            if round.id != round_id
                || index >= self.adapters.len()
                || round.reports[index].is_some()
            {
                return;
            }
            let descriptor = self.adapters[index].descriptor();
            report.name = descriptor.name.to_string();
            report.priority = descriptor.priority;
            report.api = descriptor.api;
            report.capabilities = report.capabilities.intersect(descriptor.capabilities);
            report.session = self.sessions.get(&index).map(session_state);
            round.reports[index] = Some(report.clone());
            round.remaining = round.remaining.saturating_sub(1);
            (round.remaining == 0, self.plan.is_none() && !round.decided)
        };
        self.latest_reports[index] = Some(report);

        // Bootstrap as soon as the required routes are provable. Once a plan is
        // live, wait for the complete concurrent assessment round so a fast
        // lower provider cannot repeatedly hide a slower optional collaborator.
        if bootstrap_can_decide || round_complete {
            self.evaluate_round().await;
        }
        self.refresh_status();
        if round_complete {
            self.round = None;
        }
    }

    async fn evaluate_round(&mut self) {
        let decision = {
            let Some(round) = self.round.as_ref() else {
                return;
            };
            plan_from_reports(&self.adapters, &round.reports)
        };
        match decision {
            PlanDecision::Pending => return,
            PlanDecision::NoProvider(missing) => {
                self.transition_note = Some(format!(
                    "no complete provider route: missing {}",
                    missing.join(", ")
                ));
                let _ = self.reconcile_target(None).await;
            }
            PlanDecision::Ready(plan) => {
                if let Err(error) = self.reconcile_target(Some(plan)).await {
                    self.transition_note = Some(error.to_string());
                }
            }
        }
        if let Some(round) = self.round.as_mut() {
            round.decided = true;
        }
        if let Some(initial_tx) = self.initial_tx.take() {
            let _ = initial_tx.send(());
        }
    }

    async fn reconcile_target(&mut self, target: Option<RoutePlan>) -> Result<()> {
        if self.plan == target && self.required_sessions_usable(target) {
            self.pending_transition = None;
            self.transition_note = None;
            return self.synchronize_publications().await;
        }

        let threshold = if self.plan.is_none() {
            1
        } else if plan_score(target, &self.adapters) > plan_score(self.plan, &self.adapters) {
            self.config.promotion_observations
        } else {
            self.config.failover_observations
        }
        .max(1);
        let observations = match self.pending_transition {
            Some(pending) if pending.target == target => pending.observations.saturating_add(1),
            _ => 1,
        };
        self.pending_transition = Some(PendingTransition {
            target,
            observations,
        });
        if observations < threshold {
            self.transition_note = Some(format!(
                "candidate routes stable for {observations}/{threshold} observations"
            ));
            return Ok(());
        }
        self.pending_transition = None;
        self.transition_to(target).await
    }

    fn required_sessions_usable(&self, plan: Option<RoutePlan>) -> bool {
        let Some(plan) = plan else {
            return self.sessions.is_empty();
        };
        plan.indices().into_iter().all(|index| {
            self.sessions.get(&index).is_some_and(|session| {
                session_state(session) != ProviderSessionState::Lost
                    && session.capabilities().supports(plan.required_from(index))
            })
        })
    }

    async fn transition_to(&mut self, target: Option<RoutePlan>) -> Result<()> {
        self.transition_note = Some(match target {
            Some(plan) => format!("reconciling routes to {}", plan_label(plan, &self.adapters)),
            None => "retiring unavailable routes".to_string(),
        });
        self.refresh_status();

        let old_plan = self.plan;
        let mut opened = Vec::new();
        if let Err(error) = self.apply_transition(target, old_plan, &mut opened).await {
            self.plan = old_plan;
            if let Err(cleanup_error) = self.restore_previous_plan(old_plan, &opened).await {
                tracing::warn!(
                    %cleanup_error,
                    "mDNS route transition cleanup will retry during reconciliation"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    async fn apply_transition(
        &mut self,
        target: Option<RoutePlan>,
        old_plan: Option<RoutePlan>,
        opened: &mut Vec<usize>,
    ) -> Result<()> {
        let target_indices = target.map(RoutePlan::indices).unwrap_or_default();

        // Open genuinely new read/write collaborators before changing any route.
        for index in target_indices.iter().copied() {
            if self.sessions.contains_key(&index) {
                continue;
            }
            let plan = target.ok_or_else(|| {
                provider_error(
                    "control-plane",
                    ProviderOperation::Open,
                    ProviderFailure::Rejected,
                    "provider index exists without a target route plan",
                )
            })?;
            self.open_session(index, plan).await?;
            opened.push(index);
        }

        // A lost or capability-stale session must be retired before reopening
        // the same native provider epoch.
        let replacements = target
            .map(|plan| {
                plan.indices()
                    .into_iter()
                    .filter(|index| {
                        self.sessions.get(index).is_some_and(|session| {
                            session_state(session) == ProviderSessionState::Lost
                                || !session.capabilities().supports(plan.required_from(*index))
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let changed_publications = self
            .publications
            .iter()
            .filter_map(|(id, materialized)| {
                let expected = target.map(|plan| {
                    plan.publication_provider(materialized.announcement.address.is_some())
                });
                (expected != Some(materialized.provider)
                    || replacements.contains(&materialized.provider))
                .then(|| id.clone())
            })
            .collect::<Vec<_>>();
        for id in changed_publications {
            self.withdraw_one(&id).await?;
        }

        let browse_changed = old_plan.map(|plan| plan.browse) != target.map(|plan| plan.browse)
            || old_plan
                .map(|plan| replacements.contains(&plan.browse))
                .unwrap_or(false);
        if browse_changed {
            self.advance_browse_generation();
        }

        self.shutdown_indices(&replacements).await?;
        for index in replacements {
            let plan = target.ok_or_else(|| {
                provider_error(
                    "control-plane",
                    ProviderOperation::Open,
                    ProviderFailure::Rejected,
                    "replacement exists without a target route plan",
                )
            })?;
            self.open_session(index, plan).await?;
        }

        let leaving = self
            .sessions
            .keys()
            .copied()
            .filter(|index| !target_indices.contains(index))
            .collect::<Vec<_>>();
        self.shutdown_indices(&leaving).await?;

        self.plan = target;
        self.advance_status_generation();
        self.transition_note = None;
        self.synchronize_publications().await
    }

    async fn restore_previous_plan(
        &mut self,
        previous: Option<RoutePlan>,
        opened: &[usize],
    ) -> Result<()> {
        let previous_indices = previous.map(RoutePlan::indices).unwrap_or_default();
        let unneeded = opened
            .iter()
            .copied()
            .filter(|index| !previous_indices.contains(index))
            .collect::<Vec<_>>();
        let mut first_error = self.shutdown_indices(&unneeded).await.err();

        if let Some(plan) = previous {
            for index in previous_indices {
                if self.sessions.contains_key(&index) {
                    continue;
                }
                if let Err(error) = self.open_session(index, plan).await {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Err(error) = self.synchronize_publications().await {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn open_session(&mut self, index: usize, plan: RoutePlan) -> Result<()> {
        let adapter = Arc::clone(&self.adapters[index]);
        let descriptor = adapter.descriptor();
        let session = tokio::time::timeout(self.config.open_timeout, adapter.open())
            .await
            .map_err(|_| {
                provider_error(
                    descriptor.name,
                    ProviderOperation::Open,
                    ProviderFailure::Timeout,
                    format!("open exceeded {:?}", self.config.open_timeout),
                )
            })??;
        let required = plan.required_from(index);
        if !session.capabilities().supports(required) {
            session.shutdown().await?;
            return Err(provider_error(
                descriptor.name,
                ProviderOperation::Open,
                ProviderFailure::Rejected,
                format!(
                    "session declared {}; route requires {}",
                    session.capabilities().summary(),
                    required.summary()
                ),
            ));
        }
        if session_state(&session) == ProviderSessionState::Lost {
            session.shutdown().await?;
            return Err(provider_error(
                descriptor.name,
                ProviderOperation::Open,
                ProviderFailure::Lost,
                "session was lost during open",
            ));
        }
        self.sessions.insert(index, session);
        Ok(())
    }

    async fn shutdown_indices(&mut self, indices: &[usize]) -> Result<()> {
        let mut first_error = None;
        for index in indices {
            let Some(session) = self.sessions.get(index).cloned() else {
                continue;
            };
            match tokio::time::timeout(self.config.shutdown_timeout, session.shutdown()).await {
                Ok(Ok(())) => {
                    self.sessions.remove(index);
                }
                Ok(Err(error)) => {
                    self.transition_note = Some(format!(
                        "{} session shutdown failed: {error}",
                        self.adapters[*index].descriptor().name
                    ));
                    first_error.get_or_insert(error);
                }
                Err(_) => {
                    let error = provider_error(
                        self.adapters[*index].descriptor().name,
                        ProviderOperation::Shutdown,
                        ProviderFailure::Timeout,
                        format!("shutdown exceeded {:?}", self.config.shutdown_timeout),
                    );
                    self.transition_note = Some(format!(
                        "{} session shutdown exceeded {:?}",
                        self.adapters[*index].descriptor().name,
                        self.config.shutdown_timeout
                    ));
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn publish_one(&mut self, announcement: Announcement) -> Result<()> {
        let plan = self.plan.ok_or_else(|| {
            provider_error(
                "control-plane",
                ProviderOperation::Publish,
                ProviderFailure::Unavailable,
                "no publication route is armed",
            )
        })?;
        let index = plan.publication_provider(announcement.address.is_some());
        if self
            .publications
            .get(&announcement.id)
            .is_some_and(|current| {
                current.provider == index && current.announcement == announcement
            })
        {
            self.publication_failures.remove(&announcement.id);
            return Ok(());
        }
        let previous = self
            .publications
            .get(&announcement.id)
            .map(|materialized| materialized.announcement.clone());
        if previous.is_some() {
            self.withdraw_one(&announcement.id).await?;
        }
        let session = self.sessions.get(&index).cloned().ok_or_else(|| {
            provider_error(
                self.adapters[index].descriptor().name,
                ProviderOperation::Publish,
                ProviderFailure::Unavailable,
                "publication route has no open session",
            )
        })?;
        let result = tokio::time::timeout(
            self.config.operation_timeout,
            session.publish(&announcement),
        )
        .await
        .map_err(|_| {
            provider_error(
                self.adapters[index].descriptor().name,
                ProviderOperation::Publish,
                ProviderFailure::Timeout,
                format!("publication exceeded {:?}", self.config.operation_timeout),
            )
        })?;
        match result {
            Ok(lease) => {
                self.publication_failures.remove(&announcement.id);
                self.publications.insert(
                    announcement.id.clone(),
                    MaterializedPublication {
                        announcement,
                        provider: index,
                        lease,
                    },
                );
                Ok(())
            }
            Err(error) => {
                self.publication_failures
                    .insert(announcement.id.clone(), error.to_string());
                if let Some(previous) = previous {
                    if let Err(restore_error) = Box::pin(self.publish_one(previous)).await {
                        self.publication_failures.insert(
                            announcement.id,
                            format!(
                                "replacement failed: {error}; prior publication restoration failed: {restore_error}"
                            ),
                        );
                    }
                }
                Err(error)
            }
        }
    }

    async fn withdraw_one(&mut self, id: &str) -> Result<()> {
        let Some(materialized) = self.publications.get_mut(id) else {
            self.publication_failures.remove(id);
            return Ok(());
        };
        tokio::time::timeout(self.config.operation_timeout, materialized.lease.withdraw())
            .await
            .map_err(|_| {
                provider_error(
                    materialized.lease.provider_name(),
                    ProviderOperation::Withdraw,
                    ProviderFailure::Timeout,
                    format!("withdrawal exceeded {:?}", self.config.operation_timeout),
                )
            })??;
        self.publications.remove(id);
        self.publication_failures.remove(id);
        Ok(())
    }

    async fn synchronize_publications(&mut self) -> Result<()> {
        let mut first_error = None;
        let desired = self.registry.desired_announcements()?;
        let desired_ids = desired
            .iter()
            .map(|announcement| announcement.id.as_str())
            .collect::<HashSet<_>>();
        self.publication_failures
            .retain(|id, _| desired_ids.contains(id.as_str()));
        let stale = self
            .publications
            .keys()
            .filter(|id| !desired_ids.contains(id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for id in stale {
            if let Err(error) = self.withdraw_one(&id).await {
                self.publication_failures.insert(id, error.to_string());
                first_error.get_or_insert(error);
            }
        }
        if self.plan.is_some() {
            for announcement in desired {
                if let Err(error) = self.publish_one(announcement.clone()).await {
                    self.publication_failures
                        .insert(announcement.id, error.to_string());
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn open_browse(
        &mut self,
        service_type: &str,
        is_meta: bool,
    ) -> Result<(ProviderBrowse, u64)> {
        let plan = self.plan.ok_or_else(|| {
            provider_error(
                "control-plane",
                ProviderOperation::Browse,
                ProviderFailure::Unavailable,
                "no continuous browse route is armed",
            )
        })?;
        let session = self.sessions.get(&plan.browse).ok_or_else(|| {
            provider_error(
                self.adapters[plan.browse].descriptor().name,
                ProviderOperation::Browse,
                ProviderFailure::Unavailable,
                "browse route has no open session",
            )
        })?;
        let provider = self.adapters[plan.browse].descriptor().name;
        let browse = tokio::time::timeout(
            self.config.operation_timeout,
            session.browse(service_type, is_meta),
        )
        .await
        .map_err(|_| {
            provider_error(
                provider,
                ProviderOperation::Browse,
                ProviderFailure::Timeout,
                format!(
                    "browse startup exceeded {:?}",
                    self.config.operation_timeout
                ),
            )
        })??;
        Ok((browse, *self.browse_generation_tx.borrow()))
    }

    async fn resolve(&mut self, name: &str, service_type: &str) -> Result<ProviderService> {
        let plan = self.plan.ok_or_else(|| {
            provider_error(
                "control-plane",
                ProviderOperation::Resolve,
                ProviderFailure::Unavailable,
                "no provider routes are armed",
            )
        })?;
        let index = plan.resolve.ok_or_else(|| {
            provider_error(
                "control-plane",
                ProviderOperation::Resolve,
                ProviderFailure::Unavailable,
                "no direct-resolution route is armed",
            )
        })?;
        let session = self.sessions.get(&index).ok_or_else(|| {
            provider_error(
                self.adapters[index].descriptor().name,
                ProviderOperation::Resolve,
                ProviderFailure::Unavailable,
                "resolution route has no open session",
            )
        })?;
        let provider = self.adapters[index].descriptor().name;
        tokio::time::timeout(
            self.config.operation_timeout,
            session.resolve(name, service_type),
        )
        .await
        .map_err(|_| {
            provider_error(
                provider,
                ProviderOperation::Resolve,
                ProviderFailure::Timeout,
                format!("resolution exceeded {:?}", self.config.operation_timeout),
            )
        })?
    }

    async fn release_everything(&mut self) -> Result<()> {
        let ids = self.publications.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            if let Err(error) = self.withdraw_one(&id).await {
                tracing::warn!(%id, %error, "publication withdrawal deferred to provider shutdown");
            }
        }
        let indices = self.sessions.keys().copied().collect::<Vec<_>>();
        self.shutdown_indices(&indices).await?;
        self.publications.clear();
        self.publication_failures.clear();
        self.plan = None;
        Ok(())
    }

    fn refresh_status(&self) {
        let (desired, registry_pending) = self.registry.publication_intent_counts();
        let established = self.publications.len();
        let mut providers = self
            .latest_reports
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for report in &mut providers {
            if let Some((index, _)) = self
                .adapters
                .iter()
                .enumerate()
                .find(|(_, adapter)| adapter.descriptor().name == report.name)
            {
                report.session = self.sessions.get(&index).map(session_state);
            }
        }
        let recovering = self
            .sessions
            .values()
            .any(|session| session_state(session) != ProviderSessionState::Ready);
        let state = if self.transition_note.is_some() {
            ControlPlaneState::Reconciling
        } else if self.plan.is_none()
            || recovering
            || desired != established
            || !self.publication_failures.is_empty()
        {
            ControlPlaneState::Degraded
        } else {
            ControlPlaneState::Ready
        };
        let routes = self
            .plan
            .map_or_else(MdnsRoutes::default, |plan| MdnsRoutes {
                publish: Some(self.adapters[plan.publish].descriptor().name.to_string()),
                explicit_publish: Some(
                    self.adapters[plan.explicit_publish]
                        .descriptor()
                        .name
                        .to_string(),
                ),
                browse: Some(self.adapters[plan.browse].descriptor().name.to_string()),
                resolve: plan
                    .resolve
                    .map(|index| self.adapters[index].descriptor().name.to_string()),
            });
        let mut status = self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.state = state;
        status.routes = routes;
        status.providers = providers;
        status.publications = PublicationSync {
            desired,
            established,
            pending: registry_pending.max(desired.saturating_sub(established)),
            failed: self.publication_failures.len(),
        };
        status.transition.clone_from(&self.transition_note);
    }

    fn advance_browse_generation(&self) {
        let next = self.browse_generation_tx.borrow().saturating_add(1);
        self.browse_generation_tx.send_replace(next);
    }

    fn advance_status_generation(&self) {
        let mut status = self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.generation = status.generation.saturating_add(1);
    }

    fn set_stopped(&self) {
        let mut status = self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.state = ControlPlaneState::Stopped;
        status.routes = MdnsRoutes::default();
        status.transition = None;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PlanDecision {
    Pending,
    Ready(RoutePlan),
    NoProvider(Vec<&'static str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteDecision {
    Pending,
    Selected(usize),
    Missing,
}

fn plan_from_reports(
    adapters: &[Arc<dyn MdnsAdapter>],
    reports: &[Option<MdnsProviderReport>],
) -> PlanDecision {
    let regular_publish = MdnsCapabilities {
        publish: true,
        withdraw: true,
        ..MdnsCapabilities::default()
    };
    let explicit_publish = MdnsCapabilities {
        explicit_address: true,
        ..regular_publish
    };
    let browse = MdnsCapabilities {
        continuous_browse: true,
        browse_resolves: true,
        ..MdnsCapabilities::default()
    };
    let direct = MdnsCapabilities {
        direct_resolve: true,
        ..MdnsCapabilities::default()
    };
    let publish = select_required_route(adapters, reports, regular_publish);
    let explicit = select_required_route(adapters, reports, explicit_publish);
    let browse_route = select_required_route(adapters, reports, browse);
    if [publish, explicit, browse_route].contains(&RouteDecision::Pending) {
        return PlanDecision::Pending;
    }
    let mut missing = Vec::new();
    let RouteDecision::Selected(publish) = publish else {
        missing.push("publication");
        return PlanDecision::NoProvider(missing);
    };
    let RouteDecision::Selected(explicit_publish) = explicit else {
        missing.push("explicit-address publication");
        return PlanDecision::NoProvider(missing);
    };
    let RouteDecision::Selected(browse) = browse_route else {
        missing.push("continuous browse+resolve");
        return PlanDecision::NoProvider(missing);
    };
    let resolve = select_optional_route(adapters, reports, direct);
    PlanDecision::Ready(RoutePlan {
        publish,
        explicit_publish,
        browse,
        resolve,
    })
}

fn select_required_route(
    adapters: &[Arc<dyn MdnsAdapter>],
    reports: &[Option<MdnsProviderReport>],
    required: MdnsCapabilities,
) -> RouteDecision {
    for (index, adapter) in adapters.iter().enumerate() {
        if !adapter.descriptor().capabilities.supports(required) {
            continue;
        }
        let Some(report) = reports.get(index).and_then(Option::as_ref) else {
            return RouteDecision::Pending;
        };
        if report.availability == ProviderAvailability::Ready
            && report.capabilities.supports(required)
        {
            return RouteDecision::Selected(index);
        }
    }
    RouteDecision::Missing
}

fn select_optional_route(
    adapters: &[Arc<dyn MdnsAdapter>],
    reports: &[Option<MdnsProviderReport>],
    required: MdnsCapabilities,
) -> Option<usize> {
    for (index, adapter) in adapters.iter().enumerate() {
        if !adapter.descriptor().capabilities.supports(required) {
            continue;
        }
        let report = reports.get(index).and_then(Option::as_ref)?;
        if report.availability == ProviderAvailability::Ready
            && report.capabilities.supports(required)
        {
            return Some(index);
        }
    }
    None
}

fn plan_score(plan: Option<RoutePlan>, adapters: &[Arc<dyn MdnsAdapter>]) -> u64 {
    let Some(plan) = plan else {
        return 0;
    };
    u64::from(adapters[plan.publish].descriptor().priority)
        + u64::from(adapters[plan.explicit_publish].descriptor().priority)
        + u64::from(adapters[plan.browse].descriptor().priority)
        + plan
            .resolve
            .map(|index| u64::from(adapters[index].descriptor().priority))
            .unwrap_or(0)
}

fn plan_label(plan: RoutePlan, adapters: &[Arc<dyn MdnsAdapter>]) -> String {
    plan.indices()
        .into_iter()
        .map(|index| adapters[index].descriptor().name)
        .collect::<Vec<_>>()
        .join("+")
}

fn session_state(session: &Arc<dyn ProviderSession>) -> ProviderSessionState {
    *session.state().borrow()
}

fn stopped_error(operation: ProviderOperation) -> MdnsError {
    provider_error(
        "control-plane",
        operation,
        ProviderFailure::Lost,
        "control plane stopped",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::ProviderDescriptor;
    use crate::protocol::RegisterPayload;
    use crate::provider::{ProviderAddress, ProviderEvent};
    use crate::registry::LeasePolicy;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct Descriptor(ProviderDescriptor);

    #[async_trait::async_trait]
    impl MdnsAdapter for Descriptor {
        fn descriptor(&self) -> ProviderDescriptor {
            self.0
        }

        async fn assess(&self) -> MdnsProviderReport {
            unreachable!("pure planner test")
        }

        async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
            unreachable!("pure planner test")
        }
    }

    fn ready(adapter: &dyn MdnsAdapter) -> MdnsProviderReport {
        let descriptor = adapter.descriptor();
        MdnsProviderReport {
            name: descriptor.name.to_string(),
            priority: descriptor.priority,
            api: descriptor.api,
            availability: ProviderAvailability::Ready,
            installed: crate::adapter::ProbeFact::Yes,
            configured: crate::adapter::ProbeFact::Yes,
            running: crate::adapter::ProbeFact::Yes,
            capabilities: descriptor.capabilities,
            session: None,
            detail: "ready".to_string(),
        }
    }

    #[test]
    fn preferred_full_provider_decides_without_lower_report() {
        let avahi: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "avahi",
            300,
            crate::adapter::ProviderApi::SystemDbus,
            MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
        )));
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "native",
            100,
            crate::adapter::ProviderApi::Embedded,
            MdnsCapabilities::FULL_PROVIDER,
        )));
        let adapters = vec![avahi, native];
        let reports = vec![Some(ready(adapters[0].as_ref())), None];
        let PlanDecision::Ready(plan) = plan_from_reports(&adapters, &reports) else {
            panic!("preferred complete provider should decide all required routes");
        };
        assert_eq!(plan.indices(), vec![0]);
    }

    #[test]
    fn partial_system_provider_composes_with_native() {
        let resolved_caps = MdnsCapabilities {
            publish: true,
            withdraw: true,
            direct_resolve: true,
            ..MdnsCapabilities::default()
        };
        let resolved: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "systemd-resolved",
            200,
            crate::adapter::ProviderApi::SystemDbus,
            resolved_caps,
        )));
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "native",
            100,
            crate::adapter::ProviderApi::Embedded,
            MdnsCapabilities::FULL_PROVIDER,
        )));
        let adapters = vec![resolved, native];
        let reports = adapters
            .iter()
            .map(|adapter| Some(ready(adapter.as_ref())))
            .collect::<Vec<_>>();
        let PlanDecision::Ready(plan) = plan_from_reports(&adapters, &reports) else {
            panic!("composite route plan expected");
        };
        assert_eq!(plan.publish, 0);
        assert_eq!(plan.resolve, Some(0));
        assert_eq!(plan.explicit_publish, 1);
        assert_eq!(plan.browse, 1);
    }

    #[test]
    fn optional_resolver_does_not_block_required_routes() {
        let optional: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "optional-resolver",
            200,
            crate::adapter::ProviderApi::SystemDbus,
            MdnsCapabilities {
                direct_resolve: true,
                ..MdnsCapabilities::default()
            },
        )));
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor(ProviderDescriptor::new(
            "native",
            100,
            crate::adapter::ProviderApi::Embedded,
            MdnsCapabilities::FULL_PROVIDER,
        )));
        let adapters = vec![optional, native];
        let reports = vec![None, Some(ready(adapters[1].as_ref()))];
        let PlanDecision::Ready(plan) = plan_from_reports(&adapters, &reports) else {
            panic!("required routes should not wait for optional resolution");
        };
        assert_eq!(plan.resolve, None);
        assert_eq!(plan.browse, 1);
    }

    struct TestAdapter {
        descriptor: ProviderDescriptor,
        available: AtomicBool,
        open_succeeds: AtomicBool,
        opens: AtomicUsize,
        assessment_delay: Duration,
        session: Arc<TestSession>,
    }

    impl TestAdapter {
        fn new(
            descriptor: ProviderDescriptor,
            available: bool,
            log: Arc<Mutex<Vec<String>>>,
        ) -> Arc<Self> {
            Self::new_delayed(descriptor, available, Duration::ZERO, log)
        }

        fn new_delayed(
            descriptor: ProviderDescriptor,
            available: bool,
            assessment_delay: Duration,
            log: Arc<Mutex<Vec<String>>>,
        ) -> Arc<Self> {
            Arc::new(Self {
                descriptor,
                available: AtomicBool::new(available),
                open_succeeds: AtomicBool::new(true),
                opens: AtomicUsize::new(0),
                assessment_delay,
                session: Arc::new(TestSession::new(descriptor, log)),
            })
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::Release);
        }

        fn set_open_succeeds(&self, succeeds: bool) {
            self.open_succeeds.store(succeeds, Ordering::Release);
        }

        fn set_publish_succeeds(&self, succeeds: bool) {
            self.session
                .publish_succeeds
                .store(succeeds, Ordering::Release);
        }
    }

    #[async_trait::async_trait]
    impl MdnsAdapter for TestAdapter {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor
        }

        async fn assess(&self) -> MdnsProviderReport {
            if !self.assessment_delay.is_zero() {
                tokio::time::sleep(self.assessment_delay).await;
            }
            let available = self.available.load(Ordering::Acquire);
            MdnsProviderReport {
                name: self.descriptor.name.to_string(),
                priority: self.descriptor.priority,
                api: self.descriptor.api,
                availability: if available {
                    ProviderAvailability::Ready
                } else {
                    ProviderAvailability::Absent
                },
                installed: if available {
                    crate::adapter::ProbeFact::Yes
                } else {
                    crate::adapter::ProbeFact::No
                },
                configured: crate::adapter::ProbeFact::Yes,
                running: if available {
                    crate::adapter::ProbeFact::Yes
                } else {
                    crate::adapter::ProbeFact::No
                },
                capabilities: if available {
                    self.descriptor.capabilities
                } else {
                    MdnsCapabilities::default()
                },
                session: None,
                detail: if available { "ready" } else { "absent" }.to_string(),
            }
        }

        async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
            if !self.available.load(Ordering::Acquire)
                || !self.open_succeeds.load(Ordering::Acquire)
            {
                return Err(provider_error(
                    self.descriptor.name,
                    ProviderOperation::Open,
                    ProviderFailure::Unavailable,
                    "test adapter absent",
                ));
            }
            self.opens.fetch_add(1, Ordering::AcqRel);
            Ok(self.session.clone())
        }
    }

    struct TestSession {
        descriptor: ProviderDescriptor,
        state_tx: watch::Sender<ProviderSessionState>,
        state_rx: watch::Receiver<ProviderSessionState>,
        log: Arc<Mutex<Vec<String>>>,
        browse_senders: Mutex<Vec<mpsc::Sender<ProviderEvent>>>,
        publish_succeeds: AtomicBool,
    }

    impl TestSession {
        fn new(descriptor: ProviderDescriptor, log: Arc<Mutex<Vec<String>>>) -> Self {
            let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
            Self {
                descriptor,
                state_tx,
                state_rx,
                log,
                browse_senders: Mutex::new(Vec::new()),
                publish_succeeds: AtomicBool::new(true),
            }
        }

        fn record(&self, event: impl Into<String>) {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.into());
        }
    }

    #[async_trait::async_trait]
    impl ProviderSession for TestSession {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor
        }

        fn capabilities(&self) -> MdnsCapabilities {
            self.descriptor.capabilities
        }

        fn state(&self) -> watch::Receiver<ProviderSessionState> {
            self.state_rx.clone()
        }

        async fn publish(&self, announcement: &Announcement) -> Result<Box<dyn PublicationLease>> {
            self.record(format!(
                "{}:publish:{}",
                self.descriptor.name, announcement.id
            ));
            if !self.publish_succeeds.load(Ordering::Acquire) {
                return Err(provider_error(
                    self.descriptor.name,
                    ProviderOperation::Publish,
                    ProviderFailure::Rejected,
                    "test publication rejected",
                ));
            }
            Ok(Box::new(TestPublicationLease {
                id: announcement.id.clone(),
                provider: self.descriptor.name,
                log: Arc::clone(&self.log),
                withdrawn: false,
            }))
        }

        async fn browse(&self, service_type: &str, _is_meta: bool) -> Result<ProviderBrowse> {
            self.record(format!("{}:browse:{service_type}", self.descriptor.name));
            let (tx, rx) = mpsc::channel(8);
            self.browse_senders
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(tx);
            Ok(ProviderBrowse::new(
                rx,
                Box::new(TestBrowseLease {
                    provider: self.descriptor.name,
                    service_type: service_type.to_string(),
                    log: Arc::clone(&self.log),
                    closed: false,
                }),
            ))
        }

        async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
            self.record(format!("{}:resolve:{name}", self.descriptor.name));
            Ok(ProviderService {
                name: name.to_string(),
                service_type: service_type.to_string(),
                host: Some("test.local.".to_string()),
                addresses: vec![ProviderAddress {
                    address: "192.0.2.1".parse().expect("test address"),
                    interface_index: Some(1),
                    interface_name: Some("test0".to_string()),
                }],
                port: Some(4242),
                txt: HashMap::new(),
            })
        }

        async fn shutdown(&self) -> Result<()> {
            self.record(format!("{}:shutdown", self.descriptor.name));
            Ok(())
        }
    }

    struct TestPublicationLease {
        id: String,
        provider: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        withdrawn: bool,
    }

    #[async_trait::async_trait]
    impl PublicationLease for TestPublicationLease {
        fn announcement_id(&self) -> &str {
            &self.id
        }

        fn provider_name(&self) -> &'static str {
            self.provider
        }

        async fn withdraw(&mut self) -> Result<()> {
            if !self.withdrawn {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("{}:withdraw:{}", self.provider, self.id));
                self.withdrawn = true;
            }
            Ok(())
        }
    }

    struct TestBrowseLease {
        provider: &'static str,
        service_type: String,
        log: Arc<Mutex<Vec<String>>>,
        closed: bool,
    }

    #[async_trait::async_trait]
    impl BrowseLease for TestBrowseLease {
        fn provider_name(&self) -> &'static str {
            self.provider
        }

        async fn close(&mut self) -> Result<()> {
            if !self.closed {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("{}:close:{}", self.provider, self.service_type));
                self.closed = true;
            }
            Ok(())
        }
    }

    fn fast_config() -> ControlPlaneConfig {
        ControlPlaneConfig {
            probe_interval: Duration::from_millis(10),
            inspect_timeout: Duration::from_secs(1),
            open_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
            initial_timeout: Duration::from_secs(1),
            failover_observations: 1,
            promotion_observations: 1,
        }
    }

    fn test_payload() -> RegisterPayload {
        RegisterPayload {
            name: "test-service".to_string(),
            service_type: "_koi-test._tcp.local.".to_string(),
            port: 4242,
            ip: None,
            lease_secs: None,
            txt: HashMap::from([("source".to_string(), "test".to_string())]),
        }
    }

    async fn wait_for_route(
        control_plane: &MdnsControlPlane,
        route: impl Fn(&MdnsRoutes) -> Option<&str>,
        expected: &str,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let status = control_plane.status();
                if route(&status.routes) == Some(expected) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("route transition");
    }

    #[tokio::test]
    async fn publication_and_withdrawal_are_acknowledged_owned_leases() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let adapter = TestAdapter::new(
            ProviderDescriptor::new(
                "test-full",
                500,
                crate::adapter::ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
            ),
            true,
            Arc::clone(&log),
        );
        let registry = Arc::new(RegistrationRegistry::new());
        let control_plane =
            MdnsControlPlane::start_catalog(vec![adapter], Arc::clone(&registry), fast_config())
                .await
                .expect("start control plane");

        let attempt = registry.begin_registration(
            "reg-1".to_string(),
            test_payload(),
            LeasePolicy::Permanent,
            None,
        );
        let announcement = registry
            .desired_announcement(attempt.outcome.id())
            .expect("announcement");
        control_plane
            .publish(announcement)
            .await
            .expect("acknowledged publication");
        registry
            .confirm_publication(attempt.outcome.id())
            .expect("confirm registry");
        assert_eq!(control_plane.status().publications.established, 1);

        let withdrawal = registry
            .begin_withdrawal(attempt.outcome.id())
            .expect("withdrawal intent");
        control_plane
            .withdraw(attempt.outcome.id())
            .await
            .expect("acknowledged withdrawal");
        registry.commit_withdrawal(withdrawal);
        assert_eq!(control_plane.status().publications.established, 0);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["test-full:publish:reg-1", "test-full:withdraw:reg-1"]
        );
        control_plane.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn optional_resolver_promotion_does_not_disturb_write_or_browse_routes() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let resolver = TestAdapter::new(
            ProviderDescriptor::new(
                "resolver",
                500,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities {
                    direct_resolve: true,
                    ..MdnsCapabilities::default()
                },
            ),
            false,
            Arc::clone(&log),
        );
        let fallback = TestAdapter::new(
            ProviderDescriptor::new(
                "fallback",
                400,
                crate::adapter::ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER,
            ),
            true,
            Arc::clone(&log),
        );
        let registry = Arc::new(RegistrationRegistry::new());
        let adapters: Vec<Arc<dyn MdnsAdapter>> = vec![resolver.clone(), fallback.clone()];
        let control_plane =
            MdnsControlPlane::start_catalog(adapters, Arc::clone(&registry), fast_config())
                .await
                .expect("start control plane");
        assert_eq!(
            control_plane.status().routes.publish.as_deref(),
            Some("fallback")
        );
        assert_eq!(control_plane.status().routes.resolve, None);

        let attempt = registry.begin_registration(
            "reg-2".to_string(),
            test_payload(),
            LeasePolicy::Permanent,
            None,
        );
        control_plane
            .publish(registry.desired_announcement("reg-2").unwrap())
            .await
            .expect("publish");
        registry.confirm_publication("reg-2").unwrap();
        let browse = control_plane
            .browse("_koi-test._tcp.local.", false)
            .await
            .expect("browse");
        let generation = control_plane.status().generation;
        resolver.set_available(true);
        wait_for_route(
            &control_plane,
            |routes| routes.resolve.as_deref(),
            "resolver",
        )
        .await;

        let status = control_plane.status();
        assert_eq!(status.routes.publish.as_deref(), Some("fallback"));
        assert_eq!(status.routes.browse.as_deref(), Some("fallback"));
        assert!(status.generation > generation);
        let events = log.lock().unwrap().clone();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "fallback:publish:reg-2")
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event == "fallback:withdraw:reg-2"));
        assert_eq!(fallback.opens.load(Ordering::Acquire), 1);
        assert_eq!(resolver.opens.load(Ordering::Acquire), 1);

        browse.close().await.expect("close browse");
        control_plane.shutdown().await.expect("shutdown");
        drop(attempt);
    }

    #[tokio::test]
    async fn slow_optional_provider_is_not_starved_by_fast_required_routes() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let resolver = TestAdapter::new_delayed(
            ProviderDescriptor::new(
                "slow-resolver",
                500,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities {
                    direct_resolve: true,
                    ..MdnsCapabilities::default()
                },
            ),
            false,
            Duration::from_millis(5),
            Arc::clone(&log),
        );
        let fallback = TestAdapter::new(
            ProviderDescriptor::new(
                "fast-fallback",
                400,
                crate::adapter::ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER,
            ),
            true,
            log,
        );
        let registry = Arc::new(RegistrationRegistry::new());
        let adapters: Vec<Arc<dyn MdnsAdapter>> = vec![resolver.clone(), fallback];
        let mut config = fast_config();
        config.promotion_observations = 2;
        let control_plane = MdnsControlPlane::start_catalog(adapters, registry, config)
            .await
            .expect("start control plane");
        assert_eq!(control_plane.status().routes.resolve, None);

        resolver.set_available(true);
        wait_for_route(
            &control_plane,
            |routes| routes.resolve.as_deref(),
            "slow-resolver",
        )
        .await;
        assert_eq!(resolver.opens.load(Ordering::Acquire), 1);
        control_plane.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn failed_composite_transition_retires_sessions_opened_for_the_candidate() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let publisher = TestAdapter::new(
            ProviderDescriptor::new(
                "candidate-publisher",
                600,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities {
                    publish: true,
                    withdraw: true,
                    ..MdnsCapabilities::default()
                },
            ),
            false,
            Arc::clone(&log),
        );
        let browser = TestAdapter::new(
            ProviderDescriptor::new(
                "candidate-browser",
                500,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities {
                    publish: true,
                    withdraw: true,
                    continuous_browse: true,
                    browse_resolves: true,
                    explicit_address: true,
                    ..MdnsCapabilities::default()
                },
            ),
            false,
            Arc::clone(&log),
        );
        let fallback = TestAdapter::new(
            ProviderDescriptor::new(
                "fallback",
                100,
                crate::adapter::ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER,
            ),
            true,
            Arc::clone(&log),
        );
        let adapters: Vec<Arc<dyn MdnsAdapter>> =
            vec![publisher.clone(), browser.clone(), fallback];
        let control_plane = MdnsControlPlane::start_catalog(
            adapters,
            Arc::new(RegistrationRegistry::new()),
            fast_config(),
        )
        .await
        .expect("start control plane");
        browser.set_open_succeeds(false);
        publisher.set_available(true);
        browser.set_available(true);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .any(|entry| entry == "candidate-publisher:shutdown")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("candidate cleanup");

        publisher.set_available(false);
        browser.set_available(false);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let status = control_plane.status();
        assert_eq!(status.routes.publish.as_deref(), Some("fallback"));
        assert!(status
            .providers
            .iter()
            .find(|provider| provider.name == "candidate-publisher")
            .is_some_and(|provider| provider.session.is_none()));
        control_plane.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn failed_publication_replay_restores_the_previous_working_plan() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let preferred = TestAdapter::new(
            ProviderDescriptor::new(
                "preferred",
                500,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
            ),
            false,
            Arc::clone(&log),
        );
        let fallback = TestAdapter::new(
            ProviderDescriptor::new(
                "fallback",
                100,
                crate::adapter::ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
            ),
            true,
            Arc::clone(&log),
        );
        let registry = Arc::new(RegistrationRegistry::new());
        let adapters: Vec<Arc<dyn MdnsAdapter>> = vec![preferred.clone(), fallback];
        let control_plane =
            MdnsControlPlane::start_catalog(adapters, Arc::clone(&registry), fast_config())
                .await
                .expect("start control plane");

        let attempt = registry.begin_registration(
            "reg-replay".to_string(),
            test_payload(),
            LeasePolicy::Permanent,
            None,
        );
        control_plane
            .publish(registry.desired_announcement("reg-replay").unwrap())
            .await
            .expect("initial fallback publication");
        registry.confirm_publication("reg-replay").unwrap();

        preferred.set_publish_succeeds(false);
        preferred.set_available(true);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let events = log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let fallback_publishes = events
                    .iter()
                    .filter(|event| event.as_str() == "fallback:publish:reg-replay")
                    .count();
                if events
                    .iter()
                    .any(|event| event == "preferred:publish:reg-replay")
                    && fallback_publishes >= 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("failed transition rollback");
        preferred.set_available(false);

        let status = control_plane.status();
        assert_eq!(status.routes.publish.as_deref(), Some("fallback"));
        assert_eq!(status.publications.desired, 1);
        assert_eq!(status.publications.established, 1);
        assert_eq!(status.publications.failed, 0);
        assert!(log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|event| event == "preferred:shutdown"));

        control_plane.shutdown().await.expect("shutdown");
        drop(attempt);
    }

    #[tokio::test]
    async fn recovering_session_is_not_reopened_or_replaced_by_itself() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let adapter = TestAdapter::new(
            ProviderDescriptor::new(
                "recovering",
                500,
                crate::adapter::ProviderApi::SystemDbus,
                MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
            ),
            true,
            log,
        );
        let registry = Arc::new(RegistrationRegistry::new());
        let adapters: Vec<Arc<dyn MdnsAdapter>> = vec![adapter.clone()];
        let control_plane = MdnsControlPlane::start_catalog(adapters, registry, fast_config())
            .await
            .expect("start control plane");
        assert_eq!(adapter.opens.load(Ordering::Acquire), 1);
        adapter
            .session
            .state_tx
            .send_replace(ProviderSessionState::Recovering);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(adapter.opens.load(Ordering::Acquire), 1);
        assert_eq!(
            control_plane.status().routes.publish.as_deref(),
            Some("recovering")
        );
        adapter
            .session
            .state_tx
            .send_replace(ProviderSessionState::Ready);
        control_plane.shutdown().await.expect("shutdown");
    }
}
