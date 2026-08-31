//! Capability-aware runtime orchestration for mDNS providers.
//!
//! The supervisor is the one stable port seen by `MdnsCore`. Platform adapters
//! report independently; this actor turns those reports into a provider plan,
//! serializes transitions, retains the provider-facing publication projection,
//! and fences browse events from retired generations.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use crate::adapter::{AdapterApi, AdapterReadiness, AdapterReport, MdnsAdapter, MdnsCapabilities};
use crate::error::{MdnsError, Result};
use crate::native::NativeMdnsAdapter;
use crate::provider::{MdnsProvider, ProviderBrowse, ProviderService, ProviderStatus};

const COMMAND_CAPACITY: usize = 512;
const BROWSE_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
struct SupervisorConfig {
    probe_interval: Duration,
    inspect_timeout: Duration,
    arm_timeout: Duration,
    shutdown_timeout: Duration,
    initial_timeout: Duration,
    failover_observations: u8,
    promotion_observations: u8,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(2),
            inspect_timeout: Duration::from_secs(6),
            arm_timeout: Duration::from_secs(8),
            shutdown_timeout: Duration::from_secs(5),
            initial_timeout: Duration::from_secs(20),
            failover_observations: 2,
            promotion_observations: 3,
        }
    }
}

/// Stable, provider-neutral runtime facade.
pub struct MdnsSupervisor {
    command_tx: mpsc::Sender<Command>,
    status: Arc<RwLock<ProviderStatus>>,
    capabilities: Arc<RwLock<MdnsCapabilities>>,
    available: Arc<AtomicBool>,
    generation_tx: watch::Sender<u64>,
}

impl MdnsSupervisor {
    /// Start with platform facilities. The built-in Koi provider is appended
    /// here—not by an OS composition branch—so it is always the lowest-priority
    /// catalog entry on every platform.
    pub async fn start(mut platform_adapters: Vec<Arc<dyn MdnsAdapter>>) -> Result<Self> {
        if platform_adapters
            .iter()
            .any(|adapter| adapter.name() == "native")
        {
            return Err(MdnsError::Daemon(
                "the platform catalog cannot replace the reserved native Koi adapter".to_string(),
            ));
        }
        let native: Arc<dyn MdnsAdapter> = Arc::new(NativeMdnsAdapter);
        if let Some(adapter) = platform_adapters
            .iter()
            .find(|adapter| adapter.priority() <= native.priority())
        {
            return Err(MdnsError::Daemon(format!(
                "platform adapter {} priority {} must be greater than reserved native priority {}",
                adapter.name(),
                adapter.priority(),
                native.priority()
            )));
        }
        platform_adapters.push(native);
        Self::start_catalog(platform_adapters, SupervisorConfig::default()).await
    }

    async fn start_catalog(
        mut adapters: Vec<Arc<dyn MdnsAdapter>>,
        config: SupervisorConfig,
    ) -> Result<Self> {
        if adapters.is_empty() {
            return Err(MdnsError::Daemon(
                "mDNS provider catalog cannot be empty".to_string(),
            ));
        }
        adapters.sort_by(|left, right| {
            right
                .priority()
                .cmp(&left.priority())
                .then_with(|| left.name().cmp(right.name()))
        });
        let mut names = HashSet::new();
        for adapter in &adapters {
            if !names.insert(adapter.name()) {
                return Err(MdnsError::Daemon(format!(
                    "duplicate mDNS adapter name: {}",
                    adapter.name()
                )));
            }
        }

        let status = Arc::new(RwLock::new(ProviderStatus {
            name: "none".to_string(),
            healthy: false,
            detail: "probing provider catalog".to_string(),
        }));
        let capabilities = Arc::new(RwLock::new(MdnsCapabilities::default()));
        let available = Arc::new(AtomicBool::new(false));
        let (generation_tx, _) = watch::channel(0_u64);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (initial_tx, initial_rx) = oneshot::channel();
        let actor = SupervisorActor {
            adapters,
            command_tx: command_tx.clone(),
            command_rx,
            status: Arc::clone(&status),
            capabilities: Arc::clone(&capabilities),
            available: Arc::clone(&available),
            generation_tx: generation_tx.clone(),
            config: config.clone(),
            active: None,
            retiring: Vec::new(),
            publications: HashMap::new(),
            latest_reports: Vec::new(),
            round: None,
            next_round: 0,
            pending_transition: None,
            transition_note: None,
            initial_tx: Some(initial_tx),
        };
        let actor_task = tokio::spawn(actor.run());
        match tokio::time::timeout(config.initial_timeout, initial_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                actor_task.abort();
                return Err(MdnsError::Daemon(
                    "mDNS supervisor stopped during initial reconciliation".to_string(),
                ));
            }
            Err(_) => {
                actor_task.abort();
                return Err(MdnsError::Daemon(
                    "mDNS provider inspection timed out during bootstrap".to_string(),
                ));
            }
        }

        Ok(Self {
            command_tx,
            status,
            capabilities,
            available,
            generation_tx,
        })
    }

    fn send(&self, command: Command) -> Result<()> {
        self.command_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    MdnsError::Daemon("mDNS supervisor command queue full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    MdnsError::Daemon("mDNS supervisor stopped".to_string())
                }
            })
    }
}

#[async_trait::async_trait]
impl MdnsProvider for MdnsSupervisor {
    fn name(&self) -> &'static str {
        "supervisor"
    }

    fn capabilities(&self) -> MdnsCapabilities {
        *self
            .capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn api(&self) -> AdapterApi {
        AdapterApi::Orchestrated
    }

    fn status(&self) -> ProviderStatus {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()> {
        if !self.available.load(Ordering::Acquire) {
            return Err(MdnsError::Daemon(
                "no mDNS publication provider is currently armed".to_string(),
            ));
        }
        self.send(Command::Register(Publication {
            key: publication_key(name, service_type),
            name: name.to_string(),
            service_type: service_type.to_string(),
            port,
            ip: ip.map(str::to_string),
            txt: txt.clone(),
        }))
    }

    fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        self.send(Command::Unregister(publication_key(name, service_type)))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Browse {
                service_type: service_type.to_string(),
                is_meta,
                reply: reply_tx,
            })
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor stopped".to_string()))?;
        let (mut raw, generation) = reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor dropped browse reply".to_string()))??;
        let mut generation_rx = self.generation_tx.subscribe();
        let (tx, rx) = mpsc::channel(BROWSE_CAPACITY);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = generation_rx.changed() => {
                        if changed.is_err() || *generation_rx.borrow() != generation {
                            break;
                        }
                    }
                    event = raw.recv() => {
                        let Some(event) = event else { break; };
                        if *generation_rx.borrow() != generation || tx.send(event).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Resolve {
                name: name.to_string(),
                service_type: service_type.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor stopped".to_string()))?;
        reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor dropped resolve reply".to_string()))?
    }

    fn stop_browse(&self, service_type: &str) -> Result<()> {
        self.send(Command::StopBrowse(service_type.to_string()))
    }

    async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Shutdown(reply_tx))
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor stopped".to_string()))?;
        reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("mDNS supervisor dropped shutdown reply".to_string()))?
            .map_err(MdnsError::Daemon)
    }
}

enum Command {
    Inspected {
        round: u64,
        index: usize,
        report: AdapterReport,
    },
    Register(Publication),
    Unregister(String),
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
    StopBrowse(String),
    Shutdown(oneshot::Sender<std::result::Result<(), String>>),
}

#[derive(Clone)]
struct Publication {
    key: String,
    name: String,
    service_type: String,
    port: u16,
    ip: Option<String>,
    txt: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderPlan {
    publish: usize,
    explicit_publish: usize,
    browse: usize,
    direct_resolve: Option<usize>,
}

impl ProviderPlan {
    fn publication_provider(self, explicit: bool) -> usize {
        if explicit {
            self.explicit_publish
        } else {
            self.publish
        }
    }

    fn indices(self) -> Vec<usize> {
        let mut indices = vec![self.publish, self.explicit_publish, self.browse];
        if let Some(index) = self.direct_resolve {
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
        if self.direct_resolve == Some(index) {
            required.direct_resolve = true;
        }
        required
    }

    fn aggregate_capabilities(self) -> MdnsCapabilities {
        MdnsCapabilities::FULL_PROVIDER.union(MdnsCapabilities {
            direct_resolve: self.direct_resolve.is_some(),
            ..MdnsCapabilities::default()
        })
    }
}

struct ActivePlan {
    plan: ProviderPlan,
    providers: HashMap<usize, Arc<dyn MdnsProvider>>,
}

struct ProbeRound {
    id: u64,
    reports: Vec<Option<AdapterReport>>,
    remaining: usize,
    decided: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTransition {
    target: Option<ProviderPlan>,
    observations: u8,
}

struct SupervisorActor {
    adapters: Vec<Arc<dyn MdnsAdapter>>,
    command_tx: mpsc::Sender<Command>,
    command_rx: mpsc::Receiver<Command>,
    status: Arc<RwLock<ProviderStatus>>,
    capabilities: Arc<RwLock<MdnsCapabilities>>,
    available: Arc<AtomicBool>,
    generation_tx: watch::Sender<u64>,
    config: SupervisorConfig,
    active: Option<ActivePlan>,
    retiring: Vec<(usize, Arc<dyn MdnsProvider>)>,
    publications: HashMap<String, Publication>,
    latest_reports: Vec<Option<AdapterReport>>,
    round: Option<ProbeRound>,
    next_round: u64,
    pending_transition: Option<PendingTransition>,
    transition_note: Option<String>,
    initial_tx: Option<oneshot::Sender<()>>,
}

impl SupervisorActor {
    async fn run(mut self) {
        self.latest_reports = vec![None; self.adapters.len()];
        self.begin_probe();
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
                    self.refresh_status();
                    self.begin_probe();
                }
            }
        }
        self.available.store(false, Ordering::Release);
        self.set_capabilities(MdnsCapabilities::default());
        self.set_status("none", false, "mDNS supervisor stopped".to_string());
    }

    async fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Inspected {
                round,
                index,
                report,
            } => self.handle_inspection(round, index, report).await,
            Command::Register(publication) => self.register(publication),
            Command::Unregister(key) => self.unregister(&key),
            Command::Browse {
                service_type,
                is_meta,
                reply,
            } => {
                let result = self.browse(&service_type, is_meta).await;
                let _ = reply.send(result);
            }
            Command::Resolve {
                name,
                service_type,
                reply,
            } => {
                let result = self.resolve(&name, &service_type).await;
                let _ = reply.send(result);
            }
            Command::StopBrowse(service_type) => self.stop_browse(&service_type),
            Command::Shutdown(reply) => {
                self.available.store(false, Ordering::Release);
                self.advance_generation();
                let result = self.release_everything().await;
                let _ = reply.send(result);
                return false;
            }
        }
        true
    }

    fn begin_probe(&mut self) {
        if self.round.is_some() {
            return;
        }
        self.next_round = self.next_round.saturating_add(1);
        let round_id = self.next_round;
        self.round = Some(ProbeRound {
            id: round_id,
            reports: vec![None; self.adapters.len()],
            remaining: self.adapters.len(),
            decided: false,
        });
        for (index, adapter) in self.adapters.iter().cloned().enumerate() {
            let command_tx = self.command_tx.clone();
            let inspect_timeout = self.config.inspect_timeout;
            tokio::spawn(async move {
                let report = match tokio::time::timeout(inspect_timeout, adapter.inspect()).await {
                    Ok(report) => report,
                    Err(_) => AdapterReport::failed_inspection(
                        adapter.as_ref(),
                        AdapterReadiness::Unavailable,
                        format!("inspection exceeded {inspect_timeout:?}"),
                    ),
                };
                let _ = command_tx
                    .send(Command::Inspected {
                        round: round_id,
                        index,
                        report,
                    })
                    .await;
            });
        }
    }

    async fn handle_inspection(&mut self, round_id: u64, index: usize, mut report: AdapterReport) {
        let Some(round) = self.round.as_mut() else {
            return;
        };
        if round.id != round_id || index >= self.adapters.len() || round.reports[index].is_some() {
            return;
        }
        let adapter = &self.adapters[index];
        report.name = adapter.name();
        report.priority = adapter.priority();
        report.api = adapter.api();
        let maximum = adapter.capabilities();
        let claimed = report.capabilities;
        report.capabilities = claimed.intersect(maximum);
        if report.capabilities != claimed {
            report.detail = format!(
                "{}; ignored capabilities outside the adapter's declared maximum",
                report.detail
            );
        }
        round.reports[index] = Some(report.clone());
        round.remaining = round.remaining.saturating_sub(1);
        self.latest_reports[index] = Some(report);

        if !round.decided {
            self.evaluate_round().await;
        }
        self.refresh_status();
        let finished = self
            .round
            .as_ref()
            .is_some_and(|round| round.remaining == 0 && round.decided);
        if finished {
            self.round = None;
        }
    }

    async fn evaluate_round(&mut self) {
        loop {
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
                        "no complete provider plan: missing {}",
                        missing.join(", ")
                    ));
                    let _ = self.reconcile_target(None).await;
                    self.mark_round_decided();
                    self.complete_initial();
                    return;
                }
                PlanDecision::Ready(plan) => match self.reconcile_target(Some(plan)).await {
                    ReconcileOutcome::Stable => {
                        self.mark_round_decided();
                        self.complete_initial();
                        return;
                    }
                    ReconcileOutcome::AdapterFailed { index, detail } => {
                        self.mark_adapter_failed(index, detail);
                        continue;
                    }
                },
            }
        }
    }

    fn mark_round_decided(&mut self) {
        if let Some(round) = self.round.as_mut() {
            round.decided = true;
        }
    }

    fn mark_adapter_failed(&mut self, index: usize, detail: String) {
        let Some(adapter) = self.adapters.get(index) else {
            return;
        };
        let report = AdapterReport::failed_inspection(
            adapter.as_ref(),
            AdapterReadiness::Unavailable,
            detail,
        );
        self.latest_reports[index] = Some(report.clone());
        if let Some(round) = self.round.as_mut() {
            round.reports[index] = Some(report);
            round.decided = false;
        }
    }

    fn complete_initial(&mut self) {
        if let Some(initial_tx) = self.initial_tx.take() {
            let _ = initial_tx.send(());
        }
    }

    async fn reconcile_target(&mut self, target: Option<ProviderPlan>) -> ReconcileOutcome {
        let current = self.active.as_ref().map(|active| active.plan);
        let current_healthy = self.active_healthy();
        if current == target && current_healthy {
            self.pending_transition = None;
            self.transition_note = None;
            return ReconcileOutcome::Stable;
        }
        if current.is_none() && target.is_none() && self.retiring.is_empty() {
            self.pending_transition = None;
            return ReconcileOutcome::Stable;
        }

        let threshold = if current.is_none() {
            1
        } else if !current_healthy || target.is_none() {
            self.config.failover_observations
        } else if plan_score(target, &self.adapters) > plan_score(current, &self.adapters) {
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
                "candidate plan stable for {observations}/{threshold} observations"
            ));
            return ReconcileOutcome::Stable;
        }

        self.pending_transition = None;
        self.transition_to(target).await
    }

    async fn transition_to(&mut self, target: Option<ProviderPlan>) -> ReconcileOutcome {
        self.available.store(false, Ordering::Release);
        self.advance_generation();
        self.transition_note = Some(match target {
            Some(plan) => format!("arming {}", plan_label(plan, &self.adapters)),
            None => "retiring provider plan".to_string(),
        });
        self.refresh_status();

        if let Some(active) = self.active.take() {
            self.retiring.extend(active.providers);
        }
        if let Err(detail) = self.retire_pending().await {
            self.transition_note = Some(detail);
            return ReconcileOutcome::Stable;
        }
        let Some(plan) = target else {
            self.set_capabilities(MdnsCapabilities::default());
            self.transition_note =
                Some("no complete provider plan is currently available".to_string());
            return ReconcileOutcome::Stable;
        };

        let mut providers = HashMap::new();
        for index in plan.indices() {
            let adapter = Arc::clone(&self.adapters[index]);
            let result = tokio::time::timeout(self.config.arm_timeout, adapter.arm()).await;
            let provider = match result {
                Ok(Ok(provider)) => provider,
                Ok(Err(error)) => {
                    self.retiring.extend(providers);
                    let _ = self.retire_pending().await;
                    return ReconcileOutcome::AdapterFailed {
                        index,
                        detail: format!("arm failed: {error}"),
                    };
                }
                Err(_) => {
                    self.retiring.extend(providers);
                    let _ = self.retire_pending().await;
                    return ReconcileOutcome::AdapterFailed {
                        index,
                        detail: format!("arm exceeded {:?}", self.config.arm_timeout),
                    };
                }
            };
            let required = plan.required_from(index);
            if !provider.capabilities().supports(required) {
                self.retiring.push((index, provider));
                self.retiring.extend(providers);
                let _ = self.retire_pending().await;
                return ReconcileOutcome::AdapterFailed {
                    index,
                    detail: format!(
                        "armed provider declared {}, plan requires {}",
                        adapter.capabilities().summary(),
                        required.summary()
                    ),
                };
            }
            providers.insert(index, provider);
        }

        for publication in self.publications.values() {
            let index = plan.publication_provider(publication.ip.is_some());
            let Some(provider) = providers.get(&index) else {
                self.retiring.extend(providers);
                let _ = self.retire_pending().await;
                return ReconcileOutcome::AdapterFailed {
                    index,
                    detail: "publication route was not armed".to_string(),
                };
            };
            if let Err(error) = provider.register(
                &publication.name,
                &publication.service_type,
                publication.port,
                publication.ip.as_deref(),
                &publication.txt,
            ) {
                self.retiring.extend(providers);
                let _ = self.retire_pending().await;
                return ReconcileOutcome::AdapterFailed {
                    index,
                    detail: format!("publication replay failed: {error}"),
                };
            }
        }

        let label = plan_label(plan, &self.adapters);
        tracing::info!(providers = %label, "mDNS provider plan armed");
        self.active = Some(ActivePlan { plan, providers });
        self.available.store(true, Ordering::Release);
        self.set_capabilities(plan.aggregate_capabilities());
        self.transition_note = None;
        self.refresh_status();
        ReconcileOutcome::Stable
    }

    async fn retire_pending(&mut self) -> std::result::Result<(), String> {
        if self.retiring.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.retiring);
        let mut failures = Vec::new();
        for (index, provider) in pending {
            match tokio::time::timeout(self.config.shutdown_timeout, provider.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failures.push(format!("{}: {error}", self.adapters[index].name()));
                    self.retiring.push((index, provider));
                }
                Err(_) => {
                    failures.push(format!(
                        "{}: shutdown exceeded {:?}",
                        self.adapters[index].name(),
                        self.config.shutdown_timeout
                    ));
                    self.retiring.push((index, provider));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "refusing to arm a replacement until retired providers release resources: {}",
                failures.join("; ")
            ))
        }
    }

    fn register(&mut self, publication: Publication) {
        let Some(active) = self.active.as_ref() else {
            self.transition_note = Some("publication arrived with no active plan".to_string());
            self.refresh_status();
            return;
        };
        let index = active.plan.publication_provider(publication.ip.is_some());
        let Some(provider) = active.providers.get(&index) else {
            self.transition_note = Some("active publication route is missing".to_string());
            self.refresh_status();
            return;
        };
        let result = provider.register(
            &publication.name,
            &publication.service_type,
            publication.port,
            publication.ip.as_deref(),
            &publication.txt,
        );
        if let Err(error) = result {
            self.transition_note = Some(format!(
                "publication failed through {}: {error}",
                provider.name()
            ));
        } else {
            self.publications
                .insert(publication.key.clone(), publication);
        }
        self.refresh_status();
    }

    fn unregister(&mut self, key: &str) {
        let Some(publication) = self.publications.remove(key) else {
            return;
        };
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let index = active.plan.publication_provider(publication.ip.is_some());
        if let Some(provider) = active.providers.get(&index) {
            if let Err(error) = provider.unregister(&publication.name, &publication.service_type) {
                self.transition_note = Some(format!(
                    "withdrawal failed through {}: {error}",
                    provider.name()
                ));
            }
        }
        self.refresh_status();
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<(ProviderBrowse, u64)> {
        let active = self.active.as_ref().ok_or_else(|| {
            MdnsError::Daemon("no continuous mDNS browse provider is armed".to_string())
        })?;
        let provider = active
            .providers
            .get(&active.plan.browse)
            .ok_or_else(|| MdnsError::Daemon("active mDNS browse route is missing".to_string()))?;
        let browse = provider.browse(service_type, is_meta).await?;
        Ok((browse, *self.generation_tx.borrow()))
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| MdnsError::Daemon("no direct mDNS resolver is armed".to_string()))?;
        let index = active.plan.direct_resolve.ok_or_else(|| {
            MdnsError::Daemon("active provider plan has no direct resolver".to_string())
        })?;
        active
            .providers
            .get(&index)
            .ok_or_else(|| MdnsError::Daemon("active direct-resolve route is missing".to_string()))?
            .resolve(name, service_type)
            .await
    }

    fn stop_browse(&mut self, service_type: &str) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        if let Some(provider) = active.providers.get(&active.plan.browse) {
            if let Err(error) = provider.stop_browse(service_type) {
                self.transition_note = Some(format!(
                    "stop browse failed through {}: {error}",
                    provider.name()
                ));
                self.refresh_status();
            }
        }
    }

    fn active_healthy(&self) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active
                .providers
                .values()
                .all(|provider| provider.status().healthy)
        })
    }

    fn refresh_status(&self) {
        let reports = self
            .latest_reports
            .iter()
            .flatten()
            .map(AdapterReport::concise)
            .collect::<Vec<_>>()
            .join("; ");
        if let Some(active) = self.active.as_ref() {
            let label = plan_label(active.plan, &self.adapters);
            let mut provider_details = active
                .providers
                .iter()
                .map(|(index, provider)| (*index, provider.status().detail))
                .collect::<Vec<_>>();
            provider_details.sort_by_key(|(index, _)| *index);
            let provider_details = provider_details
                .into_iter()
                .map(|(_, detail)| detail)
                .collect::<Vec<_>>()
                .join("; ");
            let healthy = self.available.load(Ordering::Acquire) && self.active_healthy();
            let note = self
                .transition_note
                .as_ref()
                .map(|note| format!("; {note}"))
                .unwrap_or_default();
            self.set_status(
                &label,
                healthy,
                format!(
                    "generation {}; routes {}; {provider_details}{note}; candidates [{reports}]",
                    *self.generation_tx.borrow(),
                    plan_routes(active.plan, &self.adapters)
                ),
            );
        } else {
            let note = self
                .transition_note
                .clone()
                .unwrap_or_else(|| "no provider plan armed".to_string());
            self.set_status("none", false, format!("{note}; candidates [{reports}]"));
        }
    }

    fn set_status(&self, name: &str, healthy: bool, detail: String) {
        let mut status = self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.name = name.to_string();
        status.healthy = healthy;
        status.detail = detail;
    }

    fn set_capabilities(&self, capabilities: MdnsCapabilities) {
        *self
            .capabilities
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = capabilities;
    }

    fn advance_generation(&self) {
        let next = self.generation_tx.borrow().saturating_add(1);
        self.generation_tx.send_replace(next);
    }

    async fn release_everything(&mut self) -> std::result::Result<(), String> {
        if let Some(active) = self.active.take() {
            self.retiring.extend(active.providers);
        }
        self.retire_pending().await
    }
}

enum ReconcileOutcome {
    Stable,
    AdapterFailed { index: usize, detail: String },
}

#[derive(Debug, PartialEq, Eq)]
enum PlanDecision {
    Pending,
    Ready(ProviderPlan),
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
    reports: &[Option<AdapterReport>],
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

    let publish = select_route(adapters, reports, regular_publish);
    let explicit = select_route(adapters, reports, explicit_publish);
    let browse_route = select_route(adapters, reports, browse);
    let direct_route = select_route(adapters, reports, direct);
    if [publish, explicit, browse_route, direct_route].contains(&RouteDecision::Pending) {
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
    let direct_resolve = match direct_route {
        RouteDecision::Selected(index) => Some(index),
        RouteDecision::Missing => None,
        RouteDecision::Pending => unreachable!("handled above"),
    };
    PlanDecision::Ready(ProviderPlan {
        publish,
        explicit_publish,
        browse,
        direct_resolve,
    })
}

fn select_route(
    adapters: &[Arc<dyn MdnsAdapter>],
    reports: &[Option<AdapterReport>],
    required: MdnsCapabilities,
) -> RouteDecision {
    for (index, adapter) in adapters.iter().enumerate() {
        if !adapter.capabilities().supports(required) {
            continue;
        }
        let Some(report) = reports.get(index).and_then(Option::as_ref) else {
            return RouteDecision::Pending;
        };
        if report.readiness == AdapterReadiness::Ready && report.capabilities.supports(required) {
            return RouteDecision::Selected(index);
        }
    }
    RouteDecision::Missing
}

fn plan_score(plan: Option<ProviderPlan>, adapters: &[Arc<dyn MdnsAdapter>]) -> u64 {
    let Some(plan) = plan else {
        return 0;
    };
    u64::from(adapters[plan.publish].priority())
        + u64::from(adapters[plan.explicit_publish].priority())
        + u64::from(adapters[plan.browse].priority())
        + plan
            .direct_resolve
            .map(|index| u64::from(adapters[index].priority()))
            .unwrap_or(0)
}

fn plan_label(plan: ProviderPlan, adapters: &[Arc<dyn MdnsAdapter>]) -> String {
    plan.indices()
        .into_iter()
        .map(|index| adapters[index].name())
        .collect::<Vec<_>>()
        .join("+")
}

fn plan_routes(plan: ProviderPlan, adapters: &[Arc<dyn MdnsAdapter>]) -> String {
    format!(
        "publish={}, explicit={}, browse={}, direct-resolve={}",
        adapters[plan.publish].name(),
        adapters[plan.explicit_publish].name(),
        adapters[plan.browse].name(),
        plan.direct_resolve
            .map(|index| adapters[index].name())
            .unwrap_or("browse fallback")
    )
}

fn publication_key(name: &str, service_type: &str) -> String {
    format!("{name}\0{service_type}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Mutex;

    use crate::adapter::ProbeFact;
    use crate::provider::{ProviderAddress, ProviderEvent};

    #[derive(Debug)]
    struct Descriptor {
        name: &'static str,
        priority: u16,
        capabilities: MdnsCapabilities,
    }

    #[async_trait::async_trait]
    impl MdnsAdapter for Descriptor {
        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> u16 {
            self.priority
        }

        fn api(&self) -> AdapterApi {
            AdapterApi::Embedded
        }

        fn capabilities(&self) -> MdnsCapabilities {
            self.capabilities
        }

        async fn inspect(&self) -> AdapterReport {
            unreachable!("pure planner test")
        }

        async fn arm(&self) -> Result<Arc<dyn MdnsProvider>> {
            unreachable!("pure planner test")
        }
    }

    fn ready(adapter: &dyn MdnsAdapter) -> AdapterReport {
        AdapterReport {
            name: adapter.name(),
            priority: adapter.priority(),
            api: adapter.api(),
            readiness: AdapterReadiness::Ready,
            installed: crate::adapter::ProbeFact::Yes,
            configured: crate::adapter::ProbeFact::Yes,
            running: crate::adapter::ProbeFact::Yes,
            capabilities: adapter.capabilities(),
            detail: "ready".to_string(),
        }
    }

    #[tokio::test]
    async fn platform_catalog_cannot_shadow_native_koi() {
        let shadow: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "native",
            priority: u16::MAX,
            capabilities: MdnsCapabilities::FULL_PROVIDER,
        });
        let result = MdnsSupervisor::start(vec![shadow]).await;
        assert!(matches!(
            result,
            Err(MdnsError::Daemon(message)) if message.contains("reserved native Koi adapter")
        ));
    }

    #[tokio::test]
    async fn platform_catalog_cannot_undercut_native_priority() {
        let lower: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "platform-low",
            priority: 99,
            capabilities: MdnsCapabilities::FULL_PROVIDER,
        });
        let result = MdnsSupervisor::start(vec![lower]).await;
        assert!(matches!(
            result,
            Err(MdnsError::Daemon(message)) if message.contains("reserved native priority")
        ));
    }

    #[test]
    fn full_preferred_provider_collapses_to_one_adapter() {
        let avahi: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "avahi",
            priority: 300,
            capabilities: MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
        });
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "native",
            priority: 100,
            capabilities: MdnsCapabilities::FULL_PROVIDER,
        });
        let adapters = vec![avahi, native];
        let reports = vec![Some(ready(adapters[0].as_ref())), None];
        let PlanDecision::Ready(plan) = plan_from_reports(&adapters, &reports) else {
            panic!("preferred provider should decide every route")
        };
        assert_eq!(plan.indices(), vec![0]);
    }

    #[test]
    fn partial_system_provider_and_native_form_a_capability_plan() {
        let resolved_capabilities = MdnsCapabilities {
            publish: true,
            withdraw: true,
            direct_resolve: true,
            ..MdnsCapabilities::default()
        };
        let resolved: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "systemd-resolved",
            priority: 200,
            capabilities: resolved_capabilities,
        });
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "native",
            priority: 100,
            capabilities: MdnsCapabilities::FULL_PROVIDER,
        });
        let adapters = vec![resolved, native];
        let reports = adapters
            .iter()
            .map(|adapter| Some(ready(adapter.as_ref())))
            .collect::<Vec<_>>();
        let PlanDecision::Ready(plan) = plan_from_reports(&adapters, &reports) else {
            panic!("complementary provider plan expected")
        };
        assert_eq!(plan.publish, 0);
        assert_eq!(plan.direct_resolve, Some(0));
        assert_eq!(plan.explicit_publish, 1);
        assert_eq!(plan.browse, 1);
    }

    #[test]
    fn lower_route_does_not_wait_for_irrelevant_partial_adapter() {
        let partial: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "partial",
            priority: 200,
            capabilities: MdnsCapabilities {
                publish: true,
                withdraw: true,
                ..MdnsCapabilities::default()
            },
        });
        let native: Arc<dyn MdnsAdapter> = Arc::new(Descriptor {
            name: "native",
            priority: 100,
            capabilities: MdnsCapabilities::FULL_PROVIDER,
        });
        let adapters = vec![partial, native];
        let reports = vec![None, Some(ready(adapters[1].as_ref()))];
        let required = MdnsCapabilities {
            continuous_browse: true,
            browse_resolves: true,
            ..MdnsCapabilities::default()
        };
        assert_eq!(
            select_route(&adapters, &reports, required),
            RouteDecision::Selected(1)
        );
    }

    struct StatefulAdapter {
        name: &'static str,
        priority: u16,
        readiness: AtomicU8,
        events: Arc<Mutex<Vec<String>>>,
        browse_senders: Arc<Mutex<Vec<mpsc::Sender<ProviderEvent>>>>,
    }

    impl StatefulAdapter {
        fn new(name: &'static str, priority: u16, events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name,
                priority,
                readiness: AtomicU8::new(1),
                events,
                browse_senders: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn set_ready(&self, ready: bool) {
            self.readiness.store(u8::from(ready), Ordering::Release);
        }

        fn report(&self) -> AdapterReport {
            let ready = self.readiness.load(Ordering::Acquire) == 1;
            AdapterReport {
                name: self.name,
                priority: self.priority,
                api: AdapterApi::Embedded,
                readiness: if ready {
                    AdapterReadiness::Ready
                } else {
                    AdapterReadiness::Absent
                },
                installed: ProbeFact::Yes,
                configured: ProbeFact::Yes,
                running: if ready { ProbeFact::Yes } else { ProbeFact::No },
                capabilities: MdnsCapabilities::FULL_PROVIDER,
                detail: if ready { "ready" } else { "absent" }.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl MdnsAdapter for StatefulAdapter {
        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> u16 {
            self.priority
        }

        fn api(&self) -> AdapterApi {
            AdapterApi::Embedded
        }

        fn capabilities(&self) -> MdnsCapabilities {
            MdnsCapabilities::FULL_PROVIDER
        }

        async fn inspect(&self) -> AdapterReport {
            self.report()
        }

        async fn arm(&self) -> Result<Arc<dyn MdnsProvider>> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("arm:{}", self.name));
            Ok(Arc::new(StatefulProvider {
                name: self.name,
                events: Arc::clone(&self.events),
                browse_senders: Arc::clone(&self.browse_senders),
            }))
        }
    }

    struct StatefulProvider {
        name: &'static str,
        events: Arc<Mutex<Vec<String>>>,
        browse_senders: Arc<Mutex<Vec<mpsc::Sender<ProviderEvent>>>>,
    }

    #[async_trait::async_trait]
    impl MdnsProvider for StatefulProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn capabilities(&self) -> MdnsCapabilities {
            MdnsCapabilities::FULL_PROVIDER
        }

        fn api(&self) -> AdapterApi {
            AdapterApi::Embedded
        }

        fn status(&self) -> ProviderStatus {
            ProviderStatus {
                name: self.name.to_string(),
                healthy: true,
                detail: "test provider".to_string(),
            }
        }

        fn register(
            &self,
            name: &str,
            _service_type: &str,
            _port: u16,
            _ip: Option<&str>,
            _txt: &HashMap<String, String>,
        ) -> Result<()> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("register:{}:{name}", self.name));
            Ok(())
        }

        fn unregister(&self, name: &str, _service_type: &str) -> Result<()> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("unregister:{}:{name}", self.name));
            Ok(())
        }

        async fn browse(&self, _service_type: &str, _is_meta: bool) -> Result<ProviderBrowse> {
            let (tx, rx) = mpsc::channel(8);
            self.browse_senders
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(tx);
            Ok(rx)
        }

        fn stop_browse(&self, _service_type: &str) -> Result<()> {
            Ok(())
        }

        async fn shutdown(&self) -> Result<()> {
            // Deliberately retain browse senders: the supervisor's generation
            // fence, not well-behaved test-provider shutdown, must reject them.
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("shutdown:{}", self.name));
            Ok(())
        }
    }

    fn fast_config() -> SupervisorConfig {
        SupervisorConfig {
            probe_interval: Duration::from_millis(20),
            inspect_timeout: Duration::from_millis(100),
            arm_timeout: Duration::from_millis(100),
            shutdown_timeout: Duration::from_millis(100),
            initial_timeout: Duration::from_secs(1),
            failover_observations: 2,
            promotion_observations: 2,
        }
    }

    async fn wait_for(mut predicate: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while tokio::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition did not become true before deadline");
    }

    #[tokio::test]
    async fn runtime_switch_is_break_before_make_and_replays_publications() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let preferred = Arc::new(StatefulAdapter::new("preferred", 300, Arc::clone(&events)));
        let fallback = Arc::new(StatefulAdapter::new("fallback", 100, Arc::clone(&events)));
        let supervisor =
            MdnsSupervisor::start_catalog(vec![preferred.clone(), fallback.clone()], fast_config())
                .await
                .expect("start supervisor");
        assert_eq!(supervisor.status().name, "preferred");

        supervisor
            .register("service", "_test._tcp.local.", 4242, None, &HashMap::new())
            .expect("register projection");
        wait_for(|| {
            events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .any(|event| event == "register:preferred:service")
        })
        .await;

        preferred.set_ready(false);
        wait_for(|| supervisor.status().name == "fallback").await;
        let after_failover = events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let stopped = after_failover
            .iter()
            .position(|event| event == "shutdown:preferred")
            .expect("preferred retired");
        let armed = after_failover
            .iter()
            .position(|event| event == "arm:fallback")
            .expect("fallback armed");
        let replayed = after_failover
            .iter()
            .position(|event| event == "register:fallback:service")
            .expect("publication replayed");
        assert!(
            stopped < armed,
            "old provider must stop before replacement arm"
        );
        assert!(armed < replayed, "replay follows replacement arm");

        preferred.set_ready(true);
        wait_for(|| supervisor.status().name == "preferred").await;
        let after_promotion = events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let fallback_stopped = after_promotion
            .iter()
            .rposition(|event| event == "shutdown:fallback")
            .expect("fallback retired");
        let preferred_rearmed = after_promotion
            .iter()
            .rposition(|event| event == "arm:preferred")
            .expect("preferred rearmed");
        assert!(fallback_stopped < preferred_rearmed);
        supervisor.shutdown().await.expect("shutdown supervisor");
    }

    #[tokio::test]
    async fn retired_browse_generation_cannot_emit_late_events() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let preferred = Arc::new(StatefulAdapter::new("preferred", 300, Arc::clone(&events)));
        let fallback = Arc::new(StatefulAdapter::new("fallback", 100, Arc::clone(&events)));
        let preferred_senders = Arc::clone(&preferred.browse_senders);
        let supervisor =
            MdnsSupervisor::start_catalog(vec![preferred.clone(), fallback.clone()], fast_config())
                .await
                .expect("start supervisor");
        let mut browse = supervisor
            .browse("_test._tcp.local.", false)
            .await
            .expect("start browse");
        let sender = preferred_senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .cloned()
            .expect("preferred browse sender");
        sender
            .send(ProviderEvent::Found(ProviderService {
                name: "before".to_string(),
                service_type: "_test._tcp".to_string(),
                host: None,
                addresses: vec![ProviderAddress {
                    address: "127.0.0.1".parse().expect("IP"),
                    interface_index: None,
                    interface_name: None,
                }],
                port: Some(1),
                txt: HashMap::new(),
            }))
            .await
            .expect("emit before transition");
        assert!(browse.recv().await.is_some());

        preferred.set_ready(false);
        wait_for(|| supervisor.status().name == "fallback").await;
        let late = sender
            .send(ProviderEvent::Removed {
                name: "late".to_string(),
                service_type: "_test._tcp".to_string(),
            })
            .await;
        assert!(
            late.is_err(),
            "generation retirement closes the old raw browse"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), browse.recv())
                .await
                .is_ok_and(|event| event.is_none()),
            "retired generation must close without forwarding a late event"
        );
        supervisor.shutdown().await.expect("shutdown supervisor");
    }
}
