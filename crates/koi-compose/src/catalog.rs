//! Authoritative cross-domain Device/Service/Endpoint catalog.
//!
//! Domain snapshots remain the source of truth. This runtime retains bounded
//! provenance and freshness while publishing one coalescing latest-value view.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use koi_common::integration::{
    CertmeshRosterSnapshot, CertmeshSnapshot, MdnsDiscoverySnapshot, MdnsDiscoveryValue,
    MdnsSnapshot, ProxyEntriesSnapshot,
};
use koi_common::service::{
    AddressEvidence, AddressFamily, Ambiguity, AvailableAction, CheckEvidence, CheckKind,
    CheckResult, Device, DeviceCondition, DeviceId, Endpoint, EndpointId, EndpointOwner,
    IdentityConfidence, InstallationId, KoiPresence, LastKnownService, LocalCandidate,
    MeshIdentity, MeshIdentityState, NameEvidence, NetworkClassification, NetworkScope,
    NetworkScopeId, Observation, ObservationId, ObservationKind, ObservationState,
    OperationSummary, PreferencesMode, PreferencesStatus, Service, ServiceCondition, ServiceId,
    ServiceKind, TransportEncryption, CATALOG_SCHEMA, INSTALLATION_ID_TXT_KEY, SERVICE_ID_TXT_KEY,
};
use koi_common::status::StatusFeed;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const MAX_SERVICES: usize = 4_096;
pub const MAX_OBSERVATIONS_PER_SERVICE: usize = 16;
pub const MAX_CHECKS_PER_SERVICE: usize = 32;
pub const STALE_RETENTION: Duration = Duration::from_secs(10 * 60);
const EXPIRY_TICK: Duration = Duration::from_secs(1);
const MAX_RETAINED_EVIDENCE: usize = MAX_SERVICES * MAX_OBSERVATIONS_PER_SERVICE;
const DERIVATION_VERSION: &str = "koi-catalog-v1";

#[derive(Clone, Default)]
pub(crate) struct CatalogSources {
    pub mdns: Option<Arc<dyn MdnsSnapshot>>,
    pub certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    pub preferences: Option<Arc<koi_preferences::PreferencesCore>>,
}

#[derive(Clone, Default)]
struct CatalogInputs {
    mdns: Option<Arc<MdnsDiscoverySnapshot>>,
    certmesh: Option<Arc<CertmeshRosterSnapshot>>,
    dns: Option<Arc<koi_dns::DnsCatalogSnapshot>>,
    health: Option<Arc<koi_health::HealthSnapshot>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntimeStatus>>,
    proxy_entries: Option<Arc<ProxyEntriesSnapshot>>,
    runtime: Option<Arc<koi_runtime::RuntimeStatus>>,
    preferences: Option<Arc<PreferencesStatus>>,
    availability: SourceAvailability,
}

#[derive(Debug, Clone, Copy, Default)]
struct SourceAvailability {
    mdns: bool,
    certmesh: bool,
    dns: bool,
    health: bool,
    proxy: bool,
    runtime: bool,
}

impl SourceAvailability {
    fn from_sources(sources: &CatalogSources) -> Self {
        Self {
            mdns: sources.mdns.is_some(),
            certmesh: sources.certmesh.is_some(),
            dns: sources.dns.is_some(),
            health: sources.health.is_some(),
            proxy: sources.proxy.is_some(),
            runtime: sources.runtime.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointSeed {
    scheme: String,
    host: String,
    port: u16,
    path: Option<String>,
    scope: Option<NetworkScope>,
    owner: EndpointOwner,
    browser_usable: bool,
    encryption: TransportEncryption,
    expected_service_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvidenceSeed {
    key: String,
    source_group: String,
    source_revision: u64,
    source_generation: u64,
    kind: ObservationKind,
    provider: String,
    explicit_installation_id: Option<InstallationId>,
    explicit_service_id: Option<ServiceId>,
    durable_source_id: Option<String>,
    device_hint: String,
    display_name: String,
    service_kind: ServiceKind,
    endpoint: EndpointSeed,
    check: Option<CheckSeed>,
    starting: bool,
    managed: bool,
    local_only: bool,
    raw_reference: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckSeed {
    kind: CheckKind,
    checked_at: Option<DateTime<Utc>>,
    interval_secs: u64,
    timeout_secs: u64,
    result: CheckResult,
    reason: String,
    detail: Option<String>,
}

#[derive(Debug, Clone)]
struct RetainedEvidence {
    seed: EvidenceSeed,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    state: ObservationState,
}

struct CorrelationGroup<'a> {
    evidence: Vec<&'a RetainedEvidence>,
    device_id: DeviceId,
    explicit_id: Option<ServiceId>,
    durable_ids: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct CatalogModel {
    evidence: BTreeMap<String, RetainedEvidence>,
    revisions: BTreeMap<String, u64>,
}

#[derive(Debug)]
pub struct ServiceCatalogRuntime {
    installation_id: InstallationId,
    hostname: String,
    epoch: String,
    feed: StatusFeed<koi_common::service::CatalogSnapshot>,
    model: Mutex<CatalogModel>,
}

impl ServiceCatalogRuntime {
    pub fn new(installation_id: InstallationId, hostname: impl Into<String>) -> Self {
        let now = Utc::now();
        let epoch = uuid::Uuid::now_v7().to_string();
        Self {
            installation_id,
            hostname: hostname.into(),
            epoch: epoch.clone(),
            feed: StatusFeed::new(koi_common::service::CatalogSnapshot {
                schema: CATALOG_SCHEMA,
                epoch,
                revision: 0,
                generated_at: now,
                devices: Vec::new(),
                services: Vec::new(),
                local_candidates: Vec::new(),
            }),
            model: Mutex::new(CatalogModel::default()),
        }
    }

    pub fn status(&self) -> Arc<koi_common::service::CatalogSnapshot> {
        self.feed.current()
    }

    pub fn watch_status(&self) -> watch::Receiver<Arc<koi_common::service::CatalogSnapshot>> {
        self.feed.subscribe()
    }

    pub(crate) fn installation_id(&self) -> InstallationId {
        self.installation_id.clone()
    }

    pub(crate) fn owned_service_id(&self, role: &str) -> ServiceId {
        ServiceId::new(format!(
            "svc_{}",
            derive_hex(
                "owned-service",
                &[self.installation_id.as_str(), &role.to_ascii_lowercase()],
            )
        ))
        .expect("derived owned service ID")
    }

    fn reconcile(&self, inputs: CatalogInputs, now: DateTime<Utc>) {
        let preferences = inputs.preferences.clone();
        let mut model = self.model.lock().expect("catalog model lock");
        let (mut devices, mut services) = model.project(
            &self.installation_id,
            &self.hostname,
            &self.epoch,
            inputs,
            now,
        );
        drop(model);
        let mut local_candidates = Vec::new();
        join_preferences(
            &mut devices,
            &mut services,
            &mut local_candidates,
            preferences.as_deref(),
        );
        self.feed.update(|current| {
            if current.devices == devices
                && current.services == services
                && current.local_candidates == local_candidates
            {
                None
            } else {
                Some(koi_common::service::CatalogSnapshot {
                    schema: CATALOG_SCHEMA,
                    epoch: self.epoch.clone(),
                    revision: current.revision.saturating_add(1),
                    generated_at: now,
                    devices,
                    services,
                    local_candidates,
                })
            }
        });
    }
}

impl Default for ServiceCatalogRuntime {
    fn default() -> Self {
        Self::new(InstallationId::new_uuid_v7(), "unobserved")
    }
}

impl CatalogModel {
    fn project(
        &mut self,
        installation_id: &InstallationId,
        hostname: &str,
        epoch: &str,
        inputs: CatalogInputs,
        now: DateTime<Utc>,
    ) -> (Vec<Device>, Vec<Service>) {
        let mut current = Vec::new();
        let mut available_groups = BTreeMap::new();

        self.collect_mdns(&inputs, &mut current, &mut available_groups);
        self.collect_runtime(
            installation_id,
            &inputs,
            &mut current,
            &mut available_groups,
        );
        self.collect_proxy(
            installation_id,
            &inputs,
            &mut current,
            &mut available_groups,
        );
        self.collect_health(
            installation_id,
            &inputs,
            &mut current,
            &mut available_groups,
        );

        current.sort_by(|left, right| left.key.cmp(&right.key));
        current.dedup_by(|left, right| left.key == right.key);
        current.truncate(MAX_RETAINED_EVIDENCE);
        self.accept(current, available_groups, now);

        let mut retained: Vec<_> = self.evidence.values().collect();
        retained.sort_by_key(|evidence| {
            (
                if evidence.seed.explicit_service_id.is_some() {
                    0
                } else if evidence.seed.durable_source_id.is_some() {
                    1
                } else {
                    2
                },
                evidence.seed.key.as_str(),
            )
        });
        let mut groups: Vec<CorrelationGroup<'_>> = Vec::new();
        let mut explicit_index: BTreeMap<(ServiceId, DeviceId), usize> = BTreeMap::new();
        let mut durable_index: BTreeMap<(DeviceId, String), usize> = BTreeMap::new();
        let mut endpoint_index: BTreeMap<(DeviceId, String, String), Vec<usize>> = BTreeMap::new();
        let mut device_builders: BTreeMap<DeviceId, DeviceBuilder> = BTreeMap::new();
        for retained in retained {
            let device_id = device_id_for(&retained.seed, installation_id, epoch);
            device_builders
                .entry(device_id.clone())
                .or_insert_with(|| DeviceBuilder::new(device_id.clone()))
                .observe(retained, installation_id);

            let endpoint_key = (
                device_id.clone(),
                normalized_endpoint(&retained.seed.endpoint),
                compatible_kind(&retained.seed.service_kind),
            );
            let explicit_key = retained
                .seed
                .explicit_service_id
                .as_ref()
                .map(|id| (id.clone(), device_id.clone()));
            let durable_key = retained
                .seed
                .durable_source_id
                .as_ref()
                .map(|id| (device_id.clone(), id.clone()));
            let group_index = explicit_key
                .as_ref()
                .and_then(|key| explicit_index.get(key).copied())
                .or_else(|| {
                    durable_key
                        .as_ref()
                        .and_then(|key| durable_index.get(key).copied())
                })
                .or_else(|| {
                    endpoint_index.get(&endpoint_key).and_then(|candidates| {
                        candidates.iter().copied().find(|index| {
                            let group = &groups[*index];
                            match (
                                group.explicit_id.as_ref(),
                                retained.seed.explicit_service_id.as_ref(),
                            ) {
                                (Some(left), Some(right)) => left == right,
                                _ => true,
                            }
                        })
                    })
                })
                .unwrap_or_else(|| {
                    groups.push(CorrelationGroup {
                        evidence: Vec::new(),
                        device_id: device_id.clone(),
                        explicit_id: retained.seed.explicit_service_id.clone(),
                        durable_ids: BTreeSet::new(),
                    });
                    groups.len() - 1
                });
            let group = &mut groups[group_index];
            group.evidence.push(retained);
            if group.explicit_id.is_none() {
                group.explicit_id = retained.seed.explicit_service_id.clone();
            }
            if let Some(durable) = &retained.seed.durable_source_id {
                group.durable_ids.insert(durable.clone());
            }
            if let Some(key) = explicit_key {
                explicit_index.insert(key, group_index);
            }
            if let Some(key) = durable_key {
                durable_index.insert(key, group_index);
            }
            endpoint_index
                .entry(endpoint_key)
                .or_default()
                .push(group_index);
        }

        let mut explicit_counts = BTreeMap::<ServiceId, usize>::new();
        for group in &groups {
            if let Some(id) = &group.explicit_id {
                *explicit_counts.entry(id.clone()).or_default() += 1;
            }
        }
        let mut services = Vec::new();
        for group in groups {
            let identity_conflict = group
                .explicit_id
                .as_ref()
                .is_some_and(|id| explicit_counts.get(id).copied().unwrap_or(0) > 1);
            let service_id = if identity_conflict {
                ServiceId::new(format!(
                    "svc_{}",
                    derive_hex(
                        "conflicting-explicit-service",
                        &[
                            group.explicit_id.as_ref().unwrap().as_str(),
                            group.device_id.as_str(),
                        ],
                    )
                ))
                .expect("derived conflict service ID")
            } else if let Some(id) = &group.explicit_id {
                id.clone()
            } else if let Some(durable) = group.durable_ids.iter().next() {
                ServiceId::new(format!(
                    "svc_{}",
                    derive_hex("durable-service", &[installation_id.as_str(), durable],)
                ))
                .expect("derived durable service ID")
            } else {
                let first = group.evidence[0];
                service_id_for(&first.seed, &group.device_id, installation_id)
            };
            let first = group.evidence[0];
            let mut builder = ServiceBuilder::new(service_id, group.device_id, first);
            builder.confidence = if identity_conflict {
                IdentityConfidence::Ambiguous
            } else if group.explicit_id.is_some() {
                IdentityConfidence::Explicit
            } else if group.evidence.len() > 1 || !group.durable_ids.is_empty() {
                IdentityConfidence::Correlated
            } else {
                IdentityConfidence::Observed
            };
            builder.identity_conflict = identity_conflict;
            for evidence in group.evidence {
                builder.observe(evidence, installation_id);
            }
            services.push(builder);
        }

        self.add_catalog_devices(
            &inputs,
            installation_id,
            hostname,
            epoch,
            &mut device_builders,
        );

        let mut devices: Vec<_> = device_builders
            .into_values()
            .map(DeviceBuilder::finish)
            .collect();
        devices.sort_by(|left, right| left.id.cmp(&right.id));

        let mut services: Vec<_> = services
            .into_iter()
            .map(|service| service.finish(now))
            .collect();
        services.sort_by(|left, right| left.id.cmp(&right.id));
        if services.len() > MAX_SERVICES {
            services.sort_by_key(|service| {
                (
                    service_retention_rank(service.condition),
                    service.id.clone(),
                )
            });
            services.truncate(MAX_SERVICES);
            services.sort_by(|left, right| left.id.cmp(&right.id));
            let retained_devices: BTreeSet<_> = services
                .iter()
                .map(|service| service.device_id.clone())
                .collect();
            devices.retain(|device| retained_devices.contains(&device.id));
        }
        (devices, services)
    }

    fn accept(
        &mut self,
        seeds: Vec<EvidenceSeed>,
        available_groups: BTreeMap<String, (u64, bool)>,
        now: DateTime<Utc>,
    ) {
        let mut accepted_groups = BTreeSet::new();
        for (group, (revision, _)) in &available_groups {
            let prior = self.revisions.get(group).copied().unwrap_or(0);
            if *revision >= prior {
                self.revisions.insert(group.clone(), *revision);
                accepted_groups.insert(group.clone());
            }
        }

        let current_keys: BTreeSet<_> = seeds
            .iter()
            .filter(|seed| accepted_groups.contains(&seed.source_group))
            .map(|seed| seed.key.clone())
            .collect();
        let retention = TimeDelta::from_std(STALE_RETENTION).expect("valid stale retention");
        for seed in seeds {
            if !accepted_groups.contains(&seed.source_group) {
                continue;
            }
            let available = available_groups
                .get(&seed.source_group)
                .is_some_and(|(_, available)| *available);
            if !available && !self.evidence.contains_key(&seed.key) {
                continue;
            }
            self.evidence
                .entry(seed.key.clone())
                .and_modify(|retained| {
                    retained.seed = seed.clone();
                    retained.state = if available {
                        retained.last_seen = now;
                        retained.valid_until = now + retention;
                        ObservationState::Current
                    } else {
                        ObservationState::SourceUnavailable
                    };
                })
                .or_insert(RetainedEvidence {
                    seed,
                    first_seen: now,
                    last_seen: now,
                    valid_until: now + retention,
                    state: ObservationState::Current,
                });
        }

        for retained in self.evidence.values_mut() {
            let Some((_, available)) = available_groups.get(&retained.seed.source_group) else {
                retained.state = ObservationState::SourceUnavailable;
                continue;
            };
            if !accepted_groups.contains(&retained.seed.source_group) {
                continue;
            }
            if !current_keys.contains(&retained.seed.key) {
                retained.state = if *available {
                    ObservationState::Withdrawn
                } else {
                    ObservationState::SourceUnavailable
                };
            }
        }
        self.evidence
            .retain(|_, retained| retained.valid_until > now);
        if self.evidence.len() > MAX_RETAINED_EVIDENCE {
            let mut keys: Vec<_> = self
                .evidence
                .iter()
                .map(|(key, value)| {
                    (
                        observation_retention_rank(value.state),
                        value.last_seen,
                        key.clone(),
                    )
                })
                .collect();
            keys.sort();
            for (_, _, key) in keys
                .into_iter()
                .take(self.evidence.len() - MAX_RETAINED_EVIDENCE)
            {
                self.evidence.remove(&key);
            }
        }
    }

    fn collect_mdns(
        &self,
        inputs: &CatalogInputs,
        seeds: &mut Vec<EvidenceSeed>,
        groups: &mut BTreeMap<String, (u64, bool)>,
    ) {
        let Some(snapshot) = &inputs.mdns else {
            groups.insert("mdns".into(), (0, false));
            return;
        };
        for source in &snapshot.sources {
            let group = mdns_group(&source.query, source.provider.as_deref());
            groups.insert(
                group,
                (
                    snapshot.revision,
                    inputs.availability.mdns && source.available,
                ),
            );
        }
        if snapshot.observations.is_empty() {
            let group = "mdns|legacy".to_string();
            groups.insert(group.clone(), (snapshot.revision, inputs.availability.mdns));
            for record in &snapshot.records {
                seeds.push(mdns_seed(record, &group, snapshot.revision, 0, None));
            }
            return;
        }
        for observation in &snapshot.observations {
            let MdnsDiscoveryValue::ServiceRecord { record } = &observation.value else {
                continue;
            };
            let group = mdns_group(
                &observation.source.query,
                observation.source.provider.as_deref(),
            );
            groups.entry(group.clone()).or_insert((
                snapshot.revision,
                inputs.availability.mdns && observation.source.available,
            ));
            seeds.push(mdns_seed(
                record,
                &group,
                snapshot.revision,
                observation.source.generation,
                observation.source.provider.as_deref(),
            ));
        }
    }

    fn collect_runtime(
        &self,
        installation_id: &InstallationId,
        inputs: &CatalogInputs,
        seeds: &mut Vec<EvidenceSeed>,
        groups: &mut BTreeMap<String, (u64, bool)>,
    ) {
        let group = "runtime".to_string();
        let Some(snapshot) = &inputs.runtime else {
            groups.insert(group, (0, false));
            return;
        };
        groups.insert(
            group.clone(),
            (
                snapshot.revision,
                inputs.availability.runtime && snapshot.active,
            ),
        );
        for instance in &snapshot.instances {
            if instance.metadata.enable == Some(false) {
                continue;
            }
            for port in &instance.ports {
                if let Some(seed) =
                    runtime_seed(instance, port, installation_id, &group, snapshot.revision)
                {
                    seeds.push(seed);
                }
            }
        }
    }

    fn collect_proxy(
        &self,
        installation_id: &InstallationId,
        inputs: &CatalogInputs,
        seeds: &mut Vec<EvidenceSeed>,
        groups: &mut BTreeMap<String, (u64, bool)>,
    ) {
        let group = "proxy".to_string();
        let revision = inputs
            .proxy_entries
            .as_ref()
            .map(|snapshot| snapshot.revision)
            .unwrap_or(0)
            .max(
                inputs
                    .proxy
                    .as_ref()
                    .map(|snapshot| snapshot.revision)
                    .unwrap_or(0),
            );
        groups.insert(group.clone(), (revision, inputs.availability.proxy));
        let Some(status) = &inputs.proxy else { return };
        for listener in &status.proxies {
            seeds.push(proxy_seed(listener, installation_id, &group, revision));
        }
    }

    fn collect_health(
        &self,
        installation_id: &InstallationId,
        inputs: &CatalogInputs,
        seeds: &mut Vec<EvidenceSeed>,
        groups: &mut BTreeMap<String, (u64, bool)>,
    ) {
        let group = "health".to_string();
        let Some(snapshot) = &inputs.health else {
            groups.insert(group, (0, false));
            return;
        };
        groups.insert(
            group.clone(),
            (
                snapshot.revision,
                inputs.availability.health && snapshot.running,
            ),
        );
        for service in &snapshot.services {
            if let Some(seed) = health_seed(service, installation_id, &group, snapshot.revision) {
                seeds.push(seed);
            }
        }
    }

    fn add_catalog_devices(
        &self,
        inputs: &CatalogInputs,
        installation_id: &InstallationId,
        hostname: &str,
        epoch: &str,
        devices: &mut BTreeMap<DeviceId, DeviceBuilder>,
    ) {
        let local = explicit_device_id(installation_id);
        devices.entry(local.clone()).or_insert_with(|| {
            let mut builder = DeviceBuilder::new(local);
            builder.names.insert(hostname.to_string(), BTreeSet::new());
            builder.koi_presence = KoiPresence::Identified {
                installation_id: installation_id.clone(),
            };
            builder.has_current = true;
            builder
        });
        if let Some(roster) = &inputs.certmesh {
            for member in &roster.active_members {
                let id = derived_device_id(
                    epoch,
                    &format!("certmesh|{}", normalize_host(&member.hostname)),
                );
                let builder = devices
                    .entry(id.clone())
                    .or_insert_with(|| DeviceBuilder::new(id));
                builder.names.entry(member.hostname.clone()).or_default();
                builder.mesh_state = match member.status.as_str() {
                    "active" => MeshIdentityState::Member,
                    "unhealthy" => MeshIdentityState::Unhealthy,
                    _ => MeshIdentityState::Unknown,
                };
                if inputs.availability.certmesh {
                    builder.has_current = true;
                } else {
                    builder.has_stale = true;
                }
            }
        }
        if let Some(dns) = &inputs.dns {
            for entry in &dns.entries {
                let scope = network_scope(&entry.ip, "dns", None);
                let hint = format!("dns|{}|{}", normalize_host(&entry.name), entry.ip);
                let id = derived_device_id(epoch, &hint);
                let builder = devices
                    .entry(id.clone())
                    .or_insert_with(|| DeviceBuilder::new(id));
                builder.names.entry(entry.name.clone()).or_default();
                builder
                    .addresses
                    .entry(entry.ip.clone())
                    .or_insert((scope.map(|scope| scope.id), BTreeSet::new()));
                if inputs.availability.dns {
                    builder.has_current = true;
                } else {
                    builder.has_stale = true;
                }
            }
        }
    }
}

struct DeviceBuilder {
    id: Option<DeviceId>,
    names: BTreeMap<String, BTreeSet<ObservationId>>,
    addresses: BTreeMap<String, (Option<NetworkScopeId>, BTreeSet<ObservationId>)>,
    koi_presence: KoiPresence,
    mesh_state: MeshIdentityState,
    mesh_observations: BTreeSet<ObservationId>,
    has_current: bool,
    has_stale: bool,
    has_ambiguity: bool,
}

impl Default for DeviceBuilder {
    fn default() -> Self {
        Self {
            id: None,
            names: BTreeMap::new(),
            addresses: BTreeMap::new(),
            koi_presence: KoiPresence::Absent,
            mesh_state: MeshIdentityState::Unknown,
            mesh_observations: BTreeSet::new(),
            has_current: false,
            has_stale: false,
            has_ambiguity: false,
        }
    }
}

impl DeviceBuilder {
    fn new(id: DeviceId) -> Self {
        Self {
            id: Some(id),
            koi_presence: KoiPresence::Absent,
            mesh_state: MeshIdentityState::Unknown,
            ..Self::default()
        }
    }

    fn observe(&mut self, retained: &RetainedEvidence, local: &InstallationId) {
        let observation_id = observation_id(&retained.seed);
        self.names
            .entry(retained.seed.device_hint.clone())
            .or_default()
            .insert(observation_id.clone());
        let endpoint = &retained.seed.endpoint;
        self.addresses
            .entry(endpoint.host.clone())
            .or_insert_with(|| {
                (
                    endpoint.scope.as_ref().map(|scope| scope.id.clone()),
                    BTreeSet::new(),
                )
            })
            .1
            .insert(observation_id.clone());
        if let Some(installation_id) = &retained.seed.explicit_installation_id {
            self.koi_presence = KoiPresence::Identified {
                installation_id: installation_id.clone(),
            };
        } else if &retained.seed.provider == "koi" {
            self.koi_presence = KoiPresence::Observed;
        }
        if retained.seed.explicit_installation_id.as_ref() == Some(local) {
            self.koi_presence = KoiPresence::Identified {
                installation_id: local.clone(),
            };
        }
        match retained.state {
            ObservationState::Current => self.has_current = true,
            ObservationState::Stale | ObservationState::SourceUnavailable => self.has_stale = true,
            ObservationState::Withdrawn => {}
        }
    }

    fn finish(self) -> Device {
        Device {
            schema: CATALOG_SCHEMA,
            id: self.id.expect("device builder id"),
            names: self
                .names
                .into_iter()
                .map(|(value, ids)| NameEvidence {
                    value,
                    observation_ids: ids.into_iter().collect(),
                })
                .collect(),
            addresses: self
                .addresses
                .into_iter()
                .map(|(address, (network_scope_id, ids))| AddressEvidence {
                    address,
                    network_scope_id,
                    observation_ids: ids.into_iter().collect(),
                })
                .collect(),
            koi_presence: self.koi_presence,
            mesh_identity: MeshIdentity {
                state: self.mesh_state,
                observation_ids: self.mesh_observations.into_iter().collect(),
            },
            condition: if self.has_ambiguity {
                DeviceCondition::Ambiguous
            } else if self.has_current {
                DeviceCondition::Present
            } else if self.has_stale {
                DeviceCondition::Stale
            } else {
                DeviceCondition::Absent
            },
        }
    }
}

struct ServiceBuilder {
    id: ServiceId,
    device_id: DeviceId,
    display_names: BTreeSet<String>,
    kind: ServiceKind,
    confidence: IdentityConfidence,
    endpoints: BTreeMap<EndpointId, Endpoint>,
    observations: BTreeMap<ObservationId, Observation>,
    checks: Vec<CheckEvidence>,
    has_current: bool,
    has_stale: bool,
    has_withdrawn: bool,
    starting: bool,
    managed: bool,
    local_only: bool,
    identity_conflict: bool,
}

impl ServiceBuilder {
    fn new(id: ServiceId, device_id: DeviceId, retained: &RetainedEvidence) -> Self {
        Self {
            id,
            device_id,
            display_names: BTreeSet::new(),
            kind: retained.seed.service_kind.clone(),
            confidence: if retained.seed.explicit_service_id.is_some() {
                IdentityConfidence::Explicit
            } else if retained.seed.durable_source_id.is_some() {
                IdentityConfidence::Correlated
            } else {
                IdentityConfidence::Observed
            },
            endpoints: BTreeMap::new(),
            observations: BTreeMap::new(),
            checks: Vec::new(),
            has_current: false,
            has_stale: false,
            has_withdrawn: false,
            starting: false,
            managed: false,
            local_only: true,
            identity_conflict: false,
        }
    }

    fn observe(&mut self, retained: &RetainedEvidence, installation_id: &InstallationId) {
        self.display_names
            .insert(retained.seed.display_name.clone());
        self.has_current |= retained.state == ObservationState::Current;
        self.has_stale |= matches!(
            retained.state,
            ObservationState::Stale | ObservationState::SourceUnavailable
        );
        self.has_withdrawn |= retained.state == ObservationState::Withdrawn;
        self.starting |= retained.seed.starting;
        self.managed |= retained.seed.managed;
        self.local_only &= retained.seed.local_only;

        let observation_id = observation_id(&retained.seed);
        let endpoint_id = endpoint_id(&retained.seed.endpoint);
        let observation = Observation {
            schema: CATALOG_SCHEMA,
            id: observation_id.clone(),
            kind: retained.seed.kind,
            source: retained.seed.source_group.clone(),
            provider: retained.seed.provider.clone(),
            source_revision: retained.seed.source_revision,
            source_generation: retained.seed.source_generation,
            network_scope_id: retained
                .seed
                .endpoint
                .scope
                .as_ref()
                .map(|scope| scope.id.clone()),
            observer_installation_id: installation_id.clone(),
            observer_device_id: Some(explicit_device_id(installation_id)),
            observed_at: retained.first_seen,
            valid_until: retained.valid_until,
            state: retained.state,
            raw_reference: retained.seed.raw_reference.clone(),
        };
        self.observations
            .insert(observation_id.clone(), observation);

        let endpoint = self
            .endpoints
            .entry(endpoint_id.clone())
            .or_insert_with(|| Endpoint {
                schema: CATALOG_SCHEMA,
                id: endpoint_id.clone(),
                scheme: retained.seed.endpoint.scheme.clone(),
                host: retained.seed.endpoint.host.clone(),
                port: retained.seed.endpoint.port,
                path: retained.seed.endpoint.path.clone(),
                network_scope: retained.seed.endpoint.scope.clone(),
                source_observation_ids: Vec::new(),
                owner: retained.seed.endpoint.owner.clone(),
                browser_usable: retained.seed.endpoint.browser_usable,
                transport_encryption: retained.seed.endpoint.encryption,
                expected_service_name: retained.seed.endpoint.expected_service_name.clone(),
                authority_needs: Vec::new(),
                reachability: Vec::new(),
                client_tls: Vec::new(),
            });
        if !endpoint.source_observation_ids.contains(&observation_id) {
            endpoint.source_observation_ids.push(observation_id);
            endpoint.source_observation_ids.sort();
        }

        if let Some(check) = &retained.seed.check {
            let checked_at = check.checked_at.unwrap_or(retained.last_seen);
            let valid_until = checked_at
                + TimeDelta::seconds(i64::try_from(check.interval_secs).unwrap_or(i64::MAX));
            let evidence = CheckEvidence {
                schema: CATALOG_SCHEMA,
                kind: check.kind,
                observer: "this_installation".into(),
                client_identity: None,
                target_endpoint_id: endpoint_id,
                checked_at,
                deadline_ms: check.interval_secs.saturating_mul(1_000),
                timeout_ms: check.timeout_secs.saturating_mul(1_000),
                valid_until,
                result: check.result,
                reason_code: check.reason.clone(),
                detail: check.detail.clone(),
                source_revision: Some(retained.seed.source_revision),
            };
            endpoint.reachability.push(evidence.clone());
            self.checks.push(evidence);
        }
    }

    fn finish(mut self, now: DateTime<Utc>) -> Service {
        self.checks.sort_by_key(|check| Reverse(check.checked_at));
        self.checks.dedup_by(|left, right| {
            left.kind == right.kind && left.target_endpoint_id == right.target_endpoint_id
        });
        self.checks.truncate(MAX_CHECKS_PER_SERVICE);
        for endpoint in self.endpoints.values_mut() {
            endpoint
                .reachability
                .sort_by_key(|check| Reverse(check.checked_at));
            endpoint.reachability.truncate(MAX_CHECKS_PER_SERVICE);
        }
        let ambiguity = if self.identity_conflict {
            Some(Ambiguity {
                reason: "conflicting_explicit_identity".into(),
                candidates: self.display_names.iter().cloned().collect(),
            })
        } else {
            (self.display_names.len() > 1).then(|| Ambiguity {
                reason: "conflicting_names".into(),
                candidates: self.display_names.iter().cloned().collect(),
            })
        };
        if ambiguity.is_some() && self.confidence == IdentityConfidence::Observed {
            self.confidence = IdentityConfidence::Ambiguous;
        }
        let passed = self
            .checks
            .iter()
            .any(|check| check.result == CheckResult::Passed && check.valid_until > now);
        let failed = self
            .checks
            .iter()
            .any(|check| check.result == CheckResult::Failed && check.valid_until > now);
        let condition = if self.confidence == IdentityConfidence::Ambiguous {
            ServiceCondition::Ambiguous
        } else if passed {
            ServiceCondition::Responding
        } else if failed {
            ServiceCondition::NotResponding
        } else if self.has_current && self.starting {
            ServiceCondition::Starting
        } else if self.has_current {
            ServiceCondition::Found
        } else if self.has_stale {
            ServiceCondition::Stale
        } else {
            ServiceCondition::Absent
        };
        let endpoints: Vec<_> = self.endpoints.into_values().collect();
        let mut actions = BTreeSet::from([AvailableAction::ViewDetails]);
        if self.has_current && condition != ServiceCondition::Ambiguous {
            if !endpoints.is_empty() {
                actions.insert(AvailableAction::CopyEndpoint);
                actions.insert(AvailableAction::Diagnose);
            }
            if endpoints.iter().any(endpoint_is_openable) {
                actions.insert(AvailableAction::Open);
            }
        }
        let mut observations: Vec<_> = self.observations.into_values().collect();
        observations.sort_by_key(|observation| Reverse(observation.observed_at));
        observations.truncate(MAX_OBSERVATIONS_PER_SERVICE);
        Service {
            schema: CATALOG_SCHEMA,
            id: self.id,
            device_id: self.device_id,
            display_name: self
                .display_names
                .into_iter()
                .next()
                .unwrap_or_else(|| "Service".into()),
            alias: None,
            kind: self.kind,
            condition,
            endpoints,
            observations,
            checks: self.checks,
            available_actions: actions.into_iter().collect(),
            favorite: false,
            local_only: self.local_only,
            managed: self.managed,
            active_operations: Vec::<OperationSummary>::new(),
            identity_confidence: self.confidence,
            ambiguity,
            last_known: None,
        }
    }
}

fn mdns_seed(
    record: &koi_common::types::ServiceRecord,
    group: &str,
    revision: u64,
    generation: u64,
    provider: Option<&str>,
) -> EvidenceSeed {
    let service_kind = kind_for_service_type(&record.service_type);
    let scheme = scheme_for_service_type(&record.service_type);
    let host = record
        .host
        .as_deref()
        .or(record.ip.as_deref())
        .unwrap_or("unknown")
        .to_string();
    let scope = record
        .ip
        .as_deref()
        .and_then(|ip| network_scope(ip, "mdns", None));
    let port = record.port.unwrap_or(0);
    let path = record.txt.get("path").cloned();
    let explicit_installation_id = record
        .txt
        .get(INSTALLATION_ID_TXT_KEY)
        .and_then(|value| InstallationId::new(value.clone()).ok());
    let explicit_service_id = record
        .txt
        .get(SERVICE_ID_TXT_KEY)
        .and_then(|value| ServiceId::new(value.clone()).ok());
    let provider = provider.unwrap_or("unknown").to_string();
    let local_id = format!(
        "{}|{}|{}|{}|{}",
        normalize_host(&record.name),
        record.service_type.to_ascii_lowercase(),
        normalize_host(&host),
        record.ip.as_deref().unwrap_or(""),
        port
    );
    EvidenceSeed {
        key: format!("mdns|{}", derive_hex("observation", &[group, &local_id])),
        source_group: group.to_string(),
        source_revision: revision,
        source_generation: generation,
        kind: ObservationKind::Mdns,
        provider,
        explicit_installation_id,
        explicit_service_id,
        durable_source_id: None,
        device_hint: record
            .host
            .clone()
            .unwrap_or_else(|| record.ip.clone().unwrap_or_else(|| record.name.clone())),
        display_name: record.name.clone(),
        service_kind: service_kind.clone(),
        endpoint: EndpointSeed {
            browser_usable: matches!(scheme.as_str(), "http" | "https")
                && !matches!(service_kind, ServiceKind::Api)
                && port != 0,
            encryption: if scheme == "https" {
                TransportEncryption::Tls
            } else if scheme == "http" {
                TransportEncryption::None
            } else {
                TransportEncryption::Unknown
            },
            scheme,
            host,
            port,
            path,
            scope,
            owner: EndpointOwner::Foreign,
            expected_service_name: record.host.clone(),
        },
        check: None,
        starting: false,
        managed: false,
        local_only: false,
        raw_reference: BTreeMap::from([
            ("name".into(), record.name.clone()),
            ("service_type".into(), record.service_type.clone()),
        ]),
    }
}

fn runtime_seed(
    instance: &koi_runtime::Instance,
    port: &koi_runtime::PortMapping,
    installation_id: &InstallationId,
    group: &str,
    revision: u64,
) -> Option<EvidenceSeed> {
    let service_type = instance
        .metadata
        .service_type
        .as_deref()
        .unwrap_or("_tcp._tcp");
    let service_kind = kind_for_service_type(service_type);
    let scheme = scheme_for_service_type(service_type);
    let display_name = instance
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| instance.name.clone());
    let durable = format!("{}:{}", instance.backend, instance.id);
    let host = pick_runtime_host(&port.host_ip, instance)?.to_string();
    let local_only = is_loopback(&host);
    let scope = network_scope(&host, "runtime", None);
    Some(EvidenceSeed {
        key: format!("runtime|{}|{}", durable, port.host_port),
        source_group: group.into(),
        source_revision: revision,
        source_generation: 0,
        kind: ObservationKind::Runtime,
        provider: instance.backend.clone(),
        explicit_installation_id: Some(installation_id.clone()),
        explicit_service_id: instance
            .metadata
            .txt
            .get(SERVICE_ID_TXT_KEY)
            .and_then(|value| ServiceId::new(value.clone()).ok()),
        durable_source_id: Some(durable),
        device_hint: "this_device".into(),
        display_name,
        service_kind: service_kind.clone(),
        endpoint: EndpointSeed {
            scheme: scheme.clone(),
            host,
            port: port.host_port,
            path: instance.metadata.health_path.clone(),
            scope,
            owner: EndpointOwner::Domain {
                name: "runtime".into(),
            },
            browser_usable: matches!(scheme.as_str(), "http" | "https")
                && !matches!(service_kind, ServiceKind::Api),
            encryption: if scheme == "https" {
                TransportEncryption::Tls
            } else if scheme == "http" {
                TransportEncryption::None
            } else {
                TransportEncryption::Unknown
            },
            expected_service_name: instance.metadata.dns_name.clone(),
        },
        check: None,
        starting: matches!(
            instance.state,
            koi_runtime::InstanceState::Restarting | koi_runtime::InstanceState::Paused
        ),
        managed: true,
        local_only,
        raw_reference: BTreeMap::from([
            ("backend".into(), instance.backend.clone()),
            ("instance_id".into(), instance.id.clone()),
        ]),
    })
}

fn proxy_seed(
    listener: &koi_proxy::ProxyStatus,
    installation_id: &InstallationId,
    group: &str,
    revision: u64,
) -> EvidenceSeed {
    let host = if listener.allow_remote {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    }
    .to_string();
    let scope = network_scope(&host, "proxy", None);
    EvidenceSeed {
        key: format!("proxy|{}", normalize_host(&listener.name)),
        source_group: group.into(),
        source_revision: revision,
        source_generation: listener.cert_revision,
        kind: ObservationKind::Proxy,
        provider: "koi-proxy".into(),
        explicit_installation_id: Some(installation_id.clone()),
        explicit_service_id: None,
        durable_source_id: Some(listener.name.clone()),
        device_hint: "this_device".into(),
        display_name: listener.name.clone(),
        service_kind: ServiceKind::Proxy,
        endpoint: EndpointSeed {
            scheme: "https".into(),
            host,
            port: listener.listen_port,
            path: None,
            scope,
            owner: EndpointOwner::Domain {
                name: "proxy".into(),
            },
            browser_usable: !listener.allow_remote,
            encryption: TransportEncryption::Tls,
            expected_service_name: Some(listener.name.clone()),
        },
        check: Some(CheckSeed {
            kind: CheckKind::ProxyListener,
            checked_at: None,
            interval_secs: 2,
            timeout_secs: 0,
            result: if listener.state == "running" {
                CheckResult::Passed
            } else if listener.state == "error" {
                CheckResult::Failed
            } else {
                CheckResult::Unknown
            },
            reason: format!("proxy_{}", listener.state),
            detail: listener.error.clone(),
        }),
        starting: listener.state == "starting",
        managed: true,
        local_only: !listener.allow_remote,
        raw_reference: BTreeMap::from([("backend".into(), listener.backend.clone())]),
    }
}

fn health_seed(
    service: &koi_health::ServiceHealth,
    installation_id: &InstallationId,
    group: &str,
    revision: u64,
) -> Option<EvidenceSeed> {
    let (scheme, host, port, path) = parse_health_target(service.kind, &service.target)?;
    let service_kind = if matches!(service.kind, koi_health::ServiceCheckKind::Http) {
        ServiceKind::Web
    } else {
        ServiceKind::Other("tcp".into())
    };
    let scope = network_scope(&host, "health", None);
    let local = is_loopback(&host);
    Some(EvidenceSeed {
        key: format!("health|{}", normalize_host(&service.name)),
        source_group: group.into(),
        source_revision: revision,
        source_generation: 0,
        kind: ObservationKind::Health,
        provider: "koi-health".into(),
        explicit_installation_id: local.then(|| installation_id.clone()),
        explicit_service_id: None,
        durable_source_id: None,
        device_hint: if local {
            "this_device".into()
        } else {
            host.clone()
        },
        display_name: service.name.clone(),
        service_kind,
        endpoint: EndpointSeed {
            browser_usable: scheme == "http" || scheme == "https",
            encryption: if scheme == "https" {
                TransportEncryption::Tls
            } else if scheme == "http" {
                TransportEncryption::None
            } else {
                TransportEncryption::Unknown
            },
            scheme,
            host,
            port,
            path,
            scope,
            owner: EndpointOwner::Domain {
                name: "health".into(),
            },
            expected_service_name: None,
        },
        check: Some(CheckSeed {
            kind: match service.kind {
                koi_health::ServiceCheckKind::Http => CheckKind::HttpResponse,
                koi_health::ServiceCheckKind::Tcp => CheckKind::TcpConnect,
            },
            checked_at: service.last_checked,
            interval_secs: service.interval_secs,
            timeout_secs: service.timeout_secs,
            result: match service.status {
                koi_health::ServiceStatus::Up => CheckResult::Passed,
                koi_health::ServiceStatus::Down => CheckResult::Failed,
                koi_health::ServiceStatus::Unknown => CheckResult::Unknown,
            },
            reason: match service.status {
                koi_health::ServiceStatus::Up => "health_up",
                koi_health::ServiceStatus::Down => "health_down",
                koi_health::ServiceStatus::Unknown => "health_unknown",
            }
            .into(),
            detail: service.message.clone(),
        }),
        starting: false,
        managed: true,
        local_only: local,
        raw_reference: BTreeMap::from([("target".into(), service.target.clone())]),
    })
}

fn parse_health_target(
    kind: koi_health::ServiceCheckKind,
    target: &str,
) -> Option<(String, String, u16, Option<String>)> {
    match kind {
        koi_health::ServiceCheckKind::Http => {
            let (scheme, rest) = target.split_once("://")?;
            if !matches!(scheme, "http" | "https") {
                return None;
            }
            let (authority, path) = rest
                .split_once('/')
                .map_or((rest, None), |(a, p)| (a, Some(format!("/{p}"))));
            let default = if scheme == "https" { 443 } else { 80 };
            let (host, port) = split_authority(authority, default)?;
            Some((scheme.into(), host, port, path))
        }
        koi_health::ServiceCheckKind::Tcp => {
            let (host, port) = split_authority(target, 0)?;
            Some(("tcp".into(), host, port, None))
        }
    }
}

fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .ok()?
            .unwrap_or(default_port);
        return (port != 0).then(|| (host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_string(), port.parse().ok()?)),
        _ if default_port != 0 => Some((authority.to_string(), default_port)),
        _ => None,
    }
}

fn kind_for_service_type(service_type: &str) -> ServiceKind {
    let service_type = service_type.to_ascii_lowercase();
    if service_type.contains("_ollama.") || service_type.contains("_mcp.") {
        ServiceKind::Api
    } else if service_type.contains("_http.") || service_type.contains("_https.") {
        ServiceKind::Web
    } else if service_type.contains("_ipp.") || service_type.contains("_printer.") {
        ServiceKind::Printer
    } else {
        ServiceKind::Other(
            service_type
                .trim_matches('.')
                .split('.')
                .next()
                .unwrap_or("unknown")
                .trim_start_matches('_')
                .to_string(),
        )
    }
}

fn compatible_kind(kind: &ServiceKind) -> String {
    match kind {
        ServiceKind::Web | ServiceKind::Proxy => "web".to_string(),
        ServiceKind::Api => "api".to_string(),
        ServiceKind::Printer => "printer".to_string(),
        ServiceKind::Database => "database".to_string(),
        ServiceKind::Runtime => "runtime".to_string(),
        ServiceKind::Other(value) => format!("other:{value}"),
    }
}

fn scheme_for_service_type(service_type: &str) -> String {
    let service_type = service_type.to_ascii_lowercase();
    if service_type.contains("_https.") {
        "https"
    } else if service_type.contains("_http.")
        || service_type.contains("_ollama.")
        || service_type.contains("_mcp.")
    {
        "http"
    } else if service_type.contains("._udp") {
        "udp"
    } else {
        "tcp"
    }
    .into()
}

fn network_scope(
    value: &str,
    route_source: &str,
    provider_scope: Option<&str>,
) -> Option<NetworkScope> {
    let unbracketed = value.trim_matches(['[', ']']);
    let (address, interface) = unbracketed
        .split_once('%')
        .map_or((unbracketed, None), |(address, zone)| {
            (address, Some(zone.to_string()))
        });
    let parsed = address.parse::<IpAddr>().ok();
    let (family, classification) = match parsed {
        Some(IpAddr::V4(ip)) => (AddressFamily::Ipv4, classify_v4(ip)),
        Some(IpAddr::V6(ip)) => (AddressFamily::Ipv6, classify_v6(ip)),
        None if !address.is_empty() => (AddressFamily::Hostname, NetworkClassification::Unknown),
        None => (AddressFamily::Unknown, NetworkClassification::Unknown),
    };
    let canonical = format!(
        "{family:?}|{}|{:?}|{}",
        interface.as_deref().unwrap_or(""),
        classification,
        provider_scope.unwrap_or("")
    );
    Some(NetworkScope {
        id: NetworkScopeId::new(format!("scope_{}", derive_hex("scope", &[&canonical])))
            .expect("derived scope ID"),
        family,
        interface,
        // The source exposes a target, not the observer's local interface
        // address. Leaving this absent is safer than inventing network scope.
        local_address: None,
        prefix_len: None,
        route_source: route_source.into(),
        classification,
        provider_scope: provider_scope.map(str::to_string),
    })
}

fn classify_v4(ip: Ipv4Addr) -> NetworkClassification {
    if ip.is_loopback() {
        NetworkClassification::Loopback
    } else if ip.is_private() || ip.is_link_local() {
        NetworkClassification::Private
    } else if ip.is_unspecified() {
        NetworkClassification::Unknown
    } else {
        NetworkClassification::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> NetworkClassification {
    if ip.is_loopback() {
        NetworkClassification::Loopback
    } else if ip.is_unicast_link_local() {
        NetworkClassification::LinkLocal
    } else if ip.is_unique_local() {
        NetworkClassification::Private
    } else if ip.is_unspecified() {
        NetworkClassification::Unknown
    } else {
        NetworkClassification::Public
    }
}

fn endpoint_is_openable(endpoint: &Endpoint) -> bool {
    if !endpoint.browser_usable
        || !matches!(endpoint.scheme.as_str(), "http" | "https")
        || !is_concrete_host(&endpoint.host)
    {
        return false;
    }
    !endpoint.network_scope.as_ref().is_some_and(|scope| {
        scope.classification == NetworkClassification::LinkLocal && scope.interface.is_none()
    })
}

fn is_loopback(value: &str) -> bool {
    value
        .trim_matches(['[', ']'])
        .split('%')
        .next()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback())
}

fn pick_runtime_host<'a>(host_ip: &'a str, instance: &'a koi_runtime::Instance) -> Option<&'a str> {
    if is_concrete_host(host_ip) {
        return Some(host_ip);
    }
    instance
        .ips
        .iter()
        .map(String::as_str)
        .find(|candidate| is_concrete_host(candidate))
}

fn is_concrete_host(host: &str) -> bool {
    let host = host.trim();
    !host.is_empty() && !matches!(host, "0.0.0.0" | "::" | "[::]")
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn mdns_group(query: &str, provider: Option<&str>) -> String {
    format!(
        "mdns|{}|{}",
        query.to_ascii_lowercase(),
        provider.unwrap_or("unknown")
    )
}

fn device_id_for(seed: &EvidenceSeed, local: &InstallationId, epoch: &str) -> DeviceId {
    if let Some(installation_id) = &seed.explicit_installation_id {
        return explicit_device_id(installation_id);
    }
    let scope = seed
        .endpoint
        .scope
        .as_ref()
        .map(|scope| scope.id.as_str())
        .unwrap_or("unknown");
    if seed.provider == "koi" {
        return explicit_device_id(local);
    }
    derived_device_id(
        epoch,
        &format!(
            "{}|{scope}|{}|{}",
            normalize_host(&seed.device_hint),
            seed.source_group,
            seed.source_generation
        ),
    )
}

fn explicit_device_id(installation_id: &InstallationId) -> DeviceId {
    DeviceId::new(format!(
        "dev_{}",
        derive_hex("installation-device", &[installation_id.as_str()])
    ))
    .expect("derived device ID")
}

fn derived_device_id(epoch: &str, evidence: &str) -> DeviceId {
    DeviceId::new(format!(
        "dev_{}",
        derive_hex("observed-device", &[epoch, evidence])
    ))
    .expect("derived device ID")
}

fn service_id_for(
    seed: &EvidenceSeed,
    device_id: &DeviceId,
    installation_id: &InstallationId,
) -> ServiceId {
    if let Some(id) = &seed.explicit_service_id {
        return id.clone();
    }
    let endpoint = normalized_endpoint(&seed.endpoint);
    let kind = format!("{:?}", seed.service_kind).to_ascii_lowercase();
    let identity = if let Some(source_id) = &seed.durable_source_id {
        derive_hex(
            "durable-service",
            &[installation_id.as_str(), source_id, &kind],
        )
    } else {
        derive_hex("observed-service", &[device_id.as_str(), &endpoint, &kind])
    };
    ServiceId::new(format!("svc_{identity}")).expect("derived service ID")
}

fn endpoint_id(seed: &EndpointSeed) -> EndpointId {
    EndpointId::new(format!(
        "ep_{}",
        derive_hex("endpoint", &[&normalized_endpoint(seed)])
    ))
    .expect("derived endpoint ID")
}

fn observation_id(seed: &EvidenceSeed) -> ObservationId {
    ObservationId::new(format!("obs_{}", derive_hex("observation", &[&seed.key])))
        .expect("derived observation ID")
}

fn normalized_endpoint(seed: &EndpointSeed) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        seed.scheme.to_ascii_lowercase(),
        normalize_host(&seed.host),
        seed.port,
        seed.path.as_deref().unwrap_or(""),
        seed.scope
            .as_ref()
            .map(|scope| scope.id.as_str())
            .unwrap_or("unknown")
    )
}

fn derive_hex(purpose: &str, parts: &[&str]) -> String {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(DERIVATION_VERSION.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(purpose.as_bytes());
    for part in parts {
        canonical.push(0);
        canonical.extend_from_slice(part.as_bytes());
    }
    koi_crypto::pinning::fingerprint_sha256(&canonical)[..32].to_string()
}

fn observation_retention_rank(state: ObservationState) -> u8 {
    match state {
        ObservationState::Withdrawn => 0,
        ObservationState::Stale | ObservationState::SourceUnavailable => 1,
        ObservationState::Current => 2,
    }
}

fn service_retention_rank(condition: ServiceCondition) -> u8 {
    match condition {
        ServiceCondition::Absent => 0,
        ServiceCondition::Stale => 1,
        ServiceCondition::Ambiguous => 2,
        ServiceCondition::Starting
        | ServiceCondition::Found
        | ServiceCondition::Responding
        | ServiceCondition::NotResponding => 3,
    }
}

fn join_preferences(
    devices: &mut Vec<Device>,
    services: &mut Vec<Service>,
    local_candidates: &mut Vec<LocalCandidate>,
    preferences: Option<&PreferencesStatus>,
) {
    let Some(preferences) = preferences else {
        return;
    };
    if preferences.mode != PreferencesMode::Writable {
        return;
    }

    let dismissed: BTreeSet<_> = preferences
        .candidates
        .iter()
        .filter(|record| record.dismissed)
        .map(|record| (record.candidate_id.clone(), record.candidate_key.clone()))
        .collect();
    local_candidates
        .retain(|candidate| !dismissed.contains(&(candidate.id.clone(), candidate.key.clone())));

    for preference in &preferences.services {
        let service_id = preference.service_key.service_id();
        if let Some(service) = services
            .iter_mut()
            .find(|service| &service.id == service_id)
        {
            service.favorite = preference.favorite;
            service.alias.clone_from(&preference.friendly_alias);
            continue;
        }
        let Some(context) = preference
            .last_known
            .as_ref()
            .filter(|_| preference.favorite)
        else {
            continue;
        };
        if !devices.iter().any(|device| device.id == context.device_id) {
            devices.push(Device {
                schema: CATALOG_SCHEMA,
                id: context.device_id.clone(),
                names: context
                    .device_name
                    .iter()
                    .map(|name| NameEvidence {
                        value: name.clone(),
                        observation_ids: Vec::new(),
                    })
                    .collect(),
                addresses: Vec::new(),
                koi_presence: KoiPresence::Absent,
                mesh_identity: MeshIdentity {
                    state: MeshIdentityState::Unknown,
                    observation_ids: Vec::new(),
                },
                condition: DeviceCondition::Absent,
            });
        }
        services.push(Service {
            schema: CATALOG_SCHEMA,
            id: service_id.clone(),
            device_id: context.device_id.clone(),
            display_name: context.display_name.clone(),
            alias: preference.friendly_alias.clone(),
            kind: context.kind.clone(),
            condition: ServiceCondition::Absent,
            endpoints: Vec::new(),
            observations: Vec::new(),
            checks: Vec::new(),
            available_actions: vec![
                AvailableAction::ViewDetails,
                AvailableAction::Favorite,
                AvailableAction::SetFriendlyAlias,
            ],
            favorite: true,
            local_only: false,
            managed: false,
            active_operations: Vec::new(),
            identity_confidence: IdentityConfidence::Observed,
            ambiguity: None,
            last_known: Some(LastKnownService {
                device_name: context.device_name.clone(),
                last_seen: context.last_seen,
                kind: context.kind.clone(),
            }),
        });
    }
    devices.sort_by(|left, right| left.id.cmp(&right.id));
    services.sort_by(|left, right| left.id.cmp(&right.id));
}

fn capture_inputs(sources: &CatalogSources, availability: SourceAvailability) -> CatalogInputs {
    CatalogInputs {
        mdns: sources.mdns.as_ref().map(|source| source.snapshot()),
        certmesh: sources.certmesh.as_ref().map(|source| source.snapshot()),
        dns: sources
            .dns
            .as_ref()
            .map(|runtime| runtime.catalog_snapshot()),
        health: sources.health.as_ref().map(|runtime| runtime.status()),
        proxy: sources.proxy.as_ref().map(|runtime| runtime.status()),
        proxy_entries: sources
            .proxy
            .as_ref()
            .map(|runtime| runtime.entries_snapshot()),
        runtime: sources.runtime.as_ref().map(|runtime| runtime.status()),
        preferences: sources
            .preferences
            .as_ref()
            .map(|preferences| preferences.status()),
        availability,
    }
}

pub(crate) fn spawn_catalog_observer(
    catalog: Arc<ServiceCatalogRuntime>,
    sources: CatalogSources,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    let mut availability = SourceAvailability::from_sources(&sources);
    let mut mdns = sources.mdns.as_ref().map(|source| source.watch_snapshot());
    let mut certmesh = sources
        .certmesh
        .as_ref()
        .map(|source| source.watch_snapshot());
    let mut dns = sources
        .dns
        .as_ref()
        .map(|runtime| runtime.watch_catalog_snapshot());
    let mut health = sources
        .health
        .as_ref()
        .map(|runtime| runtime.watch_status());
    let mut proxy = sources.proxy.as_ref().map(|runtime| runtime.watch_status());
    let mut proxy_entries = sources
        .proxy
        .as_ref()
        .map(|runtime| runtime.watch_entries());
    let mut runtime = sources
        .runtime
        .as_ref()
        .map(|runtime| runtime.watch_status());
    let mut preferences = sources
        .preferences
        .as_ref()
        .map(|preferences| preferences.watch_status());

    catalog.reconcile(capture_inputs(&sources, availability), Utc::now());
    tasks.push(tokio::spawn(async move {
        let mut expiry = tokio::time::interval(EXPIRY_TICK);
        expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                closed = watch_changed(&mut mdns) => availability.mdns &= !closed,
                closed = watch_changed(&mut certmesh) => availability.certmesh &= !closed,
                closed = watch_changed(&mut dns) => availability.dns &= !closed,
                closed = watch_changed(&mut health) => availability.health &= !closed,
                closed = watch_changed(&mut proxy) => availability.proxy &= !closed,
                closed = watch_changed(&mut proxy_entries) => availability.proxy &= !closed,
                closed = watch_changed(&mut runtime) => availability.runtime &= !closed,
                _ = watch_changed(&mut preferences) => {},
                _ = expiry.tick() => {}
            }
            catalog.reconcile(capture_inputs(&sources, availability), Utc::now());
        }
    }));
}

async fn watch_changed<T>(receiver: &mut Option<watch::Receiver<Arc<T>>>) -> bool {
    let closed = match receiver.as_mut() {
        Some(receiver) => receiver.changed().await.is_err(),
        None => pending().await,
    };
    if closed {
        *receiver = None;
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::integration::{MdnsDiscoveryObservation, MdnsDiscoverySource};
    use koi_common::types::ServiceRecord;
    use std::collections::HashMap;

    struct MockMdns {
        current: Mutex<Arc<MdnsDiscoverySnapshot>>,
        sender: Mutex<Option<watch::Sender<Arc<MdnsDiscoverySnapshot>>>>,
    }

    impl MockMdns {
        fn new(snapshot: MdnsDiscoverySnapshot) -> Self {
            let snapshot = Arc::new(snapshot);
            let (sender, _) = watch::channel(Arc::clone(&snapshot));
            Self {
                current: Mutex::new(snapshot),
                sender: Mutex::new(Some(sender)),
            }
        }

        fn close(&self) {
            self.sender.lock().unwrap().take();
        }
    }

    impl MdnsSnapshot for MockMdns {
        fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
            Arc::clone(&self.current.lock().unwrap())
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
            self.sender
                .lock()
                .unwrap()
                .as_ref()
                .expect("watch subscribed before closure")
                .subscribe()
        }
    }

    fn installation() -> InstallationId {
        InstallationId::new("0199-local").unwrap()
    }

    fn mdns_input(records: Vec<ServiceRecord>, revision: u64, available: bool) -> CatalogInputs {
        let source = MdnsDiscoverySource {
            query: "_http._tcp.local.".into(),
            provider: Some("native".into()),
            generation: 1,
            available,
        };
        CatalogInputs {
            mdns: Some(Arc::new(MdnsDiscoverySnapshot {
                revision,
                service_types: vec!["_http._tcp.local.".into()],
                records: records.clone(),
                sources: vec![source.clone()],
                observations: records
                    .into_iter()
                    .map(|record| MdnsDiscoveryObservation {
                        source: source.clone(),
                        value: MdnsDiscoveryValue::ServiceRecord { record },
                    })
                    .collect(),
            })),
            availability: SourceAvailability {
                mdns: true,
                ..SourceAvailability::default()
            },
            ..CatalogInputs::default()
        }
    }

    fn record(name: &str, host: &str, ip: &str, port: u16) -> ServiceRecord {
        ServiceRecord {
            name: name.into(),
            service_type: "_http._tcp.local.".into(),
            host: Some(host.into()),
            ip: Some(ip.into()),
            port: Some(port),
            txt: HashMap::new(),
        }
    }

    #[test]
    fn same_names_on_different_devices_remain_separate() {
        let mut model = CatalogModel::default();
        let now = Utc::now();
        let (_, services) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(
                vec![
                    record("Grafana", "one.local.", "192.168.1.10", 3000),
                    record("Grafana", "two.local.", "192.168.1.11", 3000),
                ],
                1,
                true,
            ),
            now,
        );
        assert_eq!(services.len(), 2);
        assert_ne!(services[0].device_id, services[1].device_id);
    }

    #[test]
    fn explicit_ids_merge_companion_observations_but_keep_sources() {
        let mut first = record("Grafana", "one.local.", "192.168.1.10", 3000);
        first
            .txt
            .insert(INSTALLATION_ID_TXT_KEY.into(), installation().to_string());
        first
            .txt
            .insert(SERVICE_ID_TXT_KEY.into(), "svc_explicit".into());
        let mut inputs = mdns_input(vec![first], 1, true);
        inputs.runtime = Some(Arc::new(koi_runtime::RuntimeStatus {
            revision: 4,
            active: true,
            state: koi_runtime::RuntimeWatchState::Running,
            backend: Some("docker".into()),
            backend_error: None,
            instance_count: 1,
            instances: vec![koi_runtime::Instance {
                id: "container-1".into(),
                name: "Grafana runtime".into(),
                ports: vec![koi_runtime::PortMapping {
                    host_port: 3000,
                    container_port: 3000,
                    protocol: koi_runtime::instance::PortProtocol::Tcp,
                    host_ip: "192.168.1.10".into(),
                }],
                ips: vec!["192.168.1.10".into()],
                metadata: koi_runtime::KoiMetadata {
                    service_type: Some("_http._tcp".into()),
                    txt: HashMap::from([("koi.service_id".into(), "svc_explicit".into())]),
                    ..Default::default()
                },
                backend: "docker".into(),
                state: koi_runtime::InstanceState::Running,
                discovered_at: Utc::now(),
                image: None,
            }],
        }));
        inputs.availability.runtime = true;
        let mut model = CatalogModel::default();
        let (_, services) = model.project(&installation(), "local", "epoch", inputs, Utc::now());
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].id.as_str(), "svc_explicit");
        assert_eq!(services[0].observations.len(), 2);
        assert_eq!(
            services[0].identity_confidence,
            IdentityConfidence::Explicit
        );
    }

    #[test]
    fn source_loss_stales_but_withdrawal_is_absent_and_old_revisions_do_not_resurrect() {
        let mut model = CatalogModel::default();
        let now = Utc::now();
        let source = vec![record("App", "app.local.", "192.168.1.4", 80)];
        let (_, found) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(source.clone(), 2, true),
            now,
        );
        assert_eq!(found[0].condition, ServiceCondition::Found);

        let (_, absent) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(Vec::new(), 3, true),
            now,
        );
        assert_eq!(absent[0].condition, ServiceCondition::Absent);

        let (_, still_absent) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(source.clone(), 2, true),
            now,
        );
        assert_eq!(still_absent[0].condition, ServiceCondition::Absent);

        let (_, stale) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(source, 4, false),
            now,
        );
        assert_eq!(stale[0].condition, ServiceCondition::Stale);
        let (_, expired) = model.project(
            &installation(),
            "local",
            "epoch",
            CatalogInputs::default(),
            now + TimeDelta::minutes(11),
        );
        assert!(expired.is_empty());
    }

    #[test]
    fn api_and_unknown_tcp_endpoints_never_offer_open() {
        let mut api = record("Ollama", "ai.local.", "192.168.1.5", 11434);
        api.service_type = "_ollama._tcp.local.".into();
        let mut tcp = record("Mystery", "box.local.", "192.168.1.6", 9000);
        tcp.service_type = "_mystery._tcp.local.".into();
        let mut model = CatalogModel::default();
        let (_, services) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(vec![api, tcp], 1, true),
            Utc::now(),
        );
        assert!(services
            .iter()
            .all(|service| !service.available_actions.contains(&AvailableAction::Open)));
        assert!(services.iter().all(|service| service
            .available_actions
            .contains(&AvailableAction::CopyEndpoint)));
    }

    #[test]
    fn ipv6_link_local_requires_a_zone_to_open() {
        let without = record("Web", "fe80::1", "fe80::1", 80);
        let with = record("Web", "fe80::1%12", "fe80::1%12", 80);
        let mut model = CatalogModel::default();
        let (_, services) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(vec![without, with], 1, true),
            Utc::now(),
        );
        assert_eq!(services.len(), 2);
        let openable = services
            .iter()
            .filter(|service| service.available_actions.contains(&AvailableAction::Open))
            .count();
        assert_eq!(openable, 1);
    }

    #[test]
    fn conflicting_explicit_device_identity_stays_separate_and_ambiguous() {
        let mut one = record("App", "one.local.", "192.168.1.10", 80);
        one.txt
            .insert(INSTALLATION_ID_TXT_KEY.into(), "0199-one".into());
        one.txt
            .insert(SERVICE_ID_TXT_KEY.into(), "svc_shared".into());
        let mut two = record("App", "two.local.", "192.168.1.11", 80);
        two.txt
            .insert(INSTALLATION_ID_TXT_KEY.into(), "0199-two".into());
        two.txt
            .insert(SERVICE_ID_TXT_KEY.into(), "svc_shared".into());
        let mut model = CatalogModel::default();
        let (_, services) = model.project(
            &installation(),
            "local",
            "epoch",
            mdns_input(vec![one, two], 1, true),
            Utc::now(),
        );
        assert_eq!(services.len(), 2);
        assert!(services
            .iter()
            .all(|service| service.identity_confidence == IdentityConfidence::Ambiguous));
        assert!(services
            .iter()
            .all(|service| !service.available_actions.contains(&AvailableAction::Open)));
        assert_ne!(services[0].id, services[1].id);
    }

    #[test]
    fn responding_requires_an_unexpired_positive_check_with_observer_and_target() {
        let now = Utc::now();
        let mut app = record("App", "127.0.0.1", "127.0.0.1", 80);
        app.txt
            .insert(INSTALLATION_ID_TXT_KEY.into(), installation().to_string());
        let mut inputs = mdns_input(vec![app], 1, true);
        inputs.health = Some(Arc::new(koi_health::HealthSnapshot {
            revision: 1,
            running: true,
            machines: Vec::new(),
            services: vec![koi_health::ServiceHealth {
                name: "App health".into(),
                kind: koi_health::ServiceCheckKind::Http,
                target: "http://127.0.0.1:80".into(),
                interval_secs: 30,
                timeout_secs: 5,
                status: koi_health::ServiceStatus::Up,
                last_checked: Some(now),
                last_ok: Some(now),
                message: None,
            }],
        }));
        inputs.availability.health = true;
        let mut model = CatalogModel::default();
        let (_, responding) = model.project(&installation(), "local", "epoch", inputs.clone(), now);
        assert_eq!(responding.len(), 1);
        assert_eq!(responding[0].condition, ServiceCondition::Responding);
        let check = &responding[0].checks[0];
        assert_eq!(check.observer, "this_installation");
        assert_eq!(check.target_endpoint_id, responding[0].endpoints[0].id);
        assert_eq!(check.result, CheckResult::Passed);

        let (_, expired) = model.project(
            &installation(),
            "local",
            "epoch",
            inputs,
            now + TimeDelta::seconds(31),
        );
        assert_eq!(expired[0].condition, ServiceCondition::Found);
    }

    #[test]
    fn restart_changes_epoch_but_not_explicit_service_identity() {
        let mut app = record("App", "app.local.", "192.168.1.20", 80);
        app.txt
            .insert(INSTALLATION_ID_TXT_KEY.into(), "0199-peer".into());
        app.txt
            .insert(SERVICE_ID_TXT_KEY.into(), "svc_stable".into());
        let now = Utc::now();
        let mut before = CatalogModel::default();
        let (_, before_services) = before.project(
            &installation(),
            "local",
            "epoch-before",
            mdns_input(vec![app.clone()], 1, true),
            now,
        );
        let mut after = CatalogModel::default();
        let (_, after_services) = after.project(
            &installation(),
            "local",
            "epoch-after",
            mdns_input(vec![app], 0, true),
            now,
        );
        assert_eq!(before_services[0].id, after_services[0].id);
        assert_eq!(before_services[0].device_id, after_services[0].device_id);
    }

    #[tokio::test]
    async fn observer_subscribes_before_read_stales_on_closure_and_joins_on_cancel() {
        let input = mdns_input(
            vec![record("App", "app.local.", "192.168.1.4", 80)],
            1,
            true,
        );
        let source = Arc::new(MockMdns::new((*input.mdns.unwrap()).clone()));
        let catalog = Arc::new(ServiceCatalogRuntime::new(installation(), "local"));
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();
        spawn_catalog_observer(
            Arc::clone(&catalog),
            CatalogSources {
                mdns: Some(source.clone()),
                ..CatalogSources::default()
            },
            cancel.clone(),
            &mut tasks,
        );
        assert_eq!(
            catalog.status().services[0].condition,
            ServiceCondition::Found
        );

        let mut changes = catalog.watch_status();
        source.close();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                changes.changed().await.unwrap();
                if changes.borrow().services[0].condition == ServiceCondition::Stale {
                    break;
                }
            }
        })
        .await
        .expect("catalog did not stale retained evidence after source closure");

        cancel.cancel();
        for task in tasks {
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("catalog observer did not join")
                .expect("catalog observer panicked");
        }
    }

    fn service(id: &str, name: &str) -> Service {
        Service {
            schema: CATALOG_SCHEMA,
            id: ServiceId::new(id).unwrap(),
            device_id: DeviceId::new(format!("dev_{id}")).unwrap(),
            display_name: name.into(),
            alias: None,
            kind: ServiceKind::Web,
            condition: ServiceCondition::Found,
            endpoints: Vec::new(),
            observations: Vec::new(),
            checks: Vec::new(),
            available_actions: vec![AvailableAction::Favorite],
            favorite: false,
            local_only: false,
            managed: false,
            active_operations: Vec::new(),
            identity_confidence: IdentityConfidence::Observed,
            ambiguity: None,
            last_known: None,
        }
    }

    #[test]
    fn preferences_join_by_stable_id_and_keep_absent_favorite_separate_from_stranger() {
        let last_seen = Utc::now();
        let preferences = PreferencesStatus {
            schema: koi_common::service::PREFERENCES_SCHEMA,
            epoch: "preferences-epoch".into(),
            revision: 4,
            mode: PreferencesMode::Writable,
            services: vec![koi_common::service::ServicePreference {
                service_key: koi_common::service::ServicePreferenceKey::KoiService {
                    id: ServiceId::new("svc_original").unwrap(),
                },
                favorite: true,
                friendly_alias: Some("Workshop dashboard".into()),
                last_known: Some(koi_common::service::PreferredServiceContext {
                    device_id: DeviceId::new("dev_original").unwrap(),
                    display_name: "Grafana".into(),
                    device_name: Some("workshop".into()),
                    kind: ServiceKind::Web,
                    last_condition: ServiceCondition::Found,
                    last_seen,
                }),
            }],
            candidates: Vec::new(),
            problem: None,
        };

        let mut devices = Vec::new();
        let mut services = vec![service("svc_stranger", "Grafana")];
        let mut candidates = Vec::new();
        join_preferences(
            &mut devices,
            &mut services,
            &mut candidates,
            Some(&preferences),
        );

        assert_eq!(services.len(), 2);
        let stranger = services
            .iter()
            .find(|service| service.id.as_str() == "svc_stranger")
            .unwrap();
        assert!(!stranger.favorite, "same display name is not identity");
        let absent = services
            .iter()
            .find(|service| service.id.as_str() == "svc_original")
            .unwrap();
        assert!(absent.favorite);
        assert_eq!(absent.alias.as_deref(), Some("Workshop dashboard"));
        assert_eq!(absent.condition, ServiceCondition::Absent);
        assert_eq!(absent.last_known.as_ref().unwrap().last_seen, last_seen);
        assert!(absent.endpoints.is_empty());
        assert_eq!(devices[0].condition, DeviceCondition::Absent);
    }

    #[test]
    fn candidate_dismissal_requires_the_same_recognizer_and_source_key() {
        let key = koi_common::service::CandidatePreferenceKey {
            recognizer: "process-executable-v1:ollama".into(),
            source: "windows-process-table".into(),
        };
        let candidate_id = ServiceId::new("svc_candidate").unwrap();
        let candidate = LocalCandidate {
            schema: CATALOG_SCHEMA,
            id: candidate_id.clone(),
            key: key.clone(),
            display_name: "Ollama".into(),
            kind: ServiceKind::Api,
            endpoints: Vec::new(),
            observations: Vec::new(),
            available_actions: vec![AvailableAction::DismissCandidate],
        };
        let preferences = PreferencesStatus {
            schema: koi_common::service::PREFERENCES_SCHEMA,
            epoch: "preferences-epoch".into(),
            revision: 1,
            mode: PreferencesMode::Writable,
            services: Vec::new(),
            candidates: vec![koi_common::service::CandidatePreference {
                candidate_id,
                candidate_key: key,
                dismissed: true,
            }],
            problem: None,
        };
        let mut devices = Vec::new();
        let mut services = Vec::new();
        let mut candidates = vec![candidate];
        join_preferences(
            &mut devices,
            &mut services,
            &mut candidates,
            Some(&preferences),
        );
        assert!(candidates.is_empty());
    }
}
