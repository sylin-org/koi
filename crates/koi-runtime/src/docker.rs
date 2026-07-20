//! Docker/Podman runtime backend.
//!
//! Connects to the Docker Engine API via the local socket
//! (Unix: `/var/run/docker.sock`, Windows: `//./pipe/docker_engine`).
//! Podman exposes a Docker-compatible API on a different socket path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bollard::query_parameters::{EventsOptions, InspectContainerOptions, ListContainersOptions};
use bollard::Docker;
use chrono::Utc;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::{RuntimeBackend, RuntimeEvent};
use crate::error::RuntimeError;
use crate::instance::{
    ComposeInfo, Instance, InstanceState, KoiMetadata, PortMapping, PortProtocol,
};

/// Docker/Podman runtime backend.
pub struct DockerBackend {
    client: Option<Docker>,
    socket_path: Option<String>,
    is_podman: bool,
    /// Last point-in-time inventory, seeded by RuntimeCore's startup listing.
    /// The watch loop owns a clone and uses it to emit exact stop/start/update
    /// deltas after an event-stream reconnect.
    known_instances: Mutex<HashMap<String, Instance>>,
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerBackend {
    /// Create a Docker backend with default socket detection.
    pub fn new() -> Self {
        Self {
            client: None,
            socket_path: None,
            is_podman: false,
            known_instances: Mutex::new(HashMap::new()),
        }
    }

    /// Create a Docker backend with a custom socket path.
    pub fn with_socket(path: String) -> Self {
        Self {
            client: None,
            socket_path: Some(path),
            is_podman: false,
            known_instances: Mutex::new(HashMap::new()),
        }
    }

    /// Create a Podman backend (Docker-compatible API, different defaults).
    pub fn podman() -> Self {
        Self {
            client: None,
            socket_path: None,
            is_podman: true,
            known_instances: Mutex::new(HashMap::new()),
        }
    }

    fn client(&self) -> Result<&Docker, RuntimeError> {
        self.client
            .as_ref()
            .ok_or_else(|| RuntimeError::Connection("Docker client not connected".into()))
    }

    /// Convert a Docker container inspect result into a normalized Instance.
    async fn container_to_instance(
        &self,
        client: &Docker,
        container_id: &str,
    ) -> Result<Instance, RuntimeError> {
        let info = client
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .map_err(|e| RuntimeError::Internal(format!("inspect {container_id}: {e}")))?;

        let config = info.config.as_ref();
        let labels = config
            .and_then(|c| c.labels.as_ref())
            .cloned()
            .unwrap_or_default();

        let name = info
            .name
            .as_deref()
            .unwrap_or(container_id)
            .trim_start_matches('/')
            .to_string();

        let compose = ComposeInfo::from_labels(&labels);
        let effective_name = compose.effective_name(&name).to_string();

        let ports = extract_port_mappings(&info);
        let ips = extract_ips(&info);

        let state = match info.state.as_ref().and_then(|s| s.status) {
            Some(bollard::models::ContainerStateStatusEnum::RUNNING) => InstanceState::Running,
            Some(bollard::models::ContainerStateStatusEnum::PAUSED) => InstanceState::Paused,
            Some(bollard::models::ContainerStateStatusEnum::RESTARTING) => {
                InstanceState::Restarting
            }
            _ => InstanceState::Stopped,
        };

        let image = config.and_then(|c| c.image.clone());

        // Extract environment variables for KOI_MDNS_ANNOUNCE shorthand
        let env_vars: Vec<String> = config
            .and_then(|c| c.env.as_ref())
            .cloned()
            .unwrap_or_default();

        let koi_metadata = KoiMetadata::from_labels_and_env(&labels, &env_vars);

        Ok(Instance {
            id: info.id.unwrap_or_else(|| container_id.to_string()),
            name: effective_name,
            ports,
            ips,
            metadata: koi_metadata,
            backend: if self.is_podman { "podman" } else { "docker" }.to_string(),
            state,
            discovered_at: Utc::now(),
            image,
        })
    }
}

#[async_trait::async_trait]
impl RuntimeBackend for DockerBackend {
    fn name(&self) -> &'static str {
        if self.is_podman {
            "podman"
        } else {
            "docker"
        }
    }

    async fn connect(&mut self) -> Result<(), RuntimeError> {
        let client = if let Some(ref path) = self.socket_path {
            Docker::connect_with_socket(path, 120, bollard::API_DEFAULT_VERSION)
                .map_err(|e| RuntimeError::Connection(format!("socket {path}: {e}")))?
        } else if self.is_podman {
            // Podman default socket paths
            #[cfg(unix)]
            {
                let uid = unsafe { libc::getuid() };
                let user_socket = format!("/run/user/{uid}/podman/podman.sock");
                if std::path::Path::new(&user_socket).exists() {
                    Docker::connect_with_socket(&user_socket, 120, bollard::API_DEFAULT_VERSION)
                        .map_err(|e| RuntimeError::Connection(format!("podman: {e}")))?
                } else {
                    Docker::connect_with_socket(
                        "/run/podman/podman.sock",
                        120,
                        bollard::API_DEFAULT_VERSION,
                    )
                    .map_err(|e| RuntimeError::Connection(format!("podman: {e}")))?
                }
            }
            #[cfg(not(unix))]
            {
                Docker::connect_with_local_defaults()
                    .map_err(|e| RuntimeError::Connection(format!("podman: {e}")))?
            }
        } else {
            Docker::connect_with_local_defaults()
                .map_err(|e| RuntimeError::Connection(format!("docker: {e}")))?
        };

        // Verify connectivity
        client
            .ping()
            .await
            .map_err(|e| RuntimeError::Connection(format!("ping failed: {e}")))?;

        let version = client
            .version()
            .await
            .map_err(|e| RuntimeError::Connection(format!("version check: {e}")))?;

        tracing::info!(
            backend = self.name(),
            api_version = ?version.api_version,
            "Connected to runtime"
        );

        self.client = Some(client);
        Ok(())
    }

    async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
        let client = self.client()?;

        let opts = ListContainersOptions {
            all: false, // only running containers
            ..Default::default()
        };

        let containers = client
            .list_containers(Some(opts))
            .await
            .map_err(|e| RuntimeError::Internal(format!("list containers: {e}")))?;

        let mut instances = Vec::with_capacity(containers.len());
        for container in &containers {
            if let Some(ref id) = container.id {
                match self.container_to_instance(client, id).await {
                    Ok(instance) => instances.push(instance),
                    Err(e) => {
                        tracing::warn!(id, error = %e, "Failed to inspect container, skipping");
                    }
                }
            }
        }

        if let Ok(mut known) = self.known_instances.lock() {
            *known = instances_by_id(&instances);
        }
        Ok(instances)
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<RuntimeEvent>,
        cancel: CancellationToken,
    ) -> Result<(), RuntimeError> {
        let client = self.client()?;
        let mut known = self
            .known_instances
            .lock()
            .map(|known| known.clone())
            .unwrap_or_default();
        let mut reconnect_attempt = 0_u32;
        let mut last_event_time = Utc::now().timestamp();
        let mut resume_since = None;
        loop {
            let event_filters =
                HashMap::from([("type".to_string(), vec!["container".to_string()])]);
            let opts = EventsOptions {
                since: resume_since.take(),
                filters: Some(event_filters),
                ..Default::default()
            };
            let mut stream = client.events(Some(opts));
            let disconnect_reason = loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        tracing::info!(backend = self.name(), "Watch cancelled");
                        return Ok(());
                    }
                    event = stream.next() => match event {
                        Some(Ok(event)) => {
                            if let Some(observed) = event.time {
                                last_event_time = last_event_time.max(observed);
                            }
                            match self.normalize_docker_event(client, &event).await {
                                Ok(Some(event)) => {
                                    if let Some(event) = apply_event_to_snapshot(&mut known, event) {
                                        if tx.send(event).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    tracing::warn!(%error, "Error handling Docker event");
                                }
                            }
                        }
                        Some(Err(error)) => break error.to_string(),
                        None => break "Docker event stream ended".to_string(),
                    }
                }
            };

            if tx
                .send(RuntimeEvent::BackendDisconnected {
                    backend: self.name().to_string(),
                    reason: disconnect_reason.clone(),
                })
                .await
                .is_err()
            {
                return Ok(());
            }
            tracing::warn!(
                backend = self.name(),
                reason = %disconnect_reason,
                "Runtime event stream disconnected; preserving inventory while reconnecting"
            );

            loop {
                let delay = reconnect_delay(reconnect_attempt);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(delay) => {}
                }
                reconnect_attempt = reconnect_attempt.saturating_add(1);

                if let Err(error) = client.ping().await {
                    tracing::debug!(
                        backend = self.name(),
                        attempt = reconnect_attempt,
                        %error,
                        "Runtime API is still unavailable"
                    );
                    continue;
                }
                let current = match self.list_instances().await {
                    Ok(instances) => instances,
                    Err(error) => {
                        tracing::debug!(
                            backend = self.name(),
                            attempt = reconnect_attempt,
                            %error,
                            "Runtime inventory reconciliation is not ready"
                        );
                        continue;
                    }
                };

                let (next_known, events) = reconciliation_events(&known, current);
                for event in events {
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                if tx
                    .send(RuntimeEvent::BackendReconnected {
                        backend: self.name().to_string(),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                known = next_known;
                reconnect_attempt = 0;
                // Ask Docker to replay from the last event observed before the
                // disconnect. Reconciliation establishes current truth; replay
                // closes the list→new-stream race and normal ingest is idempotent.
                resume_since = Some(replay_cursor(last_event_time));
                tracing::info!(
                    backend = self.name(),
                    instances = known.len(),
                    "Runtime event stream reconnected after exact inventory reconciliation"
                );
                break;
            }
        }
    }
}

impl DockerBackend {
    async fn normalize_docker_event(
        &self,
        client: &Docker,
        event: &bollard::models::EventMessage,
    ) -> Result<Option<RuntimeEvent>, RuntimeError> {
        let action = event.action.as_deref().unwrap_or("");
        let actor = event.actor.as_ref();
        let id = actor.and_then(|a| a.id.as_deref()).unwrap_or("");

        if id.is_empty() {
            return Ok(None);
        }

        match action {
            "start" => match self.container_to_instance(client, id).await {
                Ok(instance) => {
                    tracing::info!(
                        name = %instance.name,
                        ports = ?instance.ports.len(),
                        backend = self.name(),
                        "Instance started"
                    );
                    Ok(Some(RuntimeEvent::Started(instance)))
                }
                Err(e) => {
                    tracing::warn!(id, error = %e, "Failed to inspect started container");
                    Ok(None)
                }
            },
            "die" | "stop" | "kill" | "destroy" => {
                let name = actor
                    .and_then(|a| a.attributes.as_ref())
                    .and_then(|attrs| attrs.get("name"))
                    .cloned()
                    .unwrap_or_else(|| id.to_string());

                tracing::info!(
                    name = %name,
                    action,
                    backend = self.name(),
                    "Instance stopped"
                );
                Ok(Some(RuntimeEvent::Stopped {
                    id: id.to_string(),
                    name,
                }))
            }
            // Ignore other events (create, pause, unpause, etc.)
            _ => Ok(None),
        }
    }
}

const RECONNECT_MIN_DELAY: Duration = Duration::from_millis(250);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(5);

fn reconnect_delay(attempt: u32) -> Duration {
    let multiplier = 1_u32.checked_shl(attempt.min(8)).unwrap_or(u32::MAX);
    RECONNECT_MIN_DELAY
        .saturating_mul(multiplier)
        .min(RECONNECT_MAX_DELAY)
}

fn replay_cursor(last_event_time: i64) -> String {
    last_event_time.saturating_sub(1).to_string()
}

fn instances_by_id(instances: &[Instance]) -> HashMap<String, Instance> {
    instances
        .iter()
        .map(|instance| (instance.id.clone(), instance.clone()))
        .collect()
}

/// Apply one observed lifecycle fact to the backend snapshot and return only
/// the material normalized delta. This suppresses duplicate Docker events and
/// inclusive cursor replay without spreading idempotency policy downstream.
fn apply_event_to_snapshot(
    known: &mut HashMap<String, Instance>,
    event: RuntimeEvent,
) -> Option<RuntimeEvent> {
    match event {
        RuntimeEvent::Started(instance) | RuntimeEvent::Updated(instance) => {
            let normalized = match known.get(&instance.id) {
                Some(prior) if prior.has_same_operational_facts(&instance) => None,
                Some(_) => Some(RuntimeEvent::Updated(instance.clone())),
                None => Some(RuntimeEvent::Started(instance.clone())),
            };
            known.insert(instance.id.clone(), instance);
            normalized
        }
        RuntimeEvent::Stopped { id, name } => known
            .remove(&id)
            .map(|_| RuntimeEvent::Stopped { id, name }),
        RuntimeEvent::BackendDisconnected { backend, reason } => {
            Some(RuntimeEvent::BackendDisconnected { backend, reason })
        }
        RuntimeEvent::BackendReconnected { backend } => {
            Some(RuntimeEvent::BackendReconnected { backend })
        }
    }
}

/// Diff the last observed inventory against a reconnect snapshot. Every event
/// still flows through RuntimeState::ingest; this helper only translates the
/// backend's point-in-time truth into normalized lifecycle facts.
fn reconciliation_events(
    previous: &HashMap<String, Instance>,
    mut current: Vec<Instance>,
) -> (HashMap<String, Instance>, Vec<RuntimeEvent>) {
    current.sort_by(|left, right| left.id.cmp(&right.id));
    let next = instances_by_id(&current);
    let mut stopped: Vec<_> = previous
        .iter()
        .filter(|(id, _)| !next.contains_key(*id))
        .map(|(id, instance)| RuntimeEvent::Stopped {
            id: id.clone(),
            name: instance.name.clone(),
        })
        .collect();
    stopped.sort_by(|left, right| match (left, right) {
        (RuntimeEvent::Stopped { id: left, .. }, RuntimeEvent::Stopped { id: right, .. }) => {
            left.cmp(right)
        }
        _ => std::cmp::Ordering::Equal,
    });

    let mut events = stopped;
    events.extend(
        current
            .into_iter()
            .filter_map(|instance| match previous.get(&instance.id) {
                Some(prior) if prior.has_same_operational_facts(&instance) => None,
                Some(_) => Some(RuntimeEvent::Updated(instance)),
                None => Some(RuntimeEvent::Started(instance)),
            }),
    );
    (next, events)
}

/// Extract host-side port mappings from a container inspect result.
fn extract_port_mappings(info: &bollard::models::ContainerInspectResponse) -> Vec<PortMapping> {
    let mut mappings = Vec::new();

    let network_ports = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref());

    if let Some(ports) = network_ports {
        for (port_spec, bindings) in ports {
            let Some(bindings) = bindings else { continue };

            // Parse "80/tcp" or "53/udp"
            let (container_port, protocol) = parse_port_spec(port_spec);

            for binding in bindings {
                let host_port = binding
                    .host_port
                    .as_deref()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(0);

                if host_port == 0 {
                    continue;
                }

                let host_ip = binding.host_ip.as_deref().unwrap_or("0.0.0.0").to_string();

                mappings.push(PortMapping {
                    host_port,
                    container_port,
                    protocol,
                    host_ip,
                });
            }
        }
    }

    mappings.sort();
    mappings
}

/// Parse a Docker port specification like "80/tcp" or "53/udp".
fn parse_port_spec(spec: &str) -> (u16, PortProtocol) {
    let parts: Vec<&str> = spec.split('/').collect();
    let port = parts
        .first()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let protocol = match parts.get(1) {
        Some(&"udp") => PortProtocol::Udp,
        _ => PortProtocol::Tcp,
    };
    (port, protocol)
}

/// Extract IP addresses from a container's network settings.
fn extract_ips(info: &bollard::models::ContainerInspectResponse) -> Vec<String> {
    let mut ips = Vec::new();

    if let Some(ns) = &info.network_settings {
        // Per-network IPs (bollard 0.20 removed top-level ip_address; use networks map)
        if let Some(ref networks) = ns.networks {
            for network in networks.values() {
                if let Some(ref ip) = network.ip_address {
                    if !ip.is_empty() && !ips.contains(ip) {
                        ips.push(ip.clone());
                    }
                }
                if let Some(ref ip6) = network.global_ipv6_address {
                    if !ip6.is_empty() && !ips.contains(ip6) {
                        ips.push(ip6.clone());
                    }
                }
            }
        }
    }

    ips.sort();
    ips
}

/// Check if a Docker-compatible socket is available.
pub fn is_docker_available() -> bool {
    #[cfg(unix)]
    {
        std::path::Path::new("/var/run/docker.sock").exists()
    }
    #[cfg(windows)]
    {
        // Check for Docker Desktop named pipe
        // We can't stat named pipes on Windows, so try to connect
        std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Check if Podman is available.
pub fn is_podman_available() -> bool {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let user_socket = format!("/run/user/{uid}/podman/podman.sock");
        std::path::Path::new(&user_socket).exists()
            || std::path::Path::new("/run/podman/podman.sock").exists()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(id: &str, name: &str) -> Instance {
        Instance {
            id: id.into(),
            name: name.into(),
            ports: Vec::new(),
            ips: Vec::new(),
            metadata: KoiMetadata::default(),
            backend: "docker".into(),
            state: InstanceState::Running,
            discovered_at: Utc::now(),
            image: None,
        }
    }

    #[test]
    fn parse_tcp_port_spec() {
        let (port, proto) = parse_port_spec("80/tcp");
        assert_eq!(port, 80);
        assert_eq!(proto, PortProtocol::Tcp);
    }

    #[test]
    fn parse_udp_port_spec() {
        let (port, proto) = parse_port_spec("53/udp");
        assert_eq!(port, 53);
        assert_eq!(proto, PortProtocol::Udp);
    }

    #[test]
    fn parse_bare_port_defaults_to_tcp() {
        let (port, proto) = parse_port_spec("443");
        assert_eq!(port, 443);
        assert_eq!(proto, PortProtocol::Tcp);
    }

    #[test]
    fn docker_backend_name() {
        let docker = DockerBackend::new();
        assert_eq!(docker.name(), "docker");

        let podman = DockerBackend::podman();
        assert_eq!(podman.name(), "podman");
    }

    #[test]
    fn reconnect_reconciliation_emits_exact_stops_updates_and_starts() {
        let previous = HashMap::from([
            ("gone".to_string(), instance("gone", "old-service")),
            ("same".to_string(), instance("same", "existing-service")),
            (
                "unchanged".to_string(),
                instance("unchanged", "stable-service"),
            ),
        ]);
        let (next, events) = reconciliation_events(
            &previous,
            vec![
                instance("unchanged", "stable-service"),
                instance("new", "new-service"),
                instance("same", "renamed"),
            ],
        );

        assert_eq!(next.len(), 3);
        assert_eq!(
            next.get("same").map(|item| item.name.as_str()),
            Some("renamed")
        );
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0],
            RuntimeEvent::Stopped { id, name }
                if id == "gone" && name == "old-service"
        ));
        assert!(matches!(
            &events[1],
            RuntimeEvent::Started(instance) if instance.id == "new"
        ));
        assert!(matches!(
            &events[2],
            RuntimeEvent::Updated(instance)
                if instance.id == "same" && instance.name == "renamed"
        ));
    }

    #[test]
    fn reconnect_reconciliation_ignores_observation_time_for_unchanged_instances() {
        let prior = instance("same", "stable-service");
        let mut relisted = prior.clone();
        relisted.discovered_at = prior.discovered_at + chrono::Duration::seconds(30);

        let (next, events) =
            reconciliation_events(&HashMap::from([(prior.id.clone(), prior)]), vec![relisted]);

        assert_eq!(next.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn snapshot_ingest_suppresses_replay_and_emits_only_material_deltas() {
        let prior = instance("same", "stable-service");
        let mut known = HashMap::from([(prior.id.clone(), prior.clone())]);
        let mut replayed = prior;
        replayed.discovered_at += chrono::Duration::seconds(30);

        assert!(apply_event_to_snapshot(&mut known, RuntimeEvent::Started(replayed)).is_none());

        let renamed = instance("same", "renamed-service");
        assert!(matches!(
            apply_event_to_snapshot(&mut known, RuntimeEvent::Started(renamed)),
            Some(RuntimeEvent::Updated(instance)) if instance.name == "renamed-service"
        ));
        assert!(matches!(
            apply_event_to_snapshot(
                &mut known,
                RuntimeEvent::Stopped {
                    id: "same".into(),
                    name: "renamed-service".into(),
                },
            ),
            Some(RuntimeEvent::Stopped { .. })
        ));
        assert!(apply_event_to_snapshot(
            &mut known,
            RuntimeEvent::Stopped {
                id: "same".into(),
                name: "renamed-service".into(),
            },
        )
        .is_none());
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(0), Duration::from_millis(250));
        assert_eq!(reconnect_delay(1), Duration::from_millis(500));
        assert_eq!(reconnect_delay(5), RECONNECT_MAX_DELAY);
        assert_eq!(reconnect_delay(u32::MAX), RECONNECT_MAX_DELAY);
    }

    #[test]
    fn reconnect_replay_cursor_is_inclusive_without_underflow() {
        assert_eq!(replay_cursor(1_784_522_000), "1784521999");
        assert_eq!(replay_cursor(i64::MIN), i64::MIN.to_string());
    }
}
