//! Docker/Podman runtime backend.
//!
//! Connects to the Docker Engine API via the local socket
//! (Unix: `/var/run/docker.sock`, Windows: `//./pipe/docker_engine`).
//! Podman exposes a Docker-compatible API on a different socket path.

use std::collections::HashMap;

use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::system::EventsOptions;
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
        }
    }

    /// Create a Docker backend with a custom socket path.
    pub fn with_socket(path: String) -> Self {
        Self {
            client: None,
            socket_path: Some(path),
            is_podman: false,
        }
    }

    /// Create a Podman backend (Docker-compatible API, different defaults).
    pub fn podman() -> Self {
        Self {
            client: None,
            socket_path: None,
            is_podman: true,
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
            Some(bollard::secret::ContainerStateStatusEnum::RUNNING) => InstanceState::Running,
            Some(bollard::secret::ContainerStateStatusEnum::PAUSED) => InstanceState::Paused,
            Some(bollard::secret::ContainerStateStatusEnum::RESTARTING) => {
                InstanceState::Restarting
            }
            _ => InstanceState::Stopped,
        };

        let image = config.and_then(|c| c.image.clone());

        let koi_metadata = KoiMetadata::from_labels(&labels);

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

        let opts = ListContainersOptions::<String> {
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

        Ok(instances)
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<RuntimeEvent>,
        cancel: CancellationToken,
    ) -> Result<(), RuntimeError> {
        let client = self.client()?;

        let event_filters = HashMap::from([("type".to_string(), vec!["container".to_string()])]);
        let opts = EventsOptions::<String> {
            filters: event_filters,
            ..Default::default()
        };

        let mut stream = client.events(Some(opts));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!(backend = self.name(), "Watch cancelled");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = self.handle_docker_event(client, &tx, &ev).await {
                                tracing::warn!(error = %e, "Error handling Docker event");
                            }
                        }
                        Some(Err(e)) => {
                            let _ = tx.send(RuntimeEvent::BackendDisconnected {
                                backend: self.name().to_string(),
                                reason: e.to_string(),
                            }).await;
                            tracing::error!(error = %e, "Docker event stream error");
                            break;
                        }
                        None => {
                            tracing::info!("Docker event stream ended");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl DockerBackend {
    async fn handle_docker_event(
        &self,
        client: &Docker,
        tx: &mpsc::Sender<RuntimeEvent>,
        event: &bollard::secret::EventMessage,
    ) -> Result<(), RuntimeError> {
        let action = event.action.as_deref().unwrap_or("");
        let actor = event.actor.as_ref();
        let id = actor.and_then(|a| a.id.as_deref()).unwrap_or("");

        if id.is_empty() {
            return Ok(());
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
                    let _ = tx.send(RuntimeEvent::Started(instance)).await;
                }
                Err(e) => {
                    tracing::warn!(id, error = %e, "Failed to inspect started container");
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
                let _ = tx
                    .send(RuntimeEvent::Stopped {
                        id: id.to_string(),
                        name,
                    })
                    .await;
            }
            // Ignore other events (create, pause, unpause, etc.)
            _ => {}
        }

        Ok(())
    }
}

/// Extract host-side port mappings from a container inspect result.
fn extract_port_mappings(info: &bollard::secret::ContainerInspectResponse) -> Vec<PortMapping> {
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
fn extract_ips(info: &bollard::secret::ContainerInspectResponse) -> Vec<String> {
    let mut ips = Vec::new();

    if let Some(ns) = &info.network_settings {
        // Primary IP
        if let Some(ref ip) = ns.ip_address {
            if !ip.is_empty() && !ips.contains(ip) {
                ips.push(ip.clone());
            }
        }

        // Per-network IPs
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
}
