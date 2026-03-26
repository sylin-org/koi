//! Integration tests for the Docker backend.
//!
//! These tests require a running Docker daemon. They are marked `#[ignore]`
//! for CI and run manually or via `cargo test -- --ignored --test-threads=1`.
//!
//! Must run single-threaded: tests share Docker daemon state (containers,
//! event stream) and will interfere with each other under parallelism.

use std::time::Duration;

use koi_runtime::backend::RuntimeBackendKind;
use koi_runtime::instance::{InstanceState, PortProtocol};
use koi_runtime::RuntimeBackend;
use koi_runtime::{RuntimeConfig, RuntimeCore};
use tokio_util::sync::CancellationToken;

/// Helper: check if Docker is available before running tests.
async fn require_docker() -> bool {
    let mut backend = koi_runtime::docker::DockerBackend::new();
    backend.connect().await.is_ok()
}

#[tokio::test]
#[ignore] // requires running Docker daemon
async fn connect_to_docker_and_list_instances() {
    if !require_docker().await {
        eprintln!("Docker not available, skipping");
        return;
    }

    let mut backend = koi_runtime::docker::DockerBackend::new();
    backend.connect().await.expect("should connect to Docker");

    let instances = backend
        .list_instances()
        .await
        .expect("should list containers");

    println!("Found {} running container(s):", instances.len());
    for inst in &instances {
        println!(
            "  {} ({}): {} ports, state={:?}, image={:?}",
            inst.name,
            &inst.id[..12],
            inst.ports.len(),
            inst.state,
            inst.image.as_deref().unwrap_or("?")
        );
        for port in &inst.ports {
            println!(
                "    {}:{} -> {} ({:?})",
                port.host_ip, port.host_port, port.container_port, port.protocol
            );
        }
    }

    // We should find at least one running container
    assert!(
        !instances.is_empty(),
        "expected at least one running container"
    );

    // Every instance should be in Running state
    for inst in &instances {
        assert_eq!(inst.state, InstanceState::Running);
        assert!(!inst.name.is_empty());
        assert!(!inst.id.is_empty());
        assert_eq!(inst.backend, "docker");
    }
}

#[tokio::test]
#[ignore]
async fn port_mappings_are_extracted() {
    if !require_docker().await {
        eprintln!("Docker not available, skipping");
        return;
    }

    let mut backend = koi_runtime::docker::DockerBackend::new();
    backend.connect().await.unwrap();

    let instances = backend.list_instances().await.unwrap();

    // Find any container with published ports
    let with_ports: Vec<_> = instances.iter().filter(|i| !i.ports.is_empty()).collect();

    assert!(
        !with_ports.is_empty(),
        "expected at least one container with published ports"
    );

    for inst in with_ports {
        for port in &inst.ports {
            assert!(port.host_port > 0, "host port should be non-zero");
            assert!(port.container_port > 0, "container port should be non-zero");
            assert!(
                port.protocol == PortProtocol::Tcp || port.protocol == PortProtocol::Udp,
                "protocol should be tcp or udp"
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn runtime_core_start_watching_discovers_existing() {
    if !require_docker().await {
        eprintln!("Docker not available, skipping");
        return;
    }

    let config = RuntimeConfig {
        backend_kind: RuntimeBackendKind::Docker,
        socket_path: None,
    };
    let core = RuntimeCore::new(config);
    let cancel = CancellationToken::new();

    core.start_watching(cancel.clone())
        .await
        .expect("should start watching");

    // Give the event processing a moment
    tokio::time::sleep(Duration::from_millis(500)).await;

    let status = core.status().await;
    assert!(status.active, "runtime should be active");
    assert_eq!(status.backend.as_deref(), Some("docker"));
    assert!(
        status.instance_count > 0,
        "should have discovered existing containers"
    );

    let instances = core.list_instances().await.unwrap();
    println!(
        "RuntimeCore tracked {} instance(s) via Docker",
        instances.len()
    );
    for inst in &instances {
        println!("  {} — {:?}", inst.name, inst.state);
    }

    cancel.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
#[ignore]
async fn lifecycle_watch_detects_start_and_stop() {
    if !require_docker().await {
        eprintln!("Docker not available, skipping");
        return;
    }

    let config = RuntimeConfig {
        backend_kind: RuntimeBackendKind::Docker,
        socket_path: None,
    };
    let core = RuntimeCore::new(config);
    let cancel = CancellationToken::new();
    let mut events = core.subscribe();

    // Clean up stale container from previous runs of THIS test
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", "koi-runtime-test"])
        .output()
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    core.start_watching(cancel.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let initial_count = core.list_instances().await.unwrap().len();

    // Start a test container
    println!("Starting test container...");
    let start_output = tokio::process::Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            "koi-runtime-test",
            "--label",
            "koi.type=_http._tcp",
            "--label",
            "koi.txt.version=1.0",
            "-p",
            "19876:80",
            "nginx:alpine",
        ])
        .output()
        .await
        .expect("docker run should succeed");

    assert!(
        start_output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&start_output.stderr)
    );

    // Wait for the Started event
    let started = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(event) = events.recv().await {
                if let koi_runtime::RuntimeEvent::Started(inst) = &event {
                    if inst.name.contains("koi-runtime-test") {
                        return inst.clone();
                    }
                }
            }
        }
    })
    .await
    .expect("should receive Started event within 10s");

    println!("Received Started event for: {}", started.name);
    assert_eq!(started.state, InstanceState::Running);
    assert_eq!(started.backend, "docker");

    // Verify port mapping
    let http_port = started.ports.iter().find(|p| p.container_port == 80);
    assert!(http_port.is_some(), "should have port 80 mapped");
    assert_eq!(http_port.unwrap().host_port, 19876);

    // Verify koi labels were parsed
    assert_eq!(started.metadata.service_type.as_deref(), Some("_http._tcp"));
    assert_eq!(
        started.metadata.txt.get("version").map(String::as_str),
        Some("1.0")
    );

    // Verify instance count increased
    let new_count = core.list_instances().await.unwrap().len();
    assert_eq!(new_count, initial_count + 1);

    // Stop the test container
    println!("Stopping test container...");
    let stop_output = tokio::process::Command::new("docker")
        .args(["rm", "-f", "koi-runtime-test"])
        .output()
        .await
        .expect("docker rm should succeed");
    assert!(stop_output.status.success());

    // Wait for the Stopped event
    let stopped = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(event) = events.recv().await {
                if let koi_runtime::RuntimeEvent::Stopped { name, .. } = &event {
                    if name.contains("koi-runtime-test") {
                        return name.clone();
                    }
                }
            }
        }
    })
    .await
    .expect("should receive Stopped event within 10s");

    println!("Received Stopped event for: {}", stopped);

    // Verify instance count decreased
    tokio::time::sleep(Duration::from_millis(200)).await;
    let final_count = core.list_instances().await.unwrap().len();
    assert_eq!(final_count, initial_count);

    cancel.cancel();
}

#[tokio::test]
#[ignore]
async fn heuristics_resolve_known_ports() {
    use koi_runtime::heuristics;

    // Verify against the actual containers running locally
    if !require_docker().await {
        return;
    }

    let mut backend = koi_runtime::docker::DockerBackend::new();
    backend.connect().await.unwrap();
    let instances = backend.list_instances().await.unwrap();

    for inst in &instances {
        for port in &inst.ports {
            let service_type = heuristics::resolve_service_type(
                port.host_port,
                port.protocol == PortProtocol::Udp,
                inst.metadata.service_type.as_deref(),
            );
            println!("  {}:{} → {}", inst.name, port.host_port, service_type);
            assert!(!service_type.is_empty());
        }
    }
}

#[tokio::test]
#[ignore]
async fn metadata_from_labels_round_trip() {
    if !require_docker().await {
        return;
    }

    // Start a container with koi labels
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", "koi-label-test"])
        .output()
        .await;

    let output = tokio::process::Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            "koi-label-test",
            "--label",
            "koi.enable=true",
            "--label",
            "koi.type=_mqtt._tcp",
            "--label",
            "koi.name=My MQTT Broker",
            "--label",
            "koi.dns.name=mqtt",
            "--label",
            "koi.txt.version=3.1.1",
            "--label",
            "koi.health.path=/health",
            "--label",
            "koi.health.kind=http",
            "--label",
            "koi.proxy.port=8883",
            "-p",
            "19877:1883",
            "nginx:alpine",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "docker run failed");

    // Give Docker a moment to register the container
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut backend = koi_runtime::docker::DockerBackend::new();
    backend.connect().await.unwrap();
    let instances = backend.list_instances().await.unwrap();

    let test_inst = instances
        .iter()
        .find(|i| i.name.contains("koi-label-test"))
        .expect("should find koi-label-test container");

    // Verify all labels were parsed
    assert_eq!(test_inst.metadata.enable, Some(true));
    assert_eq!(
        test_inst.metadata.service_type.as_deref(),
        Some("_mqtt._tcp")
    );
    assert_eq!(test_inst.metadata.name.as_deref(), Some("My MQTT Broker"));
    assert_eq!(test_inst.metadata.dns_name.as_deref(), Some("mqtt"));
    assert_eq!(
        test_inst.metadata.txt.get("version").map(String::as_str),
        Some("3.1.1")
    );
    assert_eq!(test_inst.metadata.health_path.as_deref(), Some("/health"));
    assert_eq!(test_inst.metadata.health_kind.as_deref(), Some("http"));
    assert_eq!(test_inst.metadata.proxy_port, Some(8883));

    // Verify port mapping
    let mqtt_port = test_inst.ports.iter().find(|p| p.container_port == 1883);
    assert!(mqtt_port.is_some());
    assert_eq!(mqtt_port.unwrap().host_port, 19877);

    // Cleanup
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", "koi-label-test"])
        .output()
        .await;
}
