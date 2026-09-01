//! Windows control-plane probe: publish through the live catalog and print
//! the structured control-plane status every second, so route transitions,
//! hysteresis, and recovery can be observed (and stalled states diagnosed)
//! while the platform mDNS facilities are manipulated underneath the process.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hold_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(120);

    let core = koi_compose::mdns::build_core(tokio_util::sync::CancellationToken::new()).await?;
    println!("armed: {:?}", core.control_plane_status().routes);

    let payload = koi_mdns::protocol::RegisterPayload {
        name: "Koi CP Probe".to_string(),
        service_type: "_koi-cp-probe._tcp.local.".to_string(),
        port: 43211,
        ip: None,
        lease_secs: None,
        txt: std::collections::HashMap::from([(
            "source".to_string(),
            "control-plane-probe".to_string(),
        )]),
    };
    let registration = core.register(payload).await?;
    println!("registered: {}", registration.id);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(hold_secs);
    let mut last_generation = 0_u64;
    while tokio::time::Instant::now() < deadline {
        let status = core.control_plane_status();
        if status.generation != last_generation {
            last_generation = status.generation;
            println!(
                "generation {} state={} routes={:?} publications={:?} transition={:?}",
                status.generation, status.state, status.routes, status.publications, status.transition
            );
            for provider in &status.providers {
                println!(
                    "  {}: availability={} session={:?} running={} detail={}",
                    provider.name, provider.availability, provider.session, provider.running, provider.detail
                );
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    core.unregister(&registration.id).await?;
    println!("withdrawn; shutting down");
    core.shutdown().await?;
    Ok(())
}
