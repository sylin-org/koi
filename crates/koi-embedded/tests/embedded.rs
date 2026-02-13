use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koi_config::state::DnsEntry;
use koi_embedded::{Builder, KoiEvent, ServiceMode};
use koi_proxy::ProxyEntry;

fn temp_data_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("koi-embedded-test-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn builder_defaults_build() {
    let koi = Builder::new().build();
    assert!(koi.is_ok());
}

#[tokio::test]
async fn dns_add_entry_emits_event() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = temp_data_dir();
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(true)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .build()?;
    let handle = koi.start().await?;

    let mut rx = handle.subscribe();
    let dns = handle.dns()?;

    let entry = DnsEntry {
        name: "test.lan".to_string(),
        ip: "127.0.0.1".to_string(),
        ttl: None,
    };
    dns.add_entry(entry)?;

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await??;
    match event {
        KoiEvent::DnsEntryUpdated { name, ip } => {
            assert_eq!(name, "test.lan");
            assert_eq!(ip, "127.0.0.1");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn dns_remove_entry_emits_event() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = temp_data_dir();
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(true)
        .health(false)
        .certmesh(false)
        .proxy(false)
        .build()?;
    let handle = koi.start().await?;
    let dns = handle.dns()?;
    let mut rx = handle.subscribe();

    // Add an entry first, then drain its event.
    let entry = DnsEntry {
        name: "remove-me.lan".to_string(),
        ip: "10.0.0.1".to_string(),
        ttl: None,
    };
    dns.add_entry(entry)?;
    let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await??;

    dns.remove_entry("remove-me.lan")?;

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await??;
    match event {
        KoiEvent::DnsEntryRemoved { name } => {
            assert_eq!(name, "remove-me.lan");
        }
        other => panic!("expected DnsEntryRemoved, got {other:?}"),
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn proxy_upsert_and_remove_emit_events() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = temp_data_dir();
    let koi = Builder::new()
        .data_dir(&data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .certmesh(false)
        .proxy(true)
        .build()?;
    let handle = koi.start().await?;

    let mut rx = handle.subscribe();
    let proxy = handle.proxy()?;

    // upsert
    let entry = ProxyEntry {
        name: "test-proxy".to_string(),
        listen_port: 19090,
        backend: "http://127.0.0.1:18080".to_string(),
        allow_remote: false,
    };
    proxy.upsert(entry).await?;

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await??;
    match event {
        KoiEvent::ProxyEntryUpdated { entry } => {
            assert_eq!(entry.name, "test-proxy");
            assert_eq!(entry.listen_port, 19090);
            assert_eq!(entry.backend, "http://127.0.0.1:18080");
        }
        other => panic!("expected ProxyEntryUpdated, got {other:?}"),
    }

    // remove
    proxy.remove("test-proxy").await?;

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await??;
    match event {
        KoiEvent::ProxyEntryRemoved { name } => {
            assert_eq!(name, "test-proxy");
        }
        other => panic!("expected ProxyEntryRemoved, got {other:?}"),
    }

    handle.shutdown().await?;
    Ok(())
}
