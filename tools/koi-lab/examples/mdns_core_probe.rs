//! Layer-2 diagnostic: koi_mdns::MdnsCore meta-query on this machine.

use std::time::Duration;

#[tokio::main]
async fn main() {
    let core = koi_mdns::MdnsCore::new().await.expect("mdns core");
    let sub = core
        .subscribe_type("_services._dns-sd._udp.local.")
        .await
        .expect("meta subscribe");
    println!("subscribed; receiving 15s...");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut found = 0;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), sub.recv()).await {
            Ok(Ok(event)) => match &event {
                koi_mdns::MdnsEvent::Found(record) => {
                    found += 1;
                    println!("Found: name={}", record.name);
                }
                other => println!("other: {other:?}"),
            },
            Ok(Err(koi_mdns::BrowseRecvError::Closed)) => {
                println!("subscription closed");
                break;
            }
            Ok(Err(koi_mdns::BrowseRecvError::Lagged { dropped })) => {
                let snapshot = core.discovery_snapshot();
                println!(
                    "subscription lagged by {dropped}; authoritative snapshot revision={} records={}",
                    snapshot.revision,
                    snapshot.records.len()
                );
            }
            Err(_) => {}
        }
    }
    println!("total Found: {found}");
}
