//! Standalone W5 diagnostic: raw mdns-sd meta-query browse on this machine.
//! Isolates mdns-sd/Windows from all koi layers. Prints every event.

use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;

const META_QUERY: &str = "_services._dns-sd._udp.local.";

fn main() {
    let mdns = ServiceDaemon::new().expect("mdns daemon");
    let receiver = mdns.browse(META_QUERY).expect("meta browse");
    println!("browsing {META_QUERY} for 15s...");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut found = 0;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => match event {
                ServiceEvent::ServiceFound(ty, fullname) => {
                    found += 1;
                    println!("ServiceFound: ty={ty} fullname={fullname}");
                }
                ServiceEvent::SearchStarted(ty) => println!("SearchStarted: {ty}"),
                ServiceEvent::SearchStopped(ty) => println!("SearchStopped: {ty}"),
                other => println!("other: {other:?}"),
            },
            Err(e) => {
                println!("recv error: {e}");
                break;
            }
        }
    }
    println!("total ServiceFound: {found}");
    let _ = mdns.stop_browse(META_QUERY);
}
