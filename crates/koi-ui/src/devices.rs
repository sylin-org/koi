//! Pure device and discovery-comparison projections over existing domain snapshots.
pub use koi_common::{integration::MdnsDiscoverySnapshot, service::DeviceId};
use koi_common::{service::*, types::ServiceRecord};
use std::collections::{BTreeMap, BTreeSet};

pub fn label(device: &Device) -> &str {
    device
        .names
        .first()
        .map_or("Unnamed device", |name| name.value.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: DeviceId,
    pub label: String,
    pub endpoint: String,
}

/// Only current, unambiguous Koi installations with an advertised MCP endpoint.
/// This is a discovery hint, never authenticated identity or proof of access.
pub fn peers(catalog: &CatalogSnapshot) -> Vec<Peer> {
    if catalog.local_device_id.is_none() {
        return Vec::new();
    }
    catalog
        .devices
        .iter()
        .filter_map(|device| {
            if catalog.local_device_id.as_ref() == Some(&device.id)
                || device.condition != DeviceCondition::Present
                || !matches!(device.koi_presence, KoiPresence::Identified { .. })
            {
                return None;
            }
            let endpoints: BTreeSet<String> = catalog
                .services
                .iter()
                .filter(|service| {
                    service.device_id == device.id
                        && matches!(
                            service.condition,
                            ServiceCondition::Found | ServiceCondition::Responding
                        )
                })
                .flat_map(|service| {
                    service.endpoints.iter().filter_map(|endpoint| {
                        let announced = service.observations.iter().any(|observation| {
                            observation.kind == ObservationKind::Mdns
                                && observation.state == ObservationState::Current
                                && observation.valid_until > catalog.generated_at
                                && endpoint.source_observation_ids.contains(&observation.id)
                                && observation.raw_reference.get("service_type").is_some_and(
                                    |kind| kind.eq_ignore_ascii_case("_mcp._tcp.local."),
                                )
                        });
                        if !announced
                            || !matches!(endpoint.scheme.as_str(), "http" | "https")
                            || endpoint.port == 0
                        {
                            return None;
                        }
                        let mut url = url::Url::parse("http://localhost/").ok()?;
                        url.set_scheme(&endpoint.scheme).ok()?;
                        url.set_host(Some(&endpoint.host)).ok()?;
                        url.set_port(Some(endpoint.port)).ok()?;
                        // A discovered peer cannot redirect this read to this computer.
                        match url.host()? {
                            url::Host::Ipv4(ip) if ip.is_loopback() || ip.is_unspecified() => {
                                return None
                            }
                            url::Host::Ipv6(ip) if ip.is_loopback() || ip.is_unspecified() => {
                                return None
                            }
                            url::Host::Domain(name)
                                if name.eq_ignore_ascii_case("localhost")
                                    || name.ends_with(".localhost") =>
                            {
                                return None
                            }
                            _ => {}
                        }
                        Some(url.as_str().trim_end_matches('/').to_string())
                    })
                })
                .collect();
            // Ambiguous alternatives require better catalog evidence, not guessing.
            (endpoints.len() == 1).then(|| Peer {
                id: device.id.clone(),
                label: label(device).into(),
                endpoint: endpoints.into_iter().next().unwrap(),
            })
        })
        .collect()
}

pub fn peer_href(id: &DeviceId) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("peer", id.as_str())
        .finish();
    format!("?{query}#comparison")
}

#[derive(Clone, Debug)]
pub struct Reading {
    /// Adapter-selected observer label; peer identity is advertised, not verified.
    pub observer: String,
    /// Receipt time on this computer, not a claim about the peer's clock.
    pub received_at: String,
    pub result: Result<MdnsDiscoverySnapshot, String>,
}

#[derive(Clone, Debug, Default)]
pub enum Comparison {
    Unsupported,
    #[default]
    NotRun,
    Comparing,
    Finished {
        local: Box<Reading>,
        peer: Box<Reading>,
    },
    Incomplete(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Difference {
    pub only_local: Vec<String>,
    pub only_peer: Vec<String>,
    pub changed: Vec<String>,
    pub same: usize,
    pub queries: BTreeSet<String>,
}

impl Difference {
    pub fn is_empty(&self) -> bool {
        self.only_local.is_empty() && self.only_peer.is_empty() && self.changed.is_empty()
    }
}

/// Compare equal query coverage only. Provider names and generations are local
/// implementation details; neither proves two observers share a physical link.
pub fn compare(
    local: &MdnsDiscoverySnapshot,
    peer: &MdnsDiscoverySnapshot,
) -> Result<Difference, &'static str> {
    fn coverage(snapshot: &MdnsDiscoverySnapshot) -> Result<BTreeSet<String>, &'static str> {
        if snapshot.sources.is_empty()
            || snapshot
                .sources
                .iter()
                .any(|source| !source.available || source.provider.is_none())
        {
            return Err("Discovery coverage is unavailable or not reported. Open discovery on both devices, then retry.");
        }
        if snapshot
            .sources
            .iter()
            .any(|source| !source.query.ends_with(".local."))
        {
            return Err("These snapshots do not declare compatible local-network query scopes.");
        }
        Ok(snapshot
            .sources
            .iter()
            .map(|source| source.query.to_ascii_lowercase())
            .collect())
    }
    let queries = coverage(local)?;
    if queries != coverage(peer)? {
        return Err("The devices are observing different query scopes. Open the same discovery views on both devices, let discovery settle, then retry.");
    }
    let left = records(local);
    let right = records(peer);
    let mut result = Difference {
        only_local: Vec::new(),
        only_peer: Vec::new(),
        changed: Vec::new(),
        same: 0,
        queries,
    };
    for (key, records) in &left {
        match right.get(key) {
            None => result.only_local.push(key.clone()),
            Some(other) if records != other => result.changed.push(key.clone()),
            Some(_) => result.same += 1,
        }
    }
    result.only_peer = right
        .keys()
        .filter(|key| !left.contains_key(*key))
        .cloned()
        .collect();
    Ok(result)
}

// Keep all endpoint/TXT variants. Comparing names alone conceals conflicting
// same-named advertisements and changed destinations.
type RecordValue = (
    Option<String>,
    Option<String>,
    Option<u16>,
    BTreeMap<String, String>,
);
fn records(snapshot: &MdnsDiscoverySnapshot) -> BTreeMap<String, BTreeSet<RecordValue>> {
    let mut result: BTreeMap<String, BTreeSet<RecordValue>> = BTreeMap::new();
    for ServiceRecord {
        name,
        service_type,
        host,
        ip,
        port,
        txt,
    } in &snapshot.records
    {
        let key = format!(
            "{} · {}",
            name.trim_end_matches('.').to_ascii_lowercase(),
            service_type.trim_end_matches('.').to_ascii_lowercase()
        );
        result.entry(key).or_default().insert((
            host.as_ref()
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase()),
            ip.clone(),
            *port,
            txt.clone().into_iter().collect(),
        ));
    }
    result
}
