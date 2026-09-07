//! Pure Home projection and browser destinations. No transport or stored UI state.
use koi_common::service::{
    AvailableAction, CatalogSnapshot, DeviceId, EndpointId, NetworkClassification, Service,
    ServiceCondition, ServiceId, ServiceKind,
};
use url::{Host, Url};

const ATTENTION_LIMIT: usize = 5;

#[derive(Default)]
pub struct HomeQuery<'a> {
    pub search: &'a str,
    pub selected: Option<&'a ServiceId>,
    pub favorites_only: bool,
    pub peer: Option<&'a DeviceId>,
}

/// Bounded, adapter-independent presentation intent, never catalog/domain state.
#[derive(Default, Debug)]
pub struct HomeRequest {
    pub search: String,
    pub selected: Option<ServiceId>,
    pub favorites_only: bool,
    pub peer: Option<DeviceId>,
}

impl HomeRequest {
    pub fn parse(query: &str) -> Result<Self, &'static str> {
        if query.len() > 4096 {
            return Err("Home query is too long");
        }
        let mut request = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if !seen.insert(key.to_string()) {
                return Err("Duplicate Home query field");
            }
            match key.as_ref() {
                "search" => request.search = value.into_owned(),
                "selected" => {
                    request.selected =
                        Some(ServiceId::new(value.into_owned()).map_err(|_| "Invalid selection")?);
                }
                "peer" => {
                    request.peer =
                        Some(DeviceId::new(value.into_owned()).map_err(|_| "Invalid peer")?)
                }
                "favorites" if value == "1" => request.favorites_only = true,
                _ => return Err("Unknown Home query field"),
            }
        }
        Ok(request)
    }

    pub fn query(&self) -> HomeQuery<'_> {
        HomeQuery {
            search: &self.search,
            selected: self.selected.as_ref(),
            favorites_only: self.favorites_only,
            peer: self.peer.as_ref(),
        }
    }
}

impl HomeQuery<'_> {
    pub fn href(&self, selected: Option<&ServiceId>) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("search", self.search);
        if let Some(peer) = self.peer {
            query.append_pair("peer", peer.as_str());
        }
        if self.favorites_only {
            query.append_pair("favorites", "1");
        }
        if let Some(id) = selected {
            query.append_pair("selected", id.as_str());
        }
        format!(
            "?{}#{}",
            query.finish(),
            if selected.is_some() {
                "service-details"
            } else {
                "home"
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyState {
    NoDiscoveries,
    NoFavorites,
    NoMatches,
}

/// Borrow one coherent snapshot. Selection survives filtering/reordering, but a
/// missing identity is explicit; never silently select the next row in its place.
pub struct HomeProjection<'a> {
    pub favorites: Vec<&'a Service>,
    pub services: Vec<&'a Service>,
    pub selected: Option<&'a Service>,
    pub selection_missing: bool,
    pub attention: Vec<&'a Service>,
    pub attention_total: usize,
    pub empty: Option<EmptyState>,
}

pub fn project<'a>(snapshot: &'a CatalogSnapshot, query: &HomeQuery<'_>) -> HomeProjection<'a> {
    let words: Vec<_> = query
        .search
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let mut ordered: Vec<_> = snapshot.services.iter().collect();
    ordered.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    let selected = query
        .selected
        .and_then(|id| ordered.iter().copied().find(|service| service.id == *id));
    let mut attention: Vec<_> = ordered
        .iter()
        .copied()
        .filter(|service| {
            matches!(
                service.condition,
                ServiceCondition::NotResponding
                    | ServiceCondition::Stale
                    | ServiceCondition::Ambiguous
            ) || (service.favorite && service.condition == ServiceCondition::Absent)
        })
        .collect();
    let attention_total = attention.len();
    attention.truncate(ATTENTION_LIMIT);
    let matching: Vec<_> = ordered
        .iter()
        .copied()
        .filter(|service| {
            (!query.favorites_only || service.favorite) && matches_search(snapshot, service, &words)
        })
        .collect();
    let empty = if !matching.is_empty() {
        None
    } else if snapshot.services.is_empty() {
        Some(EmptyState::NoDiscoveries)
    } else if query.favorites_only && !snapshot.services.iter().any(|service| service.favorite) {
        Some(EmptyState::NoFavorites)
    } else {
        Some(EmptyState::NoMatches)
    };
    let (favorites, services) = matching.into_iter().partition(|service| service.favorite);
    HomeProjection {
        favorites,
        services,
        selected,
        selection_missing: query.selected.is_some() && selected.is_none(),
        attention,
        attention_total,
        empty,
    }
}

fn matches_search(snapshot: &CatalogSnapshot, service: &Service, words: &[String]) -> bool {
    if words.is_empty() {
        return true;
    }
    let mut fields = vec![service.display_name.as_str(), category(&service.kind)];
    fields.extend(service.alias.as_deref());
    fields.extend(
        service
            .endpoints
            .iter()
            .map(|endpoint| endpoint.host.as_str()),
    );
    if let Some(last) = &service.last_known {
        fields.extend(last.device_name.as_deref());
    }
    if let Some(device) = snapshot
        .devices
        .iter()
        .find(|device| device.id == service.device_id)
    {
        fields.extend(device.names.iter().map(|name| name.value.as_str()));
        fields.extend(
            device
                .addresses
                .iter()
                .map(|address| address.address.as_str()),
        );
    }
    let fields: Vec<_> = fields.into_iter().map(str::to_lowercase).collect();
    words
        .iter()
        .all(|word| fields.iter().any(|field| field.contains(word)))
}

pub fn category(kind: &ServiceKind) -> &str {
    match kind {
        ServiceKind::Web => "Web",
        ServiceKind::Api => "API",
        ServiceKind::Printer => "Printer",
        ServiceKind::Database => "Database",
        ServiceKind::Runtime => "Runtime",
        ServiceKind::Proxy => "Proxy",
        ServiceKind::Other(value) => value,
    }
}

/// Parsed HTTP(S), with neither URL credentials nor ambiguous authority syntax.
/// This proves URL shape only, never reachability, server identity or TLS trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDestination(Url);

impl BrowserDestination {
    pub fn parse(value: &str) -> Option<Self> {
        if value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
        {
            return None;
        }
        // Url::parse intentionally repairs forms such as http:host. At an Open
        // boundary require an explicit authority, not a parser's repair guess.
        let (scheme, rest) = value.split_once("://")?;
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return None;
        }
        let authority = rest.split(['/', '?', '#']).next()?;
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        let url = Url::parse(value).ok()?;
        if !url.username().is_empty() || url.password().is_some() || url.port() == Some(0) {
            return None;
        }
        match url.host()? {
            Host::Ipv4(ip) if ip.is_unspecified() => return None,
            Host::Ipv6(ip) if ip.is_unspecified() => return None,
            _ => {}
        }
        Some(Self(url))
    }

    /// Narrow the catalog's permission; never infer HTTP from a port, name or TXT.
    pub fn for_service(service: &Service, endpoint_id: &EndpointId) -> Option<Self> {
        if !service.available_actions.contains(&AvailableAction::Open)
            || service.kind == ServiceKind::Api
            || matches!(
                service.condition,
                ServiceCondition::Absent | ServiceCondition::Stale | ServiceCondition::Ambiguous
            )
        {
            return None;
        }
        let endpoint = service
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == *endpoint_id)?;
        if !endpoint.browser_usable
            || !matches!(endpoint.scheme.as_str(), "http" | "https")
            || endpoint.port == 0
            || endpoint.network_scope.as_ref().is_some_and(|scope| {
                scope.classification == NetworkClassification::LinkLocal
                    && scope.interface.is_none()
            })
        {
            return None;
        }
        // Hosts arrive as evidence, not URL authority strings. Reject userinfo,
        // appended paths/ports, escapes and scoped IPv6 unsupported by browsers.
        let host = &endpoint.host;
        if host.is_empty()
            || host
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || "@/?#\\%".contains(c))
        {
            return None;
        }
        let host = if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            format!("[{ip}]")
        } else {
            host.clone()
        };
        let host = Host::parse(&host).ok()?;
        let mut destination = Self::parse(&format!(
            "{}://{}:{}/",
            endpoint.scheme, host, endpoint.port
        ))?;
        if let Some(path) = endpoint.path.as_deref().filter(|path| !path.is_empty()) {
            if !path.starts_with('/')
                || path.starts_with("//")
                || path.chars().any(|c| c.is_control() || c == '\\')
            {
                return None;
            }
            let (path_query, fragment) = path
                .split_once('#')
                .map_or((path, None), |(p, f)| (p, Some(f)));
            let (path, query) = path_query
                .split_once('?')
                .map_or((path_query, None), |(p, q)| (p, Some(q)));
            destination.0.set_path(path);
            destination.0.set_query(query);
            destination.0.set_fragment(fragment);
        }
        Some(destination)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
