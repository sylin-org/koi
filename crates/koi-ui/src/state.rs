//! Ephemeral presentation intent. The catalog remains the sole inventory owner.
use koi_common::service::{CatalogSnapshot, DeviceId, Service, ServiceCondition, ServiceId};
use url::form_urlencoded;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Destination {
    #[default]
    Services,
    Mdns,
    PrivateSpace,
    Settings,
    About,
}

impl Destination {
    pub fn key(self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::Mdns => "mdns",
            Self::PrivateSpace => "private-space",
            Self::Settings => "settings",
            Self::About => "about",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Services => "Services",
            Self::Mdns => "mDNS",
            Self::PrivateSpace => "Certmesh",
            Self::Settings => "Settings",
            Self::About => "About",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServiceFilter {
    #[default]
    All,
    Responding,
    Attention,
    Absent,
}

impl ServiceFilter {
    pub fn key(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Responding => "responding",
            Self::Attention => "attention",
            Self::Absent => "absent",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All states",
            Self::Responding => "Responding",
            Self::Attention => "Needs attention",
            Self::Absent => "Absent",
        }
    }
    fn matches(self, condition: ServiceCondition) -> bool {
        match self {
            Self::All => true,
            Self::Responding => condition == ServiceCondition::Responding,
            Self::Attention => matches!(
                condition,
                ServiceCondition::NotResponding
                    | ServiceCondition::Stale
                    | ServiceCondition::Ambiguous
            ),
            Self::Absent => condition == ServiceCondition::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServiceSort {
    #[default]
    Name,
    Host,
    State,
}

impl ServiceSort {
    pub fn key(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Host => "host",
            Self::State => "state",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name A–Z",
            Self::Host => "Host A–Z",
            Self::State => "State A–Z",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UiState {
    pub destination: Destination,
    pub mdns_filter: String,
    pub mdns_type: String,
    pub query: String,
    pub host: Option<DeviceId>,
    pub filter: ServiceFilter,
    pub sort: ServiceSort,
    pub selected: Option<ServiceId>,
}

impl UiState {
    /// Both transports use this bounded allowlist. Credentials and arbitrary targets
    /// are deliberately not presentation parameters.
    pub fn parse_query(query: &str) -> Result<Self, &'static str> {
        if query.len() > 4096 {
            return Err("View query is too long");
        }
        let bytes = query.as_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            if *byte == b'%'
                && (i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit())
            {
                return Err("Invalid query encoding");
            }
        }
        let mut result = Self::default();
        let mut legacy_services_view = None;
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in form_urlencoded::parse(bytes) {
            if !seen.insert(key.to_string()) {
                return Err("Duplicate view parameter");
            }
            if value.len() > 512
                || value.chars().any(char::is_control)
                || value.contains('\u{fffd}')
            {
                return Err("Invalid view parameter");
            }
            match key.as_ref() {
                "services_view" => {
                    legacy_services_view = Some(match value.as_ref() {
                        "catalog" => false,
                        "mdns" => true,
                        _ => return Err("Unknown Services view"),
                    })
                }
                "mdns_filter" if value.len() <= 256 => result.mdns_filter = value.into_owned(),
                "mdns_type" if value.len() <= 256 => result.mdns_type = value.into_owned(),
                "tab" => {
                    result.destination = match value.as_ref() {
                        "services" => Destination::Services,
                        "mdns" => Destination::Mdns,
                        "private-space" => Destination::PrivateSpace,
                        "settings" => Destination::Settings,
                        "about" => Destination::About,
                        _ => return Err("Unknown destination"),
                    }
                }
                "q" if value.len() <= 256 => result.query = value.into_owned(),
                "host" => {
                    result.host = if value.is_empty() {
                        None
                    } else {
                        Some(
                            DeviceId::new(value.into_owned())
                                .map_err(|_| "Invalid host identity")?,
                        )
                    }
                }
                "state" => {
                    result.filter = match value.as_ref() {
                        "all" => ServiceFilter::All,
                        "responding" => ServiceFilter::Responding,
                        "attention" => ServiceFilter::Attention,
                        "absent" => ServiceFilter::Absent,
                        _ => return Err("Unknown state filter"),
                    }
                }
                "sort" => {
                    result.sort = match value.as_ref() {
                        "name" => ServiceSort::Name,
                        "host" => ServiceSort::Host,
                        "state" => ServiceSort::State,
                        _ => return Err("Unknown sort order"),
                    }
                }
                "selected" => {
                    result.selected = if value.is_empty() {
                        None
                    } else {
                        Some(
                            ServiceId::new(value.into_owned())
                                .map_err(|_| "Invalid service identity")?,
                        )
                    }
                }
                _ => return Err("Unknown view parameter"),
            }
        }
        // Links from the former Services subview remain valid, but all newly
        // rendered links use the first-class mDNS destination.
        if result.destination == Destination::Services && legacy_services_view == Some(true) {
            result.destination = Destination::Mdns;
        }
        Ok(result)
    }

    pub fn query_string(&self) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("tab", self.destination.key());
        if !self.mdns_filter.is_empty() {
            query.append_pair("mdns_filter", &self.mdns_filter);
        }
        if !self.mdns_type.is_empty() {
            query.append_pair("mdns_type", &self.mdns_type);
        }
        if !self.query.is_empty() {
            query.append_pair("q", &self.query);
        }
        if let Some(host) = &self.host {
            query.append_pair("host", host.as_str());
        }
        query.append_pair("state", self.filter.key());
        query.append_pair("sort", self.sort.key());
        if let Some(selected) = &self.selected {
            query.append_pair("selected", selected.as_str());
        }
        query.finish()
    }

    pub fn href(&self) -> String {
        format!("?{}", self.query_string())
    }

    pub fn selecting(&self, selected: Option<ServiceId>) -> Self {
        Self {
            selected,
            ..self.clone()
        }
    }

    pub fn destination_href(&self, destination: Destination) -> String {
        Self {
            destination,
            selected: None,
            ..self.clone()
        }
        .href()
    }

    /// Search and order operate only on the captured authoritative snapshot.
    /// The stable identity tie-breaker avoids a discovery-order-dependent list.
    pub fn services<'a>(&self, catalog: &'a CatalogSnapshot) -> Vec<&'a Service> {
        use crate::catalog_view::{condition_label, display_name, host_name};
        let words: Vec<_> = self
            .query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        let mut services: Vec<_> = catalog
            .services
            .iter()
            .filter(|service| {
                self.host
                    .as_ref()
                    .is_none_or(|host| host == &service.device_id)
                    && self.filter.matches(service.condition)
                    && matches_search(catalog, service, &words)
            })
            .collect();
        services.sort_by_cached_key(|service| {
            let name = display_name(service).to_lowercase();
            let primary = match self.sort {
                ServiceSort::Name => name.clone(),
                ServiceSort::Host => host_name(catalog, service).to_lowercase(),
                ServiceSort::State => condition_label(service.condition).to_lowercase(),
            };
            (primary, name, service.id.clone())
        });
        services
    }
}

/// Every query word must appear in at least one searchable field. No words
/// matches everything; word order is irrelevant.
fn matches_search(catalog: &CatalogSnapshot, service: &Service, words: &[String]) -> bool {
    use crate::catalog_view::{category, display_name, endpoint_label, host_name};
    if words.is_empty() {
        return true;
    }
    let mut fields = vec![
        display_name(service).to_lowercase(),
        service.display_name.to_lowercase(),
        category(&service.kind).to_lowercase(),
        host_name(catalog, service).to_lowercase(),
    ];
    if let Some(device) = catalog
        .devices
        .iter()
        .find(|device| device.id == service.device_id)
    {
        fields.extend(device.names.iter().map(|name| name.value.to_lowercase()));
        fields.extend(
            device
                .addresses
                .iter()
                .map(|address| address.address.to_lowercase()),
        );
    }
    if let Some(name) = service
        .last_known
        .as_ref()
        .and_then(|known| known.device_name.as_deref())
    {
        fields.push(name.to_lowercase());
    }
    fields.extend(
        service
            .endpoints
            .iter()
            .map(|endpoint| endpoint_label(endpoint).to_lowercase()),
    );
    words
        .iter()
        .all(|word| fields.iter().any(|field| field.contains(word.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::service::{
        AddressEvidence, Device, DeviceCondition, IdentityConfidence, KoiPresence, MeshIdentity,
        MeshIdentityState, NameEvidence, ServiceKind, CATALOG_SCHEMA,
    };

    fn searchable_catalog() -> CatalogSnapshot {
        let service = |id: &str, name: &str, kind: ServiceKind, device: &str| Service {
            schema: CATALOG_SCHEMA,
            id: ServiceId::new(id).unwrap(),
            device_id: DeviceId::new(device).unwrap(),
            display_name: name.into(),
            alias: None,
            kind,
            condition: ServiceCondition::Found,
            endpoints: vec![],
            observations: vec![],
            checks: vec![],
            available_actions: vec![],
            favorite: false,
            local_only: false,
            managed: false,
            active_operations: vec![],
            identity_confidence: IdentityConfidence::Observed,
            ambiguity: None,
            last_known: None,
        };
        let device = |id: &str, name: &str, address: &str| Device {
            schema: CATALOG_SCHEMA,
            id: DeviceId::new(id).unwrap(),
            names: vec![NameEvidence {
                value: name.into(),
                observation_ids: vec![],
            }],
            addresses: vec![AddressEvidence {
                address: address.into(),
                network_scope_id: None,
                observation_ids: vec![],
            }],
            koi_presence: KoiPresence::Absent,
            mesh_identity: MeshIdentity {
                state: MeshIdentityState::Unknown,
                observation_ids: vec![],
            },
            condition: DeviceCondition::Present,
        };
        CatalogSnapshot {
            devices: vec![
                device("office", "Office Mac", "192.0.2.44"),
                device("garage", "Garage NAS", "192.0.2.80"),
            ],
            services: vec![
                service("notes", "Notes", ServiceKind::Web, "office"),
                service("ledger", "Ledger", ServiceKind::Api, "office"),
                service("photos", "Photos", ServiceKind::Web, "garage"),
            ],
            ..CatalogSnapshot::default()
        }
    }

    fn found(catalog: &CatalogSnapshot, query: &str) -> Vec<String> {
        UiState {
            query: query.into(),
            ..UiState::default()
        }
        .services(catalog)
        .into_iter()
        .map(|service| service.id.as_str().to_owned())
        .collect()
    }

    #[test]
    fn every_search_word_must_match_some_service_device_or_endpoint_field() {
        let catalog = searchable_catalog();
        assert_eq!(found(&catalog, "office web"), ["notes"]);
        assert_eq!(found(&catalog, "  WEB   office "), ["notes"]);
        assert_eq!(found(&catalog, "192.0.2.80"), ["photos"]);
        assert_eq!(found(&catalog, "api 192.0.2.44"), ["ledger"]);
        assert!(found(&catalog, "office missing").is_empty());
        assert_eq!(found(&catalog, "   ").len(), 3);
    }
    #[test]
    fn view_queries_are_bounded_strict_and_round_trip_opaque_ids() {
        let state = UiState {
            destination: Destination::About,
            query: "notes & photos".into(),
            host: Some(DeviceId::new("host_\"><").unwrap()),
            selected: Some(ServiceId::new("svc_&?#\"").unwrap()),
            ..UiState::default()
        };
        assert_eq!(UiState::parse_query(&state.query_string()), Ok(state));
        for bad in [
            "token=secret",
            "tab=unknown",
            "sort=unknown",
            "state=unknown",
            "q=a&q=b",
            "q=%",
            "q=%ff",
            "q=%00",
            "host=UPPERCASE",
            "selected=has+space",
        ] {
            assert!(UiState::parse_query(bad).is_err(), "{bad}");
        }
        assert!(UiState::parse_query(&format!("q={}", "a".repeat(257))).is_err());
        assert!(UiState::parse_query(&"a".repeat(4097)).is_err());
    }

    #[test]
    fn legacy_mdns_subview_links_canonicalize_to_the_top_level_destination() {
        let state = UiState::parse_query(
            "tab=services&services_view=mdns&mdns_filter=printer&mdns_type=_ipp._tcp",
        )
        .unwrap();
        assert_eq!(state.destination, Destination::Mdns);
        assert_eq!(
            state.query_string(),
            "tab=mdns&mdns_filter=printer&mdns_type=_ipp._tcp&state=all&sort=name"
        );
        assert_eq!(
            UiState::parse_query("tab=services&services_view=catalog")
                .unwrap()
                .destination,
            Destination::Services
        );
    }
}
