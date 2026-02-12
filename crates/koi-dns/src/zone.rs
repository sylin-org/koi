use crate::resolver::DnsError;

/// Local DNS zone configuration and normalization helpers.
pub struct DnsZone {
    zone: String,
    fqdn_suffix: String,
}

impl DnsZone {
    pub fn new(zone: &str) -> Result<Self, DnsError> {
        let zone = zone.trim().trim_end_matches('.').to_lowercase();
        if zone.is_empty() || zone.contains(' ') {
            return Err(DnsError::InvalidZone(zone));
        }
        let fqdn_suffix = format!("{zone}.");
        Ok(Self { zone, fqdn_suffix })
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn fqdn_suffix(&self) -> &str {
        &self.fqdn_suffix
    }

    /// Normalize a query name into a local-zone FQDN.
    ///
    /// Returns `None` if the name is outside the local zone.
    pub fn normalize_name(&self, name: &str) -> Option<String> {
        let input = name.trim().trim_end_matches('.').to_lowercase();
        if input.is_empty() {
            return None;
        }
        if input == self.zone {
            return Some(format!("{input}."));
        }
        if input.ends_with(&format!(".{}", self.zone)) {
            return Some(format!("{input}."));
        }
        if !input.contains('.') {
            return Some(format!("{input}.{}.", self.zone));
        }
        None
    }

    pub fn is_local_name(&self, name: &str) -> bool {
        self.normalize_name(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_short_name() {
        let zone = DnsZone::new("lan").unwrap();
        assert_eq!(
            zone.normalize_name("grafana"),
            Some("grafana.lan.".to_string())
        );
    }

    #[test]
    fn normalize_fqdn() {
        let zone = DnsZone::new("lan").unwrap();
        assert_eq!(
            zone.normalize_name("grafana.lan"),
            Some("grafana.lan.".to_string())
        );
    }

    #[test]
    fn normalize_outside_zone_is_none() {
        let zone = DnsZone::new("lan").unwrap();
        assert_eq!(zone.normalize_name("grafana.local"), None);
    }
}
