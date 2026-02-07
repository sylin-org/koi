use std::collections::HashMap;
use std::sync::Mutex;

use crate::protocol::RegisterPayload;

use super::{KoiError, Result};

/// In-memory registry of our registered services.
/// The registry is the source of truth — the mdns-sd daemon is ephemeral.
/// On daemon crash, we re-register from the registry.
pub(crate) struct Registry {
    services: Mutex<HashMap<String, RegisterPayload>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            services: Mutex::new(HashMap::new()),
        }
    }

    /// Track a registration.
    pub fn insert(&self, id: String, payload: RegisterPayload) {
        let mut services = self.services.lock().unwrap();
        services.insert(id, payload);
    }

    /// Remove and return a registration.
    pub fn remove(&self, id: &str) -> Result<RegisterPayload> {
        let mut services = self.services.lock().unwrap();
        services
            .remove(id)
            .ok_or_else(|| KoiError::RegistrationNotFound(id.to_string()))
    }

    /// Get all registration IDs.
    pub fn all_ids(&self) -> Vec<String> {
        let services = self.services.lock().unwrap();
        services.keys().cloned().collect()
    }

    /// Get all registrations (for daemon recovery / re-registration).
    pub fn all(&self) -> Vec<(String, RegisterPayload)> {
        let services = self.services.lock().unwrap();
        services
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Number of active registrations.
    pub fn count(&self) -> usize {
        let services = self.services.lock().unwrap();
        services.len()
    }
}
