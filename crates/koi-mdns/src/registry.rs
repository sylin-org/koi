use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use koi_common::types::SessionId;

use crate::error::{MdnsError, Result};
use crate::protocol::{
    AdminRegistration, LeaseMode, LeaseState, RegisterPayload, RegistrationCounts,
};

// ── Types ─────────────────────────────────────────────────────────────

/// How a registration proves it's alive.
#[derive(Debug, Clone)]
pub enum LeasePolicy {
    /// Tied to a connection. Grace period starts when connection drops.
    Session { grace: Duration },
    /// Client must heartbeat within lease duration. Grace after miss.
    Heartbeat { lease: Duration, grace: Duration },
    /// Lives forever. Only explicit removal or shutdown.
    Permanent,
}

/// Current lifecycle state.
#[derive(Debug, Clone)]
pub enum RegistrationState {
    Alive,
    Draining { since: Instant },
}

/// A tracked registration with full lifecycle metadata.
pub struct Registration {
    pub payload: RegisterPayload,
    pub state: RegistrationState,
    pub policy: LeasePolicy,
    pub last_seen: Instant,
    pub session_id: Option<SessionId>,
    registered_at_wall: SystemTime,
    last_seen_wall: SystemTime,
}

/// Outcome of `insert_or_reconnect`.
pub enum InsertOutcome {
    /// Fresh registration. Used the provided new_id.
    New { id: String },
    /// Revived a DRAINING entry. Returns the old entry's ID and payload
    /// so the caller can update the daemon if the payload changed.
    Reconnected {
        id: String,
        old_payload: RegisterPayload,
    },
}

impl InsertOutcome {
    pub fn id(&self) -> &str {
        match self {
            InsertOutcome::New { id } | InsertOutcome::Reconnected { id, .. } => id,
        }
    }
}

// ── Registry ──────────────────────────────────────────────────────────

/// Registration lifecycle engine.
///
/// Tracks all registered services with lease state, session ownership,
/// and temporal metadata. All methods are thread-safe via internal Mutex.
pub(crate) struct Registry {
    registrations: Mutex<HashMap<String, Registration>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            registrations: Mutex::new(HashMap::new()),
        }
    }

    // ── Public API ────────────────────────────────────────────────────

    /// Insert a new registration, or reconnect to a DRAINING entry
    /// that matches by name + service type. Atomic under the lock.
    pub fn insert_or_reconnect(
        &self,
        new_id: String,
        payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
    ) -> InsertOutcome {
        self.insert_or_reconnect_at(new_id, payload, policy, session_id, Instant::now())
    }

    /// Remove a registration (explicit unregister). Returns its payload
    /// so the caller can send goodbye packets.
    pub fn remove(&self, id: &str) -> Result<RegisterPayload> {
        let mut regs = self.registrations.lock().unwrap();
        regs.remove(id)
            .map(|r| r.payload)
            .ok_or_else(|| MdnsError::RegistrationNotFound(id.to_string()))
    }

    /// Record a heartbeat. Resets last_seen. Revives if DRAINING.
    pub fn heartbeat(&self, id: &str) -> Result<u64> {
        self.heartbeat_at(id, Instant::now())
    }

    /// Mark all registrations for a session as DRAINING.
    /// Returns IDs that transitioned.
    pub fn drain_session(&self, session_id: &SessionId) -> Vec<String> {
        self.drain_session_at(session_id, Instant::now())
    }

    /// Admin: force-drain a specific registration.
    pub fn force_drain(&self, id: &str) -> Result<()> {
        self.force_drain_at(id, Instant::now())
    }

    /// Admin: force-revive a DRAINING registration.
    pub fn force_revive(&self, id: &str) -> Result<()> {
        let mut regs = self.registrations.lock().unwrap();
        let reg = regs
            .get_mut(id)
            .ok_or_else(|| MdnsError::RegistrationNotFound(id.to_string()))?;
        match &reg.state {
            RegistrationState::Draining { .. } => {
                reg.state = RegistrationState::Alive;
                reg.last_seen = Instant::now();
                reg.last_seen_wall = SystemTime::now();
                Ok(())
            }
            RegistrationState::Alive => Err(MdnsError::NotDraining(id.to_string())),
        }
    }

    /// Sweep for expired registrations. Single-pass retain().
    /// Transitions missed heartbeats Alive → Draining.
    /// Collects grace-expired entries and removes them.
    /// Returns (id, payload) pairs that need goodbye packets.
    pub fn reap(&self) -> Vec<(String, RegisterPayload)> {
        self.reap_at(Instant::now())
    }

    /// Resolve a partial ID to a full ID. Errors if ambiguous or not found.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<String> {
        let regs = self.registrations.lock().unwrap();
        let matches: Vec<&String> = regs.keys().filter(|id| id.starts_with(prefix)).collect();
        match matches.len() {
            0 => Err(MdnsError::RegistrationNotFound(prefix.to_string())),
            1 => Ok(matches[0].clone()),
            _ => Err(MdnsError::AmbiguousId(prefix.to_string())),
        }
    }

    /// Snapshot all registrations for admin display.
    pub fn snapshot(&self) -> Vec<(String, AdminRegistration)> {
        let now = Instant::now();
        let regs = self.registrations.lock().unwrap();
        regs.iter()
            .map(|(id, reg)| (id.clone(), to_admin_registration(id, reg, now)))
            .collect()
    }

    /// Snapshot one registration for admin display.
    pub fn snapshot_one(&self, id: &str) -> Result<AdminRegistration> {
        let now = Instant::now();
        let regs = self.registrations.lock().unwrap();
        regs.get(id)
            .map(|reg| to_admin_registration(id, reg, now))
            .ok_or_else(|| MdnsError::RegistrationNotFound(id.to_string()))
    }

    /// Counts by state (for admin status).
    pub fn counts(&self) -> RegistrationCounts {
        let regs = self.registrations.lock().unwrap();
        let mut alive = 0;
        let mut draining = 0;
        let mut permanent = 0;
        for reg in regs.values() {
            if matches!(reg.policy, LeasePolicy::Permanent) {
                permanent += 1;
            }
            match &reg.state {
                RegistrationState::Alive => alive += 1,
                RegistrationState::Draining { .. } => draining += 1,
            }
        }
        RegistrationCounts {
            alive,
            draining,
            permanent,
            total: regs.len(),
        }
    }

    /// Get all registration IDs (for shutdown).
    pub fn all_ids(&self) -> Vec<String> {
        let regs = self.registrations.lock().unwrap();
        regs.keys().cloned().collect()
    }

    // ── Testable _at variants ─────────────────────────────────────────

    pub(crate) fn insert_or_reconnect_at(
        &self,
        new_id: String,
        payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
        now: Instant,
    ) -> InsertOutcome {
        let mut regs = self.registrations.lock().unwrap();

        // Look for a DRAINING entry matching name + service type
        let reconnect_id = regs
            .iter()
            .find(|(_, reg)| {
                matches!(reg.state, RegistrationState::Draining { .. })
                    && reg.payload.name == payload.name
                    && reg.payload.service_type == payload.service_type
            })
            .map(|(id, _)| id.clone());

        if let Some(existing_id) = reconnect_id {
            let reg = regs.get_mut(&existing_id).unwrap();
            let old_payload = reg.payload.clone();
            reg.payload = payload;
            reg.state = RegistrationState::Alive;
            reg.policy = policy;
            reg.last_seen = now;
            reg.last_seen_wall = SystemTime::now();
            reg.session_id = session_id;
            InsertOutcome::Reconnected {
                id: existing_id,
                old_payload,
            }
        } else {
            let id = new_id.clone();
            let wall = SystemTime::now();
            regs.insert(
                new_id,
                Registration {
                    payload,
                    state: RegistrationState::Alive,
                    policy,
                    last_seen: now,
                    session_id,
                    registered_at_wall: wall,
                    last_seen_wall: wall,
                },
            );
            InsertOutcome::New { id }
        }
    }

    pub(crate) fn heartbeat_at(&self, id: &str, now: Instant) -> Result<u64> {
        let mut regs = self.registrations.lock().unwrap();
        let reg = regs
            .get_mut(id)
            .ok_or_else(|| MdnsError::RegistrationNotFound(id.to_string()))?;
        reg.last_seen = now;
        reg.last_seen_wall = SystemTime::now();
        if matches!(reg.state, RegistrationState::Draining { .. }) {
            reg.state = RegistrationState::Alive;
        }
        let lease_secs = match &reg.policy {
            LeasePolicy::Heartbeat { lease, .. } => lease.as_secs(),
            _ => 0,
        };
        Ok(lease_secs)
    }

    pub(crate) fn drain_session_at(&self, session_id: &SessionId, now: Instant) -> Vec<String> {
        let mut regs = self.registrations.lock().unwrap();
        let mut drained = Vec::new();
        for (id, reg) in regs.iter_mut() {
            if reg.session_id.as_ref() == Some(session_id)
                && matches!(reg.state, RegistrationState::Alive)
                && !matches!(reg.policy, LeasePolicy::Permanent)
            {
                reg.state = RegistrationState::Draining { since: now };
                drained.push(id.clone());
            }
        }
        drained
    }

    pub(crate) fn force_drain_at(&self, id: &str, now: Instant) -> Result<()> {
        let mut regs = self.registrations.lock().unwrap();
        let reg = regs
            .get_mut(id)
            .ok_or_else(|| MdnsError::RegistrationNotFound(id.to_string()))?;
        match &reg.state {
            RegistrationState::Alive => {
                reg.state = RegistrationState::Draining { since: now };
                Ok(())
            }
            RegistrationState::Draining { .. } => Err(MdnsError::AlreadyDraining(id.to_string())),
        }
    }

    pub(crate) fn reap_at(&self, now: Instant) -> Vec<(String, RegisterPayload)> {
        let mut expired = Vec::new();
        let mut regs = self.registrations.lock().unwrap();

        regs.retain(|id, reg| {
            match (&reg.state, &reg.policy) {
                // Permanent - never expires
                (_, LeasePolicy::Permanent) => true,

                // Session, alive - connection still open
                (RegistrationState::Alive, LeasePolicy::Session { .. }) => true,

                // Draining - check grace (both session and heartbeat)
                (RegistrationState::Draining { since }, LeasePolicy::Session { grace })
                | (RegistrationState::Draining { since }, LeasePolicy::Heartbeat { grace, .. }) => {
                    if now.duration_since(*since) >= *grace {
                        expired.push((id.clone(), reg.payload.clone()));
                        false
                    } else {
                        true
                    }
                }

                // Heartbeat, alive - check if lease expired
                (RegistrationState::Alive, LeasePolicy::Heartbeat { lease, .. }) => {
                    if now.duration_since(reg.last_seen) >= *lease {
                        // Transition to draining; grace starts now
                        reg.state = RegistrationState::Draining { since: now };
                    }
                    true // Don't remove yet - grace period begins
                }
            }
        });

        expired
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn to_admin_registration(id: &str, reg: &Registration, now: Instant) -> AdminRegistration {
    let (mode, lease_secs, grace_secs) = match &reg.policy {
        LeasePolicy::Session { grace } => (LeaseMode::Session, None, grace.as_secs()),
        LeasePolicy::Heartbeat { lease, grace } => {
            (LeaseMode::Heartbeat, Some(lease.as_secs()), grace.as_secs())
        }
        LeasePolicy::Permanent => (LeaseMode::Permanent, None, 0),
    };

    let state = match &reg.state {
        RegistrationState::Alive => LeaseState::Alive,
        RegistrationState::Draining { .. } => LeaseState::Draining,
    };

    AdminRegistration {
        id: id.to_string(),
        name: reg.payload.name.clone(),
        service_type: reg.payload.service_type.clone(),
        port: reg.payload.port,
        mode,
        state,
        lease_secs,
        remaining_secs: remaining_secs_for(reg, now),
        grace_secs,
        session_id: reg.session_id.as_ref().map(|s| s.0.clone()),
        registered_at: format_epoch(reg.registered_at_wall),
        last_seen: format_epoch(reg.last_seen_wall),
        txt: reg.payload.txt.clone(),
    }
}

fn remaining_secs_for(reg: &Registration, now: Instant) -> Option<u64> {
    match (&reg.state, &reg.policy) {
        (RegistrationState::Alive, LeasePolicy::Heartbeat { lease, .. }) => {
            let deadline = reg.last_seen + *lease;
            Some(deadline.saturating_duration_since(now).as_secs())
        }
        (RegistrationState::Draining { since }, LeasePolicy::Session { grace })
        | (RegistrationState::Draining { since }, LeasePolicy::Heartbeat { grace, .. }) => {
            let deadline = *since + *grace;
            Some(deadline.saturating_duration_since(now).as_secs())
        }
        _ => None,
    }
}

fn format_epoch(t: SystemTime) -> String {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(name: &str, stype: &str) -> RegisterPayload {
        RegisterPayload {
            name: name.to_string(),
            service_type: stype.to_string(),
            port: 8080,
            ip: None,
            lease_secs: None,
            txt: HashMap::new(),
        }
    }

    fn session(id: &str) -> Option<SessionId> {
        Some(SessionId(id.to_string()))
    }

    fn session_policy(grace_ms: u64) -> LeasePolicy {
        LeasePolicy::Session {
            grace: Duration::from_millis(grace_ms),
        }
    }

    fn heartbeat_policy(lease_ms: u64, grace_ms: u64) -> LeasePolicy {
        LeasePolicy::Heartbeat {
            lease: Duration::from_millis(lease_ms),
            grace: Duration::from_millis(grace_ms),
        }
    }

    // ── insert_or_reconnect ───────────────────────────────────────────

    #[test]
    fn insert_creates_new_registration() {
        let reg = Registry::new();
        let outcome = reg.insert_or_reconnect(
            "abc123".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        assert!(matches!(outcome, InsertOutcome::New { ref id } if id == "abc123"));
        assert_eq!(reg.counts().total, 1);
    }

    #[test]
    fn insert_reconnects_draining_entry() {
        let reg = Registry::new();
        let now = Instant::now();

        reg.insert_or_reconnect_at(
            "abc123".into(),
            payload("Svc", "_http._tcp"),
            session_policy(1000),
            session("s1"),
            now,
        );

        reg.drain_session_at(&SessionId("s1".into()), now);

        // New registration with same name+type reconnects
        let outcome = reg.insert_or_reconnect_at(
            "new456".into(),
            payload("Svc", "_http._tcp"),
            session_policy(1000),
            session("s2"),
            now,
        );

        match &outcome {
            InsertOutcome::Reconnected { id, .. } => assert_eq!(id, "abc123"),
            _ => panic!("Expected Reconnected"),
        }
        assert_eq!(reg.counts().total, 1);
    }

    #[test]
    fn insert_does_not_reconnect_alive_entry() {
        let reg = Registry::new();

        reg.insert_or_reconnect(
            "abc123".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );

        let outcome = reg.insert_or_reconnect(
            "def456".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s2"),
        );

        assert!(matches!(outcome, InsertOutcome::New { ref id } if id == "def456"));
        assert_eq!(reg.counts().total, 2);
    }

    #[test]
    fn reconnect_returns_old_payload() {
        let reg = Registry::new();
        let now = Instant::now();

        let mut old = payload("Svc", "_http._tcp");
        old.port = 8080;
        reg.insert_or_reconnect_at("abc".into(), old, session_policy(1000), session("s1"), now);
        reg.drain_session_at(&SessionId("s1".into()), now);

        let mut new = payload("Svc", "_http._tcp");
        new.port = 9090;
        let outcome =
            reg.insert_or_reconnect_at("new".into(), new, session_policy(1000), session("s2"), now);

        match outcome {
            InsertOutcome::Reconnected { old_payload, .. } => {
                assert_eq!(old_payload.port, 8080);
            }
            _ => panic!("Expected Reconnected"),
        }
    }

    // ── remove ────────────────────────────────────────────────────────

    #[test]
    fn remove_returns_payload() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        let p = reg.remove("abc").unwrap();
        assert_eq!(p.name, "Svc");
        assert_eq!(reg.counts().total, 0);
    }

    #[test]
    fn remove_not_found_returns_error() {
        let reg = Registry::new();
        assert!(reg.remove("nonexistent").is_err());
    }

    // ── heartbeat ─────────────────────────────────────────────────────

    #[test]
    fn heartbeat_extends_lease() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            heartbeat_policy(1000, 500),
            None,
            start,
        );

        // Heartbeat at +200ms resets last_seen
        reg.heartbeat_at("abc", start + Duration::from_millis(200))
            .unwrap();

        // Reap at +1100ms: lease is 1000ms from last_seen (+200ms),
        // so deadline is +1200ms. Should still be alive.
        let expired = reg.reap_at(start + Duration::from_millis(1100));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().alive, 1);
    }

    #[test]
    fn heartbeat_revives_draining_entry() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            heartbeat_policy(100, 500),
            None,
            start,
        );

        // Lease expires → transitions to draining
        reg.reap_at(start + Duration::from_millis(150));
        assert_eq!(reg.counts().draining, 1);

        // Heartbeat revives
        reg.heartbeat_at("abc", start + Duration::from_millis(200))
            .unwrap();
        assert_eq!(reg.counts().alive, 1);
        assert_eq!(reg.counts().draining, 0);
    }

    #[test]
    fn heartbeat_not_found_returns_error() {
        let reg = Registry::new();
        assert!(reg.heartbeat("nonexistent").is_err());
    }

    // ── drain_session ─────────────────────────────────────────────────

    #[test]
    fn drain_session_transitions_matching() {
        let reg = Registry::new();
        let sid = SessionId("s1".into());

        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc1", "_http._tcp"),
            session_policy(100),
            Some(sid.clone()),
        );
        reg.insert_or_reconnect(
            "b".into(),
            payload("Svc2", "_http._tcp"),
            session_policy(100),
            Some(sid.clone()),
        );

        let drained = reg.drain_session(&sid);
        assert_eq!(drained.len(), 2);
        assert_eq!(reg.counts().draining, 2);
    }

    #[test]
    fn drain_session_ignores_other_sessions() {
        let reg = Registry::new();

        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc1", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        reg.insert_or_reconnect(
            "b".into(),
            payload("Svc2", "_http._tcp"),
            session_policy(100),
            session("s2"),
        );

        let drained = reg.drain_session(&SessionId("s1".into()));
        assert_eq!(drained.len(), 1);
        assert_eq!(reg.counts().alive, 1);
        assert_eq!(reg.counts().draining, 1);
    }

    #[test]
    fn drain_session_ignores_permanent() {
        let reg = Registry::new();
        let sid = SessionId("s1".into());

        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            Some(sid.clone()),
        );

        let drained = reg.drain_session(&sid);
        assert!(drained.is_empty());
        assert_eq!(reg.counts().alive, 1);
    }

    // ── force_drain / force_revive ────────────────────────────────────

    #[test]
    fn force_drain_transitions_to_draining() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );

        reg.force_drain("abc").unwrap();
        assert_eq!(reg.counts().draining, 1);
    }

    #[test]
    fn force_drain_already_draining_returns_error() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        reg.force_drain("abc").unwrap();
        assert!(matches!(
            reg.force_drain("abc"),
            Err(MdnsError::AlreadyDraining(_))
        ));
    }

    #[test]
    fn force_revive_transitions_to_alive() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        reg.force_drain("abc").unwrap();
        reg.force_revive("abc").unwrap();
        assert_eq!(reg.counts().alive, 1);
        assert_eq!(reg.counts().draining, 0);
    }

    #[test]
    fn force_revive_not_draining_returns_error() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        assert!(matches!(
            reg.force_revive("abc"),
            Err(MdnsError::NotDraining(_))
        ));
    }

    // ── reap ──────────────────────────────────────────────────────────

    #[test]
    fn reap_expires_grace_elapsed_session() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
            start,
        );
        reg.drain_session_at(&SessionId("s1".into()), start);

        // Before grace: nothing to reap
        let expired = reg.reap_at(start + Duration::from_millis(50));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().total, 1);

        // After grace: entry expired
        let expired = reg.reap_at(start + Duration::from_millis(150));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, "abc");
        assert_eq!(reg.counts().total, 0);
    }

    #[test]
    fn reap_transitions_heartbeat_to_draining_then_expires() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            heartbeat_policy(100, 200),
            None,
            start,
        );

        // Before lease: alive
        let expired = reg.reap_at(start + Duration::from_millis(50));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().alive, 1);

        // After lease, before grace: draining (lease=100ms, so at +150ms → draining)
        let expired = reg.reap_at(start + Duration::from_millis(150));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().draining, 1);

        // After grace: expired (draining started at +150ms, grace=200ms → deadline +350ms)
        let expired = reg.reap_at(start + Duration::from_millis(400));
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn reap_ignores_permanent() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
            start,
        );

        let expired = reg.reap_at(start + Duration::from_secs(3600));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().total, 1);
    }

    #[test]
    fn reap_ignores_session_alive() {
        let reg = Registry::new();
        let start = Instant::now();

        reg.insert_or_reconnect_at(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            session_policy(100),
            session("s1"),
            start,
        );

        // Session alive - reaper doesn't touch it regardless of elapsed time
        let expired = reg.reap_at(start + Duration::from_secs(3600));
        assert!(expired.is_empty());
        assert_eq!(reg.counts().total, 1);
    }

    // ── resolve_prefix ────────────────────────────────────────────────

    #[test]
    fn resolve_prefix_finds_unique_match() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc123".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        assert_eq!(reg.resolve_prefix("abc").unwrap(), "abc123");
    }

    #[test]
    fn resolve_prefix_exact_match() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc123".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        assert_eq!(reg.resolve_prefix("abc123").unwrap(), "abc123");
    }

    #[test]
    fn resolve_prefix_errors_on_ambiguous() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "abc123".into(),
            payload("Svc1", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        reg.insert_or_reconnect(
            "abc456".into(),
            payload("Svc2", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        assert!(matches!(
            reg.resolve_prefix("abc"),
            Err(MdnsError::AmbiguousId(_))
        ));
    }

    #[test]
    fn resolve_prefix_errors_on_not_found() {
        let reg = Registry::new();
        assert!(matches!(
            reg.resolve_prefix("xyz"),
            Err(MdnsError::RegistrationNotFound(_))
        ));
    }

    // ── counts ────────────────────────────────────────────────────────

    #[test]
    fn counts_reflect_current_state() {
        let reg = Registry::new();

        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc1", "_http._tcp"),
            session_policy(100),
            session("s1"),
        );
        reg.insert_or_reconnect(
            "b".into(),
            payload("Svc2", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        reg.insert_or_reconnect(
            "c".into(),
            payload("Svc3", "_http._tcp"),
            session_policy(100),
            session("s2"),
        );

        reg.force_drain("c").unwrap();

        let c = reg.counts();
        assert_eq!(c.alive, 2); // a (session alive) + b (permanent)
        assert_eq!(c.draining, 1); // c
        assert_eq!(c.permanent, 1); // b
        assert_eq!(c.total, 3);
    }

    // ── snapshot ──────────────────────────────────────────────────────

    #[test]
    fn snapshot_includes_all_registrations() {
        let reg = Registry::new();

        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc1", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        reg.insert_or_reconnect(
            "b".into(),
            payload("Svc2", "_http._tcp"),
            session_policy(30000),
            session("s1"),
        );

        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn snapshot_one_returns_correct_fields() {
        let reg = Registry::new();

        reg.insert_or_reconnect(
            "abc".into(),
            payload("Svc", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );

        let admin = reg.snapshot_one("abc").unwrap();
        assert_eq!(admin.id, "abc");
        assert_eq!(admin.name, "Svc");
        assert_eq!(admin.service_type, "_http._tcp");
        assert_eq!(admin.mode, LeaseMode::Permanent);
        assert_eq!(admin.state, LeaseState::Alive);
        assert!(admin.lease_secs.is_none());
        assert!(admin.remaining_secs.is_none());
        assert_eq!(admin.grace_secs, 0);
    }

    #[test]
    fn snapshot_one_not_found() {
        let reg = Registry::new();
        assert!(reg.snapshot_one("xyz").is_err());
    }

    // ── all_ids ───────────────────────────────────────────────────────

    #[test]
    fn all_ids_returns_all_registration_ids() {
        let reg = Registry::new();
        reg.insert_or_reconnect(
            "a".into(),
            payload("Svc1", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        reg.insert_or_reconnect(
            "b".into(),
            payload("Svc2", "_http._tcp"),
            LeasePolicy::Permanent,
            None,
        );
        let mut ids = reg.all_ids();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }
}
