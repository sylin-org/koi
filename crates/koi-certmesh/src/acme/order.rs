//! ACME orders, authorizations, and challenges (RFC 8555 §7.1.3–7.1.6).
//!
//! State model (in-memory; orders are short-lived and not persisted):
//!
//! ```text
//! Order ── authorizations ──> Authz ── challenges ──> Challenge (dns-01)
//!   │
//!   ├─ identifiers (the requested names; all in-zone, validated at new-order)
//!   ├─ status: pending → ready → valid (→ invalid on failure)
//!   └─ certificate id (set at finalize)
//! ```
//!
//! The **security boundary** lives here and in [`finalize`]:
//! - identifiers are validated to be in-zone at order creation (out-of-zone →
//!   `rejectedIdentifier`); the wildcard `*.<zone>` is allowed;
//! - at finalize, every CSR SAN MUST be one of the order's authorized
//!   identifiers, else the order is rejected and nothing is signed.

use std::collections::HashMap;
use std::sync::Mutex;

use koi_common::id::generate_short_id;
use serde::Serialize;

/// Status of an ACME order (RFC 8555 §7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// Status of an authorization (RFC 8555 §7.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthzStatus {
    Pending,
    Valid,
    Invalid,
}

/// Status of a challenge (RFC 8555 §7.1.5 / §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// A dns-01 challenge.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Challenge id (path component under `/acme/chall/<id>`).
    pub id: String,
    /// The challenge token (the client mixes this with its account thumbprint).
    pub token: String,
    pub status: ChallengeStatus,
}

/// An authorization for a single identifier.
#[derive(Debug, Clone)]
pub struct Authz {
    pub id: String,
    /// The DNS name being authorized (no wildcard prefix; `wildcard` flags it).
    pub identifier: String,
    /// Whether the identifier was requested as `*.identifier`.
    pub wildcard: bool,
    pub status: AuthzStatus,
    pub challenge: Challenge,
    /// The account that owns this authorization's order.
    pub account_id: String,
}

/// An order.
#[derive(Debug, Clone)]
pub struct Order {
    pub id: String,
    pub account_id: String,
    /// The requested identifiers (DNS names; wildcards carry the `*.` prefix).
    pub identifiers: Vec<String>,
    pub status: OrderStatus,
    /// Ids of this order's authorizations.
    pub authz_ids: Vec<String>,
    /// Certificate id once finalized.
    pub certificate_id: Option<String>,
}

impl Order {
    /// The set of names this order authorizes a certificate for — i.e. exactly
    /// the requested identifiers. The finalize CSR check uses this as the
    /// allow-list: every CSR SAN must be a member.
    pub fn authorized_names(&self) -> &[String] {
        &self.identifiers
    }
}

/// An issued certificate (leaf + CA chain PEM).
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub id: String,
    pub chain_pem: String,
}

/// In-memory store of orders, authorizations, and issued certs. Not persisted —
/// orders are short-lived; a daemon restart simply drops in-flight orders and
/// the client starts a new one (accounts, which DO persist, are unaffected).
#[derive(Default)]
pub struct OrderStore {
    orders: Mutex<HashMap<String, Order>>,
    authzs: Mutex<HashMap<String, Authz>>,
    certs: Mutex<HashMap<String, IssuedCertificate>>,
}

impl OrderStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new order with one pending authorization (+ dns-01 challenge)
    /// per identifier. Identifiers must already be validated as in-zone by the
    /// caller. Returns the created order.
    pub fn create_order(&self, account_id: &str, identifiers: Vec<String>) -> Order {
        let order_id = generate_short_id();
        let mut authz_ids = Vec::with_capacity(identifiers.len());

        {
            let mut authzs = self.authzs.lock().unwrap_or_else(|e| e.into_inner());
            for ident in &identifiers {
                let (name, wildcard) = match ident.strip_prefix("*.") {
                    Some(base) => (base.to_string(), true),
                    None => (ident.clone(), false),
                };
                let authz_id = generate_short_id();
                let challenge = Challenge {
                    id: generate_short_id(),
                    token: generate_token(),
                    status: ChallengeStatus::Pending,
                };
                authzs.insert(
                    authz_id.clone(),
                    Authz {
                        id: authz_id.clone(),
                        identifier: name,
                        wildcard,
                        status: AuthzStatus::Pending,
                        challenge,
                        account_id: account_id.to_string(),
                    },
                );
                authz_ids.push(authz_id);
            }
        }

        let order = Order {
            id: order_id.clone(),
            account_id: account_id.to_string(),
            identifiers,
            status: OrderStatus::Pending,
            authz_ids,
            certificate_id: None,
        };
        self.orders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(order_id, order.clone());
        order
    }

    pub fn get_order(&self, id: &str) -> Option<Order> {
        self.orders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    pub fn get_authz(&self, id: &str) -> Option<Authz> {
        self.authzs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Find an authorization by its challenge id.
    pub fn authz_by_challenge(&self, challenge_id: &str) -> Option<Authz> {
        self.authzs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|a| a.challenge.id == challenge_id)
            .cloned()
    }

    /// Mark a challenge (and its authz) valid, then recompute the order status:
    /// when every authz of the order is valid, the order moves pending → ready.
    pub fn mark_challenge_valid(&self, authz_id: &str) {
        let order_id = {
            let mut authzs = self.authzs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(authz) = authzs.get_mut(authz_id) else {
                return;
            };
            authz.status = AuthzStatus::Valid;
            authz.challenge.status = ChallengeStatus::Valid;
            // Find the owning order.
            let orders = self.orders.lock().unwrap_or_else(|e| e.into_inner());
            orders
                .values()
                .find(|o| o.authz_ids.contains(&authz_id.to_string()))
                .map(|o| o.id.clone())
        };
        if let Some(order_id) = order_id {
            self.recompute_order_status(&order_id);
        }
    }

    /// Mark a challenge (and its authz, and its order) invalid.
    pub fn mark_challenge_invalid(&self, authz_id: &str) {
        let mut authzs = self.authzs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(authz) = authzs.get_mut(authz_id) {
            authz.status = AuthzStatus::Invalid;
            authz.challenge.status = ChallengeStatus::Invalid;
            let order_id = {
                let orders = self.orders.lock().unwrap_or_else(|e| e.into_inner());
                orders
                    .values()
                    .find(|o| o.authz_ids.contains(&authz_id.to_string()))
                    .map(|o| o.id.clone())
            };
            drop(authzs);
            if let Some(order_id) = order_id {
                if let Some(o) = self
                    .orders
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&order_id)
                {
                    o.status = OrderStatus::Invalid;
                }
            }
        }
    }

    /// Recompute an order's status from its authorizations.
    fn recompute_order_status(&self, order_id: &str) {
        let authzs = self.authzs.lock().unwrap_or_else(|e| e.into_inner());
        let mut orders = self.orders.lock().unwrap_or_else(|e| e.into_inner());
        let Some(order) = orders.get_mut(order_id) else {
            return;
        };
        // Already finalized states are terminal.
        if matches!(order.status, OrderStatus::Valid | OrderStatus::Invalid) {
            return;
        }
        let all_valid = order.authz_ids.iter().all(|id| {
            authzs
                .get(id)
                .map(|a| a.status == AuthzStatus::Valid)
                .unwrap_or(false)
        });
        if all_valid {
            order.status = OrderStatus::Ready;
        }
    }

    /// Store an issued certificate and bind it to the order, moving the order to
    /// `valid`. Returns the certificate id.
    pub fn record_certificate(&self, order_id: &str, chain_pem: String) -> String {
        let cert_id = generate_short_id();
        self.certs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            cert_id.clone(),
            IssuedCertificate {
                id: cert_id.clone(),
                chain_pem,
            },
        );
        if let Some(order) = self
            .orders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(order_id)
        {
            order.certificate_id = Some(cert_id.clone());
            order.status = OrderStatus::Valid;
        }
        cert_id
    }

    pub fn get_certificate(&self, cert_id: &str) -> Option<IssuedCertificate> {
        self.certs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cert_id)
            .cloned()
    }
}

/// Generate a challenge token: a URL-safe random string (RFC 8555 §8.1 requires
/// ≥128 bits of entropy and the base64url alphabet).
fn generate_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_creates_one_authz_per_identifier() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["a.lan".into(), "b.lan".into()]);
        assert_eq!(order.authz_ids.len(), 2);
        assert_eq!(order.status, OrderStatus::Pending);
        for id in &order.authz_ids {
            let authz = store.get_authz(id).unwrap();
            assert_eq!(authz.status, AuthzStatus::Pending);
            assert_eq!(authz.challenge.status, ChallengeStatus::Pending);
            assert!(!authz.challenge.token.is_empty());
        }
    }

    #[test]
    fn wildcard_identifier_strips_prefix_and_flags() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["*.lan".into()]);
        let authz = store.get_authz(&order.authz_ids[0]).unwrap();
        assert_eq!(authz.identifier, "lan");
        assert!(authz.wildcard);
    }

    #[test]
    fn order_becomes_ready_when_all_authz_valid() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["a.lan".into(), "b.lan".into()]);
        store.mark_challenge_valid(&order.authz_ids[0]);
        assert_eq!(
            store.get_order(&order.id).unwrap().status,
            OrderStatus::Pending,
            "still pending while one authz is unvalidated"
        );
        store.mark_challenge_valid(&order.authz_ids[1]);
        assert_eq!(
            store.get_order(&order.id).unwrap().status,
            OrderStatus::Ready,
            "ready once every authz is valid"
        );
    }

    #[test]
    fn invalid_challenge_invalidates_order() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["a.lan".into()]);
        store.mark_challenge_invalid(&order.authz_ids[0]);
        assert_eq!(
            store.get_order(&order.id).unwrap().status,
            OrderStatus::Invalid
        );
    }

    #[test]
    fn authz_by_challenge_finds_it() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["a.lan".into()]);
        let authz = store.get_authz(&order.authz_ids[0]).unwrap();
        let found = store.authz_by_challenge(&authz.challenge.id).unwrap();
        assert_eq!(found.id, authz.id);
    }

    #[test]
    fn record_certificate_makes_order_valid() {
        let store = OrderStore::new();
        let order = store.create_order("acct-1", vec!["a.lan".into()]);
        let cert_id = store.record_certificate(&order.id, "PEM".into());
        let o = store.get_order(&order.id).unwrap();
        assert_eq!(o.status, OrderStatus::Valid);
        assert_eq!(o.certificate_id.as_deref(), Some(cert_id.as_str()));
        assert_eq!(store.get_certificate(&cert_id).unwrap().chain_pem, "PEM");
    }
}
