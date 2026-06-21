//! ACME accounts (RFC 8555 §7.1.2) and their persistence.
//!
//! An account is identified by its EC public key (the JWK in the newAccount
//! request). Its stable id is the RFC 7638 thumbprint of that JWK. Every
//! subsequent ACME request authenticates by `kid` = the account URL, which
//! embeds the account id; the server looks the account's JWK back up by id and
//! verifies the request signature against it.
//!
//! **Persistence:** accounts persist to `certmesh/acme/accounts.json`. A real
//! ACME client (Caddy/Traefik/lego) caches its account URL + key and renews
//! after a daemon restart — if the account vanished on restart, the client would
//! get `accountDoesNotExist` and renewals would break. Nonces and orders are
//! short-lived and stay in memory.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::acme::jws::{self, Jwk};
use crate::error::CertmeshError;

/// A registered ACME account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// The account id — the RFC 7638 thumbprint of the account JWK. Stable,
    /// derived, and used to build the account URL (`/acme/acct/<id>`).
    pub id: String,
    /// The account's EC public key (its identity). All requests by this account
    /// are verified against this JWK.
    pub jwk: Jwk,
    /// Contact URIs supplied at registration (informational only).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Account status (`valid` / `deactivated`).
    pub status: AccountStatus,
}

/// ACME account status (RFC 8555 §7.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
}

/// The on-disk account database.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AccountDb {
    accounts: Vec<Account>,
}

/// A concurrency-safe, persisted account store.
pub struct AccountStore {
    accounts: Mutex<HashMap<String, Account>>,
    path: std::path::PathBuf,
}

impl AccountStore {
    /// Load the account store from `path` (or start empty if absent).
    pub fn load(path: &Path) -> Self {
        let map = match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<AccountDb>(&json) {
                Ok(db) => db.accounts.into_iter().map(|a| (a.id.clone(), a)).collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "ACME accounts.json parse failed; starting empty");
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Self {
            accounts: Mutex::new(map),
            path: path.to_path_buf(),
        }
    }

    /// Find an account by its JWK thumbprint id.
    pub fn get(&self, id: &str) -> Option<Account> {
        self.accounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Register a new account for `jwk`, or return the existing one if this key
    /// already registered (newAccount is idempotent on the key — RFC 8555 §7.3).
    ///
    /// Returns `(account, created)` where `created` is false for an existing key.
    pub fn register(
        &self,
        jwk: Jwk,
        contacts: Vec<String>,
    ) -> Result<(Account, bool), CertmeshError> {
        let id = jws::jwk_thumbprint(&jwk);
        let mut map = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(&id) {
            return Ok((existing.clone(), false));
        }
        let account = Account {
            id: id.clone(),
            jwk,
            contacts,
            status: AccountStatus::Valid,
        };
        map.insert(id, account.clone());
        let snapshot: Vec<Account> = map.values().cloned().collect();
        drop(map);
        self.persist(&snapshot)?;
        Ok((account, true))
    }

    /// Persist the current account set to disk (atomic via koi_common::persist).
    fn persist(&self, accounts: &[Account]) -> Result<(), CertmeshError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = AccountDb {
            accounts: accounts.to_vec(),
        };
        koi_common::persist::write_json_pretty(&self.path, &db).map_err(CertmeshError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use p256::ecdsa::SigningKey;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    }

    fn random_jwk() -> Jwk {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64().encode(point.x().unwrap()),
            y: b64().encode(point.y().unwrap()),
        }
    }

    #[test]
    fn register_is_idempotent_on_key() {
        let dir = std::env::temp_dir().join("koi-acme-acct-test-1");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("accounts.json");
        let store = AccountStore::load(&path);

        let jwk = random_jwk();
        let (a1, created1) = store.register(jwk.clone(), vec![]).unwrap();
        assert!(created1);
        let (a2, created2) = store.register(jwk, vec![]).unwrap();
        assert!(!created2, "same key must NOT create a second account");
        assert_eq!(a1.id, a2.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accounts_persist_across_reload() {
        let dir = std::env::temp_dir().join("koi-acme-acct-test-2");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("accounts.json");

        let id = {
            let store = AccountStore::load(&path);
            let (a, _) = store.register(random_jwk(), vec![]).unwrap();
            a.id
        };
        // Reload from disk: the account must still be there (renewal survival).
        let store2 = AccountStore::load(&path);
        assert!(
            store2.get(&id).is_some(),
            "account must survive a reload (daemon restart)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_account_is_none() {
        let dir = std::env::temp_dir().join("koi-acme-acct-test-3");
        let _ = std::fs::remove_dir_all(&dir);
        let store = AccountStore::load(&dir.join("accounts.json"));
        assert!(store.get("nonexistent-thumbprint").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
