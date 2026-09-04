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
#[derive(Default)]
pub struct AccountStore {
    accounts: Mutex<HashMap<String, Account>>,
}

pub(crate) struct PreparedAccountRegistration {
    pub(crate) account: Account,
    pub(crate) created: bool,
    pub(crate) bytes: Option<Vec<u8>>,
}

pub(crate) struct PreparedAccountReplacement {
    accounts: HashMap<String, Account>,
    pub(crate) bytes: Option<Vec<u8>>,
}

impl AccountStore {
    /// Load the durable account registry. Only `NotFound` means an empty store;
    /// corruption and other filesystem failures make aggregate bootstrap fail.
    pub(crate) fn load(path: &Path) -> Result<Self, CertmeshError> {
        let map = match std::fs::read_to_string(path) {
            Ok(json) => {
                Self::prepare_replacement(Some(&json))
                    .map_err(|error| {
                        CertmeshError::Internal(format!(
                            "persisted ACME account registry at '{}' is invalid: {error}",
                            path.display()
                        ))
                    })?
                    .accounts
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(CertmeshError::Io(error)),
        };
        Ok(Self {
            accounts: Mutex::new(map),
        })
    }

    /// Find an account by its JWK thumbprint id.
    pub fn get(&self, id: &str) -> Option<Account> {
        self.accounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Forget every account only after the owning Certmesh transaction removed
    /// or replaced the persisted account database.
    pub(crate) fn clear(&self) {
        self.accounts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    /// Snapshot the durable account model for encrypted backup or authority
    /// promotion. Empty registries stay absent on the wire and on disk.
    pub(crate) fn export_json(&self) -> Result<Option<String>, CertmeshError> {
        let map = self
            .accounts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if map.is_empty() {
            return Ok(None);
        }
        let mut accounts = map.values().cloned().collect::<Vec<_>>();
        accounts.sort_by(|left, right| left.id.cmp(&right.id));
        serde_json::to_string(&AccountDb { accounts })
            .map(Some)
            .map_err(|error| CertmeshError::Internal(format!("serialize ACME accounts: {error}")))
    }

    /// Validate and canonicalize a transferred account registry without
    /// changing the live model. The caller commits `bytes` with the rest of the
    /// Certmesh generation, then calls [`Self::commit_replacement`].
    pub(crate) fn prepare_replacement(
        json: Option<&str>,
    ) -> Result<PreparedAccountReplacement, CertmeshError> {
        let Some(json) = json else {
            return Ok(PreparedAccountReplacement {
                accounts: HashMap::new(),
                bytes: None,
            });
        };
        let db: AccountDb = serde_json::from_str(json).map_err(|error| {
            CertmeshError::InvalidPayload(format!("invalid transferred ACME accounts: {error}"))
        })?;
        let mut accounts = HashMap::with_capacity(db.accounts.len());
        for account in db.accounts {
            let expected = jws::jwk_thumbprint(&account.jwk);
            if account.id != expected {
                return Err(CertmeshError::InvalidPayload(format!(
                    "ACME account id '{}' does not match its key",
                    account.id
                )));
            }
            if accounts.insert(account.id.clone(), account).is_some() {
                return Err(CertmeshError::InvalidPayload(
                    "transferred ACME account registry contains duplicate ids".into(),
                ));
            }
        }
        let bytes = if accounts.is_empty() {
            None
        } else {
            let mut snapshot = accounts.values().cloned().collect::<Vec<_>>();
            snapshot.sort_by(|left, right| left.id.cmp(&right.id));
            Some(
                serde_json::to_vec_pretty(&AccountDb { accounts: snapshot }).map_err(|error| {
                    CertmeshError::Internal(format!("serialize ACME accounts: {error}"))
                })?,
            )
        };
        Ok(PreparedAccountReplacement { accounts, bytes })
    }

    /// Publish a transferred registry only after its artifact transaction has
    /// committed.
    pub(crate) fn commit_replacement(&self, prepared: PreparedAccountReplacement) {
        *self
            .accounts
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = prepared.accounts;
    }

    /// Prepare a registration without mutating live state or persistence.
    pub(crate) fn prepare_registration(
        &self,
        jwk: Jwk,
        contacts: Vec<String>,
    ) -> Result<PreparedAccountRegistration, CertmeshError> {
        let id = jws::jwk_thumbprint(&jwk);
        let map = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(&id) {
            return Ok(PreparedAccountRegistration {
                account: existing.clone(),
                created: false,
                bytes: None,
            });
        }
        let account = Account {
            id: id.clone(),
            jwk,
            contacts,
            status: AccountStatus::Valid,
        };
        let mut snapshot = map.values().cloned().collect::<Vec<_>>();
        snapshot.push(account.clone());
        snapshot.sort_by(|left, right| left.id.cmp(&right.id));
        let bytes =
            serde_json::to_vec_pretty(&AccountDb { accounts: snapshot }).map_err(|error| {
                CertmeshError::Internal(format!("serialize ACME accounts: {error}"))
            })?;
        Ok(PreparedAccountRegistration {
            account,
            created: true,
            bytes: Some(bytes),
        })
    }

    /// Apply a registration only after its aggregate artifact committed.
    pub(crate) fn commit_registration(&self, prepared: &PreparedAccountRegistration) {
        if prepared.created {
            self.accounts
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(prepared.account.id.clone(), prepared.account.clone());
        }
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

    fn register(
        store: &AccountStore,
        path: &Path,
        jwk: Jwk,
        contacts: Vec<String>,
    ) -> Result<(Account, bool), CertmeshError> {
        let prepared = store.prepare_registration(jwk, contacts)?;
        if let Some(bytes) = &prepared.bytes {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, bytes)?;
        }
        store.commit_registration(&prepared);
        Ok((prepared.account, prepared.created))
    }

    #[test]
    fn register_is_idempotent_on_key() {
        let dir = std::env::temp_dir().join("koi-acme-acct-test-1");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("accounts.json");
        let store = AccountStore::load(&path).unwrap();

        let jwk = random_jwk();
        let (a1, created1) = register(&store, &path, jwk.clone(), vec![]).unwrap();
        assert!(created1);
        let (a2, created2) = register(&store, &path, jwk, vec![]).unwrap();
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
            let store = AccountStore::load(&path).unwrap();
            let (a, _) = register(&store, &path, random_jwk(), vec![]).unwrap();
            a.id
        };
        // Reload from disk: the account must still be there (renewal survival).
        let store2 = AccountStore::load(&path).unwrap();
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
        let store = AccountStore::load(&dir.join("accounts.json")).unwrap();
        assert!(store.get("nonexistent-thumbprint").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_persisted_accounts_fail_instead_of_becoming_empty() {
        let dir = std::env::temp_dir().join(format!(
            "koi-acme-acct-corrupt-{}",
            koi_common::id::generate_short_id()
        ));
        let path = dir.join("accounts.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ definitely not account json").unwrap();

        let error = match AccountStore::load(&path) {
            Ok(_) => panic!("corrupt account registry must fail"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted ACME account registry")),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_not_found_account_read_errors_are_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "koi-acme-acct-read-error-{}",
            koi_common::id::generate_short_id()
        ));
        let path = dir.join("accounts.json");
        std::fs::create_dir_all(&path).unwrap();

        assert!(matches!(
            AccountStore::load(&path),
            Err(CertmeshError::Io(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
