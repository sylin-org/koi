//! Reload hooks, member roles, and CA unlock / auto-unlock.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

struct PreparedUnlock {
    ca: ca::PreparedCaLoad,
    auth: Option<AuthState>,
}

fn prepare_unlock(
    passphrase: &str,
    paths: &CertmeshPaths,
) -> Result<PreparedUnlock, CertmeshError> {
    let ca = ca::prepare_ca_load(passphrase, paths)?;
    let auth_path = paths.auth_path();
    let auth = if auth_path.exists() {
        let json = std::fs::read_to_string(&auth_path)?;
        let stored: koi_crypto::auth::StoredAuth = serde_json::from_str(&json)
            .map_err(|error| CertmeshError::Internal(format!("auth.json parse error: {error}")))?;
        Some(
            stored
                .unlock(passphrase)
                .map_err(|error| CertmeshError::Internal(format!("auth unlock failed: {error}")))?,
        )
    } else {
        None
    };
    Ok(PreparedUnlock { ca, auth })
}

fn commit_prepared_unlock_under_transition(
    domain: &CertmeshDomain,
    prepared: PreparedUnlock,
) -> Result<(), CertmeshError> {
    let outcome = if let Some(migration) = prepared.ca.migration {
        let outcome =
            domain.commit_artifacts_under_transition(migration.transaction(&domain.paths))?;
        tracing::info!("CA key migrated to envelope encryption");
        Some(outcome)
    } else {
        None
    };
    if let Some(auth) = prepared.auth {
        *domain.auth.lock() = Some(auth);
    }
    *domain.ca.lock() = Some(prepared.ca.state);
    if let Some(outcome) = outcome {
        domain.finish_commit_under_transition(outcome)?;
    } else {
        domain.refresh_status_under_transition();
    }
    Ok(())
}

fn persist_unlock_failure(
    repository: &repository::CertmeshRepository,
    paths: &CertmeshPaths,
    via: &str,
) {
    let mut transaction = repository::ArtifactTransaction::new();
    let audit = transaction
        .append(
            paths.audit_log_path(),
            audit::render_entry("unlock_failed", &[("via", via)]),
            true,
        )
        .and_then(|()| repository.commit_durable(transaction));
    if let Err(error) = audit {
        tracing::warn!(%error, "Could not persist failed-unlock audit");
    }
}

impl CertmeshCore {
    /// Set the post-renewal reload hook for a member.
    pub async fn set_reload_hook(&self, hostname: &str, hook: &str) -> Result<(), CertmeshError> {
        self.set_reload_hook_for(None, hostname, hook).await
    }

    /// Set a hook with an optional mTLS principal. A remote principal may only
    /// mutate its own active roster entry; local management passes `None` after
    /// its DAT/loopback boundary has authenticated the operator.
    pub async fn set_reload_hook_for(
        &self,
        authenticated_cn: Option<&str>,
        hostname: &str,
        hook: &str,
    ) -> Result<(), CertmeshError> {
        // Validate at domain boundary — all callers (HTTP, embedded, CLI) are
        // protected by the single source of truth in `validate_reload_hook`.
        validate_reload_hook(hook)?;
        let authenticated_cn = authenticated_cn.map(str::to_string);
        let hostname = hostname.to_string();
        let hook = hook.to_string();
        let logged_hostname = hostname.clone();
        let logged_hook = hook.clone();
        self.run_blocking_transition(move |domain| {
            if authenticated_cn
                .as_deref()
                .is_some_and(|caller| caller != hostname)
            {
                return Err(CertmeshError::Forbidden(format!(
                    "authenticated principal may only set its own reload hook ({hostname})"
                )));
            }
            if domain.roster.lock().is_revoked(&hostname) {
                domain.commit_audit_under_transition(
                    "mtls_revoked_rejected",
                    &[("hostname", hostname.as_str()), ("op", "set_hook")],
                )?;
                return Err(CertmeshError::Revoked(hostname));
            }
            let ((), outcome) = domain.commit_roster_under_transition(
                false,
                Some(audit::render_entry(
                    "reload_hook_updated",
                    &[("hostname", hostname.as_str())],
                )),
                |roster| {
                    let member = roster.find_member_mut(&hostname).ok_or_else(|| {
                        CertmeshError::NotFound(format!("member not found: {hostname}"))
                    })?;
                    member.reload_hook = Some(hook);
                    Ok(())
                },
            )?;
            domain.finish_commit_under_transition(outcome)?;
            Ok::<(), CertmeshError>(())
        })
        .await??;

        tracing::info!(
            hostname = logged_hostname,
            hook = logged_hook,
            "Reload hook set"
        );
        Ok(())
    }

    /// Set the role of a member in the roster.
    pub async fn set_member_role(
        &self,
        hostname: &str,
        role: roster::MemberRole,
    ) -> Result<(), CertmeshError> {
        let hostname = hostname.to_string();
        let logged_hostname = hostname.clone();
        let committed_role = role.clone();
        self.run_blocking_transition(move |domain| {
            let ((), outcome) = domain.commit_roster_under_transition(true, None, |roster| {
                let member = roster.find_member_mut(&hostname).ok_or_else(|| {
                    CertmeshError::Internal(format!("member not found: {hostname}"))
                })?;
                member.role = committed_role;
                Ok(())
            })?;
            domain.finish_commit_under_transition(outcome)?;
            Ok::<(), CertmeshError>(())
        })
        .await??;

        tracing::info!(hostname = logged_hostname, role = ?role, "Member role updated");
        Ok(())
    }

    /// Unlock the CA with a passphrase.
    pub async fn unlock(&self, passphrase: &str) -> Result<(), CertmeshError> {
        let paths = self.state.paths.clone();
        let repository = Arc::clone(&self.state.repository);
        let passphrase = passphrase.to_string();
        self.run_blocking_transition(move |domain| match prepare_unlock(&passphrase, &paths) {
            Ok(prepared) => commit_prepared_unlock_under_transition(domain, prepared),
            Err(error) => {
                persist_unlock_failure(&repository, &paths, "passphrase");
                Err(error)
            }
        })
        .await??;

        tracing::info!("CA unlocked");
        Ok(())
    }

    /// Unlock the CA with a pre-unwrapped master key (TOTP or auto-unlock).
    ///
    /// This bypasses passphrase-based auth.json decryption. The auth
    /// credential (for API gating) is not loaded - callers should use
    /// the slot table's embedded TOTP shared_secret for verification
    /// if auth gating is needed.
    pub async fn unlock_with_master_key(&self, master_key: &[u8; 32]) -> Result<(), CertmeshError> {
        let paths = self.state.paths.clone();
        let master_key = *master_key;
        self.run_blocking_transition(move |domain| {
            let ca_state = ca::load_ca_with_master_key(&master_key, &paths)?;
            *domain.ca.lock() = Some(ca_state);
            tracing::info!("CA unlocked via master key (non-passphrase slot)");
            domain.refresh_status_under_transition();
            Ok(())
        })
        .await?
    }

    /// Unlock the CA using a TOTP code against the unlock slot table.
    ///
    /// Loads the slot table, verifies the TOTP code, unwraps the master
    /// key, and decrypts the CA key.
    pub async fn unlock_with_totp(&self, code: &str) -> Result<(), CertmeshError> {
        let paths = self.state.paths.clone();
        let code = code.to_string();
        self.run_blocking_transition(move |domain| {
            let slot_table = ca::load_slot_table(&paths.slot_table_path())?.ok_or_else(|| {
                CertmeshError::NoSlotFound(
                    "no slot table found - CA may use legacy passphrase format".into(),
                )
            })?;
            if !slot_table.has_totp_slot() {
                return Err(CertmeshError::NoSlotFound(
                    "TOTP unlock is not configured for this CA".into(),
                ));
            }
            let master_key = slot_table.unwrap_with_totp(&code).map_err(|error| {
                let message = error.to_string();
                if message.contains("invalid TOTP code") {
                    CertmeshError::InvalidAuth
                } else {
                    CertmeshError::Crypto(message)
                }
            })?;
            let ca_state = ca::load_ca_with_master_key(&master_key, &paths)?;
            *domain.ca.lock() = Some(ca_state);
            tracing::info!("CA unlocked via master key (non-passphrase slot)");
            domain.refresh_status_under_transition();
            Ok(())
        })
        .await?
    }

    // ── Auto-unlock key management ──────────────────────────────────

    /// Vault key under which the auto-unlock passphrase is stored.
    pub(crate) const VAULT_AUTO_UNLOCK_KEY: &'static str = "certmesh-auto-unlock";

    /// Save a passphrase for automatic unlock on reboot, rooted at explicit
    /// paths so the vault is co-located with the CA it unlocks.
    ///
    /// Uses the koi-crypto vault which automatically selects the strongest
    /// available backend: platform credential store (DPAPI, Keychain,
    /// Secret Service) first, machine-bound Argon2id derivation as fallback.
    /// The counterpart reader is [`Self::read_auto_unlock_key`].
    pub(crate) fn save_auto_unlock_key_at(
        paths: &CertmeshPaths,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        vault.store(Self::VAULT_AUTO_UNLOCK_KEY, passphrase)?;
        tracing::info!(
            backend = vault.backend_name(),
            "Auto-unlock key saved to vault"
        );
        // The aggregate command retires any legacy plaintext artifact through
        // its repository transaction. This helper owns only the Vault effect.
        let _ = koi_crypto::tpm::delete_key_material("koi-auto-unlock");
        Ok(())
    }

    /// Read the stored auto-unlock passphrase from the vault, if any.
    ///
    /// The auto-unlock passphrase lives in the koi-crypto vault (written by
    /// [`Self::save_auto_unlock_key_at`], which deletes any legacy plaintext
    /// file). The durable slot marker is the desired-state authority; this
    /// helper only reads credential material after that marker has been checked.
    ///
    /// Returns `Ok(None)` when no key is stored, `Ok(Some(pp))` when one is
    /// found, and `Err` when the vault cannot be opened or read.
    pub(crate) fn read_auto_unlock_key(
        paths: &CertmeshPaths,
    ) -> Result<Option<Zeroizing<String>>, CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        Ok(match vault.retrieve(Self::VAULT_AUTO_UNLOCK_KEY)? {
            Some(pp) if !pp.is_empty() => Some(Zeroizing::new(pp)),
            _ => None,
        })
    }

    /// Restore the exact vault value observed before a cross-store command.
    /// The durable slot marker remains the authority over whether this value is
    /// active; this compensation only avoids retaining an inert secret.
    pub(crate) fn restore_auto_unlock_key_at(
        paths: &CertmeshPaths,
        previous: Option<Zeroizing<String>>,
    ) -> Result<(), CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        match previous {
            Some(value) => vault.store(Self::VAULT_AUTO_UNLOCK_KEY, &value)?,
            None => {
                vault.delete(Self::VAULT_AUTO_UNLOCK_KEY)?;
            }
        }
        Ok(())
    }

    /// Try to auto-unlock the CA from the vault.
    ///
    /// Returns `Ok(true)` if the CA was unlocked, `Ok(false)` if no
    /// stored key exists, and `Err` if the key exists but decryption
    /// failed (corrupt key, changed passphrase, etc.).
    pub async fn try_auto_unlock(&self) -> Result<bool, CertmeshError> {
        // F11: refuse auto-unlock if the machine fingerprint changed since the CA
        // was created (a VM clone / disk restore onto new hardware). Fail-safe —
        // boot LOCKED and require a manual passphrase. Checked BEFORE touching the
        // vault so a cloned host can't auto-unlock with the copied vault key.
        // `machine_binding_ok` shells out on Windows/macOS, so run it off the
        // executor. (The real daemon boot path is `koi_compose::init_certmesh_core`,
        // which gates auto-unlock with the same free function — this method mirrors
        // it for embedded/programmatic callers.)
        let paths = self.state.paths.clone();
        let repository = Arc::clone(&self.state.repository);
        self.run_blocking_transition(move |domain| {
            let auto_unlock_enabled = ca::load_slot_table(&paths.slot_table_path())?
                .is_some_and(|table| table.has_auto_unlock());
            if !auto_unlock_enabled {
                // The durable marker is authoritative. Retire an inert
                // legacy credential through Vault's serialized transaction
                // boundary without opening or creating a master key.
                koi_crypto::vault::Vault::delete_persisted_entry(
                    paths.data_dir(),
                    CertmeshCore::VAULT_AUTO_UNLOCK_KEY,
                )?;
                return Ok(false);
            }
            if !machine_binding_ok(&paths) {
                let mut transaction = repository::ArtifactTransaction::new();
                let audit = transaction
                    .append(
                        paths.audit_log_path(),
                        audit::render_entry("auto_unlock_refused_machine_changed", &[]),
                        true,
                    )
                    .and_then(|()| repository.commit_durable(transaction));
                if let Err(error) = audit {
                    tracing::warn!(%error, "Could not persist auto-unlock refusal audit");
                }
                tracing::error!(
                    "machine fingerprint changed since CA creation (clone/restore?) — refusing \
                         auto-unlock. Run `koi certmesh unlock` to unlock manually on this host."
                );
                return Ok(false);
            }

            let passphrase = match CertmeshCore::read_auto_unlock_key(&paths)? {
                Some(passphrase) => passphrase,
                None => return Ok(false),
            };
            match prepare_unlock(&passphrase, &paths) {
                Ok(prepared) => {
                    commit_prepared_unlock_under_transition(domain, prepared)?;
                    tracing::info!("CA auto-unlocked via vault");
                    Ok(true)
                }
                Err(error) => {
                    persist_unlock_failure(&repository, &paths, "auto");
                    Err(error)
                }
            }
        })
        .await?
    }
}
