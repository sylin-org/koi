//! Reload hooks, member roles, and CA unlock / auto-unlock.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

impl CertmeshCore {
    /// Set the post-renewal reload hook for a member.
    pub async fn set_reload_hook(&self, hostname: &str, hook: &str) -> Result<(), CertmeshError> {
        // Validate at domain boundary — all callers (HTTP, embedded, CLI) are
        // protected by the single source of truth in `validate_reload_hook`.
        validate_reload_hook(hook)?;
        // touch_roster: reload_hook is not bundle content, so no seq bump — but
        // the write still serializes behind the single writer (F8).
        self.state
            .touch_roster(|roster| {
                let member = roster.find_member_mut(hostname).ok_or_else(|| {
                    CertmeshError::NotFound(format!("member not found: {hostname}"))
                })?;
                member.reload_hook = Some(hook.to_string());
                Ok(())
            })
            .await?;

        tracing::info!(hostname, hook, "Reload hook set");
        Ok(())
    }

    /// Set the role of a member in the roster.
    pub async fn set_member_role(
        &self,
        hostname: &str,
        role: roster::MemberRole,
    ) -> Result<(), CertmeshError> {
        self.state
            .touch_roster(|roster| {
                let member = roster.find_member_mut(hostname).ok_or_else(|| {
                    CertmeshError::Internal(format!("member not found: {hostname}"))
                })?;
                member.role = role.clone();
                Ok(())
            })
            .await?;

        tracing::info!(hostname, role = ?role, "Member role updated");
        Ok(())
    }

    /// Unlock the CA with a passphrase.
    pub async fn unlock(&self, passphrase: &str) -> Result<(), CertmeshError> {
        let ca_state = match ca::load_ca(passphrase, &self.state.paths) {
            Ok(ca) => ca,
            Err(e) => {
                // Audit the failed unlock before returning (ADR-017 F9/F14).
                let _ = audit::append_entry_to(
                    &self.state.paths.audit_log_path(),
                    "unlock_failed",
                    &[("via", "passphrase")],
                );
                return Err(e);
            }
        };

        // Load auth credential from auth.json
        let auth_path = self.state.paths.auth_path();
        if auth_path.exists() {
            let json = std::fs::read_to_string(&auth_path)?;
            let stored: koi_crypto::auth::StoredAuth = serde_json::from_str(&json)
                .map_err(|e| CertmeshError::Internal(format!("auth.json parse error: {e}")))?;
            let auth_state = stored
                .unlock(passphrase)
                .map_err(|e| CertmeshError::Internal(format!("auth unlock failed: {e}")))?;
            *self.state.auth.lock().await = Some(auth_state);
        }

        *self.state.ca.lock().await = Some(ca_state);

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
        let ca_state = ca::load_ca_with_master_key(master_key, &self.state.paths)?;
        *self.state.ca.lock().await = Some(ca_state);
        tracing::info!("CA unlocked via master key (non-passphrase slot)");
        Ok(())
    }

    /// Unlock the CA using a TOTP code against the unlock slot table.
    ///
    /// Loads the slot table, verifies the TOTP code, unwraps the master
    /// key, and decrypts the CA key.
    pub async fn unlock_with_totp(&self, code: &str) -> Result<(), CertmeshError> {
        let slot_table =
            ca::load_slot_table(&self.state.paths.slot_table_path())?.ok_or_else(|| {
                CertmeshError::NoSlotFound(
                    "no slot table found - CA may use legacy passphrase format".into(),
                )
            })?;

        if !slot_table.has_totp_slot() {
            return Err(CertmeshError::NoSlotFound(
                "TOTP unlock is not configured for this CA".into(),
            ));
        }

        let master_key = slot_table.unwrap_with_totp(code).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("invalid TOTP code") {
                CertmeshError::InvalidAuth
            } else {
                CertmeshError::Crypto(msg)
            }
        })?;

        self.unlock_with_master_key(&master_key).await
    }

    // ── Auto-unlock key management ──────────────────────────────────

    /// Vault key under which the auto-unlock passphrase is stored.
    const VAULT_AUTO_UNLOCK_KEY: &'static str = "certmesh-auto-unlock";

    /// Save a passphrase for automatic unlock on reboot, rooted at explicit
    /// paths so the vault is co-located with the CA it unlocks.
    ///
    /// Uses the koi-crypto vault which automatically selects the strongest
    /// available backend: platform credential store (DPAPI, Keychain,
    /// Secret Service) first, machine-bound Argon2id derivation as fallback.
    /// The counterpart reader is [`Self::read_auto_unlock_key`].
    pub fn save_auto_unlock_key_at(
        paths: &CertmeshPaths,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        vault.store(Self::VAULT_AUTO_UNLOCK_KEY, passphrase)?;
        tracing::info!(
            backend = vault.backend_name(),
            "Auto-unlock key saved to vault"
        );
        // Remove any legacy file/credential store entries
        let _ = std::fs::remove_file(paths.auto_unlock_key_path());
        let _ = koi_crypto::tpm::delete_key_material("koi-auto-unlock");
        Ok(())
    }

    /// Read the stored auto-unlock passphrase from the vault, if any.
    ///
    /// The auto-unlock passphrase lives in the koi-crypto vault (written by
    /// [`Self::save_auto_unlock_key_at`], which deletes any legacy plaintext
    /// file). This is the **single source of truth** for that location:
    /// boot paths that need to unlock the CA at construction time call this
    /// instead of reading a plaintext file that no longer exists.
    ///
    /// Returns `Ok(None)` when no key is stored, `Ok(Some(pp))` when one is
    /// found, and `Err` when the vault cannot be opened or read.
    pub fn read_auto_unlock_key(
        paths: &CertmeshPaths,
    ) -> Result<Option<Zeroizing<String>>, CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        Ok(match vault.retrieve(Self::VAULT_AUTO_UNLOCK_KEY)? {
            Some(pp) if !pp.is_empty() => Some(Zeroizing::new(pp)),
            _ => None,
        })
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
        let bound_ok = tokio::task::spawn_blocking(move || machine_binding_ok(&paths))
            .await
            .unwrap_or(true);
        if !bound_ok {
            let _ = audit::append_entry_to(
                &self.state.paths.audit_log_path(),
                "auto_unlock_refused_machine_changed",
                &[],
            );
            tracing::error!(
                "machine fingerprint changed since CA creation (clone/restore?) — refusing \
                 auto-unlock. Run `koi certmesh unlock` to unlock manually on this host."
            );
            return Ok(false);
        }

        let passphrase = match Self::read_auto_unlock_key(&self.state.paths)? {
            Some(pp) => pp,
            None => return Ok(false),
        };
        self.unlock(&passphrase).await?;
        tracing::info!("CA auto-unlocked via vault");
        Ok(true)
    }

    /// Configure auto-unlock from the create-time `auto_unlock` decision.
    ///
    /// This is the **single source of truth** for the unlock-on-boot decision.
    /// When `auto_unlock` is true and a passphrase is present, the passphrase
    /// is saved to the koi-crypto vault (read back at boot by
    /// [`Self::read_auto_unlock_key`]) and the slot table is marked. Call it
    /// after CA creation from any init path (direct API or ceremony).
    pub fn configure_auto_unlock(
        &self,
        auto_unlock: bool,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        if auto_unlock && !passphrase.is_empty() {
            let paths = self.paths();
            Self::save_auto_unlock_key_at(paths, passphrase)?;

            // Mark auto-unlock in the slot table (if it exists)
            let slot_path = paths.slot_table_path();
            if let Some(mut table) = ca::load_slot_table(&slot_path)? {
                table.add_auto_unlock();
                ca::save_slot_table(&table, &slot_path)?;
            }
        }
        Ok(())
    }
}
