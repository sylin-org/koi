//! TLS termination for the proxy data plane: hot-reloadable certificate resolution.
//!
//! Proxy owns explicit per-entry overrides under `proxy-certs/<entry>/`. A
//! Certmesh identity is supplied through a typed, in-process composition port;
//! this domain never discovers another domain by reading its files. The selected
//! identity changes on the next handshake without restarting the listener.

use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};

use notify::{RecursiveMode, Watcher};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_common::integration::{TlsIdentitySnapshot, TlsIdentitySource};

use crate::config::ProxyEntry;
use crate::ProxyError;

/// Where a listener's certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
    /// An operator-managed pair was found in Proxy's per-entry override directory.
    Override,
    /// The local trust-domain identity arrived through the composition port.
    Certmesh,
    /// No usable cert on disk; a self-signed cert was generated.
    SelfSigned,
}

impl CertSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CertSource::Override => "override",
            CertSource::Certmesh => "certmesh",
            CertSource::SelfSigned => "self-signed",
        }
    }
}

/// Observable certificate selection. Revision changes only when either the
/// selected bytes or their provenance changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertSelectionStatus {
    pub revision: u64,
    pub source: CertSource,
}

struct SelectedCert {
    certified: Arc<CertifiedKey>,
    source: CertSource,
    change_token: [u8; 32],
}

/// A [`ResolvesServerCert`] whose certificate can be swapped at runtime.
#[derive(Debug)]
pub struct CertResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl CertResolver {
    fn new(initial: Arc<CertifiedKey>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    fn swap(&self, next: Arc<CertifiedKey>) {
        if let Ok(mut guard) = self.current.write() {
            *guard = next;
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().map(|guard| Arc::clone(&guard))
    }
}

/// The result of building a listener's TLS state.
pub struct TlsSetup {
    pub config: Arc<ServerConfig>,
    pub cert_status: watch::Receiver<CertSelectionStatus>,
    /// Kept alive by the listener. Certmesh observation is an async task and
    /// needs no filesystem watcher.
    pub override_watcher: Option<notify::RecommendedWatcher>,
    /// Async certificate observers owned by the listener that consumes this
    /// setup. They are never detached from the listener lifecycle.
    pub background: TlsBackground,
}

/// Owned async portion of one listener's certificate selection pipeline.
pub struct TlsBackground {
    tasks: Vec<JoinHandle<()>>,
}

impl TlsBackground {
    pub async fn shutdown_until(&mut self, deadline: tokio::time::Instant) {
        for task in &mut self.tasks {
            if task.is_finished() {
                let _ = (&mut *task).await;
                continue;
            }
            if tokio::time::timeout_at(deadline, &mut *task).await.is_err() {
                task.abort();
                let _ = (&mut *task).await;
            }
        }
        self.tasks.clear();
    }
}

impl Drop for TlsBackground {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Build a [`ServerConfig`] and arm both certificate inputs before returning.
pub fn build_tls(
    entry: &ProxyEntry,
    certificate_overrides_dir: &Path,
    tls_identity: Option<Arc<dyn TlsIdentitySource>>,
    cancel: CancellationToken,
) -> Result<TlsSetup, ProxyError> {
    let (fallback_cert, fallback_key) = generate_self_signed(entry)?;
    let fallback = build_certified_key(&fallback_cert, &fallback_key)?;

    // Subscribe before the initial read so a Certmesh rotation racing startup
    // is either selected now or remains pending on the watch receiver.
    let identity_watch = tls_identity
        .as_ref()
        .map(|source| source.watch_tls_identity());
    let initial_identity = identity_watch
        .as_ref()
        .map(|status| status.borrow().clone());

    let override_dir = certificate_overrides_dir.join(&entry.name);
    let (updates_tx, updates_rx) = mpsc::channel(8);
    let override_watcher = spawn_override_watcher(&override_dir, updates_tx.clone());

    let selected = select_cert(entry, &override_dir, initial_identity.as_deref(), &fallback);
    let resolver = Arc::new(CertResolver::new(Arc::clone(&selected.certified)));

    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::Io(format!("tls config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>);

    let initial_status = CertSelectionStatus {
        revision: 0,
        source: selected.source,
    };
    let (status_tx, status_rx) = watch::channel(initial_status);
    let mut background = Vec::with_capacity(2);
    if let Some(task) = spawn_identity_signal(identity_watch, updates_tx.clone(), cancel.clone()) {
        background.push(task);
    }
    drop(updates_tx);
    background.push(spawn_selection_observer(
        entry.clone(),
        override_dir,
        tls_identity,
        fallback,
        selected.change_token,
        Arc::clone(&resolver),
        status_tx,
        updates_rx,
        cancel,
    ));

    Ok(TlsSetup {
        config: Arc::new(config),
        cert_status: status_rx,
        override_watcher,
        background: TlsBackground { tasks: background },
    })
}

/// Bridge filesystem callbacks into the bounded async update channel. Failure
/// disables only explicit override hot reload; the Certmesh port remains live.
fn spawn_override_watcher(
    override_dir: &Path,
    updates: mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    if let Err(error) = std::fs::create_dir_all(override_dir) {
        tracing::warn!(
            %error,
            dir = %override_dir.display(),
            "Proxy certificate override directory unavailable"
        );
        return None;
    }
    let mut watcher =
        match notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
            if result.is_ok() {
                let _ = updates.try_send(());
            }
        }) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::warn!(%error, "Proxy certificate override watcher unavailable");
                return None;
            }
        };
    if let Err(error) = watcher.watch(override_dir, RecursiveMode::NonRecursive) {
        tracing::warn!(
            %error,
            dir = %override_dir.display(),
            "Proxy certificate override watch unavailable"
        );
        return None;
    }
    Some(watcher)
}

fn spawn_identity_signal(
    identity: Option<watch::Receiver<Arc<TlsIdentitySnapshot>>>,
    updates: mpsc::Sender<()>,
    cancel: CancellationToken,
) -> Option<JoinHandle<()>> {
    let mut identity = identity?;
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = identity.changed() => {
                    if changed.is_err() || updates.send(()).await.is_err() {
                        break;
                    }
                }
            }
        }
    }))
}

#[allow(clippy::too_many_arguments)]
fn spawn_selection_observer(
    entry: ProxyEntry,
    override_dir: std::path::PathBuf,
    tls_identity: Option<Arc<dyn TlsIdentitySource>>,
    fallback: Arc<CertifiedKey>,
    mut selected_token: [u8; 32],
    resolver: Arc<CertResolver>,
    status: watch::Sender<CertSelectionStatus>,
    mut updates: mpsc::Receiver<()>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                update = updates.recv() => {
                    if update.is_none() {
                        break;
                    }
                    // Atomic file replacement can emit a burst. Give the pair a
                    // moment to settle, then collapse every queued notification.
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    while updates.try_recv().is_ok() {}
                    let identity = tls_identity.as_ref().map(|provider| provider.tls_identity());
                    let selected = select_cert(
                        &entry,
                        &override_dir,
                        identity.as_deref(),
                        &fallback,
                    );
                    let current = *status.borrow();
                    if current.source != selected.source
                        || selected_token != selected.change_token
                    {
                        selected_token = selected.change_token;
                        resolver.swap(selected.certified);
                        status.send_replace(CertSelectionStatus {
                            revision: current.revision.saturating_add(1),
                            source: selected.source,
                        });
                    }
                }
            }
        }
    })
}

/// Select from independent, explicitly owned inputs. A bad or removed higher
/// priority source falls through immediately; it never leaves stale key material
/// in the live resolver.
fn select_cert(
    entry: &ProxyEntry,
    override_dir: &Path,
    identity: Option<&TlsIdentitySnapshot>,
    fallback: &Arc<CertifiedKey>,
) -> SelectedCert {
    if let Some((certified, change_token)) = find_override_cert(entry, override_dir) {
        return SelectedCert {
            certified,
            source: CertSource::Override,
            change_token,
        };
    }
    if let Some(material) = identity.and_then(|snapshot| snapshot.material.as_ref()) {
        match build_certified_key(
            material.certificate_chain_pem.as_bytes(),
            material.private_key_pem.as_bytes(),
        ) {
            Ok(certified) => {
                return SelectedCert {
                    certified,
                    source: CertSource::Certmesh,
                    change_token: material_token(
                        material.certificate_chain_pem.as_bytes(),
                        material.private_key_pem.as_bytes(),
                    ),
                }
            }
            Err(error) => tracing::warn!(
                name = %entry.name,
                identity = %material.hostname,
                %error,
                "Composed TLS identity was unusable; using self-signed fallback"
            ),
        }
    }
    SelectedCert {
        certified: Arc::clone(fallback),
        source: CertSource::SelfSigned,
        // One fallback is generated per listener and retained for its lifetime.
        change_token: [0; 32],
    }
}

fn find_override_cert(entry: &ProxyEntry, dir: &Path) -> Option<(Arc<CertifiedKey>, [u8; 32])> {
    let cert = dir.join("fullchain.pem");
    let key = dir.join("key.pem");
    if !(cert.is_file() && key.is_file()) {
        return None;
    }
    let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(&cert), std::fs::read(&key)) else {
        return None;
    };
    match build_certified_key(&cert_pem, &key_pem) {
        Ok(certified) => Some((certified, material_token(&cert_pem, &key_pem))),
        Err(error) => {
            tracing::warn!(
                name = %entry.name,
                dir = %dir.display(),
                %error,
                "Proxy certificate override is unusable; trying next source"
            );
            None
        }
    }
}

/// Process-local equality token only. Length-prefixing makes the two inputs
/// unambiguous; SHA-256 avoids treating a non-cryptographic hash collision as
/// "unchanged" and accidentally retaining stale key material.
fn material_token(certificate: &[u8], private_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(certificate.len().to_le_bytes());
    hasher.update(certificate);
    hasher.update(private_key.len().to_le_bytes());
    hasher.update(private_key);
    hasher.finalize().into()
}

/// Generate a self-signed cert/key PEM pair for an entry.
fn generate_self_signed(entry: &ProxyEntry) -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
    let mut sans = vec!["localhost".to_string()];
    if !entry.name.is_empty() && entry.name != "localhost" {
        sans.push(entry.name.clone());
    }
    let generated = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| ProxyError::Io(format!("self-signed cert generation failed: {e}")))?;
    Ok((
        generated.cert.pem().into_bytes(),
        generated.key_pair.serialize_pem().into_bytes(),
    ))
}

/// Parse PEM cert chain + private key into a rustls [`CertifiedKey`].
fn build_certified_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, ProxyError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| ProxyError::Io(format!("cert parse: {e}")))?;
    if certs.is_empty() {
        return Err(ProxyError::Io("no certificates in PEM".to_string()));
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| ProxyError::Io(format!("key parse: {e}")))?;

    let signing_key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| ProxyError::Io(format!("load private key: {e}")))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Process-wide rustls crypto provider (aws-lc-rs, the workspace default). Built
/// explicitly to avoid depending on a global `install_default` ordering elsewhere
/// in the daemon (reqwest / axum-server also use rustls).
///
/// Key-exchange preference is classic-only, deliberately: rustls 0.23.4x's
/// aws-lc-rs default puts the X25519MLKEM768 hybrid FIRST, and Windows Schannel
/// fails that handshake outright at the LSA (SEC_E_INTERNAL_ERROR) even when the
/// client itself offers the group — measured 2026-08-27 against Schannel curl on
/// Windows 10.0.26200 (mirrors koi-certmesh's provider rationale).
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            provider.kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            ];
            Arc::new(provider)
        })
        .clone()
}

#[cfg(test)]
mod kx_group_tests {
    use super::*;

    /// The proxy's TLS must never offer a post-quantum hybrid: Schannel cannot
    /// complete that handshake, and OS-native clients are the product surface.
    #[test]
    fn key_exchange_preference_is_classic_only() {
        use rustls::NamedGroup;
        let groups: Vec<NamedGroup> = provider().kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            vec![
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1
            ]
        );
    }
}
