//! TLS termination for the proxy data plane: hot-reloadable certificate resolution.
//!
//! A single [`rustls::ServerConfig`] is built once per listener; its
//! [`ResolvesServerCert`] reads the current [`CertifiedKey`] from a lock on every
//! handshake, so swapping the key (when a cert file changes on disk) is picked up
//! on the next handshake with **no listener restart** — hot reload is free.
//!
//! The certificate is resolved in priority order:
//! 1. `certs/<entry.name>/{fullchain.pem,key.pem}` — explicit per-entry cert
//! 2. `certs/<hostname>/{fullchain.pem,key.pem}`   — the local certmesh member cert
//! 3. a generated self-signed cert (zero-config fallback)
//!
//! The cert watcher bridges `notify` (which runs on its own non-tokio thread) into
//! a tokio task via a channel — it **never** calls `tokio::spawn` from notify's
//! thread, which is the second latent panic the old data plane carried.

use std::io::BufReader;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

use notify::{RecursiveMode, Watcher};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio_util::sync::CancellationToken;

use crate::config::ProxyEntry;
use crate::ProxyError;

/// Where a listener's certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
    /// A cert/key pair was found on disk (certmesh deposits certs there).
    Certmesh,
    /// No usable cert on disk; a self-signed cert was generated.
    SelfSigned,
}

impl CertSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CertSource::Certmesh => "certmesh",
            CertSource::SelfSigned => "self-signed",
        }
    }
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
    pub cert_source: CertSource,
    pub resolver: Arc<CertResolver>,
}

/// Build a [`ServerConfig`] for an entry, resolving (or generating) its cert.
pub fn build_tls(entry: &ProxyEntry) -> Result<TlsSetup, ProxyError> {
    let (certified, cert_source) = resolve_initial(entry)?;
    let resolver = Arc::new(CertResolver::new(certified));

    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::Io(format!("tls config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>);

    Ok(TlsSetup {
        config: Arc::new(config),
        cert_source,
        resolver,
    })
}

/// Spawn the cert-change watcher. Returns the [`notify::RecommendedWatcher`], which
/// the caller must keep alive for the listener's lifetime. Hot reload is best-effort:
/// any failure to set up the watcher disables reload but never fails the listener.
pub fn spawn_cert_watcher(
    entry: ProxyEntry,
    resolver: Arc<CertResolver>,
    cancel: CancellationToken,
) -> Option<notify::RecommendedWatcher> {
    let certs_dir = koi_common::paths::koi_certs_dir();
    if let Err(e) = std::fs::create_dir_all(&certs_dir) {
        tracing::warn!(error = %e, "Proxy cert watcher: cannot create certs dir; hot-reload disabled");
        return None;
    }

    // Bounded channel coalesces bursts of fs events. `try_send` from notify's
    // thread is non-blocking and needs no tokio runtime context.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(8);
    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if res.is_ok() {
                let _ = tx.try_send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = %e, "Proxy cert watcher: init failed; hot-reload disabled");
                return None;
            }
        };

    if let Err(e) = watcher.watch(&certs_dir, RecursiveMode::Recursive) {
        tracing::warn!(error = %e, dir = %certs_dir.display(),
            "Proxy cert watcher: watch failed; hot-reload disabled");
        return None;
    }

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => {
                    if msg.is_none() {
                        break;
                    }
                    // Drain any coalesced events before reloading once.
                    while rx.try_recv().is_ok() {}
                    reload_cert(&entry, &resolver).await;
                }
            }
        }
    });

    Some(watcher)
}

/// Re-read the on-disk cert (if any) and swap it in. A missing on-disk cert is a
/// no-op: we keep the current (possibly self-signed) cert rather than churning a
/// fresh self-signed one on every unrelated filesystem event.
async fn reload_cert(entry: &ProxyEntry, resolver: &Arc<CertResolver>) {
    let entry = entry.clone();
    let built =
        tokio::task::spawn_blocking(move || find_file_cert(&entry).map(|ck| (ck, entry.name)))
            .await
            .ok()
            .flatten();
    if let Some((certified, name)) = built {
        resolver.swap(certified);
        tracing::info!(name = %name, "Proxy TLS cert reloaded");
    }
}

/// Resolve the initial cert: an on-disk pair if present, else self-signed.
fn resolve_initial(entry: &ProxyEntry) -> Result<(Arc<CertifiedKey>, CertSource), ProxyError> {
    if let Some(certified) = find_file_cert(entry) {
        return Ok((certified, CertSource::Certmesh));
    }
    let (cert_pem, key_pem) = generate_self_signed(entry)?;
    let certified = build_certified_key(&cert_pem, &key_pem)?;
    Ok((certified, CertSource::SelfSigned))
}

/// Candidate cert directories, in priority order.
fn cert_candidate_dirs(entry: &ProxyEntry) -> Vec<PathBuf> {
    let certs = koi_common::paths::koi_certs_dir();
    let mut dirs = vec![certs.join(&entry.name)];
    if let Ok(host) = hostname::get() {
        let host = host.to_string_lossy().to_string();
        if !host.is_empty() && host != entry.name {
            dirs.push(certs.join(host));
        }
    }
    dirs
}

/// Find and parse the first usable on-disk cert pair for an entry, or `None`.
fn find_file_cert(entry: &ProxyEntry) -> Option<Arc<CertifiedKey>> {
    for dir in cert_candidate_dirs(entry) {
        let cert = dir.join("fullchain.pem");
        let key = dir.join("key.pem");
        if !(cert.is_file() && key.is_file()) {
            continue;
        }
        let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(&cert), std::fs::read(&key)) else {
            continue;
        };
        match build_certified_key(&cert_pem, &key_pem) {
            Ok(certified) => return Some(certified),
            Err(e) => tracing::warn!(
                name = %entry.name, dir = %dir.display(), error = %e,
                "Proxy cert files present but unusable; trying next source"
            ),
        }
    }
    None
}

/// Generate a self-signed cert/key PEM pair for an entry.
fn generate_self_signed(entry: &ProxyEntry) -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
    let mut sans = vec!["localhost".to_string()];
    if !entry.name.is_empty() && entry.name != "localhost" {
        sans.push(entry.name.clone());
    }
    if let Ok(host) = hostname::get() {
        let host = host.to_string_lossy().to_string();
        if !host.is_empty() && !sans.contains(&host) {
            sans.push(host);
        }
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
    let mut cert_reader = BufReader::new(cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| ProxyError::Io(format!("cert parse: {e}")))?;
    if certs.is_empty() {
        return Err(ProxyError::Io("no certificates in PEM".to_string()));
    }

    let mut key_reader = BufReader::new(key_pem);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| ProxyError::Io(format!("key parse: {e}")))?
        .ok_or_else(|| ProxyError::Io("no private key in PEM".to_string()))?;

    let signing_key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| ProxyError::Io(format!("load private key: {e}")))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Process-wide rustls crypto provider (aws-lc-rs, the workspace default). Built
/// explicitly to avoid depending on a global `install_default` ordering elsewhere
/// in the daemon (reqwest / axum-server also use rustls).
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}
