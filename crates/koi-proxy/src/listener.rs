use std::net::SocketAddr;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::ProxyEntry;
use crate::forwarder::{forward_request, ForwardState};
use crate::ProxyError;

pub struct ProxyListener {
    entry: ProxyEntry,
    cancel: CancellationToken,
    config: RustlsConfig,
    watcher: Option<RecommendedWatcher>,
}

impl ProxyListener {
    pub async fn new(entry: ProxyEntry, cancel: CancellationToken) -> Result<Self, ProxyError> {
        let tls = load_tls_config(&entry).await?;
        Ok(Self {
            entry,
            cancel,
            config: tls,
            watcher: None,
        })
    }

    pub async fn run(self) -> Result<(), ProxyError> {
        let backend = Url::parse(&self.entry.backend)
            .map_err(|e| ProxyError::InvalidConfig(format!("Invalid backend URL: {e}")))?;

        let forward_state = ForwardState {
            backend,
            client: reqwest::Client::new(),
        };

        let app = Router::new()
            .route("/", any(proxy_handler))
            .route("/*path", any(proxy_handler))
            .with_state(forward_state);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.entry.listen_port));
        let cancel = self.cancel.clone();
        let server = axum_server::bind_rustls(addr, self.config.clone())
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());

        tokio::select! {
            result = server => {
                result.map_err(|e| ProxyError::Io(e.to_string()))?;
            }
            _ = cancel.cancelled() => {
                return Ok(());
            }
        }

        Ok(())
    }

    pub async fn watch_certs(&mut self) -> Result<(), ProxyError> {
        let cert_dir_path = cert_dir(&self.entry);
        let entry = self.entry.clone();
        let config = self.config.clone();

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |_| {
            let entry = entry.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let cert = cert_dir(&entry).join("fullchain.pem");
                let key = cert_dir(&entry).join("key.pem");
                if let Err(e) = config.reload_from_pem_file(cert, key).await {
                    tracing::warn!(error = %e, name = %entry.name, "Proxy TLS reload failed");
                } else {
                    tracing::info!(name = %entry.name, "Proxy TLS config reloaded");
                }
            });
        })
        .map_err(|e| ProxyError::Io(e.to_string()))?;

        watcher
            .watch(&cert_dir_path, RecursiveMode::NonRecursive)
            .map_err(|e| ProxyError::Io(e.to_string()))?;

        self.watcher = Some(watcher);
        Ok(())
    }
}

async fn proxy_handler(
    State(state): State<ForwardState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> impl IntoResponse {
    match forward_request(State(state), req, Some(addr)).await {
        Ok(resp) => resp.into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({
                "error": "proxy_error",
                "message": e.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn load_tls_config(entry: &ProxyEntry) -> Result<RustlsConfig, ProxyError> {
    let cert = cert_dir(entry).join("fullchain.pem");
    let key = cert_dir(entry).join("key.pem");
    RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|e| ProxyError::Io(e.to_string()))
}

fn cert_dir(entry: &ProxyEntry) -> std::path::PathBuf {
    koi_common::paths::koi_certs_dir().join(&entry.name)
}
