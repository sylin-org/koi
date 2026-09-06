//! Optional server-auth HTTPS for private browser access; never an operator router.
use crate::browser_access::{BrowserAccess, BrowserSurface};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

struct Live {
    revision: u64,
    cancel: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}
impl Drop for Live {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

pub(crate) async fn supervise(
    access: BrowserAccess,
    catalog: Arc<koi_compose::catalog::ServiceCatalogRuntime>,
    cancel: CancellationToken,
) {
    let mut identity_rx = access.identity().map(|source| source.watch_tls_identity());
    let mut live: Option<Live> = None;
    loop {
        let identity = access.identity().map(|source| source.tls_identity());
        let desired = access.status().settings.phone;
        let revision = identity
            .as_ref()
            .and_then(|s| s.material.as_ref().map(|_| s.revision));
        if live.as_ref().is_some_and(|live| {
            !desired || revision != Some(live.revision) || live.task.is_finished()
        }) {
            stop(&mut live).await;
            access.observed(false, None);
        }
        if desired && live.is_none() {
            let attempt = async {
                let snapshot = identity.as_ref().ok_or_else(|| anyhow::anyhow!("Enable CertMesh and establish a usable identity for private phone access."))?;
                let material = snapshot.material.as_ref().ok_or_else(|| anyhow::anyhow!("CertMesh identity is unavailable. Private phone access will resume when it recovers."))?;
                let (origin, _) = access.phone_identity().ok_or_else(|| anyhow::anyhow!("No valid browser HTTPS address is available."))?;
                let port = access.port().ok_or_else(|| anyhow::anyhow!("The configured operator port leaves no browser HTTPS port."))?;
                let interfaces = crate::network::lan_ipv4_interfaces()?;
                let interface = interfaces.first().ok_or_else(|| anyhow::anyhow!("Connect this computer to a network before connecting a phone."))?;
                let firewall = crate::pond::assess_firewall(port, &interface.name).await;
                if firewall.state == koi_common::pond::PondFirewallState::Blocked {
                    anyhow::bail!("Phone access is blocked by the host firewall: {}", firewall.detail);
                }
                // Firewall observation can await a process. Recheck desire and identity
                // before making that snapshot available to a new listener.
                if cancel.is_cancelled() || !access.status().settings.phone
                    || access.identity().is_none_or(|source| source.tls_identity().revision != snapshot.revision) {
                    anyhow::bail!("Settings or CertMesh identity changed while preparing HTTPS.");
                }
                let resolver = koi_certmesh::mtls::ReloadableServerCert::from_pem(&material.certificate_chain_pem, &material.private_key_pem)?;
                let config = koi_certmesh::mtls::build_server_auth_config_with_resolver(resolver)?;
                let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await?;
                let child = cancel.child_token();
                let surface = BrowserSurface { access: access.clone(), origin, catalog: catalog.clone(), local: false };
                let task_cancel = child.clone();
                let task = tokio::spawn(serve(listener, crate::browser_access::public_routes(surface), config, task_cancel));
                let reason = if firewall.state == koi_common::pond::PondFirewallState::Unknown {
                    format!("HTTPS is listening; firewall could not be verified. The phone must resolve {} and trust its CertMesh issuer.", material.hostname)
                } else {
                    format!("HTTPS is listening. The phone must resolve {} and trust its CertMesh issuer.", material.hostname)
                };
                Ok::<_, anyhow::Error>((snapshot.revision, child, task, reason))
            }.await;
            match attempt {
                Ok((revision, child, task, reason)) => {
                    live = Some(Live {
                        revision,
                        cancel: child,
                        task,
                    });
                    access.observed(true, Some(reason));
                }
                Err(error) => access.observed(
                    false,
                    Some(format!("Private phone access is waiting: {error}")),
                ),
            }
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = access.changed() => {},
            _ = async {
                match &mut identity_rx {
                    Some(rx) => { if rx.changed().await.is_err() { std::future::pending::<()>().await; } },
                    None => std::future::pending::<()>().await,
                }
            } => {},
            _ = tokio::time::sleep(Duration::from_secs(3)) => {},
        }
    }
    access.shutdown();
    stop(&mut live).await;
}
async fn stop(live: &mut Option<Live>) {
    if let Some(mut live) = live.take() {
        live.cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(3), &mut live.task)
            .await
            .is_err()
        {
            live.task.abort();
            let _ = (&mut live.task).await;
        }
    }
}

// Bounded session ownership follows the existing server-auth ACME adapter. No
// unjoined child survives shutdown or identity loss, including stalled handshakes.
async fn serve(
    listener: TcpListener,
    app: axum::Router,
    config: rustls::ServerConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut sessions = JoinSet::new();
    loop {
        let tcp = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sessions.join_next(), if !sessions.is_empty() => continue,
            result = listener.accept(), if sessions.len() < 128 => result?.0,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let child = cancel.clone();
        sessions.spawn(async move {
            let stream = tokio::select! {
                _ = child.cancelled() => return,
                result = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)) => match result { Ok(Ok(stream)) => stream, _ => return },
            };
            let io = TokioIo::new(stream);
            let builder = Builder::new(TokioExecutor::new());
            let service = hyper_util::service::TowerToHyperService::new(app);
            tokio::select! {
                _ = child.cancelled() => {},
                _ = builder.serve_connection_with_upgrades(io, service) => {},
            }
        });
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn https_accepts_normal_server_validation_and_joins_idle_connections() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let resolver = koi_certmesh::mtls::ReloadableServerCert::from_pem(
            &certified.cert.pem(),
            &certified.key_pair.serialize_pem(),
        )
        .unwrap();
        let config = koi_certmesh::mtls::build_server_auth_config_with_resolver(resolver).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let app =
            axum::Router::new().route("/ui", axum::routing::get(|| async { "Connect with Koi" }));
        let server = tokio::spawn(serve(listener, app, config, cancel.clone()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut tls = connector
            .connect("localhost".try_into().unwrap(), socket)
            .await
            .unwrap();
        tls.write_all(b"GET /ui HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut data = Vec::new();
        tls.read_to_end(&mut data).await.unwrap();
        assert!(String::from_utf8(data)
            .unwrap()
            .contains("Connect with Koi"));
        let idle = tokio::net::TcpStream::connect(address).await.unwrap();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(idle);
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
}
