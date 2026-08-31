//! Linux systemd-resolved mDNS resource adapter.
//!
//! resolve1 exposes real DNS-SD publication and point-resolution methods on
//! newer systemd releases, but it does not expose a continuous service browser
//! and its publication API cannot carry Koi's explicit-address contract. Koi
//! therefore observes and cooperates with it as a native collaborator while
//! other adapters own only the capability routes resolve1 does not implement.

#![allow(clippy::too_many_arguments)] // resolve1's fixed D-Bus method signatures.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use tokio::sync::{mpsc, oneshot};
use zbus::names::BusName;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

use crate::adapter::{
    AdapterApi, AdapterReadiness, AdapterReport, MdnsAdapter, MdnsCapabilities, ProbeFact,
};
use crate::error::MdnsError;
use crate::provider::{
    MdnsProvider, ProviderAddress, ProviderBrowse, ProviderService, ProviderStatus,
};
use crate::Result;

const RESOLVE_DESTINATION: &str = "org.freedesktop.resolve1";
const RESOLVED_PRIORITY: u16 = 200;
const COMMAND_CAPACITY: usize = 256;

type ResolveServiceReply = (
    Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
    Vec<Vec<u8>>,
    String,
    String,
    String,
    u64,
);

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    interface = "org.freedesktop.resolve1.Manager"
)]
trait ResolveManager {
    #[zbus(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> zbus::Result<String>;

    #[zbus(name = "RegisterService")]
    fn register_service(
        &self,
        id: &str,
        name_template: &str,
        service_type: &str,
        service_port: u16,
        service_priority: u16,
        service_weight: u16,
        txt_data: Vec<HashMap<String, Vec<u8>>>,
    ) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "UnregisterService")]
    fn unregister_service(&self, service_path: &OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(name = "ResolveService")]
    fn resolve_service(
        &self,
        interface_index: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        family: i32,
        flags: u64,
    ) -> zbus::Result<ResolveServiceReply>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    interface = "org.freedesktop.DBus.Introspectable"
)]
trait ResolveIntrospectable {
    #[zbus(name = "Introspect")]
    fn introspect(&self) -> zbus::Result<String>;
}

/// Adapter for the host's resolve1 service.
#[derive(Debug, Default)]
pub struct SystemdResolvedAdapter;

#[async_trait::async_trait]
impl MdnsAdapter for SystemdResolvedAdapter {
    fn name(&self) -> &'static str {
        "systemd-resolved"
    }

    fn priority(&self) -> u16 {
        RESOLVED_PRIORITY
    }

    fn api(&self) -> AdapterApi {
        AdapterApi::SystemDbus
    }

    fn capabilities(&self) -> MdnsCapabilities {
        // Maximum shape. Live inspection intersects this with the methods and
        // MulticastDNS mode actually present on the host.
        MdnsCapabilities {
            publish: true,
            withdraw: true,
            continuous_browse: false,
            browse_resolves: false,
            direct_resolve: true,
            explicit_address: false,
        }
    }

    async fn inspect(&self) -> AdapterReport {
        inspect_resolved(self).await
    }

    async fn arm(&self) -> Result<Arc<dyn MdnsProvider>> {
        let report = inspect_resolved(self).await;
        if report.readiness != AdapterReadiness::Ready {
            return Err(MdnsError::Daemon(format!(
                "systemd-resolved cannot be armed: {}",
                report.detail
            )));
        }
        let connection = Connection::system().await.map_err(|error| {
            MdnsError::Daemon(format!("cannot connect to resolve1 system D-Bus: {error}"))
        })?;
        Ok(Arc::new(SystemdResolvedProvider::start(
            connection,
            report.capabilities,
            report.detail,
        )))
    }
}

/// Armed resolve1 operations. Unsupported operations remain absent from the
/// capability flags and are never routed here by the agnostic supervisor.
struct SystemdResolvedProvider {
    connection: Connection,
    command_tx: mpsc::Sender<ResolvedCommand>,
    status: Arc<RwLock<ProviderStatus>>,
    capabilities: MdnsCapabilities,
}

impl SystemdResolvedProvider {
    fn start(connection: Connection, capabilities: MdnsCapabilities, detail: String) -> Self {
        let status = Arc::new(RwLock::new(ProviderStatus {
            name: "systemd-resolved".to_string(),
            healthy: true,
            detail,
        }));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let actor = ResolvedActor {
            connection: connection.clone(),
            command_rx,
            status: Arc::clone(&status),
            registrations: HashMap::new(),
            next_id: 0,
        };
        tokio::spawn(actor.run());
        Self {
            connection,
            command_tx,
            status,
            capabilities,
        }
    }

    fn send(&self, command: ResolvedCommand) -> Result<()> {
        self.command_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    MdnsError::Daemon("systemd-resolved command queue full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    MdnsError::Daemon("systemd-resolved adapter stopped".to_string())
                }
            })
    }
}

#[async_trait::async_trait]
impl MdnsProvider for SystemdResolvedProvider {
    fn name(&self) -> &'static str {
        "systemd-resolved"
    }

    fn capabilities(&self) -> MdnsCapabilities {
        self.capabilities
    }

    fn api(&self) -> AdapterApi {
        AdapterApi::SystemDbus
    }

    fn status(&self) -> ProviderStatus {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()> {
        if !self.capabilities.publish {
            return Err(MdnsError::Daemon(
                "resolve1 publication is not available in the current mDNS mode".to_string(),
            ));
        }
        if ip.is_some() {
            return Err(MdnsError::Daemon(
                "resolve1 cannot publish an explicit service address".to_string(),
            ));
        }
        let (service_type, _) = split_service_type(service_type)?;
        self.send(ResolvedCommand::Register(ResolvedRegistration {
            key: registration_key(name, &service_type),
            name: name.to_string(),
            service_type,
            port,
            txt: txt
                .iter()
                .map(|(key, value)| (key.clone(), value.as_bytes().to_vec()))
                .collect(),
        }))
    }

    fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        let (service_type, _) = split_service_type(service_type)?;
        self.send(ResolvedCommand::Unregister(registration_key(
            name,
            &service_type,
        )))
    }

    async fn browse(&self, _service_type: &str, _is_meta: bool) -> Result<ProviderBrowse> {
        Err(MdnsError::Daemon(
            "resolve1 does not expose continuous DNS-SD browse".to_string(),
        ))
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        if !self.capabilities.direct_resolve {
            return Err(MdnsError::Daemon(
                "resolve1 direct service resolution is unavailable".to_string(),
            ));
        }
        let (service_type, domain) = split_service_type(service_type)?;
        let manager = ResolveManagerProxy::new(&self.connection)
            .await
            .map_err(|error| MdnsError::Daemon(format!("resolve1 proxy failed: {error}")))?;
        let (srv, txt, canonical_name, canonical_type, _, _) = manager
            .resolve_service(0, name, &service_type, &domain, 0, 0)
            .await
            .map_err(|error| {
                MdnsError::Daemon(format!("resolve1 ResolveService failed: {error}"))
            })?;
        let (_, _, port, host, raw_addresses, canonical_host) =
            srv.into_iter().next().ok_or_else(|| {
                MdnsError::Daemon(format!(
                    "resolve1 returned no SRV data for {name}.{service_type}"
                ))
            })?;
        let addresses = raw_addresses
            .into_iter()
            .filter_map(|(interface_index, _family, bytes)| {
                address_from_bytes(&bytes).map(|address| ProviderAddress {
                    address,
                    interface_index: (interface_index > 0).then_some(interface_index as u32),
                    interface_name: None,
                })
            })
            .collect();
        Ok(ProviderService {
            name: if canonical_name.is_empty() {
                name.to_string()
            } else {
                canonical_name
            },
            service_type: canonical_type
                .trim_end_matches('.')
                .trim_end_matches(".local")
                .to_string(),
            host: Some(if canonical_host.is_empty() {
                host
            } else {
                canonical_host
            }),
            addresses,
            port: Some(port),
            txt: decode_txt(&txt),
        })
    }

    fn stop_browse(&self, _service_type: &str) -> Result<()> {
        Err(MdnsError::Daemon(
            "resolve1 does not expose continuous DNS-SD browse".to_string(),
        ))
    }

    async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ResolvedCommand::Shutdown(reply_tx))
            .await
            .map_err(|_| MdnsError::Daemon("systemd-resolved adapter stopped".to_string()))?;
        reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("systemd-resolved dropped shutdown reply".to_string()))
    }
}

enum ResolvedCommand {
    Register(ResolvedRegistration),
    Unregister(String),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone)]
struct ResolvedRegistration {
    key: String,
    name: String,
    service_type: String,
    port: u16,
    txt: HashMap<String, Vec<u8>>,
}

struct ResolvedActor {
    connection: Connection,
    command_rx: mpsc::Receiver<ResolvedCommand>,
    status: Arc<RwLock<ProviderStatus>>,
    registrations: HashMap<String, OwnedObjectPath>,
    next_id: u64,
}

impl ResolvedActor {
    async fn run(mut self) {
        while let Some(command) = self.command_rx.recv().await {
            match command {
                ResolvedCommand::Register(registration) => self.register(registration).await,
                ResolvedCommand::Unregister(key) => self.unregister(&key).await,
                ResolvedCommand::Shutdown(reply) => {
                    self.release_all().await;
                    let _ = reply.send(());
                    break;
                }
            }
        }
        set_status(&self.status, false, "adapter stopped".to_string());
    }

    async fn register(&mut self, registration: ResolvedRegistration) {
        self.unregister(&registration.key).await;
        let manager = match ResolveManagerProxy::new(&self.connection).await {
            Ok(manager) => manager,
            Err(error) => {
                set_status(
                    &self.status,
                    false,
                    format!("resolve1 proxy failed: {error}"),
                );
                return;
            }
        };
        self.next_id = self.next_id.saturating_add(1);
        let id = format!("koi-{}-{}", std::process::id(), self.next_id);
        let name_template = registration.name.replace('%', "%%");
        let txt = vec![registration.txt.clone()];
        match manager
            .register_service(
                &id,
                &name_template,
                &registration.service_type,
                registration.port,
                0,
                0,
                txt,
            )
            .await
        {
            Ok(path) => {
                self.registrations.insert(registration.key, path);
                set_status(
                    &self.status,
                    true,
                    "resolve1 publication and point-resolution via system D-Bus".to_string(),
                );
            }
            Err(error) => set_status(
                &self.status,
                false,
                format!("resolve1 RegisterService failed: {error}"),
            ),
        }
    }

    async fn unregister(&mut self, key: &str) {
        let Some(path) = self.registrations.remove(key) else {
            return;
        };
        match ResolveManagerProxy::new(&self.connection).await {
            Ok(manager) => {
                if let Err(error) = manager.unregister_service(&path).await {
                    set_status(
                        &self.status,
                        false,
                        format!("resolve1 UnregisterService failed: {error}"),
                    );
                }
            }
            Err(error) => {
                set_status(
                    &self.status,
                    false,
                    format!("resolve1 proxy failed: {error}"),
                );
            }
        }
    }

    async fn release_all(&mut self) {
        let keys: Vec<String> = self.registrations.keys().cloned().collect();
        for key in keys {
            self.unregister(&key).await;
        }
    }
}

fn registration_key(name: &str, service_type: &str) -> String {
    format!("{name}\0{service_type}")
}

fn split_service_type(value: &str) -> Result<(String, String)> {
    let canonical = value.trim_end_matches('.');
    let without_local = canonical.strip_suffix(".local").ok_or_else(|| {
        MdnsError::InvalidServiceType(format!("resolve1 only supports .local: {value}"))
    })?;
    if !without_local.starts_with('_') || !without_local.contains("._") {
        return Err(MdnsError::InvalidServiceType(value.to_string()));
    }
    Ok((without_local.to_string(), "local".to_string()))
}

fn address_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn decode_txt(items: &[Vec<u8>]) -> HashMap<String, String> {
    items
        .iter()
        .filter_map(|item| {
            let text = String::from_utf8_lossy(item);
            let (key, value) = text.split_once('=').unwrap_or((&text, ""));
            (!key.is_empty()).then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

fn set_status(status: &RwLock<ProviderStatus>, healthy: bool, detail: String) {
    let mut status = status
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.healthy = healthy;
    status.detail = detail;
}

async fn inspect_resolved(adapter: &SystemdResolvedAdapter) -> AdapterReport {
    let failed = |readiness, detail| AdapterReport::failed_inspection(adapter, readiness, detail);
    let connection = match Connection::system().await {
        Ok(connection) => connection,
        Err(error) => {
            return failed(
                AdapterReadiness::Unavailable,
                format!("system D-Bus unavailable: {error}"),
            );
        }
    };
    let dbus = match zbus::fdo::DBusProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(error) => {
            return failed(
                AdapterReadiness::Unavailable,
                format!("cannot inspect the system D-Bus: {error}"),
            );
        }
    };
    let bus_name = match BusName::try_from(RESOLVE_DESTINATION) {
        Ok(name) => name,
        Err(error) => {
            return failed(
                AdapterReadiness::Unavailable,
                format!("invalid resolve1 D-Bus name: {error}"),
            );
        }
    };
    match dbus.name_has_owner(bus_name).await {
        Ok(false) => {
            let installed = dbus
                .list_activatable_names()
                .await
                .map(|names| {
                    if names
                        .iter()
                        .any(|name| name.as_str() == RESOLVE_DESTINATION)
                    {
                        ProbeFact::Yes
                    } else {
                        ProbeFact::Unknown
                    }
                })
                .unwrap_or(ProbeFact::Unknown);
            return AdapterReport {
                name: adapter.name(),
                priority: adapter.priority(),
                api: adapter.api(),
                readiness: AdapterReadiness::Absent,
                installed,
                configured: ProbeFact::Unknown,
                running: ProbeFact::No,
                capabilities: MdnsCapabilities::default(),
                detail: "resolve1 has no live D-Bus owner; Koi did not activate it".to_string(),
            };
        }
        Err(error) => {
            return failed(
                AdapterReadiness::Unavailable,
                format!("cannot determine whether resolve1 is running: {error}"),
            );
        }
        Ok(true) => {}
    }

    let manager = match ResolveManagerProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(error) => {
            return failed(
                AdapterReadiness::Unavailable,
                format!("cannot create the resolve1 manager proxy: {error}"),
            );
        }
    };
    let mdns_mode = match manager.multicast_dns().await {
        Ok(mode) => mode,
        Err(error) => {
            return AdapterReport {
                name: adapter.name(),
                priority: adapter.priority(),
                api: adapter.api(),
                readiness: AdapterReadiness::Unavailable,
                installed: ProbeFact::Yes,
                configured: ProbeFact::Unknown,
                running: ProbeFact::Yes,
                capabilities: MdnsCapabilities::default(),
                detail: format!("resolve1 MulticastDNS property failed: {error}"),
            };
        }
    };
    let introspection = match ResolveIntrospectableProxy::new(&connection).await {
        Ok(proxy) => proxy.introspect().await,
        Err(error) => Err(error),
    };
    let xml = match introspection {
        Ok(xml) => xml,
        Err(error) => {
            return AdapterReport {
                name: adapter.name(),
                priority: adapter.priority(),
                api: adapter.api(),
                readiness: AdapterReadiness::Unavailable,
                installed: ProbeFact::Yes,
                configured: configured_fact(&mdns_mode),
                running: ProbeFact::Yes,
                capabilities: MdnsCapabilities::default(),
                detail: format!("resolve1 API introspection failed: {error}"),
            };
        }
    };

    let capabilities = capabilities_from(&mdns_mode, &xml);
    let configured = configured_fact(&mdns_mode);
    let readiness = if configured == ProbeFact::Yes {
        AdapterReadiness::Ready
    } else {
        AdapterReadiness::Unavailable
    };
    AdapterReport {
        name: adapter.name(),
        priority: adapter.priority(),
        api: adapter.api(),
        readiness,
        installed: ProbeFact::Yes,
        configured,
        running: ProbeFact::Yes,
        capabilities,
        detail: format!(
            "resolve1 MulticastDNS={mdns_mode}; platform APIs {}; continuous browse and \
             explicit-address publication unavailable",
            capabilities.summary()
        ),
    }
}

fn configured_fact(mode: &str) -> ProbeFact {
    match mode {
        "yes" | "resolve" => ProbeFact::Yes,
        "no" => ProbeFact::No,
        _ => ProbeFact::Unknown,
    }
}

fn capabilities_from(mode: &str, introspection: &str) -> MdnsCapabilities {
    let method = |name: &str| introspection.contains(&format!("<method name=\"{name}\""));
    let mode_supports_mdns = matches!(mode, "yes" | "resolve");
    let can_publish = mode == "yes" && method("RegisterService");
    MdnsCapabilities {
        publish: can_publish,
        withdraw: can_publish && method("UnregisterService"),
        continuous_browse: false,
        browse_resolves: false,
        direct_resolve: mode_supports_mdns && method("ResolveService"),
        explicit_address: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_api_shape_remains_a_partial_collaborator() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        let capabilities = capabilities_from("yes", xml);
        assert!(capabilities.publish);
        assert!(capabilities.withdraw);
        assert!(capabilities.direct_resolve);
        assert!(!capabilities.continuous_browse);
        assert!(!capabilities.explicit_address);
        assert!(!capabilities.satisfies_provider_contract());
    }

    #[test]
    fn resolve_only_mode_does_not_claim_publication() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        let capabilities = capabilities_from("resolve", xml);
        assert!(!capabilities.publish);
        assert!(!capabilities.withdraw);
        assert!(capabilities.direct_resolve);
    }

    #[test]
    fn unknown_mode_claims_no_capabilities() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        assert_eq!(
            capabilities_from("future-value", xml),
            MdnsCapabilities::default()
        );
    }

    #[tokio::test]
    #[ignore = "requires systemd-resolved on the system bus"]
    async fn real_resolve1_report_declares_only_live_capabilities() {
        let report = SystemdResolvedAdapter.inspect().await;
        assert_eq!(report.name, "systemd-resolved");
        assert_eq!(report.api, AdapterApi::SystemDbus);
        assert!(!report.satisfies_full_contract());
        assert_ne!(report.running, ProbeFact::Unknown);
    }

    #[tokio::test]
    #[ignore = "requires writable systemd-resolved DNS-SD D-Bus APIs"]
    async fn real_resolve1_publish_point_resolve_and_withdraw() {
        let adapter = SystemdResolvedAdapter;
        let report = adapter.inspect().await;
        assert!(report.capabilities.publish, "resolve1 report: {report:?}");
        assert!(
            report.capabilities.direct_resolve,
            "resolve1 report: {report:?}"
        );
        let provider = adapter.arm().await.expect("arm resolve1 provider");
        let name = format!("koi-resolve1-{}", std::process::id());
        provider
            .register(
                &name,
                "_koi-test._tcp.local.",
                43125,
                None,
                &HashMap::from([("source".to_string(), "resolve1".to_string())]),
            )
            .expect("queue resolve1 publication");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        let resolved = loop {
            match provider.resolve(&name, "_koi-test._tcp.local.").await {
                Ok(service) => break service,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(%error, "waiting for resolve1 publication");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => panic!("resolve1 publication did not resolve: {error}"),
            }
        };
        assert_eq!(resolved.port, Some(43125));
        assert_eq!(resolved.txt.get("source"), Some(&"resolve1".to_string()));
        provider
            .unregister(&name, "_koi-test._tcp.local.")
            .expect("queue resolve1 withdrawal");
        provider
            .shutdown()
            .await
            .expect("shutdown resolve1 provider");
    }
}
