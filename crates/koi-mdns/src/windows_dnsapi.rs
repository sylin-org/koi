//! Windows mDNS provider backed by the official `dnsapi.dll` DNS-SD surface.
//!
//! dnsapi is a partial collaborator with the same shape as Linux resolve1: it
//! contributes the discovery read routes (continuous browse, browse-driven
//! resolution, and direct point resolution) while the publication route stays
//! with another provider. The split is evidence-driven: the 2026-09-01 lab
//! probe proved the read routes end-to-end against independent Avahi peers,
//! and equally proved that the Windows DNS Client responder answers no peer
//! queries for `DnsServiceRegister` records on this network, so claiming the
//! publication route would strand every announcement. Publication returns to
//! this provider only when a probe proves peers can resolve its records.
//!
//! All dnsapi types stay inside this module; provider-neutral values cross the
//! session boundary.

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::NetworkManagement::Dns::{
    DnsServiceBrowse, DnsServiceBrowseCancel, DnsServiceFreeInstance, DnsServiceResolve,
    DnsServiceResolveCancel, DNS_RECORDW, DNS_SERVICE_BROWSE_REQUEST, DNS_SERVICE_CANCEL,
    DNS_SERVICE_INSTANCE, DNS_SERVICE_RESOLVE_REQUEST, DNS_TYPE_PTR,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};

use crate::adapter::{
    failed_assessment, MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderAddress, ProviderBrowse, ProviderEvent,
    ProviderService, ProviderSession, PublicationLease,
};
use crate::Result;

const DNSAPI_PRIORITY: u16 = 200;
const CALL_WAIT: Duration = Duration::from_secs(7);
const HEALTH_INTERVAL: Duration = Duration::from_secs(2);
const RESOLVE_WAIT: Duration = Duration::from_secs(6);
const EVENT_BRIDGE_POLL: Duration = Duration::from_millis(50);
const BROWSE_CHANNEL_CAPACITY: usize = 512;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor::new(
    "windows-dns-sd",
    DNSAPI_PRIORITY,
    ProviderApi::Win32DnsApi,
    MdnsCapabilities {
        publish: false,
        withdraw: false,
        continuous_browse: true,
        browse_resolves: true,
        direct_resolve: true,
        explicit_address: false,
    },
);

/// The dnsapi DNS-SD entry points the read routes actually call. Publication
/// exports are deliberately not required: this adapter claims browse and
/// resolve only, so a Windows build without the registration surface still
/// counts as installed for the routes Koi arms.
const REQUIRED_EXPORTS: &[&str] = &[
    "DnsServiceBrowse",
    "DnsServiceBrowseCancel",
    "DnsServiceResolve",
    "DnsServiceResolveCancel",
    "DnsServiceFreeInstance",
];

/// The async DNS-SD calls return "pending" and deliver results through the
/// completion callback; pending is the call-level success path.
const DNS_CALL_SUCCESS: i32 = 0;
const DNS_CALL_PENDING: i32 = 9506;
/// Callback-level statuses arrive as DNS_STATUS (unsigned).
const DNS_CB_SUCCESS: u32 = 0;

#[derive(Debug, Default)]
pub struct WindowsDnsSdAdapter;

#[async_trait::async_trait]
impl MdnsAdapter for WindowsDnsSdAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn assess(&self) -> MdnsProviderReport {
        match inspect() {
            Ok(inspection) => inspection.report,
            Err(report) => report,
        }
    }

    async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
        let inspection = inspect().map_err(|report| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Open,
                ProviderFailure::Unavailable,
                report.detail,
            )
        })?;
        Ok(Arc::new(DnsApiSession::start(inspection.capabilities)))
    }
}

struct DnsApiInspection {
    report: MdnsProviderReport,
    capabilities: MdnsCapabilities,
}

/// Read-only inspection of the Windows DNS Client facility. Shared by `assess`
/// and `open` so capability claims come from the same measured facts.
fn inspect() -> std::result::Result<DnsApiInspection, MdnsProviderReport> {
    let failed = |availability, detail| failed_assessment(DESCRIPTOR, availability, detail);

    let exports = export_probe();
    if !exports.complete {
        return Err(failed(
            ProviderAvailability::Absent,
            format!(
                "dnsapi.dll is missing DNS-SD entry points: {}",
                exports.missing.join(", ")
            ),
        ));
    }

    let running = dnscache_running();

    let availability = if running {
        ProviderAvailability::Ready
    } else {
        ProviderAvailability::Unavailable
    };
    let usable = availability == ProviderAvailability::Ready;
    let capabilities = if usable {
        DESCRIPTOR.capabilities
    } else {
        MdnsCapabilities::default()
    };

    // No registry multicast policy is claimed as an mDNS fact:
    // DNSClient\EnableMulticast is Microsoft's documented LLMNR switch
    // (ADMX "Turn off multicast name resolution"), not an mDNS control.
    let report = MdnsProviderReport {
        name: DESCRIPTOR.name.to_string(),
        priority: DESCRIPTOR.priority,
        api: DESCRIPTOR.api,
        availability,
        installed: ProbeFact::Yes,
        configured: ProbeFact::NotApplicable,
        running: if running {
            ProbeFact::Yes
        } else {
            ProbeFact::No
        },
        capabilities,
        session: None,
        detail: format!(
            "official Windows DNS-SD via dnsapi.dll; DNS Client (Dnscache) {}; \
             read routes only: the OS responder answers no peer queries for registered records \
             (lab probe 2026-09-01), so publication stays with another provider",
            if running { "running" } else { "stopped" },
        ),
    };
    Ok(DnsApiInspection {
        report,
        capabilities,
    })
}

struct ExportProbe {
    complete: bool,
    missing: Vec<&'static str>,
}

fn export_probe() -> &'static ExportProbe {
    static EXPORTS: OnceLock<ExportProbe> = OnceLock::new();
    EXPORTS.get_or_init(|| {
        let module = unsafe { LoadLibraryW(wide("dnsapi.dll").as_ptr()) };
        if module.is_null() {
            return ExportProbe {
                complete: false,
                missing: REQUIRED_EXPORTS.to_vec(),
            };
        }
        let mut missing: Vec<&'static str> = Vec::new();
        for name in REQUIRED_EXPORTS {
            let symbol: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
            let proc = unsafe { GetProcAddress(module, symbol.as_ptr()) };
            if proc.is_none() {
                missing.push(name);
            }
        }
        ExportProbe {
            complete: missing.is_empty(),
            missing,
        }
    })
}

/// Whether a Windows service is running. Querying service state is read-only
/// and needs no elevation. Shared with the Bonjour adapter's assessment.
pub(crate) fn service_running(name: &str) -> bool {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return false;
        }
        let service = OpenServiceW(scm, wide(name).as_ptr(), SERVICE_QUERY_STATUS);
        if service.is_null() {
            CloseServiceHandle(scm);
            return false;
        }
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0u32;
        let ok = QueryServiceStatusEx(
            service,
            0, // SC_STATUS_PROCESS_INFO
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        let running = ok != 0 && status.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        running
    }
}

/// Whether the DNS Client service, which hosts the mDNS responder, is running.
fn dnscache_running() -> bool {
    service_running("Dnscache")
}

// ── session ───────────────────────────────────────────────────────────

struct DnsApiSession {
    state_tx: watch::Sender<ProviderSessionState>,
    state_rx: watch::Receiver<ProviderSessionState>,
    capabilities: MdnsCapabilities,
    bridges: Mutex<Vec<BridgeRegistration>>,
    health: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DnsApiSession {
    fn start(capabilities: MdnsCapabilities) -> Self {
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        let health_tx = state_tx.clone();
        let health = tokio::spawn(async move {
            let mut was_running = dnscache_running();
            let mut interval = tokio::time::interval(HEALTH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // the first tick fires immediately; skip it
            loop {
                interval.tick().await;
                let running = dnscache_running();
                if running == was_running {
                    continue;
                }
                if !running {
                    tracing::info!(
                        provider = DESCRIPTOR.name,
                        "DNS Client stopped; session is recovering"
                    );
                    health_tx.send_replace(ProviderSessionState::Recovering);
                } else {
                    tracing::info!(
                        provider = DESCRIPTOR.name,
                        "DNS Client returned; session is ready again"
                    );
                    health_tx.send_replace(ProviderSessionState::Ready);
                }
                was_running = running;
            }
        });
        Self {
            state_tx,
            state_rx,
            capabilities,
            bridges: Mutex::new(Vec::new()),
            health: Mutex::new(Some(health)),
        }
    }
}

#[async_trait::async_trait]
impl ProviderSession for DnsApiSession {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    fn capabilities(&self) -> MdnsCapabilities {
        self.capabilities
    }

    fn state(&self) -> watch::Receiver<ProviderSessionState> {
        self.state_rx.clone()
    }

    async fn publish(&self, _announcement: &Announcement) -> Result<Box<dyn PublicationLease>> {
        Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Publish,
            ProviderFailure::Unavailable,
            "publication is not claimed: the OS responder answers no peer queries for \
             dnsapi-registered records on the observed network; the route stays with another \
             provider",
        ))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        if *self.state_tx.borrow() != ProviderSessionState::Ready {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Recovering,
                "the DNS Client is recovering; browse reconnects when it returns",
            ));
        }
        let (browse, registration) = open_dnsapi_browse(service_type, is_meta).await?;
        self.bridges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(registration);
        Ok(browse)
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        if *self.state_tx.borrow() != ProviderSessionState::Ready {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Recovering,
                "the DNS Client is recovering; resolution reconnects when it returns",
            ));
        }
        let name = name.to_string();
        let service_type = service_type.to_string();
        tokio::task::spawn_blocking(move || blocking_resolve(&name, &service_type))
            .await
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Resolve,
                    ProviderFailure::Lost,
                    format!("resolve task failed: {error}"),
                )
            })?
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(health) = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            health.abort();
        }
        let bridges = self
            .bridges
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
            .collect::<Vec<_>>();
        for bridge in bridges {
            bridge.cancel.cancel();
            let _ = bridge.reaper.await;
        }
        self.state_tx.send_replace(ProviderSessionState::Lost);
        Ok(())
    }
}

// ── browse ────────────────────────────────────────────────────────────

/// Callback-side state for one live `DnsServiceBrowse`. dnsapi invokes the
/// callback on its own worker thread, so the context is moved through a raw
/// pointer reclaimed only after the terminal status.
struct BrowseContext {
    events: mpsc::Sender<BrowseObservation>,
}

enum BrowseObservation {
    /// One PTR observation: (target name, owning query name).
    Ptr {
        target: String,
        query_name: String,
    },
    Terminal(u32),
}

/// # Safety
/// The pointer must come from [`into_raw_context`] and the terminal status
/// must already have been observed (or never arrive; the box then leaks
/// rather than race the callback thread).
unsafe fn into_raw_context(context: Box<BrowseContext>) -> *mut std::ffi::c_void {
    Box::into_raw(context) as *mut std::ffi::c_void
}

/// # Safety
/// The pointer must come from [`into_raw_context`] and dnsapi must no longer
/// reference the callback after the terminal status.
unsafe fn reclaim_context(raw: *mut std::ffi::c_void) {
    drop(Box::from_raw(raw as *mut BrowseContext));
}

/// The cancel token dnsapi filled when the browse started. Its address must
/// stay stable until `DnsServiceBrowseCancel`. Send is sound because the token
/// is an opaque handle only dnsapi dereferences.
struct CancelToken(DNS_SERVICE_CANCEL);
unsafe impl Send for CancelToken {}

struct BrowseRuntime {
    cancel: Mutex<CancelToken>,
}

struct BridgeRegistration {
    cancel: CancellationToken,
    reaper: tokio::task::JoinHandle<()>,
}

async fn open_dnsapi_browse(
    service_type: &str,
    is_meta: bool,
) -> Result<(ProviderBrowse, BridgeRegistration)> {
    let (event_tx, event_rx) = tokio_mpsc::channel(BROWSE_CHANNEL_CAPACITY);
    let (observation_tx, observation_rx) = mpsc::channel::<BrowseObservation>();
    let (terminal_tx, terminal_rx) = mpsc::channel::<()>();

    let query_name = service_type.trim_end_matches('.').to_string();
    let runtime = Arc::new(BrowseRuntime {
        cancel: Mutex::new(CancelToken(DNS_SERVICE_CANCEL {
            reserved: std::ptr::null_mut(),
        })),
    });

    let context_ptr = unsafe {
        into_raw_context(Box::new(BrowseContext {
            events: observation_tx,
        }))
    };

    unsafe extern "system" fn browse_callback(
        status: u32,
        query_context: *const std::ffi::c_void,
        record: *const DNS_RECORDW,
    ) {
        let context = unsafe { &*(query_context as *const BrowseContext) };
        if status != DNS_CB_SUCCESS || record.is_null() {
            let _ = context.events.send(BrowseObservation::Terminal(status));
            return;
        }
        let mut current = record;
        while !current.is_null() {
            let entry = unsafe { &*current };
            if entry.wType == DNS_TYPE_PTR {
                let target = unsafe { read_wide(entry.Data.PTR.pNameHost) };
                let query = unsafe { read_wide(entry.pName) };
                if !target.is_empty()
                    && context
                        .events
                        .send(BrowseObservation::Ptr {
                            target,
                            query_name: query,
                        })
                        .is_err()
                {
                    return;
                }
            }
            current = entry.pNext;
        }
    }

    let query_wide = wide(&query_name);
    let request = DNS_SERVICE_BROWSE_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        QueryName: query_wide.as_ptr(),
        Anonymous: windows_sys::Win32::NetworkManagement::Dns::DNS_SERVICE_BROWSE_REQUEST_0 {
            pBrowseCallback: Some(browse_callback),
        },
        pQueryContext: context_ptr,
    };
    let call_status = {
        let mut cancel = runtime
            .cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe { DnsServiceBrowse(&request, &mut cancel.0) }
    };
    if call_status != DNS_CALL_SUCCESS && call_status != DNS_CALL_PENDING {
        unsafe { reclaim_context(context_ptr) };
        return Err(dnsapi_error(
            ProviderOperation::Browse,
            call_status,
            "DnsServiceBrowse rejected the query",
        ));
    }

    // Reap observations on a blocking thread: meta observations surface service
    // types, ordinary observations are resolved (the Apple browse+resolve
    // two-step) before surfacing. The cancel token breaks the wait so shutdown
    // cannot hang on a silent channel.
    let cancel = CancellationToken::new();
    let reap_cancel = cancel.clone();
    let reaper = tokio::task::spawn_blocking(move || {
        loop {
            if reap_cancel.is_cancelled() {
                break;
            }
            match observation_rx.recv_timeout(EVENT_BRIDGE_POLL) {
                Ok(BrowseObservation::Terminal(status)) => {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        status,
                        "dnsapi browse stream ended"
                    );
                    break;
                }
                Ok(BrowseObservation::Ptr { target, query_name }) => {
                    if is_meta {
                        // Meta observations enumerate service types; the type
                        // name itself is the record Koi surfaces.
                        let _ = event_tx.blocking_send(ProviderEvent::Found(ProviderService {
                            name: trim_local(&target),
                            service_type: String::new(),
                            host: None,
                            addresses: Vec::new(),
                            port: None,
                            txt: HashMap::new(),
                        }));
                    } else {
                        let service_type = trim_local(&query_name);
                        match blocking_resolve(&target, &service_type) {
                            Ok(service) => {
                                let _ = event_tx.blocking_send(ProviderEvent::Resolved(service));
                            }
                            Err(error) => {
                                tracing::debug!(
                                    provider = DESCRIPTOR.name,
                                    instance = %target,
                                    %error,
                                    "browse resolve failed; instance stays unresolved"
                                );
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = terminal_tx.send(());
    });

    let browse = ProviderBrowse::new(
        event_rx,
        Box::new(DnsApiBrowseLease {
            runtime: Arc::clone(&runtime),
            context_ptr: Some(ContextPtr(context_ptr)),
            terminal_rx: Mutex::new(Some(terminal_rx)),
        }),
    );
    Ok((browse, BridgeRegistration { cancel, reaper }))
}

fn trim_local(value: &str) -> String {
    value
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

/// Owned raw context pointer handed to dnsapi. Send is sound because only our
/// code dereferences it, and only after the terminal callback.
struct ContextPtr(*mut std::ffi::c_void);
unsafe impl Send for ContextPtr {}

struct DnsApiBrowseLease {
    runtime: Arc<BrowseRuntime>,
    context_ptr: Option<ContextPtr>,
    terminal_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

#[async_trait::async_trait]
impl BrowseLease for DnsApiBrowseLease {
    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn close(&mut self) -> Result<()> {
        {
            let cancel = self
                .runtime
                .cancel
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe { DnsServiceBrowseCancel(&cancel.0) };
        }
        // Wait for the terminal callback so dnsapi no longer references the
        // context before it is reclaimed. On timeout the context is leaked
        // instead of racing the callback thread.
        let terminal_rx = self
            .terminal_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(terminal_rx) = terminal_rx {
            let observed =
                tokio::task::spawn_blocking(move || terminal_rx.recv_timeout(CALL_WAIT).is_ok())
                    .await
                    .unwrap_or(false);
            if observed {
                if let Some(context_ptr) = self.context_ptr.take() {
                    unsafe { reclaim_context(context_ptr.0) };
                }
            } else {
                tracing::debug!(
                    provider = DESCRIPTOR.name,
                    "browse cancel produced no terminal callback; context leaked by design"
                );
            }
        }
        Ok(())
    }
}

// ── resolve ───────────────────────────────────────────────────────────

struct ResolveRuntime {
    cancel: DNS_SERVICE_CANCEL,
    reply: mpsc::Sender<(u32, *const DNS_SERVICE_INSTANCE)>,
}

/// Resolve one instance through `DnsServiceResolve`, returning full service
/// data only after dnsapi delivered its completion callback.
fn blocking_resolve(instance_full_name: &str, service_type: &str) -> Result<ProviderService> {
    let (reply_tx, reply_rx) = mpsc::channel::<(u32, *const DNS_SERVICE_INSTANCE)>();
    let runtime = Box::new(ResolveRuntime {
        cancel: DNS_SERVICE_CANCEL {
            reserved: std::ptr::null_mut(),
        },
        reply: reply_tx,
    });
    let runtime_ptr = Box::into_raw(runtime);

    unsafe extern "system" fn resolve_callback(
        status: u32,
        query_context: *const std::ffi::c_void,
        instance: *const DNS_SERVICE_INSTANCE,
    ) {
        let runtime = unsafe { &*(query_context as *const ResolveRuntime) };
        let _ = runtime.reply.send((status, instance));
    }

    let mut query_name = wide(instance_full_name);
    let request = DNS_SERVICE_RESOLVE_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        QueryName: query_name.as_mut_ptr(),
        pResolveCompletionCallback: Some(resolve_callback),
        pQueryContext: runtime_ptr as *mut std::ffi::c_void,
    };
    // SAFETY: runtime_ptr stays valid for the whole operation; the cancel
    // field's address is stable from here until DnsServiceResolveCancel.
    let call_status = unsafe { DnsServiceResolve(&request, &raw mut (*runtime_ptr).cancel) };

    if call_status != DNS_CALL_SUCCESS && call_status != DNS_CALL_PENDING {
        unsafe { drop(Box::from_raw(runtime_ptr)) };
        return Err(dnsapi_error(
            ProviderOperation::Resolve,
            call_status,
            "DnsServiceResolve rejected the query",
        ));
    }

    let outcome = reply_rx.recv_timeout(RESOLVE_WAIT);
    let mut timed_out = false;
    if outcome.is_err() {
        timed_out = true;
        // SAFETY: the runtime is still alive at this point.
        unsafe { DnsServiceResolveCancel(&raw const (*runtime_ptr).cancel) };
        // Give the cancel a moment to deliver the terminal callback so no
        // reply races the reclaim.
        let _ = reply_rx.recv_timeout(Duration::from_millis(500));
    }
    // SAFETY: every send has happened (or the operation was cancelled above);
    // reclaiming now cannot race a callback that will never run.
    let runtime = unsafe { Box::from_raw(runtime_ptr) };
    drop(runtime);

    match outcome {
        Ok((DNS_CB_SUCCESS, instance)) if !instance.is_null() => unsafe {
            let service = instance_to_service(instance, service_type);
            DnsServiceFreeInstance(instance);
            service
        },
        Ok((status, _)) => Err(dnsapi_error(
            ProviderOperation::Resolve,
            status as i32,
            "DnsServiceResolve completed with an error",
        )),
        Err(_) if timed_out => Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Timeout,
            format!("DnsServiceResolve completion exceeded {RESOLVE_WAIT:?}"),
        )),
        Err(_) => Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Lost,
            "DnsServiceResolve callback channel closed",
        )),
    }
}

/// Project a completed dnsapi instance onto provider-neutral service data.
///
/// # Safety
/// `instance` must be a live dnsapi allocation whose callback already ran.
unsafe fn instance_to_service(
    instance: *const DNS_SERVICE_INSTANCE,
    service_type: &str,
) -> Result<ProviderService> {
    let full_name = read_wide((*instance).pszInstanceName);
    if full_name.is_empty() {
        return Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Protocol,
            "resolved instance carries no name",
        ));
    }
    let mut addresses = Vec::new();
    if !(*instance).ip4Address.is_null() {
        let octets = (*(*instance).ip4Address).to_le_bytes();
        addresses.push(ProviderAddress {
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )),
            interface_index: None,
            interface_name: None,
        });
    }
    if !(*instance).ip6Address.is_null() {
        let bytes = std::slice::from_raw_parts((*instance).ip6Address as *const u8, 16);
        if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
            addresses.push(ProviderAddress {
                address: std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                interface_index: None,
                interface_name: None,
            });
        }
    }
    let mut txt = HashMap::new();
    let count = (*instance).dwPropertyCount as usize;
    for index in 0..count {
        let key = read_wide(*(*instance).keys.add(index));
        let value = read_wide(*(*instance).values.add(index));
        if !key.is_empty() {
            txt.insert(key, value);
        }
    }
    Ok(ProviderService {
        name: instance_label(&full_name),
        service_type: service_type.to_string(),
        host: non_empty(read_wide((*instance).pszHostName)),
        addresses,
        port: ((*instance).wPort != 0).then_some((*instance).wPort),
        txt,
    })
}

/// The instance label is everything before the first service-type label.
fn instance_label(full_name: &str) -> String {
    match full_name.find("._") {
        Some(index) => full_name[..index].to_string(),
        None => full_name.to_string(),
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

// ── shared helpers ────────────────────────────────────────────────────

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 string owned by dnsapi, or null.
unsafe fn read_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

fn dnsapi_error(operation: ProviderOperation, status: i32, what: &str) -> MdnsError {
    let failure = if status == ERROR_INVALID_PARAMETER as i32 {
        ProviderFailure::Rejected
    } else {
        ProviderFailure::Protocol
    };
    provider_error(
        DESCRIPTOR.name,
        operation,
        failure,
        format!("{what} (dnsapi status {status})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_claims_only_proven_read_routes() {
        let capabilities = DESCRIPTOR.capabilities;
        assert!(capabilities.continuous_browse);
        assert!(capabilities.browse_resolves);
        assert!(capabilities.direct_resolve);
        assert!(!capabilities.publish);
        assert!(!capabilities.withdraw);
        assert!(!capabilities.explicit_address);
        assert!(!capabilities.satisfies_provider_contract());
    }

    #[test]
    fn instance_labels_split_at_the_service_type() {
        assert_eq!(
            instance_label("Koi MCP (test-01)._mcp._tcp.local"),
            "Koi MCP (test-01)"
        );
        assert_eq!(instance_label("plainname"), "plainname");
    }

    #[test]
    fn local_suffixes_trim_for_record_projection() {
        assert_eq!(trim_local("_mcp._tcp.local."), "_mcp._tcp");
        assert_eq!(
            trim_local("_services._dns-sd._udp.local"),
            "_services._dns-sd._udp"
        );
    }

    #[tokio::test]
    #[ignore = "requires the Windows DNS Client facility"]
    async fn real_dnsapi_report_declares_read_routes_only() {
        let report = WindowsDnsSdAdapter.assess().await;
        assert_eq!(report.name, DESCRIPTOR.name);
        assert_eq!(report.api, ProviderApi::Win32DnsApi);
        assert_eq!(report.running, ProbeFact::Yes);
        assert!(report.capabilities.continuous_browse);
        assert!(!report.capabilities.publish);
    }
}
