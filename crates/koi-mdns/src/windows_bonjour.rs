//! Windows mDNS provider backed by Apple Bonjour (`dnssd.dll`), when the
//! mDNSResponder service is genuinely installed.
//!
//! Bonjour is a full provider on Windows: it publishes acknowledged
//! registrations, browses with add/remove events, and resolves by name. It
//! deliberately does not claim explicit-address publication — `DNSServiceRegister`
//! pins records to the host identity, not to caller-chosen addresses. When
//! Bonjour is absent, `assess` reports `Absent` with the exact missing facts
//! and the control plane never opens a session.
//!
//! Threading: every dnssd connection is born, processed, and retired on one
//! owner thread. Leases only signal that owner. This is required by Bonjour's
//! no-internal-locking contract and keeps callback contexts alive until their
//! connection is either deallocated or deliberately quarantined after the
//! responder has disappeared.
//!
//! All dnssd types stay inside this module; provider-neutral values cross the
//! session boundary.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc as tokio_mpsc, watch};

use crate::adapter::{
    failed_assessment, MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderBrowse, ProviderEvent, ProviderService,
    ProviderSession, PublicationLease,
};
use crate::Result;

const BONJOUR_PRIORITY: u16 = 150;
const CALL_WAIT: Duration = Duration::from_secs(7);
const RESOLVE_WAIT: Duration = Duration::from_secs(6);
const SOCKET_POLL_SLICE: Duration = Duration::from_millis(100);
const BROWSE_CHANNEL_CAPACITY: usize = 512;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor::new(
    "bonjour",
    BONJOUR_PRIORITY,
    ProviderApi::BonjourDnsSd,
    MdnsCapabilities {
        publish: true,
        withdraw: true,
        continuous_browse: true,
        browse_resolves: true,
        direct_resolve: true,
        explicit_address: false,
    },
);

/// Product install paths `dnssd.dll` is known to occupy. System32 is probed
/// separately with a restricted loader search so Koi never binds a DLL from
/// its current directory.
const DNSSD_CANDIDATE_PATHS: &[&str] = &[
    r"C:\Program Files\Bonjour\dnssd.dll",
    r"C:\Program Files (x86)\Bonjour\dnssd.dll",
];

const K_DNSSERVICE_ERR_NO_ERROR: i32 = 0;
const K_DNSSERVICE_ERR_NAMECONFLICT: i32 = -65548;
const K_DNSSERVICE_FLAGS_ADD: u32 = 0x1;

#[derive(Debug, Default)]
pub struct WindowsBonjourAdapter;

#[async_trait::async_trait]
impl MdnsAdapter for WindowsBonjourAdapter {
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
        Ok(Arc::new(BonjourSession::start(inspection.capabilities)))
    }
}

struct BonjourInspection {
    report: MdnsProviderReport,
    capabilities: MdnsCapabilities,
}

fn inspect() -> std::result::Result<BonjourInspection, MdnsProviderReport> {
    let failed = |availability, detail| failed_assessment(DESCRIPTOR, availability, detail);

    if let Err(missing) = dnssd() {
        return Err(failed(
            ProviderAvailability::Absent,
            format!("Bonjour DNS-SD is unavailable: {missing}"),
        ));
    }

    let running = crate::windows_dnsapi::service_running("Bonjour Service");
    let availability = if running {
        ProviderAvailability::Ready
    } else {
        ProviderAvailability::Unavailable
    };
    let capabilities = if running {
        DESCRIPTOR.capabilities
    } else {
        MdnsCapabilities::default()
    };

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
            "Apple Bonjour DNS-SD via dnssd.dll; mDNSResponder service {}",
            if running { "running" } else { "not running" }
        ),
    };
    Ok(BonjourInspection {
        report,
        capabilities,
    })
}

// `dnssd()` below is both the detector and the runtime binding. It retries
// failed loads so a live install can promote without restarting Koi.

// ── dnssd FFI (runtime-loaded from dnssd.dll; absent from windows-sys) ─

type SdRef = *mut core::ffi::c_void;

type RegisterReply = unsafe extern "system" fn(
    sd_ref: SdRef,
    flags: u32,
    error_code: i32,
    name: *const u8,
    regtype: *const u8,
    domain: *const u8,
    context: *mut core::ffi::c_void,
);

type BrowseReply = unsafe extern "system" fn(
    sd_ref: SdRef,
    flags: u32,
    interface_index: u32,
    error_code: i32,
    service_name: *const u8,
    regtype: *const u8,
    reply_domain: *const u8,
    context: *mut core::ffi::c_void,
);

type ResolveReply = unsafe extern "system" fn(
    sd_ref: SdRef,
    flags: u32,
    interface_index: u32,
    error_code: i32,
    fullname: *const u8,
    hosttarget: *const u8,
    port: u16,
    txt_len: u16,
    txt_record: *const u8,
    context: *mut core::ffi::c_void,
);

/// The dnssd entry points, bound at runtime: the Bonjour SDK ships no import
/// library here, and a missing Bonjour install must be an assessment fact,
/// not a load failure of Koi itself.
struct DnssdApi {
    /// Keep the successful module load resident for every bound function
    /// pointer. Failed loads are freed and deliberately not cached.
    _library: usize,
    register: unsafe extern "system" fn(
        sdref: *mut SdRef,
        interfaceindex: u32,
        flags: u32,
        name: *const u8,
        regtype: *const u8,
        domain: *const u8,
        host: *const u8,
        port: u16,
        txtlen: u16,
        txtrecord: *const u8,
        callback: RegisterReply,
        context: *mut core::ffi::c_void,
    ) -> i32,
    browse: unsafe extern "system" fn(
        sdref: *mut SdRef,
        interfaceindex: u32,
        flags: u32,
        regtype: *const u8,
        domain: *const u8,
        callback: BrowseReply,
        context: *mut core::ffi::c_void,
    ) -> i32,
    resolve: unsafe extern "system" fn(
        sdref: *mut SdRef,
        interfaceindex: u32,
        flags: u32,
        name: *const u8,
        regtype: *const u8,
        domain: *const u8,
        callback: ResolveReply,
        context: *mut core::ffi::c_void,
    ) -> i32,
    ref_sock_fd: unsafe extern "system" fn(sdref: SdRef) -> SOCKET,
    process_result: unsafe extern "system" fn(sdref: SdRef) -> i32,
    ref_deallocate: unsafe extern "system" fn(sdref: SdRef),
}

/// Cache only a successful load. Installing Bonjour while Koi is running must
/// become visible to a later assessment without restarting the process.
fn dnssd() -> std::result::Result<&'static DnssdApi, String> {
    static API: OnceLock<DnssdApi> = OnceLock::new();
    static LOAD: Mutex<()> = Mutex::new(());
    if let Some(api) = API.get() {
        return Ok(api);
    }
    let _load = LOAD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(api) = API.get() {
        return Ok(api);
    }
    let loaded = load_dnssd()?;
    let _ = API.set(loaded);
    Ok(API.get().expect("successful dnssd load was cached"))
}

/// SAFETY: the module remains loaded and this value contains immutable
/// function pointers plus the retained module handle.
unsafe impl Sync for DnssdApi {}
unsafe impl Send for DnssdApi {}

fn load_dnssd() -> std::result::Result<DnssdApi, String> {
    /// Bind one exported symbol to its typed function pointer.
    fn symbol<T>(library: *mut core::ffi::c_void, name: &str) -> std::result::Result<T, String> {
        let bytes: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
        let proc = unsafe { GetProcAddress(library, bytes.as_ptr()) };
        match proc {
            Some(proc) => Ok(unsafe { std::mem::transmute_copy::<_, T>(&proc) }),
            None => Err(format!("dnssd.dll is missing {name}")),
        }
    }
    fn bind(library: *mut core::ffi::c_void) -> std::result::Result<DnssdApi, String> {
        Ok(DnssdApi {
            _library: library as usize,
            register: symbol(library, "DNSServiceRegister")?,
            browse: symbol(library, "DNSServiceBrowse")?,
            resolve: symbol(library, "DNSServiceResolve")?,
            ref_sock_fd: symbol(library, "DNSServiceRefSockFD")?,
            process_result: symbol(library, "DNSServiceProcessResult")?,
            ref_deallocate: symbol(library, "DNSServiceRefDeallocate")?,
        })
    }

    let mut binding_errors = Vec::new();
    let system_library = unsafe {
        LoadLibraryExW(
            wide("dnssd.dll").as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if !system_library.is_null() {
        match bind(system_library) {
            Ok(api) => return Ok(api),
            Err(error) => {
                binding_errors.push(format!("System32: {error}"));
                unsafe { FreeLibrary(system_library) };
            }
        }
    }
    for path in DNSSD_CANDIDATE_PATHS {
        let library = unsafe { LoadLibraryW(wide(path).as_ptr()) };
        if library.is_null() {
            continue;
        }
        match bind(library) {
            Ok(api) => return Ok(api),
            Err(error) => {
                binding_errors.push(format!("{path}: {error}"));
                unsafe { FreeLibrary(library) };
            }
        }
    }
    if binding_errors.is_empty() {
        Err("dnssd.dll not found in System32 or the Bonjour install directories".to_string())
    } else {
        Err(binding_errors.join("; "))
    }
}

// ── session ───────────────────────────────────────────────────────────

// Every raw DNSServiceRef is confined to one owner thread. These provider-
// neutral controls carry only cancellation and completion signals.
#[derive(Clone)]
struct ConnectionControl {
    inner: Arc<ConnectionSignal>,
}

struct ConnectionSignal {
    close_requested: AtomicBool,
    finished: Mutex<bool>,
    finished_cv: Condvar,
}

impl ConnectionControl {
    fn new() -> Self {
        Self {
            inner: Arc::new(ConnectionSignal {
                close_requested: AtomicBool::new(false),
                finished: Mutex::new(false),
                finished_cv: Condvar::new(),
            }),
        }
    }

    fn request_close(&self) {
        self.inner.close_requested.store(true, Ordering::Release);
    }

    fn close_requested(&self) -> bool {
        self.inner.close_requested.load(Ordering::Acquire)
    }

    fn finish(&self) {
        let mut finished = self
            .inner
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *finished = true;
        self.inner.finished_cv.notify_all();
    }

    fn is_finished(&self) -> bool {
        *self
            .inner
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait_finished(&self, wait: Duration) -> bool {
        let finished = self
            .inner
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *finished {
            return true;
        }
        match self
            .inner
            .finished_cv
            .wait_timeout_while(finished, wait, |finished| !*finished)
        {
            Ok((finished, _)) => *finished,
            Err(poisoned) => *poisoned.into_inner().0,
        }
    }
}

#[derive(Clone, Default)]
struct ConnectionRegistry {
    inner: Arc<Mutex<ConnectionRegistryState>>,
}

#[derive(Default)]
struct ConnectionRegistryState {
    shutting_down: bool,
    connections: Vec<ConnectionControl>,
}

impl ConnectionRegistry {
    fn track(&self, control: ConnectionControl) {
        let request_close = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .connections
                .retain(|connection| !connection.is_finished());
            let request_close = state.shutting_down;
            state.connections.push(control.clone());
            request_close
        };
        if request_close {
            control.request_close();
        }
    }

    fn begin_shutdown(&self) -> Vec<ConnectionControl> {
        let connections = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.shutting_down = true;
            state
                .connections
                .retain(|connection| !connection.is_finished());
            state.connections.clone()
        };
        for connection in &connections {
            connection.request_close();
        }
        connections
    }
}

#[derive(Debug)]
enum DriveFailure {
    InvalidSocket,
    Winsock(i32),
    SocketEvent(i16),
    Dnssd(i32),
}

impl std::fmt::Display for DriveFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSocket => write!(formatter, "DNSServiceRefSockFD returned no socket"),
            Self::Winsock(status) => write!(formatter, "WSAPoll failed (Winsock {status})"),
            Self::SocketEvent(events) => {
                write!(formatter, "Bonjour socket closed (poll flags {events:#x})")
            }
            Self::Dnssd(status) => {
                write!(formatter, "DNSServiceProcessResult failed (dnssd {status})")
            }
        }
    }
}

/// Process at most one ready callback batch. The finite socket poll makes
/// cancellation and operation deadlines real; `DNSServiceProcessResult` is
/// never used as a blocking wait primitive.
fn drive_once(
    api: &DnssdApi,
    reference: SdRef,
    wait: Duration,
) -> std::result::Result<bool, DriveFailure> {
    let socket = unsafe { (api.ref_sock_fd)(reference) };
    if socket == INVALID_SOCKET {
        return Err(DriveFailure::InvalidSocket);
    }
    let timeout = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    let mut descriptor = WSAPOLLFD {
        fd: socket,
        events: POLLRDNORM,
        revents: 0,
    };
    let ready = unsafe { WSAPoll(&mut descriptor, 1, timeout) };
    if ready == SOCKET_ERROR {
        return Err(DriveFailure::Winsock(unsafe { WSAGetLastError() } as i32));
    }
    if ready == 0 {
        return Ok(false);
    }
    if descriptor.revents & POLLRDNORM != 0 {
        let status = unsafe { (api.process_result)(reference) };
        return if status == K_DNSSERVICE_ERR_NO_ERROR {
            Ok(true)
        } else {
            Err(DriveFailure::Dnssd(status))
        };
    }
    let terminal = descriptor.revents & (POLLERR | POLLHUP | POLLNVAL);
    if terminal != 0 {
        return Err(DriveFailure::SocketEvent(terminal));
    }
    Ok(false)
}

fn remaining_slice(deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    Some(std::cmp::min(remaining, SOCKET_POLL_SLICE))
}

fn mark_publication_lost(
    state: &watch::Sender<ProviderSessionState>,
    operation: ProviderOperation,
    error: &DriveFailure,
) {
    tracing::info!(
        provider = DESCRIPTOR.name,
        operation = %operation,
        %error,
        "Bonjour owned connection failed; session must be replaced"
    );
    state.send_replace(ProviderSessionState::Lost);
}

/// Retire on the same thread that created and processed the connection. If
/// the responder is gone, calling its teardown path is both unnecessary and
/// known to hang on some Bonjour builds; the tiny callback context is then
/// deliberately quarantined instead of being freed under native code.
fn retire_owned<T>(api: &DnssdApi, reference: SdRef, runtime: Box<T>, control: &ConnectionControl) {
    if reference.is_null() {
        drop(runtime);
    } else if crate::windows_dnsapi::service_running("Bonjour Service") {
        unsafe { (api.ref_deallocate)(reference) };
        drop(runtime);
    } else {
        tracing::debug!(
            provider = DESCRIPTOR.name,
            "Bonjour responder is gone; callback context quarantined"
        );
        std::mem::forget(runtime);
    }
    control.finish();
}

async fn retire_connection(
    control: &ConnectionControl,
    state: &watch::Sender<ProviderSessionState>,
    operation: ProviderOperation,
) -> Result<()> {
    control.request_close();
    let waiter = control.clone();
    let finished = tokio::task::spawn_blocking(move || waiter.wait_finished(CALL_WAIT))
        .await
        .unwrap_or(false);
    if finished {
        return Ok(());
    }
    if !crate::windows_dnsapi::service_running("Bonjour Service") {
        // A daemon-loss race may strand the owner inside vendor teardown. It
        // still owns the ref and context, so detach that safe quarantine from
        // the new provider generation instead of blocking failover.
        control.finish();
        return Ok(());
    }
    if *state.borrow() != ProviderSessionState::Lost {
        state.send_replace(ProviderSessionState::Recovering);
    }
    Err(provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Timeout,
        format!("Bonjour connection retirement exceeded {CALL_WAIT:?}"),
    ))
}

struct BonjourSession {
    state_tx: watch::Sender<ProviderSessionState>,
    state_rx: watch::Receiver<ProviderSessionState>,
    capabilities: MdnsCapabilities,
    connections: ConnectionRegistry,
    workers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl BonjourSession {
    fn start(capabilities: MdnsCapabilities) -> Self {
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        Self {
            state_tx,
            state_rx,
            capabilities,
            connections: ConnectionRegistry::default(),
            workers: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl ProviderSession for BonjourSession {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    fn capabilities(&self) -> MdnsCapabilities {
        self.capabilities
    }

    fn state(&self) -> watch::Receiver<ProviderSessionState> {
        self.state_rx.clone()
    }

    async fn publish(&self, announcement: &Announcement) -> Result<Box<dyn PublicationLease>> {
        let service_type = regtype_from(&announcement.service_type)?;
        let request = RegisterRequest {
            name: announcement.name.clone(),
            service_type,
            port: announcement.port,
            txt: build_txt(&announcement.txt),
        };
        let connections = self.connections.clone();
        let state_tx = self.state_tx.clone();
        let outcome =
            tokio::task::spawn_blocking(move || register_native(request, connections, state_tx))
                .await
                .map_err(|error| {
                    provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Lost,
                        format!("register task failed: {error}"),
                    )
                })?;
        let registered = match outcome {
            Ok(registered) => registered,
            Err(error) => return Err(error),
        };
        Ok(Box::new(BonjourPublicationLease {
            id: announcement.id.clone(),
            control: registered.control,
            state_tx: self.state_tx.clone(),
            final_name: registered.final_name,
            active: true,
        }))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        if *self.state_tx.borrow() != ProviderSessionState::Ready {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Recovering,
                "the Bonjour daemon is recovering; browse reconnects when it returns",
            ));
        }
        let regtype = regtype_from(service_type)?;
        let (browse, worker) = match open_bonjour_browse(
            &regtype,
            is_meta,
            self.connections.clone(),
            self.state_tx.clone(),
        )
        .await
        {
            Ok(pair) => pair,
            Err(error) => return Err(error),
        };
        self.workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(worker);
        Ok(browse)
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        if *self.state_tx.borrow() != ProviderSessionState::Ready {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Recovering,
                "the Bonjour daemon is recovering; resolution reconnects when it returns",
            ));
        }
        let regtype = regtype_from(service_type)?;
        let domain = domain_of(&regtype);
        let name = name.to_string();
        let connections = self.connections.clone();
        tokio::task::spawn_blocking(move || resolve_native(&name, &regtype, &domain, connections))
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
        self.state_tx.send_replace(ProviderSessionState::Lost);
        let _ = self.connections.begin_shutdown();
        let workers = self
            .workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
            .collect::<Vec<_>>();
        for worker in workers {
            let _ = worker.await;
        }
        let connections = self.connections.begin_shutdown();
        let waiting = connections.clone();
        let retired = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + CALL_WAIT;
            waiting.into_iter().all(|connection| {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return connection.is_finished();
                };
                connection.wait_finished(remaining)
            })
        })
        .await
        .unwrap_or(false);
        if retired {
            return Ok(());
        }
        if !crate::windows_dnsapi::service_running("Bonjour Service") {
            // Any owner stranded inside vendor teardown still owns its native
            // callback context; acknowledge that quarantine so failover can
            // continue with the newly selected provider generation.
            for connection in connections {
                connection.finish();
            }
            return Ok(());
        }
        Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Shutdown,
            ProviderFailure::Timeout,
            format!("Bonjour session retirement exceeded {CALL_WAIT:?}"),
        ))
    }
}

// ── publication ───────────────────────────────────────────────────────

struct RegisterRequest {
    name: String,
    service_type: String,
    port: u16,
    txt: Vec<u8>,
}

struct RegisteredNative {
    control: ConnectionControl,
    final_name: String,
}

/// Register through `DNSServiceRegister` and wait for the completion reply.
/// The reply may rename the instance on conflict; the final name is reported.
/// The owner keeps processing after the acknowledgement so later daemon or
/// registration failures can invalidate the provider session truthfully.
fn register_native(
    request: RegisterRequest,
    connections: ConnectionRegistry,
    state_tx: watch::Sender<ProviderSessionState>,
) -> Result<RegisteredNative> {
    struct RegisterRuntime {
        reply: mpsc::Sender<(i32, String)>,
    }

    unsafe extern "system" fn register_reply(
        _sd_ref: SdRef,
        _flags: u32,
        error_code: i32,
        name: *const u8,
        _regtype: *const u8,
        _domain: *const u8,
        context: *mut core::ffi::c_void,
    ) {
        let runtime = unsafe { &*(context as *const RegisterRuntime) };
        let final_name = if name.is_null() {
            String::new()
        } else {
            unsafe { read_cstr(name) }
        };
        let _ = runtime.reply.send((error_code, final_name));
    }

    let api = match dnssd() {
        Ok(api) => api,
        Err(missing) => return Err(dnssd_missing(ProviderOperation::Publish, &missing)),
    };
    let fallback_name = request.name.clone();
    let control = ConnectionControl::new();
    connections.track(control.clone());
    let owner = control.clone();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<String>>(1);
    let thread = std::thread::Builder::new()
        .name("koi-mdns-bonjour-publish".to_string())
        .spawn(move || {
            let (reply_tx, reply_rx) = mpsc::channel::<(i32, String)>();
            let mut runtime = Box::new(RegisterRuntime { reply: reply_tx });
            let name_c = cstr(&request.name);
            let regtype_c = cstr(&request.service_type);
            let mut reference: SdRef = std::ptr::null_mut();
            let error = unsafe {
                (api.register)(
                    &mut reference,
                    0,
                    0,
                    name_c.as_ptr(),
                    regtype_c.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    request.port.to_be(),
                    request.txt.len() as u16,
                    if request.txt.len() == 1 && request.txt[0] == 0 {
                        std::ptr::null()
                    } else {
                        request.txt.as_ptr()
                    },
                    register_reply,
                    (&mut *runtime as *mut RegisterRuntime).cast(),
                )
            };
            if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
                let _ = ready_tx.send(Err(dnssd_error(
                    ProviderOperation::Publish,
                    error,
                    "DNSServiceRegister",
                )));
                retire_owned(api, reference, runtime, &owner);
                return;
            }

            let deadline = Instant::now() + CALL_WAIT;
            let mut acknowledged = false;
            loop {
                if owner.close_requested() {
                    if !acknowledged {
                        let _ = ready_tx.send(Err(provider_error(
                            DESCRIPTOR.name,
                            ProviderOperation::Publish,
                            ProviderFailure::Lost,
                            "publication was cancelled before Bonjour acknowledged it",
                        )));
                    }
                    break;
                }
                while let Ok((status, final_name)) = reply_rx.try_recv() {
                    if !acknowledged {
                        if status == K_DNSSERVICE_ERR_NO_ERROR {
                            acknowledged = true;
                            let _ = ready_tx.send(Ok(final_name));
                        } else {
                            let _ = ready_tx.send(Err(dnssd_error(
                                ProviderOperation::Publish,
                                status,
                                "DNSServiceRegister reply",
                            )));
                            owner.request_close();
                        }
                    } else if status != K_DNSSERVICE_ERR_NO_ERROR {
                        mark_publication_lost(
                            &state_tx,
                            ProviderOperation::Publish,
                            &DriveFailure::Dnssd(status),
                        );
                        owner.request_close();
                    }
                }
                if owner.close_requested() {
                    continue;
                }
                let wait = if acknowledged {
                    SOCKET_POLL_SLICE
                } else if let Some(remaining) = remaining_slice(deadline) {
                    remaining
                } else {
                    let _ = ready_tx.send(Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Timeout,
                        format!("DNSServiceRegister reply exceeded {CALL_WAIT:?}"),
                    )));
                    break;
                };
                if let Err(error) = drive_once(api, reference, wait) {
                    if !acknowledged {
                        let _ = ready_tx.send(Err(provider_error(
                            DESCRIPTOR.name,
                            ProviderOperation::Publish,
                            ProviderFailure::Lost,
                            error.to_string(),
                        )));
                    } else {
                        mark_publication_lost(&state_tx, ProviderOperation::Publish, &error);
                    }
                    break;
                }
            }
            retire_owned(api, reference, runtime, &owner);
        });
    if let Err(error) = thread {
        control.finish();
        return Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Publish,
            ProviderFailure::Lost,
            format!("could not start Bonjour connection owner: {error}"),
        ));
    }
    let final_name = match ready_rx.recv_timeout(CALL_WAIT + SOCKET_POLL_SLICE) {
        Ok(result) => result?,
        Err(_) => {
            control.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Timeout,
                format!("Bonjour publication owner exceeded {CALL_WAIT:?}"),
            ));
        }
    };
    Ok(RegisteredNative {
        control,
        final_name: if final_name.is_empty() {
            fallback_name
        } else {
            final_name
        },
    })
}

struct BonjourPublicationLease {
    id: String,
    control: ConnectionControl,
    state_tx: watch::Sender<ProviderSessionState>,
    final_name: String,
    active: bool,
}

#[async_trait::async_trait]
impl PublicationLease for BonjourPublicationLease {
    fn announcement_id(&self) -> &str {
        &self.id
    }

    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn withdraw(&mut self) -> Result<()> {
        if self.active {
            retire_connection(&self.control, &self.state_tx, ProviderOperation::Withdraw).await?;
            self.active = false;
            tracing::debug!(
                provider = DESCRIPTOR.name,
                publication = %self.id,
                name = %self.final_name,
                "Bonjour registration released"
            );
        }
        Ok(())
    }
}

impl Drop for BonjourPublicationLease {
    fn drop(&mut self) {
        if self.active {
            self.control.request_close();
        }
    }
}

// ── browse ────────────────────────────────────────────────────────────

struct BrowseRuntime {
    events: mpsc::Sender<BrowseObservation>,
    failure: AtomicI32,
}

enum BrowseObservation {
    Add { name: String, regtype: String },
    Remove { name: String, regtype: String },
    Failed(i32),
}

async fn open_bonjour_browse(
    regtype: &str,
    is_meta: bool,
    connections: ConnectionRegistry,
    state_tx: watch::Sender<ProviderSessionState>,
) -> Result<(ProviderBrowse, tokio::task::JoinHandle<()>)> {
    let (event_tx, event_rx) = tokio_mpsc::channel(BROWSE_CHANNEL_CAPACITY);
    let (observation_tx, observation_rx) = mpsc::channel::<BrowseObservation>();

    unsafe extern "system" fn browse_reply(
        _sd_ref: SdRef,
        flags: u32,
        _interface_index: u32,
        error_code: i32,
        service_name: *const u8,
        regtype: *const u8,
        _reply_domain: *const u8,
        context: *mut core::ffi::c_void,
    ) {
        let runtime = unsafe { &*(context as *const BrowseRuntime) };
        let observation = if error_code != K_DNSSERVICE_ERR_NO_ERROR {
            runtime.failure.store(error_code, Ordering::Release);
            BrowseObservation::Failed(error_code)
        } else {
            let name = if service_name.is_null() {
                String::new()
            } else {
                unsafe { read_cstr(service_name) }
            };
            let typ = if regtype.is_null() {
                String::new()
            } else {
                unsafe { read_cstr(regtype) }
            };
            if flags & K_DNSSERVICE_FLAGS_ADD != 0 {
                BrowseObservation::Add { name, regtype: typ }
            } else {
                BrowseObservation::Remove { name, regtype: typ }
            }
        };
        let _ = runtime.events.send(observation);
    }

    let api = match dnssd() {
        Ok(api) => api,
        Err(missing) => return Err(dnssd_missing(ProviderOperation::Browse, &missing)),
    };
    let control = ConnectionControl::new();
    connections.track(control.clone());
    let owner = control.clone();
    let owner_regtype = regtype.to_string();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<()>>(1);
    let callback_thread = std::thread::Builder::new()
        .name(format!("koi-mdns-bonjour-browse-{regtype}"))
        .spawn(move || {
            let mut runtime = Box::new(BrowseRuntime {
                events: observation_tx,
                failure: AtomicI32::new(K_DNSSERVICE_ERR_NO_ERROR),
            });
            let regtype_c = cstr(&owner_regtype);
            let mut reference: SdRef = std::ptr::null_mut();
            let error = unsafe {
                (api.browse)(
                    &mut reference,
                    0,
                    0,
                    regtype_c.as_ptr(),
                    std::ptr::null(),
                    browse_reply,
                    (&mut *runtime as *mut BrowseRuntime).cast(),
                )
            };
            if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
                let _ = ready_tx.send(Err(dnssd_error(
                    ProviderOperation::Browse,
                    error,
                    "DNSServiceBrowse",
                )));
                retire_owned(api, reference, runtime, &owner);
                return;
            }
            if ready_tx.send(Ok(())).is_err() {
                owner.request_close();
            }
            while !owner.close_requested() {
                if let Err(error) = drive_once(api, reference, SOCKET_POLL_SLICE) {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        operation = %ProviderOperation::Browse,
                        %error,
                        "Bonjour browse connection ended"
                    );
                    break;
                }
                let callback_error = runtime.failure.load(Ordering::Acquire);
                if callback_error != K_DNSSERVICE_ERR_NO_ERROR {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        operation = %ProviderOperation::Browse,
                        error = callback_error,
                        "Bonjour browse callback ended the connection"
                    );
                    break;
                }
            }
            retire_owned(api, reference, runtime, &owner);
        });
    if let Err(error) = callback_thread {
        control.finish();
        return Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Browse,
            ProviderFailure::Lost,
            format!("could not start Bonjour connection owner: {error}"),
        ));
    }
    let startup =
        tokio::task::spawn_blocking(move || ready_rx.recv_timeout(CALL_WAIT + SOCKET_POLL_SLICE))
            .await
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Browse,
                    ProviderFailure::Lost,
                    format!("browse startup wait failed: {error}"),
                )
            })?;
    match startup {
        Ok(result) => result?,
        Err(_) => {
            control.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Timeout,
                format!("Bonjour browse startup exceeded {CALL_WAIT:?}"),
            ));
        }
    }

    let worker_control = control.clone();
    let worker_connections = connections.clone();
    let worker = tokio::task::spawn_blocking(move || {
        loop {
            if worker_control.close_requested() || worker_control.is_finished() {
                break;
            }
            let observation = match observation_rx.recv_timeout(SOCKET_POLL_SLICE) {
                Ok(observation) => observation,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let emitted = match observation {
                BrowseObservation::Add { name, regtype } => {
                    if is_meta {
                        // Meta observations enumerate service types; the type
                        // name itself is the record Koi surfaces.
                        event_tx.blocking_send(ProviderEvent::Found(ProviderService {
                            name: trim_local(&name),
                            service_type: String::new(),
                            host: None,
                            addresses: Vec::new(),
                            port: None,
                            txt: HashMap::new(),
                        }))
                    } else {
                        let domain = domain_of(&regtype);
                        match resolve_native(&name, &regtype, &domain, worker_connections.clone()) {
                            Ok(service) => event_tx.blocking_send(ProviderEvent::Resolved(service)),
                            Err(error) => {
                                tracing::debug!(
                                    provider = DESCRIPTOR.name,
                                    instance = %name,
                                    %error,
                                    "browse resolve failed; instance stays unresolved"
                                );
                                continue;
                            }
                        }
                    }
                }
                BrowseObservation::Remove { name, regtype } => {
                    event_tx.blocking_send(ProviderEvent::Removed {
                        name,
                        service_type: trim_local(&regtype),
                    })
                }
                BrowseObservation::Failed(error) => {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        error,
                        "Bonjour browse reported an error; ending the stream"
                    );
                    break;
                }
            };
            if emitted.is_err() {
                break;
            }
        }
        worker_control.request_close();
    });

    Ok((
        ProviderBrowse::new(
            event_rx,
            Box::new(BonjourBrowseLease {
                control: control.clone(),
                state_tx: state_tx.clone(),
                active: true,
            }),
        ),
        worker,
    ))
}

struct BonjourBrowseLease {
    control: ConnectionControl,
    state_tx: watch::Sender<ProviderSessionState>,
    active: bool,
}

#[async_trait::async_trait]
impl BrowseLease for BonjourBrowseLease {
    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn close(&mut self) -> Result<()> {
        if self.active {
            retire_connection(&self.control, &self.state_tx, ProviderOperation::Browse).await?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for BonjourBrowseLease {
    fn drop(&mut self) {
        if self.active {
            self.control.request_close();
        }
    }
}

// ── resolve ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct ResolveOutcome {
    error_code: i32,
    fullname: String,
    host: String,
    port: u16,
    txt: Vec<u8>,
}

/// Resolve one instance with `DNSServiceResolve` on a dedicated connection,
/// returning full service data only after the completion reply.
fn resolve_native(
    name: &str,
    regtype: &str,
    domain: &str,
    connections: ConnectionRegistry,
) -> Result<ProviderService> {
    struct ResolveRuntime {
        reply: mpsc::Sender<ResolveOutcome>,
    }

    unsafe extern "system" fn resolve_reply(
        _sd_ref: SdRef,
        _flags: u32,
        _interface_index: u32,
        error_code: i32,
        fullname: *const u8,
        hosttarget: *const u8,
        port: u16,
        txt_len: u16,
        txt_record: *const u8,
        context: *mut core::ffi::c_void,
    ) {
        let runtime = unsafe { &*(context as *const ResolveRuntime) };
        let outcome = ResolveOutcome {
            error_code,
            fullname: if fullname.is_null() {
                String::new()
            } else {
                unsafe { read_cstr(fullname) }
            },
            host: if hosttarget.is_null() {
                String::new()
            } else {
                unsafe { read_cstr(hosttarget) }
            },
            port: u16::from_be(port),
            txt: if txt_record.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(txt_record, txt_len as usize).to_vec() }
            },
        };
        let _ = runtime.reply.send(outcome);
    }

    let api = match dnssd() {
        Ok(api) => api,
        Err(missing) => return Err(dnssd_missing(ProviderOperation::Resolve, &missing)),
    };
    let owner_name = name.to_string();
    let owner_regtype = regtype.to_string();
    let owner_domain = domain.to_string();
    let control = ConnectionControl::new();
    connections.track(control.clone());
    let owner = control.clone();
    let (result_tx, result_rx) = mpsc::sync_channel::<Result<ResolveOutcome>>(1);
    let thread = std::thread::Builder::new()
        .name("koi-mdns-bonjour-resolve".to_string())
        .spawn(move || {
            let (reply_tx, reply_rx) = mpsc::channel::<ResolveOutcome>();
            let mut runtime = Box::new(ResolveRuntime { reply: reply_tx });
            let name_c = cstr(&owner_name);
            let regtype_c = cstr(&owner_regtype);
            let domain_c = cstr(&owner_domain);
            let mut reference: SdRef = std::ptr::null_mut();
            let error = unsafe {
                (api.resolve)(
                    &mut reference,
                    0,
                    0,
                    name_c.as_ptr(),
                    regtype_c.as_ptr(),
                    domain_c.as_ptr(),
                    resolve_reply,
                    (&mut *runtime as *mut ResolveRuntime).cast(),
                )
            };
            if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
                let _ = result_tx.send(Err(dnssd_error(
                    ProviderOperation::Resolve,
                    error,
                    "DNSServiceResolve",
                )));
                retire_owned(api, reference, runtime, &owner);
                return;
            }

            let deadline = Instant::now() + RESOLVE_WAIT;
            loop {
                if let Ok(outcome) = reply_rx.try_recv() {
                    let result = if outcome.error_code == K_DNSSERVICE_ERR_NO_ERROR {
                        Ok(outcome)
                    } else {
                        Err(dnssd_error(
                            ProviderOperation::Resolve,
                            outcome.error_code,
                            "DNSServiceResolve reply",
                        ))
                    };
                    let _ = result_tx.send(result);
                    break;
                }
                if owner.close_requested() {
                    break;
                }
                let Some(wait) = remaining_slice(deadline) else {
                    let _ = result_tx.send(Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Resolve,
                        ProviderFailure::Timeout,
                        format!("DNSServiceResolve reply exceeded {RESOLVE_WAIT:?}"),
                    )));
                    break;
                };
                if let Err(error) = drive_once(api, reference, wait) {
                    let _ = result_tx.send(Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Resolve,
                        ProviderFailure::Lost,
                        error.to_string(),
                    )));
                    break;
                }
            }
            retire_owned(api, reference, runtime, &owner);
        });
    if let Err(error) = thread {
        control.finish();
        return Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Lost,
            format!("could not start Bonjour connection owner: {error}"),
        ));
    }
    let outcome = match result_rx.recv_timeout(RESOLVE_WAIT + SOCKET_POLL_SLICE) {
        Ok(result) => result?,
        Err(_) => {
            control.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Timeout,
                format!("Bonjour resolve owner exceeded {RESOLVE_WAIT:?}"),
            ));
        }
    };
    let instance = instance_label(&outcome.fullname).unwrap_or_else(|| name.to_string());
    Ok(ProviderService {
        name: instance,
        service_type: trim_local(regtype),
        host: non_empty(outcome.host),
        port: (outcome.port != 0).then_some(outcome.port),
        addresses: Vec::new(),
        txt: parse_txt(&outcome.txt),
    })
}

// ── shared helpers ────────────────────────────────────────────────────

/// Canonical service type (`_http._tcp.local.`) to dnssd regtype (`_http._tcp`).
fn regtype_from(service_type: &str) -> Result<String> {
    let trimmed = service_type
        .trim_end_matches('.')
        .trim_end_matches(".local");
    if !trimmed.starts_with('_') || !trimmed.contains("._") {
        return Err(MdnsError::InvalidServiceType(service_type.to_string()));
    }
    Ok(trimmed.to_string())
}

fn domain_of(regtype: &str) -> String {
    if regtype.to_ascii_lowercase().ends_with(".local") {
        regtype
            .rsplit_once('.')
            .map(|(_, domain)| domain.to_string())
            .unwrap_or_else(|| "local".to_string())
    } else {
        "local".to_string()
    }
}

fn trim_local(value: &str) -> String {
    value
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

/// The instance label is everything before the first service-type label.
fn instance_label(full_name: &str) -> Option<String> {
    full_name
        .find("._")
        .map(|index| full_name[..index].to_string())
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// RFC 6763 TXT wire format: a series of single-byte-prefixed "key=value"
/// strings. Empty maps produce one empty string byte, the documented encoding
/// for "no data".
fn build_txt(txt: &HashMap<String, String>) -> Vec<u8> {
    if txt.is_empty() {
        return vec![0];
    }
    let mut out = Vec::new();
    for (key, value) in txt {
        let entry_len = key.len() + 1 + value.len();
        if entry_len > 255 || key.is_empty() {
            continue;
        }
        out.push(entry_len as u8);
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
    }
    if out.is_empty() || out.len() > 65535 {
        return vec![0];
    }
    out
}

fn parse_txt(bytes: &[u8]) -> HashMap<String, String> {
    let mut txt = HashMap::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let len = bytes[cursor] as usize;
        if len == 0 {
            cursor += 1;
            continue;
        }
        let end = std::cmp::min(cursor + 1 + len, bytes.len());
        let entry = String::from_utf8_lossy(&bytes[cursor + 1..end]);
        if let Some((key, value)) = entry.split_once('=') {
            if !key.is_empty() {
                txt.insert(key.to_string(), value.to_string());
            }
        }
        cursor += 1 + len;
    }
    txt
}

fn cstr(value: &str) -> Vec<u8> {
    value.bytes().chain(std::iter::once(0)).collect()
}

/// # Safety
/// `ptr` must point to a NUL-terminated UTF-8 string owned by dnssd, or null.
unsafe fn read_cstr(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

fn dnssd_missing(operation: ProviderOperation, missing: &str) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Unavailable,
        missing.to_string(),
    )
}

fn dnssd_error(operation: ProviderOperation, status: i32, what: &str) -> MdnsError {
    let failure = if status == K_DNSSERVICE_ERR_NAMECONFLICT {
        ProviderFailure::Conflict
    } else {
        ProviderFailure::Protocol
    };
    provider_error(
        DESCRIPTOR.name,
        operation,
        failure,
        format!("{what} failed (dnssd error {status})"),
    )
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAPoll, INVALID_SOCKET, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, SOCKET,
    SOCKET_ERROR, WSAPOLLFD,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LoadLibraryW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_a_full_provider_without_explicit_addresses() {
        let capabilities = DESCRIPTOR.capabilities;
        assert!(capabilities.publish);
        assert!(capabilities.withdraw);
        assert!(capabilities.continuous_browse);
        assert!(capabilities.direct_resolve);
        assert!(!capabilities.explicit_address);
        // It cannot serve the explicit-address write route on its own, but it
        // covers ordinary publication and continuous browse without help.
        assert!(!capabilities.satisfies_provider_contract());
        assert!(capabilities.supports(MdnsCapabilities {
            publish: true,
            withdraw: true,
            continuous_browse: true,
            browse_resolves: true,
            direct_resolve: true,
            explicit_address: false,
        }));
    }

    #[test]
    fn regtype_strips_the_local_domain() {
        assert_eq!(regtype_from("_http._tcp").unwrap(), "_http._tcp");
        assert_eq!(regtype_from("_mcp._tcp.local.").unwrap(), "_mcp._tcp");
        assert!(regtype_from("bogus").is_err());
    }

    #[test]
    fn txt_wire_round_trips_pairs() {
        let bytes = build_txt(&HashMap::from([
            ("source".to_string(), "bonjour".to_string()),
            ("path".to_string(), "/v1/mcp".to_string()),
        ]));
        assert_eq!(parse_txt(&bytes).len(), 2);
        assert_eq!(
            parse_txt(&bytes).get("source").map(String::as_str),
            Some("bonjour")
        );
    }

    #[test]
    fn empty_txt_is_a_single_zero_byte() {
        assert_eq!(build_txt(&HashMap::new()), vec![0]);
        assert!(parse_txt(&build_txt(&HashMap::new())).is_empty());
    }

    #[test]
    fn instance_labels_split_at_the_service_type() {
        assert_eq!(
            instance_label("Koi MCP (test-01)._mcp._tcp.local."),
            Some("Koi MCP (test-01)".to_string())
        );
        assert_eq!(instance_label("plainname"), None);
    }

    #[test]
    fn lease_signals_owner_and_waits_for_owner_acknowledgement() {
        let control = ConnectionControl::new();
        let owner = control.clone();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let owner_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            while !owner.close_requested() {
                std::thread::park_timeout(Duration::from_millis(5));
            }
            owner.finish();
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!control.is_finished());
        control.request_close();
        assert!(control.wait_finished(Duration::from_secs(1)));
        owner_thread.join().unwrap();
    }

    #[test]
    fn registry_cancels_connections_that_arrive_during_shutdown() {
        let registry = ConnectionRegistry::default();
        assert!(registry.begin_shutdown().is_empty());

        let late = ConnectionControl::new();
        registry.track(late.clone());

        assert!(late.close_requested());
        late.finish();
        assert!(registry.begin_shutdown().is_empty());
    }

    #[test]
    fn readiness_wait_is_always_finite() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let wait = remaining_slice(deadline).unwrap();
        assert!(wait <= SOCKET_POLL_SLICE);
        assert!(remaining_slice(Instant::now() - Duration::from_millis(1)).is_none());
    }

    #[tokio::test]
    #[ignore = "requires an installed Bonjour service on Windows"]
    async fn real_bonjour_report_requires_the_responder_service() {
        let report = WindowsBonjourAdapter.assess().await;
        assert_eq!(report.name, DESCRIPTOR.name);
        assert_eq!(report.api, ProviderApi::BonjourDnsSd);
        if report.availability == ProviderAvailability::Ready {
            assert_eq!(report.running, ProbeFact::Yes);
            assert!(report.capabilities.publish);
        } else {
            assert_eq!(report.running, ProbeFact::No);
            assert_eq!(report.capabilities, MdnsCapabilities::default());
        }
    }
}
