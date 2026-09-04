//! Windows mDNS provider backed by Apple Bonjour (`dnssd.dll`), when the
//! mDNSResponder service is genuinely installed.
//!
//! Bonjour is a full provider on Windows: it publishes acknowledged
//! registrations, browses with add/remove events, and resolves by name —
//! completing each resolution with `DNSServiceGetAddrInfo` so resolved
//! services carry real addresses with the interface identity the callbacks
//! reported, and browse-driven resolves use the domain the browse callback
//! returned instead of an assumed one. It deliberately does not claim
//! explicit-address publication — `DNSServiceRegister` pins records to the
//! host identity, not to caller-chosen addresses. When Bonjour is absent,
//! `assess` reports `Absent` with the exact missing facts and the control
//! plane never opens a session.
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

use tokio::sync::{mpsc as tokio_mpsc, oneshot, watch};

use crate::adapter::{
    failed_assessment, MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderAddress, ProviderBrowse, ProviderEvent,
    ProviderService, ProviderSession, ProviderTask, PublicationLease,
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
// Flag and protocol values from Apple's dns_sd.h. The Add bit is 0x2 — 0x1 is
// kDNSServiceFlagsMoreComing — so misreading it inverts browse add/remove.
const K_DNSSERVICE_FLAGS_MORECOMING: u32 = 0x1;
const K_DNSSERVICE_FLAGS_ADD: u32 = 0x2;
const K_DNSSERVICE_PROTOCOL_IPV4: u32 = 0x01;
const K_DNSSERVICE_PROTOCOL_IPV6: u32 = 0x02;

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

type GetAddrInfoReply = unsafe extern "system" fn(
    sd_ref: SdRef,
    flags: u32,
    interface_index: u32,
    error_code: i32,
    hostname: *const u8,
    address: *const SOCKADDR,
    ttl: u32,
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
        flags: u32,
        interfaceindex: u32,
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
        flags: u32,
        interfaceindex: u32,
        regtype: *const u8,
        domain: *const u8,
        callback: BrowseReply,
        context: *mut core::ffi::c_void,
    ) -> i32,
    resolve: unsafe extern "system" fn(
        sdref: *mut SdRef,
        flags: u32,
        interfaceindex: u32,
        name: *const u8,
        regtype: *const u8,
        domain: *const u8,
        callback: ResolveReply,
        context: *mut core::ffi::c_void,
    ) -> i32,
    get_addr_info: unsafe extern "system" fn(
        sdref: *mut SdRef,
        flags: u32,
        interfaceindex: u32,
        protocols: u32,
        hostname: *const u8,
        callback: GetAddrInfoReply,
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
            get_addr_info: symbol(library, "DNSServiceGetAddrInfo")?,
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

/// One Bonjour callback thread and the connection/context confined to it.
///
/// The registry and the operation lease share this owner, but the native
/// thread handle itself has exactly one slot. `finished` is signalled only
/// after deallocation (or deliberate daemon-death quarantine), so joining is
/// a non-blocking completion proof once that barrier is observed.
struct NativeThreadOwner {
    control: ConnectionControl,
    worker: Mutex<NativeThreadState>,
}

enum NativeThreadState {
    Starting,
    Running(std::thread::JoinHandle<()>),
    Reaped,
}

impl NativeThreadOwner {
    fn new() -> Self {
        Self {
            control: ConnectionControl::new(),
            worker: Mutex::new(NativeThreadState::Starting),
        }
    }

    fn attach(&self, worker: std::thread::JoinHandle<()>) {
        let mut state = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &*state {
            NativeThreadState::Starting => *state = NativeThreadState::Running(worker),
            NativeThreadState::Reaped => drop(worker),
            NativeThreadState::Running(_) => {
                debug_assert!(false, "Bonjour callback owner attached twice");
                drop(worker);
            }
        }
    }

    fn start_failed(&self) {
        self.control.finish();
        *self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = NativeThreadState::Reaped;
    }

    fn request_close(&self) {
        self.control.request_close();
    }

    fn close_requested(&self) -> bool {
        self.control.close_requested()
    }

    fn finish(&self) {
        self.control.finish();
    }

    fn is_finished(&self) -> bool {
        self.control.is_finished()
    }

    fn is_worker_ready(&self) -> bool {
        !matches!(
            &*self
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            NativeThreadState::Starting
        )
    }

    fn wait_finished(&self, wait: Duration) -> bool {
        self.control.wait_finished(wait)
    }

    fn join_finished(&self) -> std::result::Result<(), String> {
        if !self.is_finished() {
            return Err("Bonjour owner has not crossed its release barrier".to_string());
        }
        let state = {
            let mut state = self
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::replace(&mut *state, NativeThreadState::Reaped)
        };
        match state {
            NativeThreadState::Running(worker) => worker
                .join()
                .map_err(|_| "Bonjour callback owner panicked".to_string()),
            NativeThreadState::Reaped => Ok(()),
            NativeThreadState::Starting => {
                *self
                    .worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = NativeThreadState::Starting;
                Err("Bonjour callback owner has not attached its thread".to_string())
            }
        }
    }

    fn quarantine(&self) {
        self.request_close();
        self.control.finish();
        let state = {
            let mut state = self
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::replace(&mut *state, NativeThreadState::Reaped)
        };
        if let NativeThreadState::Running(worker) = state {
            // The stopped responder can strand vendor teardown. Detaching that
            // native owner is an explicit quarantine: its callback context
            // remains on the same thread and cannot enter a new provider epoch.
            drop(worker);
        }
    }
}

impl Drop for NativeThreadOwner {
    fn drop(&mut self) {
        self.control.request_close();
    }
}

#[derive(Clone, Default)]
struct ConnectionRegistry {
    inner: Arc<Mutex<ConnectionRegistryState>>,
}

#[derive(Default)]
struct ConnectionRegistryState {
    shutting_down: bool,
    connections: Vec<Arc<NativeThreadOwner>>,
}

impl ConnectionRegistry {
    fn track(&self, owner: Arc<NativeThreadOwner>) {
        let request_close = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let request_close = state.shutting_down;
            state.connections.push(Arc::clone(&owner));
            request_close
        };
        if request_close {
            owner.request_close();
        }
    }

    fn begin_shutdown(&self) -> Vec<Arc<NativeThreadOwner>> {
        let connections = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.shutting_down = true;
            state.connections.clone()
        };
        for connection in &connections {
            connection.request_close();
        }
        connections
    }

    fn clear(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
            .clear();
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
fn retire_owned<T>(api: &DnssdApi, reference: SdRef, runtime: Box<T>, owner: &NativeThreadOwner) {
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
    owner.finish();
}

async fn retire_connection(
    owner: &NativeThreadOwner,
    state: &watch::Sender<ProviderSessionState>,
    operation: ProviderOperation,
    wait: Duration,
) -> Result<()> {
    owner.request_close();
    let deadline = tokio::time::Instant::now() + wait;
    while (!owner.is_finished() || !owner.is_worker_ready())
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(SOCKET_POLL_SLICE).await;
    }
    if owner.is_finished() && owner.is_worker_ready() {
        return owner.join_finished().map_err(|detail| {
            provider_error(DESCRIPTOR.name, operation, ProviderFailure::Lost, detail)
        });
    }
    if !crate::windows_dnsapi::service_running("Bonjour Service") {
        // A daemon-loss race may strand the owner inside vendor teardown. It
        // still owns the ref and context, so detach that safe quarantine from
        // the new provider generation instead of blocking failover.
        owner.quarantine();
        return Ok(());
    }
    if *state.borrow() != ProviderSessionState::Lost {
        state.send_replace(ProviderSessionState::Recovering);
    }
    Err(provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Timeout,
        format!("Bonjour connection retirement exceeded {wait:?}"),
    ))
}

fn finish_native_call<T>(
    owner: &NativeThreadOwner,
    operation: ProviderOperation,
    outcome: Result<T>,
    wait: Duration,
) -> Result<T> {
    owner.request_close();
    if owner.wait_finished(wait) {
        owner.join_finished().map_err(|detail| {
            provider_error(DESCRIPTOR.name, operation, ProviderFailure::Lost, detail)
        })?;
    } else if !crate::windows_dnsapi::service_running("Bonjour Service") {
        owner.quarantine();
    } else {
        return Err(provider_error(
            DESCRIPTOR.name,
            operation,
            ProviderFailure::Timeout,
            format!("Bonjour connection retirement exceeded {wait:?}"),
        ));
    }
    outcome
}

struct BonjourSession {
    state_tx: watch::Sender<ProviderSessionState>,
    state_rx: watch::Receiver<ProviderSessionState>,
    capabilities: MdnsCapabilities,
    connections: ConnectionRegistry,
    workers: BonjourWorkerRegistry,
}

impl BonjourSession {
    fn start(capabilities: MdnsCapabilities) -> Self {
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        Self {
            state_tx,
            state_rx,
            capabilities,
            connections: ConnectionRegistry::default(),
            workers: BonjourWorkerRegistry::default(),
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
        let (owner, final_name) = registered.into_parts();
        Ok(Box::new(BonjourPublicationLease {
            id: announcement.id.clone(),
            owner,
            state_tx: self.state_tx.clone(),
            final_name,
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
        if !self.workers.track(Arc::clone(&worker)) {
            let _ = browse.close().await;
            let _ = worker.join(CALL_WAIT).await;
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Lost,
                "session shutdown began during browse startup",
            ));
        }
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
        // A direct resolve has no browse context: query on any interface.
        tokio::task::spawn_blocking(move || {
            resolve_native(&name, &regtype, &domain, 0, connections)
        })
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
        let connections = self.connections.begin_shutdown();
        let workers = self.workers.begin_shutdown();
        let deadline = tokio::time::Instant::now() + CALL_WAIT;
        let mut first_error = None;
        for worker in &workers {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Err(detail) = worker.join(remaining).await {
                first_error.get_or_insert_with(|| {
                    provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Shutdown,
                        ProviderFailure::Timeout,
                        detail,
                    )
                });
            }
        }
        for connection in &connections {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Err(error) = retire_connection(
                connection,
                &self.state_tx,
                ProviderOperation::Shutdown,
                remaining,
            )
            .await
            {
                first_error.get_or_insert(error);
            }
        }
        if first_error.is_none() {
            self.workers.clear();
            self.connections.clear();
            return Ok(());
        }
        if !crate::windows_dnsapi::service_running("Bonjour Service") {
            // Any owner stranded inside vendor teardown still owns its native
            // callback context; acknowledge that quarantine so failover can
            // continue with the newly selected provider generation.
            for connection in connections {
                connection.quarantine();
            }
            self.workers.clear();
            self.connections.clear();
            return Ok(());
        }
        Err(first_error.expect("failed session retirement records an error"))
    }
}

impl Drop for BonjourSession {
    fn drop(&mut self) {
        self.state_tx.send_replace(ProviderSessionState::Lost);
        let _ = self.connections.begin_shutdown();
        for worker in self.workers.begin_shutdown() {
            worker.abort();
        }
    }
}

#[derive(Default)]
struct BonjourWorkerRegistry {
    state: Mutex<BonjourWorkerRegistryState>,
}

#[derive(Default)]
struct BonjourWorkerRegistryState {
    shutting_down: bool,
    workers: Vec<Arc<ProviderTask>>,
}

impl BonjourWorkerRegistry {
    fn track(&self, worker: Arc<ProviderTask>) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.shutting_down {
            return false;
        }
        state.workers.push(worker);
        true
    }

    fn begin_shutdown(&self) -> Vec<Arc<ProviderTask>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.shutting_down = true;
        state.workers.clone()
    }

    fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .workers
            .clear();
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
    owner: Option<Arc<NativeThreadOwner>>,
    final_name: String,
}

impl RegisteredNative {
    fn into_parts(mut self) -> (Arc<NativeThreadOwner>, String) {
        (
            self.owner.take().expect("registered owner"),
            std::mem::take(&mut self.final_name),
        )
    }
}

impl Drop for RegisteredNative {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.request_close();
        }
    }
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
    let owner = Arc::new(NativeThreadOwner::new());
    connections.track(Arc::clone(&owner));
    let thread_owner = Arc::clone(&owner);
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
                retire_owned(api, reference, runtime, &thread_owner);
                return;
            }

            let deadline = Instant::now() + CALL_WAIT;
            let mut acknowledged = false;
            loop {
                if thread_owner.close_requested() {
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
                            thread_owner.request_close();
                        }
                    } else if status != K_DNSSERVICE_ERR_NO_ERROR {
                        mark_publication_lost(
                            &state_tx,
                            ProviderOperation::Publish,
                            &DriveFailure::Dnssd(status),
                        );
                        thread_owner.request_close();
                    }
                }
                if thread_owner.close_requested() {
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
            retire_owned(api, reference, runtime, &thread_owner);
        });
    match thread {
        Ok(thread) => owner.attach(thread),
        Err(error) => {
            owner.start_failed();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Lost,
                format!("could not start Bonjour connection owner: {error}"),
            ));
        }
    }
    let final_name = match ready_rx.recv_timeout(CALL_WAIT + SOCKET_POLL_SLICE) {
        Ok(result) => result?,
        Err(_) => {
            owner.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Timeout,
                format!("Bonjour publication owner exceeded {CALL_WAIT:?}"),
            ));
        }
    };
    Ok(RegisteredNative {
        owner: Some(owner),
        final_name: if final_name.is_empty() {
            fallback_name
        } else {
            final_name
        },
    })
}

struct BonjourPublicationLease {
    id: String,
    owner: Arc<NativeThreadOwner>,
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
            retire_connection(
                &self.owner,
                &self.state_tx,
                ProviderOperation::Withdraw,
                CALL_WAIT,
            )
            .await?;
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
            self.owner.request_close();
        }
    }
}

// ── browse ────────────────────────────────────────────────────────────

struct BrowseRuntime {
    events: mpsc::Sender<BrowseObservation>,
    failure: AtomicI32,
}

enum BrowseObservation {
    /// One browse callback add: the reported instance identity plus the
    /// interface and domain the callback delivered, retained for the
    /// follow-up resolve instead of assuming interface-any/local.
    Add {
        name: String,
        regtype: String,
        domain: String,
        interface_index: u32,
    },
    Remove {
        name: String,
        regtype: String,
    },
    Failed(i32),
}

async fn open_bonjour_browse(
    regtype: &str,
    is_meta: bool,
    connections: ConnectionRegistry,
    state_tx: watch::Sender<ProviderSessionState>,
) -> Result<(ProviderBrowse, Arc<ProviderTask>)> {
    let (event_tx, event_rx) = tokio_mpsc::channel(BROWSE_CHANNEL_CAPACITY);
    let (observation_tx, observation_rx) = mpsc::channel::<BrowseObservation>();

    unsafe extern "system" fn browse_reply(
        _sd_ref: SdRef,
        flags: u32,
        interface_index: u32,
        error_code: i32,
        service_name: *const u8,
        regtype: *const u8,
        reply_domain: *const u8,
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
            let domain = if reply_domain.is_null() {
                String::new()
            } else {
                unsafe { read_cstr(reply_domain) }
            };
            if flags & K_DNSSERVICE_FLAGS_ADD != 0 {
                BrowseObservation::Add {
                    name,
                    regtype: typ,
                    domain,
                    interface_index,
                }
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
    let owner = Arc::new(NativeThreadOwner::new());
    connections.track(Arc::clone(&owner));
    let thread_owner = Arc::clone(&owner);
    let owner_regtype = regtype.to_string();
    let (ready_tx, ready_rx) = oneshot::channel::<Result<()>>();
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
                retire_owned(api, reference, runtime, &thread_owner);
                return;
            }
            if ready_tx.send(Ok(())).is_err() {
                thread_owner.request_close();
            }
            while !thread_owner.close_requested() {
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
            retire_owned(api, reference, runtime, &thread_owner);
        });
    match callback_thread {
        Ok(thread) => owner.attach(thread),
        Err(error) => {
            owner.start_failed();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Lost,
                format!("could not start Bonjour connection owner: {error}"),
            ));
        }
    }
    let startup = tokio::time::timeout(CALL_WAIT + SOCKET_POLL_SLICE, ready_rx).await;
    match startup {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => {
            owner.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Lost,
                "Bonjour browse owner dropped its readiness reply",
            ));
        }
        Err(_) => {
            owner.request_close();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Timeout,
                format!("Bonjour browse startup exceeded {CALL_WAIT:?}"),
            ));
        }
    }

    let worker_owner = Arc::clone(&owner);
    let worker_connections = connections.clone();
    let worker = Arc::new(ProviderTask::new(tokio::task::spawn_blocking(move || {
        loop {
            if worker_owner.close_requested() || worker_owner.is_finished() {
                break;
            }
            let observation = match observation_rx.recv_timeout(SOCKET_POLL_SLICE) {
                Ok(observation) => observation,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let emitted = match observation {
                BrowseObservation::Add {
                    name,
                    regtype,
                    domain,
                    interface_index,
                } => {
                    if is_meta {
                        // Meta observations enumerate service types; the type
                        // name itself is the record Koi surfaces.
                        event_tx.blocking_send(ProviderEvent::Found(ProviderService {
                            name: unescape_dnssd_label(&trim_local(&name)),
                            service_type: String::new(),
                            host: None,
                            addresses: Vec::new(),
                            port: None,
                            txt: HashMap::new(),
                        }))
                    } else {
                        // Resolve on the interface and in the domain the
                        // browse callback reported; fall back to the default
                        // domain only when the callback carried none.
                        let domain = if domain.is_empty() {
                            domain_of(&regtype)
                        } else {
                            domain
                        };
                        match resolve_native(
                            &name,
                            &regtype,
                            &domain,
                            interface_index,
                            worker_connections.clone(),
                        ) {
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
                        name: unescape_dnssd_label(&name),
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
        worker_owner.request_close();
    })));

    Ok((
        ProviderBrowse::new(
            event_rx,
            Box::new(BonjourBrowseLease {
                owner,
                worker: Arc::clone(&worker),
                state_tx: state_tx.clone(),
                active: true,
            }),
        ),
        worker,
    ))
}

struct BonjourBrowseLease {
    owner: Arc<NativeThreadOwner>,
    worker: Arc<ProviderTask>,
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
            retire_connection(
                &self.owner,
                &self.state_tx,
                ProviderOperation::Browse,
                CALL_WAIT,
            )
            .await?;
            self.worker.join(CALL_WAIT).await.map_err(|detail| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Browse,
                    ProviderFailure::Lost,
                    detail,
                )
            })?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for BonjourBrowseLease {
    fn drop(&mut self) {
        if self.active {
            self.owner.request_close();
            self.worker.abort();
        }
    }
}

// ── resolve ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct ResolveOutcome {
    error_code: i32,
    interface_index: u32,
    fullname: String,
    host: String,
    port: u16,
    txt: Vec<u8>,
}

/// Resolve one instance with `DNSServiceResolve` on a dedicated connection,
/// returning full service data only after the completion reply. Addresses are
/// completed through `DNSServiceGetAddrInfo` on the reply's interface, so the
/// surfaced record carries real native answers rather than a bare host name.
///
/// `interface_index` scopes the query: browse-driven resolves pass the
/// interface the browse callback reported (0 = any interface for direct
/// resolves).
fn resolve_native(
    name: &str,
    regtype: &str,
    domain: &str,
    interface_index: u32,
    connections: ConnectionRegistry,
) -> Result<ProviderService> {
    struct ResolveRuntime {
        reply: mpsc::Sender<ResolveOutcome>,
    }

    unsafe extern "system" fn resolve_reply(
        _sd_ref: SdRef,
        _flags: u32,
        interface_index: u32,
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
            interface_index,
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
    let owner = Arc::new(NativeThreadOwner::new());
    connections.track(Arc::clone(&owner));
    let thread_owner = Arc::clone(&owner);
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
                    interface_index,
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
                retire_owned(api, reference, runtime, &thread_owner);
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
                if thread_owner.close_requested() {
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
            retire_owned(api, reference, runtime, &thread_owner);
        });
    match thread {
        Ok(thread) => owner.attach(thread),
        Err(error) => {
            owner.start_failed();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Lost,
                format!("could not start Bonjour connection owner: {error}"),
            ));
        }
    }
    let outcome = match result_rx.recv_timeout(RESOLVE_WAIT + SOCKET_POLL_SLICE) {
        Ok(result) => result,
        Err(_) => Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Timeout,
            format!("Bonjour resolve owner exceeded {RESOLVE_WAIT:?}"),
        )),
    };
    let outcome = finish_native_call(&owner, ProviderOperation::Resolve, outcome, CALL_WAIT)?;
    let instance = instance_label(&outcome.fullname)
        .map(|label| unescape_dnssd_label(&label))
        .unwrap_or_else(|| unescape_dnssd_label(name));
    // Complete the SRV answer with real addresses for the reported host on
    // the interface the resolve reply named. A failure here degrades to a
    // host-only record instead of discarding the resolved SRV/TXT data.
    let addresses = if outcome.host.is_empty() {
        Vec::new()
    } else {
        match get_addr_info_native(&outcome.host, outcome.interface_index, &connections) {
            Ok(addresses) => addresses,
            Err(error) => {
                tracing::debug!(
                    provider = DESCRIPTOR.name,
                    host = %outcome.host,
                    interface = outcome.interface_index,
                    %error,
                    "native address completion failed; record stays host-only"
                );
                Vec::new()
            }
        }
    };
    Ok(ProviderService {
        name: instance,
        service_type: trim_local(regtype),
        host: non_empty(outcome.host),
        port: (outcome.port != 0).then_some(outcome.port),
        addresses,
        txt: parse_txt(&outcome.txt),
    })
}

/// Query the addresses of one resolved host through `DNSServiceGetAddrInfo`,
/// scoped to the interface the resolve reply reported. The connection is
/// owned and retired like every other dnssd session resource.
fn get_addr_info_native(
    hostname: &str,
    interface_index: u32,
    connections: &ConnectionRegistry,
) -> Result<Vec<ProviderAddress>> {
    struct AddrInfoRuntime {
        reply: mpsc::Sender<AddrInfoObservation>,
    }

    enum AddrInfoObservation {
        Address {
            address: std::net::IpAddr,
            interface_index: u32,
        },
        /// The final reply carried no MoreComing flag, or the query failed.
        Done(i32),
    }

    unsafe extern "system" fn addr_info_reply(
        _sd_ref: SdRef,
        flags: u32,
        interface_index: u32,
        error_code: i32,
        _hostname: *const u8,
        address: *const SOCKADDR,
        _ttl: u32,
        context: *mut core::ffi::c_void,
    ) {
        let runtime = unsafe { &*(context as *const AddrInfoRuntime) };
        if error_code != K_DNSSERVICE_ERR_NO_ERROR {
            let _ = runtime.reply.send(AddrInfoObservation::Done(error_code));
            return;
        }
        if let Some(address) = unsafe { sockaddr_address(address) } {
            let _ = runtime.reply.send(AddrInfoObservation::Address {
                address,
                interface_index,
            });
        }
        if flags & K_DNSSERVICE_FLAGS_MORECOMING == 0 {
            let _ = runtime
                .reply
                .send(AddrInfoObservation::Done(K_DNSSERVICE_ERR_NO_ERROR));
        }
    }

    let api = match dnssd() {
        Ok(api) => api,
        Err(missing) => return Err(dnssd_missing(ProviderOperation::Resolve, &missing)),
    };
    let owner = Arc::new(NativeThreadOwner::new());
    connections.track(Arc::clone(&owner));
    let thread_owner = Arc::clone(&owner);
    let (result_tx, result_rx) = mpsc::sync_channel::<Result<Vec<ProviderAddress>>>(1);
    let owner_host = hostname.to_string();
    let thread = std::thread::Builder::new()
        .name("koi-mdns-bonjour-addrinfo".to_string())
        .spawn(move || {
            let (reply_tx, reply_rx) = mpsc::channel::<AddrInfoObservation>();
            let mut runtime = Box::new(AddrInfoRuntime { reply: reply_tx });
            let host_c = cstr(&owner_host);
            let mut reference: SdRef = std::ptr::null_mut();
            let error = unsafe {
                (api.get_addr_info)(
                    &mut reference,
                    0,
                    interface_index,
                    K_DNSSERVICE_PROTOCOL_IPV4 | K_DNSSERVICE_PROTOCOL_IPV6,
                    host_c.as_ptr(),
                    addr_info_reply,
                    (&mut *runtime as *mut AddrInfoRuntime).cast(),
                )
            };
            if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
                let _ = result_tx.send(Err(dnssd_error(
                    ProviderOperation::Resolve,
                    error,
                    "DNSServiceGetAddrInfo",
                )));
                retire_owned(api, reference, runtime, &thread_owner);
                return;
            }

            let deadline = Instant::now() + RESOLVE_WAIT;
            let mut addresses: Vec<ProviderAddress> = Vec::new();
            loop {
                if let Ok(observation) = reply_rx.try_recv() {
                    match observation {
                        AddrInfoObservation::Address {
                            address,
                            interface_index,
                        } => {
                            if addresses.iter().all(|existing| existing.address != address) {
                                addresses.push(ProviderAddress {
                                    address,
                                    interface_index: (interface_index != 0)
                                        .then_some(interface_index),
                                    interface_name: None,
                                });
                            }
                        }
                        AddrInfoObservation::Done(status) => {
                            if status == K_DNSSERVICE_ERR_NO_ERROR || !addresses.is_empty() {
                                let _ = result_tx.send(Ok(addresses));
                            } else {
                                let _ = result_tx.send(Err(dnssd_error(
                                    ProviderOperation::Resolve,
                                    status,
                                    "DNSServiceGetAddrInfo reply",
                                )));
                            }
                            break;
                        }
                    }
                    continue;
                }
                if thread_owner.close_requested() {
                    let _ = result_tx.send(Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Resolve,
                        ProviderFailure::Lost,
                        "address completion was cancelled before the daemon finished",
                    )));
                    break;
                }
                let Some(wait) = remaining_slice(deadline) else {
                    // No final marker arrived; surface whatever the daemon
                    // delivered rather than discarding real answers.
                    let _ = result_tx.send(Ok(addresses));
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        "address completion ended at the deadline without a final reply"
                    );
                    break;
                };
                if let Err(error) = drive_once(api, reference, wait) {
                    if !addresses.is_empty() {
                        let _ = result_tx.send(Ok(addresses));
                    } else {
                        let _ = result_tx.send(Err(provider_error(
                            DESCRIPTOR.name,
                            ProviderOperation::Resolve,
                            ProviderFailure::Lost,
                            error.to_string(),
                        )));
                    }
                    break;
                }
            }
            retire_owned(api, reference, runtime, &thread_owner);
        });
    match thread {
        Ok(thread) => owner.attach(thread),
        Err(error) => {
            owner.start_failed();
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Lost,
                format!("could not start Bonjour connection owner: {error}"),
            ));
        }
    }
    let outcome = match result_rx.recv_timeout(RESOLVE_WAIT + SOCKET_POLL_SLICE) {
        Ok(result) => result,
        Err(_) => Err(provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Resolve,
            ProviderFailure::Timeout,
            format!("Bonjour address completion exceeded {RESOLVE_WAIT:?}"),
        )),
    };
    finish_native_call(&owner, ProviderOperation::Resolve, outcome, CALL_WAIT)
}

/// Project a Winsock sockaddr onto a provider-neutral address.
///
/// # Safety
/// `sockaddr` must be null or point to a valid Winsock sockaddr from dnssd.
unsafe fn sockaddr_address(sockaddr: *const SOCKADDR) -> Option<std::net::IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    let bytes = sockaddr.cast::<u8>();
    let family = unsafe { u16::from_ne_bytes([*bytes, *bytes.add(1)]) };
    match family {
        AF_INET => {
            let octets = unsafe { std::slice::from_raw_parts(bytes.add(4), 4) };
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        AF_INET6 => {
            let octets = unsafe { std::slice::from_raw_parts(bytes.add(8), 16) };
            <[u8; 16]>::try_from(octets)
                .ok()
                .map(|octets| std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
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

/// The default browsing domain for a direct resolve. dnssd matches the
/// qualified form: an unqualified "local" never answers on the observed
/// mDNSResponder (the probe's direct resolves timed out until the trailing
/// dot was kept), while browse callbacks deliver "local." themselves.
fn domain_of(_regtype: &str) -> String {
    "local.".to_string()
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

/// Decode dnssd's presentation escaping. Callbacks deliver instance names
/// with non-alphanumeric bytes as `\DDD` octal (a space arrives as `\032`),
/// while every other adapter surfaces real characters; provider-neutral
/// names must agree or the hub cannot correlate removals with resolved
/// records across providers.
fn unescape_dnssd_label(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte != b'\\' {
            out.push(byte);
            cursor += 1;
            continue;
        }
        // `\` followed by one to three decimal digits is one byte (dnssd
        // escapes a space as `\032` — decimal 32, the RFC 1035 presentation
        // form, not octal).
        let mut width = 0usize;
        while width < 3
            && cursor + 1 + width < bytes.len()
            && bytes[cursor + 1 + width].is_ascii_digit()
        {
            width += 1;
        }
        if width > 0 {
            let decoded: u32 = value[cursor + 1..cursor + 1 + width].parse().unwrap_or(256);
            if decoded <= 255 {
                out.push(decoded as u8);
            } else {
                // Not a byte escape after all; keep the whole run literal.
                out.extend_from_slice(&bytes[cursor..cursor + 1 + width]);
            }
            cursor += 1 + width;
        } else {
            out.push(byte);
            cursor += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    WSAGetLastError, WSAPoll, AF_INET, AF_INET6, INVALID_SOCKET, POLLERR, POLLHUP, POLLNVAL,
    POLLRDNORM, SOCKADDR, SOCKET, SOCKET_ERROR, WSAPOLLFD,
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
    fn flag_bits_match_apples_dns_sd_header() {
        // 0x1 is MoreComing and 0x2 is Add; swapping them inverts browse
        // add/remove classification.
        assert_eq!(K_DNSSERVICE_FLAGS_MORECOMING, 0x1);
        assert_eq!(K_DNSSERVICE_FLAGS_ADD, 0x2);
    }

    #[test]
    fn winsock_sockaddr_projects_to_addresses() {
        // sockaddr_in: family(2) port(2) address(4) zero(8)
        let mut v4 = [0u8; 16];
        v4[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        v4[4..8].copy_from_slice(&[192, 168, 1, 137]);
        assert_eq!(
            unsafe { sockaddr_address(v4.as_ptr() as *const SOCKADDR) },
            Some("192.168.1.137".parse().unwrap())
        );
        // sockaddr_in6: family(2) port(2) flowinfo(4) address(16) scope(4)
        let mut v6 = [0u8; 28];
        v6[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        v6[8..12].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(
            unsafe { sockaddr_address(v6.as_ptr() as *const SOCKADDR) },
            Some("2001:db8::".parse().unwrap())
        );
        // Unknown families and null yield nothing.
        let mut other = [0u8; 16];
        other[0..2].copy_from_slice(&17u16.to_ne_bytes());
        assert_eq!(
            unsafe { sockaddr_address(other.as_ptr() as *const SOCKADDR) },
            None
        );
        assert_eq!(unsafe { sockaddr_address(std::ptr::null()) }, None);
    }

    #[test]
    fn direct_resolves_use_a_qualified_default_domain() {
        // dnssd answers only the qualified form; browse callbacks themselves
        // deliver "local.".
        assert_eq!(domain_of("_mcp._tcp"), "local.");
        assert_eq!(domain_of("_mcp._tcp.local"), "local.");
    }

    #[test]
    fn dnssd_presentation_escapes_decode_to_real_characters() {
        assert_eq!(
            unescape_dnssd_label("Koi\\032MCP\\032(test-03)"),
            "Koi MCP (test-03)"
        );
        assert_eq!(unescape_dnssd_label("plain-name"), "plain-name");
        assert_eq!(unescape_dnssd_label("back\\092slash"), "back\\slash");
        // A lone backslash and non-digit tails stay literal, as does an
        // out-of-range decimal run.
        assert_eq!(unescape_dnssd_label("a\\b"), "a\\b");
        assert_eq!(unescape_dnssd_label("a\\999b"), "a\\999b");
    }

    #[test]
    fn lease_signals_owner_and_waits_for_owner_acknowledgement() {
        let owner = Arc::new(NativeThreadOwner::new());
        let thread_owner = Arc::clone(&owner);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let owner_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            while !thread_owner.close_requested() {
                std::thread::park_timeout(Duration::from_millis(5));
            }
            thread_owner.finish();
        });
        owner.attach(owner_thread);

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.is_finished());
        owner.request_close();
        assert!(owner.wait_finished(Duration::from_secs(1)));
        owner.join_finished().unwrap();
    }

    #[test]
    fn registry_cancels_connections_that_arrive_during_shutdown() {
        let registry = ConnectionRegistry::default();
        assert!(registry.begin_shutdown().is_empty());

        let late = Arc::new(NativeThreadOwner::new());
        registry.track(Arc::clone(&late));
        let thread_owner = Arc::clone(&late);
        late.attach(std::thread::spawn(move || {
            while !thread_owner.close_requested() {
                std::thread::park_timeout(Duration::from_millis(5));
            }
            thread_owner.finish();
        }));

        assert!(late.close_requested());
        assert!(late.wait_finished(Duration::from_secs(1)));
        late.join_finished().unwrap();
        assert_eq!(registry.begin_shutdown().len(), 1);
        registry.clear();
        assert!(registry.begin_shutdown().is_empty());
    }

    #[tokio::test]
    async fn cancelled_retirement_keeps_callback_owner_joinable() {
        let owner = Arc::new(NativeThreadOwner::new());
        let thread_owner = Arc::clone(&owner);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        owner.attach(std::thread::spawn(move || {
            while !thread_owner.close_requested() {
                std::thread::park_timeout(Duration::from_millis(5));
            }
            release_rx.recv().expect("release callback owner");
            thread_owner.finish();
        }));
        let (state_tx, _) = watch::channel(ProviderSessionState::Ready);
        let first = {
            let owner = Arc::clone(&owner);
            let state_tx = state_tx.clone();
            tokio::spawn(async move {
                retire_connection(&owner, &state_tx, ProviderOperation::Shutdown, CALL_WAIT).await
            })
        };
        tokio::task::yield_now().await;
        first.abort();
        first.await.expect_err("cancel first shutdown waiter");

        release_tx.send(()).expect("release callback owner");
        retire_connection(&owner, &state_tx, ProviderOperation::Shutdown, CALL_WAIT)
            .await
            .expect("retry reaps the same callback owner");
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
            // Without a ready responder the library may still be present
            // (service stopped: running = No) or wholly absent (the
            // responder cannot be probed: running = Unknown). Capabilities
            // must be empty in both shapes.
            assert!(matches!(report.running, ProbeFact::No | ProbeFact::Unknown));
            assert_eq!(report.capabilities, MdnsCapabilities::default());
        }
    }
}
