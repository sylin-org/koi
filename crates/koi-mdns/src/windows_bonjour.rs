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
//! Threading: every dnssd connection delivers its callbacks from
//! `DNSServiceProcessResult`, so each live connection owns a pump thread.
//! Closing a connection (`DNSServiceRefDeallocate`) unblocks the pump, which
//! is how browse leases shut down without leaked threads.
//!
//! All dnssd types stay inside this module; provider-neutral values cross the
//! session boundary.

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// Windows install paths `dnssd.dll` is known to occupy; the standard DLL
/// search order is tried first.
const DNSSD_CANDIDATE_PATHS: &[&str] = &[
    "dnssd.dll",
    r"C:\Program Files\Bonjour\dnssd.dll",
    r"C:\Program Files (x86)\Bonjour\dnssd.dll",
];

/// The dnssd entry points this provider needs.
const REQUIRED_EXPORTS: &[&str] = &[
    "DNSServiceRegister",
    "DNSServiceBrowse",
    "DNSServiceResolve",
    "DNSServiceProcessResult",
    "DNSServiceRefDeallocate",
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

    if let Err(missing) = export_probe() {
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

/// Load `dnssd.dll` and resolve every entry point this provider needs.
/// Returns the human-readable failure on the first missing piece.
fn export_probe() -> std::result::Result<(), String> {
    static PROBE: Mutex<Option<std::result::Result<(), String>>> = Mutex::new(None);
    let mut guard = PROBE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = guard.as_ref() {
        return cached.clone();
    }
    let probe = (|| {
        let mut library = std::ptr::null_mut();
        for path in DNSSD_CANDIDATE_PATHS {
            let handle = unsafe { LoadLibraryW(wide(path).as_ptr()) };
            if !handle.is_null() {
                library = handle;
                break;
            }
        }
        if library.is_null() {
            return Err(
                "dnssd.dll not found in the DLL search path or the Bonjour install \
                        directories"
                    .to_string(),
            );
        }
        for name in REQUIRED_EXPORTS {
            let symbol: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
            let proc = unsafe { GetProcAddress(library, symbol.as_ptr()) };
            if proc.is_none() {
                return Err(format!("dnssd.dll is missing {name}"));
            }
        }
        Ok(())
    })();
    *guard = Some(probe.clone());
    probe
}

// ── dnssd FFI (runtime-loaded from dnssd.dll; absent from windows-sys) ─

type SdRef = *mut core::ffi::c_void;

/// Owned dnssd connection reference. Send is sound because dnssd connections
/// are thread-agnostic: every use is serialized through our own threads.
struct SdRefHandle(SdRef);
unsafe impl Send for SdRefHandle {}

/// Owned raw browse-runtime pointer moved into the worker thread. Send is
/// sound because only our code dereferences it.
struct RuntimePtr(*mut BrowseRuntime);
unsafe impl Send for RuntimePtr {}

/// Reclaim the browse runtime after the connection is deallocated.
fn reclaim_runtime_ptr(ptr: RuntimePtr) {
    // SAFETY: the pointer came from Box::into_raw and no callback can run
    // after the connection's deallocation.
    unsafe { drop(Box::from_raw(ptr.0)) };
}

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
    process_result: unsafe extern "system" fn(sdref: SdRef) -> i32,
    ref_deallocate: unsafe extern "system" fn(sdref: SdRef),
}

/// The loaded entry points, cached for the process. Sound to share across
/// threads because `DnssdApi` holds only immutable function pointers.
fn dnssd() -> std::result::Result<&'static DnssdApi, String> {
    static API: Mutex<Option<std::result::Result<DnssdApi, String>>> = Mutex::new(None);
    let mut guard = API.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(load_dnssd());
    }
    match guard.as_ref().expect("api just initialized") {
        Ok(api) => Ok(unsafe { &*(api as *const DnssdApi) }),
        Err(missing) => Err(missing.clone()),
    }
}

/// SAFETY: `DnssdApi` is shared across threads through the cache above.
unsafe impl Sync for DnssdApi {}

fn load_dnssd() -> std::result::Result<DnssdApi, String> {
    let mut library = std::ptr::null_mut();
    for path in DNSSD_CANDIDATE_PATHS {
        let handle = unsafe { LoadLibraryW(wide(path).as_ptr()) };
        if !handle.is_null() {
            library = handle;
            break;
        }
    }
    if library.is_null() {
        return Err(
            "dnssd.dll not found in the DLL search path or the Bonjour install directories"
                .to_string(),
        );
    }
    /// Bind one exported symbol to its typed function pointer.
    fn symbol<T>(library: *mut core::ffi::c_void, name: &str) -> std::result::Result<T, String> {
        let bytes: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
        let proc = unsafe { GetProcAddress(library, bytes.as_ptr()) };
        match proc {
            Some(proc) => Ok(unsafe { std::mem::transmute_copy::<_, T>(&proc) }),
            None => Err(format!("dnssd.dll is missing {name}")),
        }
    }
    Ok(DnssdApi {
        register: symbol(library, "DNSServiceRegister")?,
        browse: symbol(library, "DNSServiceBrowse")?,
        resolve: symbol(library, "DNSServiceResolve")?,
        process_result: symbol(library, "DNSServiceProcessResult")?,
        ref_deallocate: symbol(library, "DNSServiceRefDeallocate")?,
    })
}

// ── session ───────────────────────────────────────────────────────────

struct BonjourSession {
    state_tx: watch::Sender<ProviderSessionState>,
    state_rx: watch::Receiver<ProviderSessionState>,
    capabilities: MdnsCapabilities,
    workers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl BonjourSession {
    fn start(capabilities: MdnsCapabilities) -> Self {
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        Self {
            state_tx,
            state_rx,
            capabilities,
            workers: Mutex::new(Vec::new()),
        }
    }

    fn mark_degraded(&self, operation: ProviderOperation, error: &MdnsError) {
        tracing::info!(
            provider = DESCRIPTOR.name,
            operation = %operation,
            %error,
            "Bonjour operation failed; session is recovering"
        );
        self.state_tx.send_replace(ProviderSessionState::Recovering);
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
        let outcome = tokio::task::spawn_blocking(move || register_native(&request))
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
            Err(error) => {
                self.mark_degraded(ProviderOperation::Publish, &error);
                return Err(error);
            }
        };
        Ok(Box::new(BonjourPublicationLease {
            id: announcement.id.clone(),
            reference: Mutex::new(Some(registered.reference)),
            final_name: registered.final_name,
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
        let (browse, worker) = match open_bonjour_browse(&regtype, is_meta).await {
            Ok(pair) => pair,
            Err(error) => {
                self.mark_degraded(ProviderOperation::Browse, &error);
                return Err(error);
            }
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
        let outcome = tokio::task::spawn_blocking(move || resolve_native(&name, &regtype, &domain))
            .await
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Resolve,
                    ProviderFailure::Lost,
                    format!("resolve task failed: {error}"),
                )
            })?;
        match outcome {
            Ok(service) => Ok(service),
            Err(error) => {
                self.mark_degraded(ProviderOperation::Resolve, &error);
                Err(error)
            }
        }
    }

    async fn shutdown(&self) -> Result<()> {
        let workers = self
            .workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
            .collect::<Vec<_>>();
        for worker in workers {
            let _ = worker.await;
        }
        self.state_tx.send_replace(ProviderSessionState::Lost);
        Ok(())
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
    /// The connection whose deallocation withdraws the record.
    reference: SdRefHandle,
    final_name: String,
}

/// Register through `DNSServiceRegister` and wait for the completion reply.
/// The reply may rename the instance on conflict; the final name is reported.
/// The returned connection must stay alive for the publication's lifetime.
fn register_native(request: &RegisterRequest) -> Result<RegisteredNative> {
    struct RegisterRuntime {
        reply: mpsc::Sender<(i32, String)>,
    }
    let (reply_tx, reply_rx) = mpsc::channel::<(i32, String)>();
    let runtime_ptr = Box::into_raw(Box::new(RegisterRuntime { reply: reply_tx }));

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
    let name_c = cstr(&request.name);
    let regtype_c = cstr(&request.service_type);
    let mut reference: SdRef = std::ptr::null_mut();
    let error = unsafe {
        (api.register)(
            &mut reference,
            0, // all interfaces
            0, // no flags: the daemon may auto-rename on conflict
            name_c.as_ptr(),
            regtype_c.as_ptr(),
            std::ptr::null(), // default domain: local
            std::ptr::null(), // default host: this machine
            request.port.to_be(),
            request.txt.len() as u16,
            if request.txt.len() == 1 && request.txt[0] == 0 {
                std::ptr::null()
            } else {
                request.txt.as_ptr()
            },
            register_reply,
            runtime_ptr as *mut core::ffi::c_void,
        )
    };
    if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
        if !reference.is_null() {
            unsafe { (api.ref_deallocate)(reference) };
        }
        unsafe { drop(Box::from_raw(runtime_ptr)) };
        return Err(dnssd_error(
            ProviderOperation::Publish,
            error,
            "DNSServiceRegister",
        ));
    }

    // Pump the connection on this thread until the completion reply arrives.
    let outcome = pump_until(
        api.process_result,
        runtime_ptr as *mut core::ffi::c_void,
        reference,
        &reply_rx,
        CALL_WAIT,
    );
    unsafe { drop(Box::from_raw(runtime_ptr)) };
    let (error_code, final_name) = match outcome {
        Some(reply) => reply,
        None => {
            unsafe { (api.ref_deallocate)(reference) };
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Timeout,
                format!("DNSServiceRegister reply exceeded {CALL_WAIT:?}"),
            ));
        }
    };
    if error_code != K_DNSSERVICE_ERR_NO_ERROR {
        unsafe { (api.ref_deallocate)(reference) };
        return Err(dnssd_error(
            ProviderOperation::Publish,
            error_code,
            "DNSServiceRegister reply",
        ));
    }
    Ok(RegisteredNative {
        reference: SdRefHandle(reference),
        final_name: if final_name.is_empty() {
            request.name.clone()
        } else {
            final_name
        },
    })
}

struct BonjourPublicationLease {
    id: String,
    reference: Mutex<Option<SdRefHandle>>,
    final_name: String,
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
        if let Some(reference) = self
            .reference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            // Deallocating a registered connection terminates the publication.
            match dnssd() {
                Ok(api) => unsafe { (api.ref_deallocate)(reference.0) },
                Err(missing) => return Err(dnssd_missing(ProviderOperation::Withdraw, &missing)),
            }
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
        if let Some(reference) = self
            .reference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            if let Ok(api) = dnssd() {
                unsafe { (api.ref_deallocate)(reference.0) };
            }
        }
    }
}

// ── browse ────────────────────────────────────────────────────────────

struct BrowseRuntime {
    events: mpsc::Sender<BrowseObservation>,
}

enum BrowseObservation {
    Add { name: String, regtype: String },
    Remove { name: String, regtype: String },
    Failed(i32),
}

async fn open_bonjour_browse(
    regtype: &str,
    is_meta: bool,
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
    let runtime_ptr = RuntimePtr(Box::into_raw(Box::new(BrowseRuntime {
        events: observation_tx,
    })));
    let mut reference: SdRef = std::ptr::null_mut();
    let regtype_c = cstr(regtype);
    let error = unsafe {
        (api.browse)(
            &mut reference,
            0,
            0,
            regtype_c.as_ptr(),
            std::ptr::null(), // default domain
            browse_reply,
            runtime_ptr.0 as *mut core::ffi::c_void,
        )
    };
    if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
        if !reference.is_null() {
            unsafe { (api.ref_deallocate)(reference) };
        }
        unsafe { drop(Box::from_raw(runtime_ptr.0)) };
        return Err(dnssd_error(
            ProviderOperation::Browse,
            error,
            "DNSServiceBrowse",
        ));
    }

    // The pump thread drives dnssd callbacks until the connection is
    // deallocated; the worker thread translates observations into Koi events,
    // resolving every added instance the way mdns-sd resolves in-process.
    let pump_reference: Arc<Mutex<Option<SdRefHandle>>> =
        Arc::new(Mutex::new(Some(SdRefHandle(reference))));
    let callback_reference = Arc::clone(&pump_reference);
    let lease_reference = Arc::clone(&pump_reference);
    let process_result = api.process_result;
    let callback_thread = std::thread::Builder::new()
        .name(format!("koi-mdns-bonjour-browse-{regtype}"))
        .spawn(move || {
            // SAFETY: the reference stays alive until the worker deallocates it;
            // this loop then returns one error later and exits.
            loop {
                let current = callback_reference
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let Some(active) = current.as_ref().map(|handle| handle.0) else {
                    break;
                };
                drop(current);
                let result = unsafe { process_result(active) };
                if result != K_DNSSERVICE_ERR_NO_ERROR {
                    break;
                }
            }
        });

    let worker = tokio::task::spawn_blocking(move || {
        while let Ok(observation) = observation_rx.recv() {
            match observation {
                BrowseObservation::Add { name, regtype } => {
                    if is_meta {
                        // Meta observations enumerate service types; the type
                        // name itself is the record Koi surfaces.
                        let _ = event_tx.blocking_send(ProviderEvent::Found(ProviderService {
                            name: trim_local(&name),
                            service_type: String::new(),
                            host: None,
                            addresses: Vec::new(),
                            port: None,
                            txt: HashMap::new(),
                        }));
                    } else {
                        let domain = domain_of(&regtype);
                        match resolve_native(&name, &regtype, &domain) {
                            Ok(service) => {
                                let _ = event_tx.blocking_send(ProviderEvent::Resolved(service));
                            }
                            Err(error) => {
                                tracing::debug!(
                                    provider = DESCRIPTOR.name,
                                    instance = %name,
                                    %error,
                                    "browse resolve failed; instance stays unresolved"
                                );
                            }
                        }
                    }
                }
                BrowseObservation::Remove { name, regtype } => {
                    let _ = event_tx.blocking_send(ProviderEvent::Removed {
                        name,
                        service_type: trim_local(&regtype),
                    });
                }
                BrowseObservation::Failed(error) => {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        error,
                        "Bonjour browse reported an error; ending the stream"
                    );
                    break;
                }
            }
        }
        // Stop the daemon connection; this also unblocks the pump thread.
        if let Some(reference) = pump_reference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            unsafe { (api.ref_deallocate)(reference.0) };
        }
        reclaim_runtime_ptr(runtime_ptr);
    });

    // Detach the callback thread: the worker's deallocation is what ends it.
    std::mem::forget(callback_thread);
    Ok((
        ProviderBrowse::new(
            event_rx,
            Box::new(BonjourBrowseLease {
                reference: Arc::clone(&lease_reference),
            }),
        ),
        worker,
    ))
}

struct BonjourBrowseLease {
    reference: Arc<Mutex<Option<SdRefHandle>>>,
}

#[async_trait::async_trait]
impl BrowseLease for BonjourBrowseLease {
    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(reference) = self
            .reference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            // Deallocating the connection ends the record stream and unblocks
            // the pump thread; the worker exits when the channel drains.
            if let Ok(api) = dnssd() {
                unsafe { (api.ref_deallocate)(reference.0) };
            }
        }
        Ok(())
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
fn resolve_native(name: &str, regtype: &str, domain: &str) -> Result<ProviderService> {
    struct ResolveRuntime {
        reply: mpsc::Sender<ResolveOutcome>,
    }
    let (reply_tx, reply_rx) = mpsc::channel::<ResolveOutcome>();
    let runtime_ptr = Box::into_raw(Box::new(ResolveRuntime { reply: reply_tx }));

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
    let name_c = cstr(name);
    let regtype_c = cstr(regtype);
    let domain_c = cstr(domain);
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
            runtime_ptr as *mut core::ffi::c_void,
        )
    };
    if error != K_DNSSERVICE_ERR_NO_ERROR || reference.is_null() {
        if !reference.is_null() {
            unsafe { (api.ref_deallocate)(reference) };
        }
        unsafe { drop(Box::from_raw(runtime_ptr)) };
        return Err(dnssd_error(
            ProviderOperation::Resolve,
            error,
            "DNSServiceResolve",
        ));
    }

    let outcome = pump_until(
        api.process_result,
        runtime_ptr as *mut core::ffi::c_void,
        reference,
        &reply_rx,
        RESOLVE_WAIT,
    );
    // A resolve connection is one-shot: always release it.
    unsafe { (api.ref_deallocate)(reference) };
    unsafe { drop(Box::from_raw(runtime_ptr)) };

    let outcome = match outcome {
        Some(outcome) => outcome,
        None => {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Timeout,
                format!("DNSServiceResolve reply exceeded {RESOLVE_WAIT:?}"),
            ))
        }
    };
    if outcome.error_code != K_DNSSERVICE_ERR_NO_ERROR {
        return Err(dnssd_error(
            ProviderOperation::Resolve,
            outcome.error_code,
            "DNSServiceResolve reply",
        ));
    }
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

/// Pump one connection until a message arrives on `reply` or the wait expires.
/// Runs on the calling (blocking) thread; the connection's callbacks fire from
/// inside `DNSServiceProcessResult`.
fn pump_until<T: std::fmt::Debug>(
    process_result: unsafe extern "system" fn(SdRef) -> i32,
    context: *mut core::ffi::c_void,
    reference: SdRef,
    reply: &mpsc::Receiver<T>,
    wait: Duration,
) -> Option<T> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Ok(message) = reply.try_recv() {
            return Some(message);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        // SAFETY: the reference stays alive for this whole call; the caller
        // deallocates it only after this function returns.
        let result = unsafe { process_result(reference) };
        if result != K_DNSSERVICE_ERR_NO_ERROR {
            // The daemon may deliver the final reply while reporting the wake
            // error; drain once more before giving up.
            return reply.try_recv().ok();
        }
        let _ = context;
    }
}

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

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

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
