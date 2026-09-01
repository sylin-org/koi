//! Win32 DNS-SD probe: real `dnsapi.dll` DNS-SD operations on the lab LAN.
//!
//! Answers ADR-039's assessment questions with observed behavior instead of
//! assumptions: does registration acknowledge a real native resource, does it
//! survive under the workstation's firewall profile, how do browse/resolve
//! callbacks deliver records, and do independent LAN peers see the traffic?
//!
//! Every phase prints one JSON evidence line and the process exits non-zero
//! only when a phase fails its own observed contract.

#![cfg(target_os = "windows")]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::Dns::{
    DnsServiceBrowse, DnsServiceBrowseCancel, DnsServiceConstructInstance, DnsServiceDeRegister,
    DnsServiceFreeInstance, DnsServiceRegister, DnsServiceResolve, DNS_RECORDW,
    DNS_SERVICE_BROWSE_REQUEST, DNS_SERVICE_CANCEL, DNS_SERVICE_INSTANCE,
    DNS_SERVICE_REGISTER_REQUEST, DNS_SERVICE_RESOLVE_REQUEST,
};

const DNS_STATUS_SUCCESS: i32 = 0;
const DNS_STATUS_SUCCESS_DWORD: u32 = 0;
/// The async DNS-SD calls return "pending"; the completion callback carries the result.
const DNS_REQUEST_PENDING: u32 = 9506;
const DNS_TYPE_PTR: u16 = 12;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const BROWSE_WINDOW: Duration = Duration::from_secs(8);

// ── callback marshaling ─────────────────────────────────────────────

/// Owned channel sender handed to dnsapi as the query context. dnsapi invokes
/// the callback on its own worker thread, so the sender must be moved through
/// a raw pointer; the box stays alive until this side drops it after the final
/// status arrives.
struct Context<T>(mpsc::Sender<T>);

impl<T> Context<T> {
    fn into_raw(self) -> *mut std::ffi::c_void {
        Box::into_raw(Box::new(self)) as *mut std::ffi::c_void
    }

    /// Reclaim the context after dnsapi is done invoking the callback.
    ///
    /// # Safety
    /// The pointer must come from [`Self::into_raw`] and must not be referenced
    /// by dnsapi anymore (terminal status received or operation cancelled).
    unsafe fn from_raw(raw: *mut std::ffi::c_void) -> Self {
        *Box::from_raw(raw as *mut Self)
    }
}

// Safety: dnsapi only copies the pointer; all use is on the thread that owns
// the matching receiver until the terminal callback has been observed.
unsafe impl<T> Send for Context<T> {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a wide string, tolerating null and empty pointers.
///
/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 buffer owned by dnsapi.
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

fn evidence(step: &str, fields: &[(&str, serde_json::Value)]) {
    let map: serde_json::Map<String, serde_json::Value> = fields
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect();
    println!(
        "{}",
        serde_json::json!({"step": step, "fields": map})
    );
}

// ── registration ─────────────────────────────────────────────────────

struct RegisterOutcome {
    status: u32,
    final_name: String,
    final_host: String,
}

/// Register one service instance and wait for dnsapi's completion callback.
/// Returns `None` when the callback never arrives (call-level failure).
fn register(
    instance_name: &str,
    host_name: &str,
    port: u16,
    txt: &BTreeMap<String, String>,
    ipv4: Option<Ipv4Addr>,
) -> Option<RegisterOutcome> {
    let keys: Vec<Vec<u16>> = txt.keys().map(|key| wide(key)).collect();
    let values: Vec<Vec<u16>> = txt.values().map(|value| wide(value)).collect();
    let key_ptrs: Vec<*const u16> = keys.iter().map(|key| key.as_ptr()).collect();
    let value_ptrs: Vec<*const u16> = values.iter().map(|value| value.as_ptr()).collect();
    let mut ip4 = ipv4.map(|address| u32::from(address).to_be());

    let instance_name_w = wide(instance_name);
    let host_name_w = wide(host_name);
    let instance: *mut DNS_SERVICE_INSTANCE = if let Some(ip4) = ip4.as_mut() {
        unsafe {
        DnsServiceConstructInstance(
            instance_name_w.as_ptr(),
            host_name_w.as_ptr(),
            ip4,
            std::ptr::null(),
            port,
            0,
            0,
            txt.len() as u32,
            key_ptrs.as_ptr(),
            value_ptrs.as_ptr(),
        )
        }
    } else {
        unsafe {
        DnsServiceConstructInstance(
            instance_name_w.as_ptr(),
            host_name_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            port,
            0,
            0,
            txt.len() as u32,
            key_ptrs.as_ptr(),
            value_ptrs.as_ptr(),
        )
        }
    };
    if instance.is_null() {
        evidence("register", &[("error", "DnsServiceConstructInstance returned null".into())]);
        return None;
    }

    let (tx, rx) = mpsc::channel::<(u32, *const DNS_SERVICE_INSTANCE)>();
    let context = Context(tx).into_raw();
    unsafe extern "system" fn register_complete(
        status: u32,
        query_context: *const std::ffi::c_void,
        instance: *const DNS_SERVICE_INSTANCE,
    ) {
        let sender = unsafe { &*(query_context as *const Context<(u32, *const DNS_SERVICE_INSTANCE)>) };
        let _ = sender.0.send((status, instance));
    }

    let request = DNS_SERVICE_REGISTER_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        pServiceInstance: instance,
        pRegisterCompletionCallback: Some(register_complete),
        pQueryContext: context,
        hCredentials: std::ptr::null_mut::<std::ffi::c_void>() as HANDLE,
        unicastEnabled: 0,
    };
    let mut cancel = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
    let call_status = unsafe { DnsServiceRegister(&request, &mut cancel) };

    let mut outcome = None;
    if call_status == DNS_STATUS_SUCCESS_DWORD || call_status == DNS_REQUEST_PENDING {
        match rx.recv_timeout(WAIT_TIMEOUT) {
            Ok((status, returned)) => unsafe {
                if !returned.is_null() {
                    let final_name = read_wide((*returned).pszInstanceName);
                    let final_host = read_wide((*returned).pszHostName);
                    DnsServiceFreeInstance(returned.cast_mut());
                    outcome = Some(RegisterOutcome {
                        status,
                        final_name,
                        final_host,
                    });
                } else {
                    outcome = Some(RegisterOutcome {
                        status,
                        final_name: String::new(),
                        final_host: String::new(),
                    });
                }
            },
            Err(_) => evidence("register", &[("error", "completion callback timed out".into())]),
        }
    } else {
        evidence("register", &[("call_status", call_status.into())]);
    }
    unsafe {
        let _ = Context::<(u32, *mut DNS_SERVICE_INSTANCE)>::from_raw(context);
        DnsServiceFreeInstance(instance);
    }
    outcome
}

fn deregister(final_name: &str, final_host: &str, port: u16, txt: &BTreeMap<String, String>) -> u32 {
    // DeRegister validates the same instance shape that was registered, so it
    // is rebuilt from the callback-returned identity instead of a raw copy.
    let keys: Vec<Vec<u16>> = txt.keys().map(|key| wide(key)).collect();
    let values: Vec<Vec<u16>> = txt.values().map(|value| wide(value)).collect();
    let key_ptrs: Vec<*const u16> = keys.iter().map(|key| key.as_ptr()).collect();
    let value_ptrs: Vec<*const u16> = values.iter().map(|value| value.as_ptr()).collect();
    let name_w = wide(final_name);
    let host_w = wide(final_host);
    let instance: *mut DNS_SERVICE_INSTANCE = unsafe {
        DnsServiceConstructInstance(
            name_w.as_ptr(),
            host_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            port,
            0,
            0,
            txt.len() as u32,
            key_ptrs.as_ptr(),
            value_ptrs.as_ptr(),
        )
    };
    if instance.is_null() {
        return u32::MAX;
    }

    let (tx, rx) = mpsc::channel::<(u32, *const DNS_SERVICE_INSTANCE)>();
    let context = Context(tx).into_raw();
    unsafe extern "system" fn deregister_complete(
        status: u32,
        query_context: *const std::ffi::c_void,
        instance: *const DNS_SERVICE_INSTANCE,
    ) {
        let sender = unsafe { &*(query_context as *const Context<(u32, *const DNS_SERVICE_INSTANCE)>) };
        let _ = sender.0.send((status, instance));
    }
    let request = DNS_SERVICE_REGISTER_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        pServiceInstance: instance,
        pRegisterCompletionCallback: Some(deregister_complete),
        pQueryContext: context,
        hCredentials: std::ptr::null_mut::<std::ffi::c_void>() as HANDLE,
        unicastEnabled: 0,
    };
    let mut cancel = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
    let call_status = unsafe { DnsServiceDeRegister(&request, &mut cancel) };

    let mut status = call_status;
    if call_status == DNS_STATUS_SUCCESS_DWORD || call_status == DNS_REQUEST_PENDING {
        match rx.recv_timeout(WAIT_TIMEOUT) {
            Ok((callback_status, returned)) => unsafe {
                status = callback_status;
                if !returned.is_null() {
                    DnsServiceFreeInstance(returned.cast_mut());
                }
            },
            Err(_) => evidence("deregister", &[("error", "completion callback timed out".into())]),
        }
    }
    unsafe {
        let _ = Context::<(u32, *mut DNS_SERVICE_INSTANCE)>::from_raw(context);
        DnsServiceFreeInstance(instance);
    }
    status
}

// ── browse ────────────────────────────────────────────────────────────

enum BrowseEvent {
    Records(Vec<String>),
    Terminal(u32),
}

/// Browse one service type for `window`, returning observed instance names.
fn browse(service_type: &str, window: Duration) -> (Vec<String>, Vec<u32>) {
    let (tx, rx) = mpsc::channel::<BrowseEvent>();
    let context = Context(tx).into_raw();
    unsafe extern "system" fn browse_complete(
        status: u32,
        query_context: *const std::ffi::c_void,
        record: *const DNS_RECORDW,
    ) {
        let sender = unsafe { &*(query_context as *const Context<BrowseEvent>) };
        if status != DNS_STATUS_SUCCESS_DWORD || record.is_null() {
            let _ = sender.0.send(BrowseEvent::Terminal(status));
            return;
        }
        let mut names = Vec::new();
        let mut current = record;
        while !current.is_null() {
            let record = unsafe { &*current };
            if record.wType == DNS_TYPE_PTR {
                let target = unsafe { read_wide(record.Data.PTR.pNameHost) };
                if !target.is_empty() {
                    names.push(target);
                }
            }
            current = record.pNext;
        }
        if names.is_empty() {
            let _ = sender.0.send(BrowseEvent::Terminal(status));
        } else {
            let _ = sender.0.send(BrowseEvent::Records(names));
        }
    }

    let query_w = wide(service_type);
    let request = DNS_SERVICE_BROWSE_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        QueryName: query_w.as_ptr(),
        Anonymous: windows_sys::Win32::NetworkManagement::Dns::DNS_SERVICE_BROWSE_REQUEST_0 {
            pBrowseCallback: Some(browse_complete),
        },
        pQueryContext: context,
    };
    let mut cancel = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
    let call_status = unsafe { DnsServiceBrowse(&request, &mut cancel) };

    let mut instances = Vec::new();
    let mut terminals = Vec::new();
    let deadline = Instant::now() + window;
    if call_status != DNS_STATUS_SUCCESS && call_status != DNS_REQUEST_PENDING as i32 {
        evidence("browse", &[("service_type", service_type.into()), ("call_status", call_status.into())]);
    } else {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(BrowseEvent::Records(names)) => instances.extend(names),
                Ok(BrowseEvent::Terminal(status)) => {
                    terminals.push(status);
                    break;
                }
                Err(_) => break,
            }
        }
    }
    unsafe {
        DnsServiceBrowseCancel(&cancel);
        // Drain the terminal callback the cancel triggers so the context is
        // unreferenced before it is reclaimed.
        while let Ok(event) = rx.try_recv() {
            if let BrowseEvent::Terminal(status) = event {
                terminals.push(status);
            }
        }
        let _ = Context::<BrowseEvent>::from_raw(context);
    }
    instances.sort();
    instances.dedup();
    (instances, terminals)
}

// ── resolve ───────────────────────────────────────────────────────────

fn resolved_json(service: &Option<ResolvedService>) -> serde_json::Value {
    match service {
        Some(service) => serde_json::json!({
            "status": service.status,
            "instance": service.instance,
            "host": service.host,
            "port": service.port,
            "txt": service.txt,
            "ipv4": service.ipv4,
            "ipv6": service.ipv6,
        }),
        None => serde_json::Value::Null,
    }
}

#[derive(Debug, Default)]
struct ResolvedService {
    status: u32,
    instance: String,
    host: String,
    port: u16,
    txt: BTreeMap<String, String>,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

/// Resolve one instance full name (e.g. `name._type._tcp.local`) via dnsapi.
fn resolve(instance_full_name: &str) -> Option<ResolvedService> {
    let (tx, rx) = mpsc::channel::<(u32, *const DNS_SERVICE_INSTANCE)>();
    let context = Context(tx).into_raw();
    unsafe extern "system" fn resolve_complete(
        status: u32,
        query_context: *const std::ffi::c_void,
        instance: *const DNS_SERVICE_INSTANCE,
    ) {
        let sender = unsafe { &*(query_context as *const Context<(u32, *const DNS_SERVICE_INSTANCE)>) };
        let _ = sender.0.send((status, instance));
    }

    let mut query_w = wide(instance_full_name);
    let request = DNS_SERVICE_RESOLVE_REQUEST {
        Version: 1,
        InterfaceIndex: 0,
        QueryName: query_w.as_mut_ptr(),
        pResolveCompletionCallback: Some(resolve_complete),
        pQueryContext: context,
    };
    let mut cancel = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
    let call_status = unsafe { DnsServiceResolve(&request, &mut cancel) };

    let mut resolved = None;
    if call_status == DNS_STATUS_SUCCESS || call_status == DNS_REQUEST_PENDING as i32 {
        match rx.recv_timeout(WAIT_TIMEOUT) {
        Ok((status, returned)) => unsafe {
            if !returned.is_null() {
                let mut service = ResolvedService {
                    status,
                    instance: read_wide((*returned).pszInstanceName),
                    host: read_wide((*returned).pszHostName),
                    port: (*returned).wPort,
                    ..ResolvedService::default()
                };
                let count = (*returned).dwPropertyCount as usize;
                for index in 0..count {
                    let key = read_wide(*(*returned).keys.add(index));
                    let value = read_wide(*(*returned).values.add(index));
                    service.txt.insert(key, value);
                }
                if !(*returned).ip4Address.is_null() {
                    let raw = *(*returned).ip4Address;
                    let octets = raw.to_le_bytes();
                    service
                        .ipv4
                        .push(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string());
                }
                if !(*returned).ip6Address.is_null() {
                    let bytes = std::slice::from_raw_parts(
                        (*returned).ip6Address as *const u8,
                        16,
                    );
                    service.ipv6.push(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes).unwrap_or([0u8; 16]),
                    ).to_string());
                }
                DnsServiceFreeInstance(returned.cast_mut());
                resolved = Some(service);
            }
        },
            Err(_) => evidence("resolve", &[("error", "completion callback timed out".into())]),
        }
    } else {
        evidence("resolve", &[("call_status", call_status.into())]);
    }
    unsafe {
        let _ = Context::<(u32, *mut DNS_SERVICE_INSTANCE)>::from_raw(context);
    }
    resolved
}

// ── hold mode ─────────────────────────────────────────────────────────

/// Register one record and hold it, so a peer can interrogate the wire while
/// the registration is alive. Emits one JSON line with the registered identity.
fn hold_mode(secs: u64) {
    let pid = std::process::id();
    let probe_name = format!("koi-win32-probe-{pid}");
    let probe_type = "_koi-probe._tcp.local";
    let host_name = format!(
        "{}.local",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "koi-host".to_string()).to_lowercase()
    );
    let txt = BTreeMap::from([
        ("source".to_string(), "win32-hold".to_string()),
        ("pid".to_string(), pid.to_string()),
    ]);
    let full_name = format!("{probe_name}.{probe_type}");
    let Some(outcome) = register(&full_name, &host_name, 43127, &txt, None) else {
        evidence("hold", &[("result", "register-failed".into())]);
        std::process::exit(1);
    };
    evidence(
        "hold",
        &[
            ("status", outcome.status.into()),
            ("name", outcome.final_name.clone().into()),
            ("host", outcome.final_host.clone().into()),
            ("hold_secs", secs.into()),
        ],
    );
    std::thread::sleep(Duration::from_secs(secs));
    let dereg = deregister(
        if outcome.final_name.is_empty() { &full_name } else { &outcome.final_name },
        if outcome.final_host.is_empty() { &host_name } else { &outcome.final_host },
        43127,
        &txt,
    );
    evidence("hold-release", &[("status", dereg.into())]);
}

// ── main sequence ─────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "hold" {
        let secs: u64 = args.get(2).and_then(|value| value.parse().ok()).unwrap_or(60);
        hold_mode(secs);
        return;
    }
    if args.len() >= 2 && args[1] == "meta" {
        let (found, terminals) = browse("_services._dns-sd._udp.local", BROWSE_WINDOW);
        evidence(
            "browse-meta",
            &[
                ("instances", serde_json::Value::Array(found.into_iter().map(serde_json::Value::from).collect())),
                ("terminals", serde_json::Value::Array(terminals.iter().map(|status| (*status).into()).collect())),
            ],
        );
        return;
    }
    if args.len() >= 3 && args[1] == "browse" {
        let (found, terminals) = browse(&args[2], Duration::from_secs(8));
        evidence(
            "browse-only",
            &[
                ("service_type", args[2].clone().into()),
                ("instances", serde_json::Value::Array(found.into_iter().map(serde_json::Value::from).collect())),
                ("terminals", serde_json::Value::Array(terminals.iter().map(|status| (*status).into()).collect())),
            ],
        );
        return;
    }
    let pid = std::process::id();
    let probe_name = format!("koi-win32-probe-{pid}");
    let probe_type = "_koi-probe._tcp.local";
    let probe_port: u16 = 43127;
    let host_name = format!(
        "{}.local",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "koi-host".to_string()).to_lowercase()
    );
    let txt = BTreeMap::from([
        ("source".to_string(), "win32-dns-sd".to_string()),
        ("pid".to_string(), pid.to_string()),
    ]);

    // Phase 1: registration under the current identity and firewall profile.
    // dnsapi expects the full DNS-SD instance name here: <Instance>._<Type>._tcp.local.
    let full_name = format!("{probe_name}.{probe_type}");
    let Some(outcome) = register(&full_name, &host_name, probe_port, &txt, None) else {
        evidence("summary", &[("result", "FAIL".into()), ("phase", "register".into())]);
        std::process::exit(1);
    };
    evidence(
        "register",
        &[
            ("status", outcome.status.into()),
            ("final_name", outcome.final_name.clone().into()),
            ("final_host", outcome.final_host.clone().into()),
        ],
    );
    if outcome.status != DNS_STATUS_SUCCESS_DWORD {
        evidence("summary", &[("result", "FAIL".into()), ("phase", "register status".into())]);
        std::process::exit(1);
    }

    // Phase 2: local browse sees the registration.
    let (seen, terminals) = browse(probe_type, BROWSE_WINDOW);
    let self_seen = seen.iter().any(|name| name == &full_name || name.starts_with(&format!("{probe_name}.")));
    evidence(
        "browse-self",
        &[
            ("instances", serde_json::Value::Array(seen.iter().cloned().map(serde_json::Value::from).collect())),
            ("self_seen", self_seen.into()),
            ("terminals", serde_json::Value::Array(terminals.iter().map(|status| (*status).into()).collect())),
        ],
    );

    // Phase 3: resolve the own record and verify port + TXT round-trip.
    let resolved = resolve(&full_name);
    let resolve_ok = resolved
        .as_ref()
        .is_some_and(|service| service.port == probe_port && service.txt.get("source").map(String::as_str) == Some("win32-dns-sd"));
    evidence(
        "resolve-self",
        &[
            ("ok", resolve_ok.into()),
            ("detail", resolved_json(&resolved)),
        ],
    );

    // Phase 4: browse the LAN peer type Koi daemons announce everywhere.
    let (peers, peer_terminals) = browse("_http._tcp.local", BROWSE_WINDOW);
    evidence(
        "browse-peer-http",
        &[
            ("instances", serde_json::Value::Array(peers.clone().into_iter().map(serde_json::Value::from).collect())),
            ("terminals", serde_json::Value::Array(peer_terminals.iter().map(|status| (*status).into()).collect())),
        ],
    );
    let peer_resolve = peers.iter().find(|name| !name.starts_with(&probe_name)).map(|peer| {
        let resolved = resolve(peer);
        evidence("resolve-peer", &[("name", (*peer).clone().into()), ("detail", resolved_json(&resolved))]);
        resolved
    });
    if peer_resolve.is_none() {
        evidence("resolve-peer", &[("skipped", "no peer instance observed".into())]);
    }

    // Phase 5: acknowledged deregistration, then browse proves removal.
    let dereg_status = deregister(
        if outcome.final_name.is_empty() { &probe_name } else { &outcome.final_name },
        if outcome.final_host.is_empty() { &host_name } else { &outcome.final_host },
        probe_port,
        &txt,
    );
    std::thread::sleep(Duration::from_secs(2));
    let (after, after_terminals) = browse(probe_type, Duration::from_secs(4));
    let gone = !after.iter().any(|name| name.starts_with(&format!("{probe_name}.")));
    evidence(
        "deregister",
        &[
            ("status", dereg_status.into()),
            ("removed_from_wire", gone.into()),
            ("remaining", serde_json::Value::Array(after.iter().cloned().map(serde_json::Value::from).collect())),
            ("terminals", serde_json::Value::Array(after_terminals.iter().map(|status| (*status).into()).collect())),
        ],
    );

    // The peer windows are informational on an empty LAN; the gate is that the
    // probe's own publication cycle (register, see, resolve, remove) was real.
    let passed = self_seen && resolve_ok && gone && dereg_status == DNS_STATUS_SUCCESS_DWORD;
    evidence("summary", &[("result", if passed { "PASS" } else { "FAIL" }.into())]);
    if !passed {
        std::process::exit(1);
    }
}
