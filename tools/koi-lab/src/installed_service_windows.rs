use std::ffi::{OsStr, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
    QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_AUTO_START,
    SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
    SERVICE_STOPPED, SERVICE_STOP_PENDING,
};
use windows_sys::Win32::System::Threading::{
    GetProcessHandleCount, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::installed_service::{NativeServiceSample, ServiceObserver};
use crate::model::{ArtifactIdentity, InstalledServiceIdentity, ObservedU64};

const RESTART_COUNT_UNAVAILABLE: &str =
    "Windows SCM exposes no supported cumulative service restart counter";
const TASK_COUNT_UNAVAILABLE: &str =
    "Windows exposes process threads but no distinct SCM task counter";

pub(super) struct WindowsScmObserver {
    service_name: String,
    expected_binary: PathBuf,
}

impl WindowsScmObserver {
    pub(super) fn new(service_name: String, expected_binary: PathBuf) -> Self {
        Self {
            service_name,
            expected_binary,
        }
    }
}

impl ServiceObserver for WindowsScmObserver {
    fn name(&self) -> &'static str {
        "windows-scm"
    }

    fn identity(&self) -> Result<InstalledServiceIdentity> {
        let service = service_snapshot(&self.service_name, true)?;
        require_running(&self.service_name, &service.status)?;
        let config = service
            .config
            .context("SCM omitted requested service configuration")?;
        if config.start_type != SERVICE_AUTO_START {
            bail!(
                "{} start policy is {}, expected AutoStart ({SERVICE_AUTO_START})",
                self.service_name,
                config.start_type
            );
        }
        let (configured_binary, arguments) = split_service_command(&config.binary_path)?;
        if !arguments
            .split_whitespace()
            .any(|argument| argument == "--daemon")
        {
            bail!(
                "{} SCM command does not contain the required --daemon argument: {:?}",
                self.service_name,
                config.binary_path
            );
        }
        let configured_binary = configured_binary.canonicalize().with_context(|| {
            format!(
                "could not resolve SCM image {}",
                configured_binary.display()
            )
        })?;
        if configured_binary != self.expected_binary {
            bail!(
                "{} SCM command names {}, expected {}",
                self.service_name,
                configured_binary.display(),
                self.expected_binary.display()
            );
        }

        let pid = service.status.dwProcessId;
        let process_binary = process_image_path(pid)?
            .canonicalize()
            .with_context(|| format!("could not resolve image for SCM pid {pid}"))?;
        if process_binary != self.expected_binary {
            bail!(
                "{} pid {} runs {}, expected {}",
                self.service_name,
                pid,
                process_binary.display(),
                self.expected_binary.display()
            );
        }

        Ok(InstalledServiceIdentity {
            observer: self.name().to_owned(),
            service_name: self.service_name.clone(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            service_definition: PathBuf::from(format!(r"SCM\{}", self.service_name)),
            exec_start: config.binary_path,
            pid,
            restart_count: ObservedU64::unavailable(RESTART_COUNT_UNAVAILABLE),
            binary: ArtifactIdentity::from_path(&process_binary)?,
            version: checked_version(&self.expected_binary)?,
        })
    }

    fn sample(&self) -> Result<NativeServiceSample> {
        let service = service_snapshot(&self.service_name, false)?;
        require_running(&self.service_name, &service.status)?;
        let pid = service.status.dwProcessId;
        let process = process_snapshot(pid)?;
        Ok(NativeServiceSample {
            pid,
            restart_count: ObservedU64::unavailable(RESTART_COUNT_UNAVAILABLE),
            rss_bytes: ObservedU64::available(process.rss_bytes),
            descriptor_count: ObservedU64::available(process.handle_count),
            thread_count: ObservedU64::available(process.thread_count),
            task_count: ObservedU64::unavailable(TASK_COUNT_UNAVAILABLE),
        })
    }
}

struct ServiceSnapshot {
    status: SERVICE_STATUS_PROCESS,
    config: Option<ServiceConfig>,
}

struct ServiceConfig {
    binary_path: String,
    start_type: u32,
}

struct ProcessSnapshot {
    rss_bytes: u64,
    handle_count: u64,
    thread_count: u64,
}

struct OwnedScHandle(SC_HANDLE);

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the successful SCM handle for its lifetime.
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the successful kernel handle for its lifetime.
        unsafe { CloseHandle(self.0) };
    }
}

fn service_snapshot(service_name: &str, include_config: bool) -> Result<ServiceSnapshot> {
    let wide_name = nul_terminated(service_name);
    // SAFETY: null machine/database names select the local active SCM database.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(std::io::Error::last_os_error()).context("could not open the local SCM");
    }
    let manager = OwnedScHandle(manager);
    let access = SERVICE_QUERY_STATUS
        | if include_config {
            SERVICE_QUERY_CONFIG
        } else {
            0
        };
    // SAFETY: manager is open and wide_name is a live NUL-terminated UTF-16 buffer.
    let service = unsafe { OpenServiceW(manager.0, wide_name.as_ptr(), access) };
    if service.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not open SCM service {service_name:?}"));
    }
    let service = OwnedScHandle(service);
    let status = query_service_status(service.0)?;
    let config = include_config
        .then(|| query_service_config(service.0))
        .transpose()?;
    Ok(ServiceSnapshot { status, config })
}

fn query_service_status(service: SC_HANDLE) -> Result<SERVICE_STATUS_PROCESS> {
    // SAFETY: status is an exactly sized writable output buffer and service has query access.
    let mut status = unsafe { zeroed::<SERVICE_STATUS_PROCESS>() };
    let mut needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            0,
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("could not query SCM service status");
    }
    Ok(status)
}

fn query_service_config(service: SC_HANDLE) -> Result<ServiceConfig> {
    let mut needed = 0;
    // SAFETY: the documented sizing call accepts a null buffer and zero length.
    unsafe { QueryServiceConfigW(service, std::ptr::null_mut(), 0, &mut needed) };
    if needed < size_of::<QUERY_SERVICE_CONFIGW>() as u32 {
        return Err(std::io::Error::last_os_error())
            .context("SCM did not return a valid configuration buffer size");
    }

    // usize storage gives the byte buffer sufficient alignment for QUERY_SERVICE_CONFIGW.
    let word_bytes = size_of::<usize>() as u32;
    let mut storage = vec![0_usize; needed.div_ceil(word_bytes) as usize];
    let buffer = storage.as_mut_ptr().cast::<u8>();
    // SAFETY: storage is writable, aligned, and at least needed bytes long.
    let ok = unsafe {
        QueryServiceConfigW(
            service,
            buffer.cast::<QUERY_SERVICE_CONFIGW>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not query SCM service configuration");
    }
    // SAFETY: QueryServiceConfigW initialized the leading structure on success.
    let config = unsafe { &*buffer.cast::<QUERY_SERVICE_CONFIGW>() };
    Ok(ServiceConfig {
        binary_path: wide_string_in_buffer(config.lpBinaryPathName, &storage)?,
        start_type: config.dwStartType,
    })
}

fn wide_string_in_buffer(pointer: *mut u16, storage: &[usize]) -> Result<String> {
    if pointer.is_null() {
        bail!("SCM returned a null service command");
    }
    let start = storage.as_ptr() as usize;
    let end = start.saturating_add(std::mem::size_of_val(storage));
    let address = pointer as usize;
    if address < start || address >= end || !(address - start).is_multiple_of(size_of::<u16>()) {
        bail!("SCM returned a service command outside its configuration buffer");
    }
    let available = (end - address) / size_of::<u16>();
    // SAFETY: the validated pointer lies in storage and available stops at its end.
    let units = unsafe { std::slice::from_raw_parts(pointer, available) };
    let length = units
        .iter()
        .position(|unit| *unit == 0)
        .context("SCM service command was not NUL-terminated")?;
    Ok(OsString::from_wide(&units[..length])
        .to_string_lossy()
        .into_owned())
}

fn process_image_path(pid: u32) -> Result<PathBuf> {
    let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: process has query access and buffer/length describe writable storage.
    let ok = unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut length) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not query image for pid {pid}"));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn process_snapshot(pid: u32) -> Result<ProcessSnapshot> {
    let process = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut memory = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: process has query/read access and memory is an exactly sized output structure.
    let ok = unsafe {
        GetProcessMemoryInfo(
            process.0,
            &mut memory,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not query memory for pid {pid}"));
    }
    let mut handles = 0;
    // SAFETY: process is live and handles is a writable output value.
    if unsafe { GetProcessHandleCount(process.0, &mut handles) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not query handle count for pid {pid}"));
    }
    Ok(ProcessSnapshot {
        rss_bytes: u64::try_from(memory.WorkingSetSize).unwrap_or(u64::MAX),
        handle_count: u64::from(handles),
        thread_count: thread_count(pid)?,
    })
}

fn open_process(pid: u32, access: u32) -> Result<OwnedHandle> {
    // SAFETY: OpenProcess receives a numeric SCM-provided process identifier.
    let process = unsafe { OpenProcess(access, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not open SCM process {pid}"));
    }
    Ok(OwnedHandle(process))
}

fn thread_count(pid: u32) -> Result<u64> {
    // SAFETY: flags request a system thread snapshot; the returned handle is owned below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("could not snapshot process threads");
    }
    let snapshot = OwnedHandle(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut count = 0_u64;
    // SAFETY: snapshot is valid and entry advertises its exact writable size.
    let mut ok = unsafe { Thread32First(snapshot.0, &mut entry) };
    while ok != 0 {
        if entry.th32OwnerProcessID == pid {
            count = count.saturating_add(1);
        }
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        // SAFETY: snapshot and entry remain valid across enumeration.
        ok = unsafe { Thread32Next(snapshot.0, &mut entry) };
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(error).context("could not enumerate process threads");
    }
    Ok(count)
}

fn require_running(service_name: &str, status: &SERVICE_STATUS_PROCESS) -> Result<()> {
    let (active_state, sub_state) = service_state(status.dwCurrentState);
    if active_state != "active" || sub_state != "running" || status.dwProcessId == 0 {
        bail!(
            "{service_name} is not an active running SCM service: {active_state}/{sub_state} (state {}, pid {})",
            status.dwCurrentState,
            status.dwProcessId
        );
    }
    Ok(())
}

fn service_state(state: u32) -> (&'static str, &'static str) {
    match state {
        SERVICE_RUNNING => ("active", "running"),
        SERVICE_START_PENDING => ("activating", "start-pending"),
        SERVICE_STOP_PENDING => ("deactivating", "stop-pending"),
        SERVICE_CONTINUE_PENDING => ("activating", "continue-pending"),
        SERVICE_PAUSE_PENDING => ("deactivating", "pause-pending"),
        SERVICE_PAUSED => ("inactive", "paused"),
        SERVICE_STOPPED => ("inactive", "stopped"),
        _ => ("unknown", "unknown"),
    }
}

fn split_service_command(command: &str) -> Result<(PathBuf, &str)> {
    let command = command.trim();
    if command.is_empty() {
        bail!("SCM service command is empty");
    }
    if let Some(quoted) = command.strip_prefix('"') {
        let end = quoted
            .find('"')
            .context("SCM service command has an unterminated executable quote")?;
        let executable = &quoted[..end];
        if executable.is_empty() {
            bail!("SCM service command has an empty executable path");
        }
        return Ok((PathBuf::from(executable), quoted[end + 1..].trim()));
    }
    let end = command.find(char::is_whitespace).unwrap_or(command.len());
    Ok((PathBuf::from(&command[..end]), command[end..].trim()))
}

fn checked_version(binary: &Path) -> Result<String> {
    let output = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to start {}", binary.display()))?;
    if !output.status.success() {
        bail!(
            "{} --version failed (exit {}): {}",
            binary.display(),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn nul_terminated(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_owned_service_commands_without_localized_output() {
        let (binary, arguments) =
            split_service_command(r#""C:\Program Files\Koi\koi.exe" --daemon"#).unwrap();
        assert_eq!(binary, PathBuf::from(r"C:\Program Files\Koi\koi.exe"));
        assert_eq!(arguments, "--daemon");

        let (binary, arguments) = split_service_command(r"C:\koi\koi.exe --daemon").unwrap();
        assert_eq!(binary, PathBuf::from(r"C:\koi\koi.exe"));
        assert_eq!(arguments, "--daemon");
        assert!(split_service_command(r#""C:\koi.exe --daemon"#).is_err());
    }

    #[test]
    fn maps_structured_scm_states_to_neutral_lifecycle() {
        assert_eq!(service_state(SERVICE_RUNNING), ("active", "running"));
        assert_eq!(
            service_state(SERVICE_START_PENDING),
            ("activating", "start-pending")
        );
        assert_eq!(service_state(SERVICE_STOPPED), ("inactive", "stopped"));
        assert_eq!(service_state(u32::MAX), ("unknown", "unknown"));
    }
}
