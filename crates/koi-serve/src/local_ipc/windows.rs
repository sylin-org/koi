use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use koi_config::local_access::LocalOperator;
use koi_mdns::MdnsCore;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    drain_sessions, observe_session_result, run_session, split_stream, LocalControlConfig,
};

/// One acquired Windows named-pipe generation. The first-instance handle is
/// created during construction and stays owned until the run loop begins.
pub(super) struct LocalControl {
    listener: NamedPipeServer,
    path: PathBuf,
    security: PipeSecurity,
    expected_sid: String,
    access: Option<koi_common::local_control::LocalDaemonAccess>,
    info: koi_common::local_control::LocalDaemonInfo,
}

impl LocalControl {
    pub(super) fn acquire(config: LocalControlConfig) -> anyhow::Result<Self> {
        let expected_sid = match &config.operator {
            LocalOperator::WindowsSid { sid } => sid.clone(),
            LocalOperator::UnixUid { .. } => {
                anyhow::bail!("Unix UID cannot authorize a Windows local-control pipe")
            }
        };
        let security = PipeSecurity::new(&expected_sid)?;
        let listener = create_server(&config.path, &security, true)?;
        Ok(Self {
            listener,
            path: config.path,
            security,
            expected_sid,
            access: config.access,
            info: config.info,
        })
    }

    pub(super) async fn run(
        self,
        mdns: Option<Arc<MdnsCore>>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let Self {
            mut listener,
            path,
            security,
            expected_sid,
            access,
            info,
        } = self;
        let session_cancel = cancel.child_token();
        let mut sessions = JoinSet::new();
        tracing::info!(pipe = %path.display(), "Local control listening (Windows named pipe)");

        // Keep the Win32 security owner in this future directly. Creating a pipe
        // borrows it only for the synchronous CreateNamedPipeW call below.
        let result: anyhow::Result<()> = loop {
            let connected = {
                let connection = listener.connect();
                tokio::pin!(connection);
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break None,
                        joined = sessions.join_next(), if !sessions.is_empty() => {
                            observe_session_result(joined);
                        }
                        connected = &mut connection => break Some(connected),
                    }
                }
            };
            let Some(connected) = connected else {
                break Ok(());
            };
            if let Err(error) = connected {
                break Err(error.into());
            }

            // Create the next secured listener while the connected instance is
            // still alive. There is never a zero-instance window in which a
            // second Koi generation can claim first-instance ownership.
            let next = match create_server(&path, &security, false) {
                Ok(next) => next,
                Err(error) => break Err(error),
            };
            let connected = std::mem::replace(&mut listener, next);

            let authorized = match peer_has_sid(&connected, &expected_sid) {
                Ok(authorized) => authorized,
                Err(error) => break Err(error),
            };
            if !authorized {
                tracing::warn!("Rejected unauthorized local-control pipe peer");
                continue;
            }

            let (reader, writer) = split_stream(connected);
            sessions.spawn(run_session(
                mdns.clone(),
                reader,
                writer,
                access.clone(),
                info.clone(),
                session_cancel.clone(),
            ));
        };

        // Drop the pending accept instance first so no new client can enter;
        // connected instances remain owned by `sessions` until bounded drain.
        drop(listener);
        session_cancel.cancel();
        drain_sessions(&mut sessions).await;
        tracing::debug!("Local control stopped (Windows named pipe)");
        result
    }
}

fn create_server(
    path: &Path,
    security: &PipeSecurity,
    first_instance: bool,
) -> anyhow::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `security` owns the descriptor referenced by `attributes` and
    // remains alive until after this synchronous CreateNamedPipeW call.
    unsafe { options.create_with_security_attributes_raw(path, security.attributes()) }
        .map_err(Into::into)
}

struct PipeSecurity {
    descriptor: *mut c_void,
    attributes: SECURITY_ATTRIBUTES,
}

// SAFETY: this value exclusively owns an immutable self-relative security
// descriptor allocated by LocalAlloc. Win32 accepts it by pointer only during
// synchronous CreateNamedPipeW; moving the owner between Tokio worker threads
// does not alias or mutate the allocation.
unsafe impl Send for PipeSecurity {}

impl PipeSecurity {
    fn new(operator_sid: &str) -> anyhow::Result<Self> {
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{operator_sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and both output pointers are valid.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        })
    }

    fn attributes(&self) -> *mut c_void {
        (&self.attributes as *const SECURITY_ATTRIBUTES)
            .cast_mut()
            .cast()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from LocalAlloc through the conversion API.
        unsafe {
            LocalFree(self.descriptor);
        }
    }
}

fn peer_has_sid(pipe: &NamedPipeServer, expected: &str) -> anyhow::Result<bool> {
    let handle = pipe.as_raw_handle() as HANDLE;
    let mut process_id = 0;
    // SAFETY: the pipe handle is live and the output pointer is valid.
    if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(process_sid(process_id)?.eq_ignore_ascii_case(expected))
}

fn process_sid(process_id: u32) -> anyhow::Result<String> {
    // SAFETY: Win32 handle APIs have no Rust-side aliasing requirements.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        unsafe { CloseHandle(process) };
        return Err(std::io::Error::last_os_error().into());
    }

    let result = token_user_sid(token);
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    result
}

fn token_user_sid(token: HANDLE) -> anyhow::Result<String> {
    let mut needed = 0;
    // Expected sizing call: failure with an updated length is success for this phase.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut buffer = vec![0_u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut string_sid = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut string_sid) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let len = (0..)
        .take_while(|&index| unsafe { *string_sid.add(index) } != 0)
        .count();
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(string_sid, len) })?;
    unsafe {
        LocalFree(string_sid.cast());
    }
    Ok(value)
}
