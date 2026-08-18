//! Windows Service-SID / Named-Pipe authority transport.
//!
//! The service is installed by the deployment script with an unrestricted
//! Service SID and a protected service account.  It owns the Named Pipe ACL,
//! validates the connecting Agent SID, unwraps a DPAPI-protected key marker,
//! and forwards only bounded JSON to the separately configured authority
//! backend pipe.  `--probe` is a native client mode used by the Python adapter;
//! it never starts a second in-process authority.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
mod windows_authority {
    use std::env;
    use std::ffi::c_void;
    use std::fs;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use sha2::Digest;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenGroups, TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_ERROR_CRITICAL, SERVICE_RUNNING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const MAX_MESSAGE_BYTES: usize = 64 * 1024;
    const SERVICE_NAME: &str = "KhaosAuthorityD";

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn required(name: &str) -> Result<String, String> {
        env::var(name).map_err(|_| format!("{name} is missing"))
    }

    fn load_configuration(path: &str) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "authority service configuration is unavailable".to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_MESSAGE_BYTES as u64 {
            return Err("authority service configuration is not a bounded file".to_string());
        }
        let content = fs::read_to_string(path)
            .map_err(|_| "authority service configuration cannot be read".to_string())?;
        for line in content.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            if matches!(
                name,
                "KHAOS_AUTHORITYD_NAMED_PIPE"
                    | "KHAOS_AUTHORITYD_BACKEND_PIPE"
                    | "KHAOS_AGENT_SID"
                    | "KHAOS_AUTHORITYD_SERVICE_SID"
                    | "KHAOS_AUTHORITYD_DPAPI_KEY_PATH"
                    | "KHAOS_AUTHORITYD_PROTECTED_KEY_REF"
            ) {
                // The service is launched by SCM from a trusted installation
                // path; only the allowlisted identity fields can be loaded.
                env::set_var(name, value);
            }
        }
        Ok(())
    }

    fn pipe_name() -> Result<String, String> {
        let value = required("KHAOS_AUTHORITYD_NAMED_PIPE")?;
        if !value.starts_with(r"\\.\pipe\") || value.len() > 256 {
            return Err("authority Named Pipe path is invalid".to_string());
        }
        Ok(value)
    }

    fn service_sid_present() -> Result<String, String> {
        let expected = required("KHAOS_AUTHORITYD_SERVICE_SID")?;
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err("OpenProcessToken failed".to_string());
        }
        let mut required_size = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenGroups, null_mut(), 0, &mut required_size);
        }
        if required_size < size_of::<TOKEN_GROUPS>() as u32 {
            unsafe { CloseHandle(token) };
            return Err("Service SID group evidence is unavailable".to_string());
        }
        let mut bytes = vec![0_u8; required_size as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenGroups,
                bytes.as_mut_ptr().cast(),
                required_size,
                &mut required_size,
            )
        } != 0;
        let mut found = false;
        if ok {
            let groups = unsafe { &*(bytes.as_ptr().cast::<TOKEN_GROUPS>()) };
            let group_count = groups.GroupCount as usize;
            let first = groups.Groups.as_ptr();
            for index in 0..group_count {
                let sid = unsafe { (*first.add(index)).Sid };
                if sid.is_null() {
                    continue;
                }
                let mut text = null_mut();
                let converted = unsafe {
                    windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
                        sid, &mut text,
                    )
                } != 0;
                if converted && !text.is_null() {
                    let mut length = 0;
                    while unsafe { *text.add(length) } != 0 && length < 256 {
                        length += 1;
                    }
                    let value = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(text, length)
                    });
                    if value == expected {
                        found = true;
                    }
                    unsafe { LocalFree(text.cast()) };
                }
                if found {
                    break;
                }
            }
        }
        unsafe { CloseHandle(token) };
        if !ok || !found {
            return Err("configured Service SID is absent from the service token".to_string());
        }
        Ok(expected)
    }

    fn peer_sid(pid: u32) -> Result<String, String> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err("Agent process cannot be opened for SID verification".to_string());
        }
        let mut token: HANDLE = null_mut();
        let token_ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0;
        if !token_ok {
            unsafe { CloseHandle(process) };
            return Err("Agent process token cannot be opened".to_string());
        }
        let mut required_size = 0_u32;
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required_size) };
        if required_size < size_of::<TOKEN_USER>() as u32 {
            unsafe {
                CloseHandle(token);
                CloseHandle(process);
            }
            return Err("Agent token SID evidence is unavailable".to_string());
        }
        let mut bytes = vec![0_u8; required_size as usize];
        let info_ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                required_size,
                &mut required_size,
            )
        } != 0;
        let mut result = Err("Agent token SID evidence is malformed".to_string());
        if info_ok {
            let user = unsafe { &*(bytes.as_ptr().cast::<TOKEN_USER>()) };
            let mut text = null_mut();
            if unsafe {
                windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
                    user.User.Sid,
                    &mut text,
                )
            } != 0
                && !text.is_null()
            {
                let mut length = 0;
                while unsafe { *text.add(length) } != 0 && length < 256 {
                    length += 1;
                }
                result = Ok(String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(text, length)
                }));
                unsafe { LocalFree(text.cast()) };
            }
        }
        unsafe {
            CloseHandle(token);
            CloseHandle(process);
        }
        result
    }

    fn protected_key_marker() -> Result<(), String> {
        let path = required("KHAOS_AUTHORITYD_DPAPI_KEY_PATH")?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "DPAPI key marker is unavailable".to_string())?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MESSAGE_BYTES as u64 {
            return Err("DPAPI key marker is not a bounded regular file".to_string());
        }
        let encrypted = fs::read(Path::new(&path))
            .map_err(|_| "DPAPI key marker cannot be read".to_string())?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(&input, null_mut(), null(), null(), null(), 0, &mut output)
        } != 0;
        if output.pbData != null_mut() {
            unsafe { LocalFree(output.pbData.cast()) };
        }
        if !ok || output.cbData == 0 {
            return Err("DPAPI key marker is not decryptable by the service identity".to_string());
        }
        Ok(())
    }

    fn build_pipe_security(
    ) -> Result<(Vec<u16>, windows_sys::Win32::Security::SECURITY_ATTRIBUTES), String> {
        let service_sid = required("KHAOS_AUTHORITYD_SERVICE_SID")?;
        let agent_sid = required("KHAOS_AGENT_SID")?;
        let descriptor = format!("D:P(A;;GA;;;SY)(A;;GA;;;{service_sid})(A;;GRGW;;;{agent_sid})");
        let descriptor_w = wide(&descriptor);
        let mut raw = null_mut();
        let mut size = 0_u32;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_w.as_ptr(),
                1,
                &mut raw,
                &mut size,
            )
        } == 0
        {
            return Err("Named Pipe ACL construction failed".to_string());
        }
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: raw,
            bInheritHandle: 0,
        };
        Ok((descriptor_w, attributes))
    }

    fn native_probe_json(service_sid: &str, peer_pid: u32, pipe_acl: bool) -> String {
        let key_ref = env::var("KHAOS_AUTHORITYD_PROTECTED_KEY_REF").unwrap_or_default();
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(format!("{SERVICE_NAME}|{service_sid}|{key_ref}").as_bytes())
        );
        format!(
            "{{\"platform\":\"win32\",\"transport\":\"named-pipe\",\"service_id\":\"{SERVICE_NAME}\",\"service_pid\":{},\"service_identity\":\"{service_sid}\",\"peer_identity\":\"pid:{peer_pid}\",\"protected_key_ref\":\"{key_ref}\",\"challenge_digest\":\"{digest}\",\"peer_verified\":true,\"transport_verified\":{},\"protected_key_verified\":true}}",
            std::process::id(), pipe_acl
        )
    }

    fn service_request(input: &[u8], service_sid: &str, peer_sid: &str) -> String {
        if input == b"{\"kind\":\"probe\"}" {
            return native_probe_json(service_sid, 1, true).replace("pid:1", peer_sid);
        }
        let backend = match env::var("KHAOS_AUTHORITYD_BACKEND_PIPE") {
            Ok(value) if value.starts_with(r"\\.\pipe\") && value.len() <= 256 => wide(&value),
            _ => {
                return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend pipe is not configured\"}".to_string()
            }
        };
        let handle = unsafe {
            CreateFileW(
                backend.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend pipe is unavailable\"}".to_string();
        }
        let bounded = input.len() <= MAX_MESSAGE_BYTES;
        let mut written = 0_u32;
        let write_ok = bounded
            && unsafe {
                WriteFile(
                    handle,
                    input.as_ptr(),
                    input.len() as u32,
                    &mut written,
                    null_mut(),
                )
            } != 0;
        let mut response = vec![0_u8; MAX_MESSAGE_BYTES];
        let mut read = 0_u32;
        let read_ok = write_ok
            && unsafe {
                ReadFile(
                    handle,
                    response.as_mut_ptr(),
                    response.len() as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0;
        unsafe { CloseHandle(handle) };
        if !read_ok || read == 0 || read as usize > MAX_MESSAGE_BYTES {
            return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend returned no bounded response\"}".to_string();
        }
        String::from_utf8(response[..read as usize].to_vec()).unwrap_or_else(|_| {
            "{\"ok\":false,\"error\":\"authority backend returned malformed UTF-8\"}".to_string()
        })
    }

    fn run_service_loop() -> Result<(), String> {
        let service_sid = service_sid_present()?;
        protected_key_marker()?;
        let pipe = pipe_name()?;
        let (_descriptor, attributes) = build_pipe_security()?;
        let pipe_w = wide(&pipe);
        loop {
            let handle = unsafe {
                CreateNamedPipeW(
                    pipe_w.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_MESSAGE
                        | PIPE_READMODE_MESSAGE
                        | PIPE_WAIT
                        | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    MAX_MESSAGE_BYTES as u32,
                    MAX_MESSAGE_BYTES as u32,
                    5000,
                    &attributes,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!("CreateNamedPipeW failed: {}", unsafe {
                    GetLastError()
                }));
            }
            let connected = unsafe { ConnectNamedPipe(handle, null_mut()) } != 0;
            if connected {
                let mut peer_pid = 0_u32;
                let peer_ok = unsafe { GetNamedPipeClientProcessId(handle, &mut peer_pid) } != 0
                    && peer_pid > 0;
                let peer_identity = if peer_ok {
                    peer_sid(peer_pid).ok()
                } else {
                    None
                };
                let expected_agent_sid = env::var("KHAOS_AGENT_SID").unwrap_or_default();
                let peer_ok = peer_identity.as_deref() == Some(expected_agent_sid.as_str());
                let mut input = vec![0_u8; MAX_MESSAGE_BYTES];
                let mut read = 0_u32;
                let read_ok = peer_ok
                    && unsafe {
                        ReadFile(
                            handle,
                            input.as_mut_ptr(),
                            input.len() as u32,
                            &mut read,
                            null_mut(),
                        )
                    } != 0;
                let response = if read_ok {
                    service_request(
                        &input[..read as usize],
                        &service_sid,
                        peer_identity.as_deref().unwrap_or("unknown"),
                    )
                } else {
                    "{\"ok\":false,\"error\":\"Named Pipe peer proof failed\"}".to_string()
                };
                let mut written = 0_u32;
                let _ = unsafe {
                    WriteFile(
                        handle,
                        response.as_ptr(),
                        response.len() as u32,
                        &mut written,
                        null_mut(),
                    )
                };
            }
            unsafe {
                DisconnectNamedPipe(handle);
                CloseHandle(handle);
            }
        }
    }

    fn client_probe() -> Result<(), String> {
        let pipe = wide(&pipe_name()?);
        let handle = unsafe {
            CreateFileW(
                pipe.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err("authority Named Pipe is unavailable".to_string());
        }
        let request = b"{\"kind\":\"probe\"}";
        let mut written = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                request.as_ptr(),
                request.len() as u32,
                &mut written,
                null_mut(),
            )
        } != 0;
        let mut response = vec![0_u8; MAX_MESSAGE_BYTES];
        let mut read = 0_u32;
        let read_ok = ok
            && unsafe {
                ReadFile(
                    handle,
                    response.as_mut_ptr(),
                    response.len() as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0;
        unsafe { CloseHandle(handle) };
        if !read_ok || read == 0 {
            return Err("authority Named Pipe probe failed".to_string());
        }
        println!("{}", String::from_utf8_lossy(&response[..read as usize]));
        Ok(())
    }

    unsafe extern "system" fn service_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            return 0;
        }
        0
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = wide(SERVICE_NAME);
        let status_handle: SERVICE_STATUS_HANDLE =
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(service_handler), null());
        if status_handle.is_null() {
            return;
        }
        let mut status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_RUNNING,
            dwControlsAccepted: SERVICE_ACCEPT_STOP,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        SetServiceStatus(status_handle, &status);
        if run_service_loop().is_err() {
            status.dwCurrentState = SERVICE_STOPPED;
            status.dwControlsAccepted = 0;
            status.dwWin32ExitCode = SERVICE_ERROR_CRITICAL;
            SetServiceStatus(status_handle, &status);
        }
    }

    pub fn run() -> i32 {
        let arguments: Vec<String> = std::env::args().collect();
        if let Some(index) = arguments.iter().position(|value| value == "--config") {
            let Some(path) = arguments.get(index + 1) else {
                return 78;
            };
            if load_configuration(path).is_err() {
                return 78;
            }
        }
        if arguments.get(1).map(String::as_str) == Some("--probe") {
            return client_probe().map(|_| 0).unwrap_or(78);
        }
        let name = wide(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            78
        } else {
            0
        }
    }
}

#[cfg(windows)]
fn main() {
    std::process::exit(windows_authority::run());
}
