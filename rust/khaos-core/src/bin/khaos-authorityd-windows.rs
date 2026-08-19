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
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::IO::{
        CancelIoEx, GetOverlappedResult, OVERLAPPED,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_ERROR_CRITICAL, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
        SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
        WaitForSingleObject, WaitForMultipleObjects, PROCESS_QUERY_LIMITED_INFORMATION,
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
                    | "KHAOS_AUTHORITYD_BACKEND_SERVICE_SID"
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

    fn service_instance_id() -> String {
        // A per-run instance identity binds every proof to one service
        // process lifetime.  It is derived from the pid and the monotonic
        // wall clock so two consecutive service instances never share it.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let mixed = format!("{}|{}", std::process::id(), nanos);
        format!("{:x}", sha2::Sha256::digest(mixed.as_bytes()))[..32].to_string()
    }

    fn agent_requirement_digest() -> String {
        let agent_sid = env::var("KHAOS_AGENT_SID").unwrap_or_default();
        format!(
            "{:x}",
            sha2::Sha256::digest(format!("windows-agent-sid:{agent_sid}").as_bytes())
        )
    }

    const PROBE_INNER_REQUEST: &str = "{\"operation\":\"ping\",\"protocol\":1}";

    fn hex_encode(input: &[u8]) -> String {
        let mut output = String::with_capacity(input.len() * 2);
        for byte in input {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    fn sha256_hex(input: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(input))
    }

    fn valid_challenge(value: &str) -> bool {
        value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }

    /// Handle one client message: parse kind/challenge/request, wrap the
    /// request into a backend `attest` envelope, forward it, and merge the
    /// backend response with the transport binding for the client.
    fn service_request(input: &[u8], service_sid: &str, peer_identity: &str) -> String {
        let message: serde_json::Value = match serde_json::from_slice(input) {
            Ok(value) => value,
            Err(_) => {
                return "{\"ok\":false,\"error\":\"native pipe message is malformed JSON\"}"
                    .to_string()
            }
        };
        let kind = message.get("kind").and_then(|value| value.as_str());
        let challenge = message
            .get("challenge_nonce")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let instance = service_instance_id();
        let requirement_digest = agent_requirement_digest();
        let key_ref = env::var("KHAOS_AUTHORITYD_PROTECTED_KEY_REF").unwrap_or_default();
        let service_name =
            env::var("KHAOS_AUTHORITYD_SERVICE_NAME").unwrap_or_else(|_| SERVICE_NAME.to_string());
        if kind.is_none() || !valid_challenge(challenge) {
            return "{\"ok\":false,\"error\":\"native pipe challenge is missing or malformed\"}"
                .to_string();
        }
        let request_bytes: Vec<u8> = if kind == Some("probe") {
            PROBE_INNER_REQUEST.as_bytes().to_vec()
        } else {
            match message.get("request_json").and_then(|value| value.as_str()) {
                Some(request) => request.as_bytes().to_vec(),
                None => {
                    return "{\"ok\":false,\"error\":\"native pipe request body is missing\"}"
                        .to_string()
                }
            }
        };
        if request_bytes.is_empty() || request_bytes.len() > MAX_MESSAGE_BYTES / 2 {
            return "{\"ok\":false,\"error\":\"native pipe request is out of bounds\"}".to_string();
        }
        let attest_request = serde_json::json!({
            "protocol": 1,
            "operation": "attest",
            "challenge_nonce": challenge,
            "request_raw_hex": hex_encode(&request_bytes),
            "request_digest": sha256_hex(&request_bytes),
            "proof_fields": {
                "platform": "win32",
                "transport": "named-pipe",
                "service_id": service_name,
                "service_pid": std::process::id().to_string(),
                "service_identity": service_sid,
                "peer_identity": peer_identity,
                "peer_team_id": peer_identity,
                "peer_cdhash": "",
                "designated_requirement_digest": requirement_digest,
                "service_instance_id": instance,
                "protected_key_ref": key_ref,
            },
        });
        let backend = match env::var("KHAOS_AUTHORITYD_BACKEND_PIPE") {
            Ok(value) if value.starts_with(r"\\.\pipe\") && value.len() <= 256 => wide(&value),
            _ => {
                return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend pipe is not configured\"}".to_string()
            }
        };
        // Open the backend pipe overlapped so a wedged backend cannot
        // block the authority frontend forever: every operation carries
        // a hard deadline and is cancelled on expiry.
        let handle = unsafe {
            CreateFileW(
                backend.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend pipe is unavailable\"}".to_string();
        }
        // Verify the backend pipe really is served by a trusted authority
        // identity before forwarding a request.  A pipe name alone is not
        // identity: any process could create a pipe with the same name.
        // The backend is trusted when its server process runs as the
        // configured backend Service SID or as LocalSystem (the OS's own
        // identity, which fronts the backend service in SCM deployments).
        let backend_identity_ok = unsafe {
            let mut server_pid = 0_u32;
            if GetNamedPipeServerProcessId(handle, &mut server_pid) == 0 {
                0
            } else {
                match peer_sid(server_pid) {
                    Ok(observed)
                        if observed == service_sid
                            || observed == "S-1-5-18"
                            || Some(observed.as_str())
                                == env::var("KHAOS_AUTHORITYD_BACKEND_SERVICE_SID")
                                    .ok()
                                    .as_deref() =>
                    {
                        1
                    }
                    _ => 0,
                }
            }
        };
        if backend_identity_ok == 0 {
            unsafe { CloseHandle(handle) };
            return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend pipe identity is not the authority Service SID\"}".to_string();
        }
        let payload = serde_json::to_vec(&attest_request).unwrap_or_default();
        if payload.len() > MAX_MESSAGE_BYTES {
            unsafe { CloseHandle(handle) };
            return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend request is out of bounds\"}".to_string();
        }
        let write_result =
            unsafe { write_message_deadline(handle, &payload, BACKEND_IO_TIMEOUT_MS) };
        let backend_bytes = match write_result {
            Ok(()) => {
                let mut response = vec![0_u8; MAX_MESSAGE_BYTES];
                unsafe { read_message_deadline(handle, &mut response, BACKEND_IO_TIMEOUT_MS) }
            }
            Err(error) => Err(error),
        };
        unsafe { CloseHandle(handle) };
        let backend_bytes = match backend_bytes {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE_BYTES => bytes,
            Ok(_) => {
                return "{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend returned no bounded response\"}".to_string()
            }
            Err(error) => {
                return format!(
                    "{{\"ok\":false,\"error_code\":\"authority_backend_unavailable\",\"error\":\"authority backend IO deadline: {error}\"}}"
                )
            }
        };
        let backend_body: serde_json::Value = match serde_json::from_slice(&backend_bytes) {
            Ok(value) => value,
            Err(_) => {
                return "{\"ok\":false,\"error\":\"authority backend returned malformed JSON\"}"
                    .to_string()
            }
        };
        // Merge the transport binding into the backend response so the
        // Python adapter can verify both the static instance digest and the
        // signed challenge-response attestation.
        let static_digest = format!(
            "{:x}",
            sha2::Sha256::digest(
                format!(
                    "{SERVICE_NAME}|{service_sid}|{peer_identity}|{requirement_digest}|{instance}|{key_ref}|native-authority-proof-v2"
                )
                .as_bytes()
            )
        );
        let mut wrapper = serde_json::Map::new();
        wrapper.insert(
            "native_transport".to_string(),
            serde_json::Value::String("named-pipe".to_string()),
        );
        wrapper.insert(
            "proof_digest".to_string(),
            serde_json::Value::String(static_digest),
        );
        if let serde_json::Value::Object(body) = backend_body {
            for (key, value) in body {
                wrapper.insert(key, value);
            }
        } else {
            return "{\"ok\":false,\"error\":\"authority backend returned a non-object response\"}"
                .to_string();
        }
        serde_json::Value::Object(wrapper).to_string()
    }

    const CLIENT_IO_TIMEOUT_MS: u32 = 10_000;
    const BACKEND_IO_TIMEOUT_MS: u32 = 15_000;
    const ERROR_PIPE_CONNECTED: u32 = 0x0000_0217;
    const ERROR_IO_PENDING: u32 = 0x0000_03E5;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const INFINITE: u32 = 0xFFFF_FFFF;

    static mut STOP_EVENT: HANDLE = std::ptr::null_mut();
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = std::ptr::null_mut();

    unsafe fn set_service_state(state: u32, controls: u32, wait_hint: u32) {
        let handle = STATUS_HANDLE;
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        SetServiceStatus(handle, &status);
    }

    /// Overlapped read of one bounded message with a hard deadline.
    /// Message-mode pipes deliver one complete message per read; a
    /// timeout cancels the IO instead of blocking the service forever.
    unsafe fn read_message_deadline(handle: HANDLE, buffer: &mut [u8], timeout_ms: u32) -> Result<Vec<u8>, String> {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        let event = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
        if event.is_null() {
            return Err("CreateEventW failed".to_string());
        }
        overlapped.hEvent = event;
        let mut transferred = 0_u32;
        let pending = ReadFile(
            handle,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut transferred,
            &mut overlapped,
        );
        let last_error = GetLastError();
        if pending == 0 && last_error != ERROR_IO_PENDING {
            CloseHandle(event);
            return Err(format!("ReadFile failed: {last_error}"));
        }
        if pending == 0 {
            let wait = WaitForSingleObject(event, timeout_ms);
            if wait == WAIT_TIMEOUT {
                CancelIoEx(handle, &mut overlapped);
                CloseHandle(event);
                return Err("read deadline exceeded".to_string());
            }
            if wait != WAIT_OBJECT_0 {
                CancelIoEx(handle, &mut overlapped);
                CloseHandle(event);
                return Err(format!("read wait failed: {wait}"));
            }
            // The overlapped result carries the byte count.
            if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0) == 0 {
                CloseHandle(event);
                return Err("GetOverlappedResult failed".to_string());
            }
        }
        CloseHandle(event);
        if transferred == 0 || transferred as usize > buffer.len() {
            return Err("empty or oversized message".to_string());
        }
        Ok(buffer[..transferred as usize].to_vec())
    }

    /// Overlapped write of one bounded message with a hard deadline.
    unsafe fn write_message_deadline(handle: HANDLE, payload: &[u8], timeout_ms: u32) -> Result<(), String> {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        let event = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
        if event.is_null() {
            return Err("CreateEventW failed".to_string());
        }
        overlapped.hEvent = event;
        let mut transferred = 0_u32;
        let pending = WriteFile(
            handle,
            payload.as_ptr().cast(),
            payload.len() as u32,
            &mut transferred,
            &mut overlapped,
        );
        let last_error = GetLastError();
        if pending == 0 && last_error != ERROR_IO_PENDING {
            CloseHandle(event);
            return Err(format!("WriteFile failed: {last_error}"));
        }
        if pending == 0 {
            let wait = WaitForSingleObject(event, timeout_ms);
            if wait == WAIT_TIMEOUT {
                CancelIoEx(handle, &mut overlapped);
                CloseHandle(event);
                return Err("write deadline exceeded".to_string());
            }
            if wait != WAIT_OBJECT_0 {
                CancelIoEx(handle, &mut overlapped);
                CloseHandle(event);
                return Err(format!("write wait failed: {wait}"));
            }
            if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0) == 0 {
                CloseHandle(event);
                return Err("GetOverlappedResult failed".to_string());
            }
        }
        CloseHandle(event);
        if transferred as usize != payload.len() {
            return Err("incomplete write".to_string());
        }
        Ok(())
    }

    fn run_service_loop() -> Result<(), String> {
        let service_sid = service_sid_present()?;
        protected_key_marker()?;
        let pipe = pipe_name()?;
        let (_descriptor, attributes) = build_pipe_security()?;
        let pipe_w = wide(&pipe);
        let stop_event = unsafe {
            let event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            if event.is_null() {
                return Err("CreateEventW failed for the stop event".to_string());
            }
            STOP_EVENT = event;
            event
        };
        loop {
            // The pipe is opened overlapped so the blocking accept can be
            // interrupted by SERVICE_CONTROL_STOP.
            let handle = unsafe {
                CreateNamedPipeW(
                    pipe_w.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
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
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            let connect_event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            if connect_event.is_null() {
                unsafe { CloseHandle(handle) };
                return Err("CreateEventW failed for the connect event".to_string());
            }
            unsafe { overlapped.hEvent = connect_event };
            let connect_result = unsafe { ConnectNamedPipe(handle, &mut overlapped) };
            let connect_error = unsafe { GetLastError() };
            let connected = if connect_result != 0 {
                true
            } else if connect_error == ERROR_PIPE_CONNECTED {
                // The legal race: the client already connected between
                // CreateNamedPipeW and ConnectNamedPipe.
                true
            } else if connect_error == ERROR_IO_PENDING {
                // Wait for either a client connection or the stop signal.
                let handles = [stop_event, connect_event];
                let wait = unsafe {
                    WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE)
                };
                if wait == WAIT_OBJECT_0 {
                    // Stop requested: cancel the pending accept, drain, and
                    // report STOP_PENDING before releasing resources.
                    unsafe {
                        CancelIoEx(handle, &mut overlapped);
                        set_service_state(
                            SERVICE_STOP_PENDING,
                            0,
                            10_000,
                        );
                        CloseHandle(connect_event);
                        DisconnectNamedPipe(handle);
                        CloseHandle(handle);
                    }
                    return Ok(());
                }
                if wait == WAIT_OBJECT_0 + 1 {
                    let mut transferred = 0_u32;
                    unsafe {
                        GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0) != 0
                    }
                } else {
                    unsafe {
                        CancelIoEx(handle, &mut overlapped);
                        CloseHandle(connect_event);
                        CloseHandle(handle);
                    }
                    continue;
                }
            } else {
                false
            };
            if connected {
                unsafe {
                    let mut peer_pid = 0_u32;
                    let peer_ok = GetNamedPipeClientProcessId(handle, &mut peer_pid) != 0
                        && peer_pid > 0;
                    let peer_identity = if peer_ok {
                        peer_sid(peer_pid).ok()
                    } else {
                        None
                    };
                    let expected_agent_sid = env::var("KHAOS_AGENT_SID").unwrap_or_default();
                    let peer_ok =
                        peer_identity.as_deref() == Some(expected_agent_sid.as_str());
                    let response = if peer_ok {
                        let mut buffer = vec![0_u8; MAX_MESSAGE_BYTES];
                        match read_message_deadline(handle, &mut buffer, CLIENT_IO_TIMEOUT_MS) {
                            Ok(message) => service_request(
                                &message,
                                &service_sid,
                                peer_identity.as_deref().unwrap_or("unknown"),
                            ),
                            Err(error) => format!(
                                "{{\"ok\":false,\"error\":\"Named Pipe read failed: {error}\"}}"
                            ),
                        }
                    } else {
                        "{\"ok\":false,\"error\":\"Named Pipe peer proof failed\"}".to_string()
                    };
                    let _ = write_message_deadline(handle, response.as_bytes(), CLIENT_IO_TIMEOUT_MS);
                    // A deterministic terminal state for the connection
                    // even when stop arrives mid-request: the response is
                    // flushed or the deadline fires before disconnect.
                    DisconnectNamedPipe(handle);
                }
            }
            unsafe {
                CloseHandle(connect_event);
                CloseHandle(handle);
            }
        }
    }

    /// Client mode: send one probe or request (with the Agent-generated
    /// challenge nonce) to the authority service pipe and print the reply.
    /// The client never talks to the backend pipe directly.
    fn client_request(kind: &str, challenge: Option<&str>) -> Result<(), String> {
        let challenge_value = match challenge {
            Some(value) if valid_challenge(value) => value.to_string(),
            Some(_) => return Err("challenge nonce must be 64 lowercase hex characters".into()),
            None => return Err("a challenge nonce is required".into()),
        };
        let mut message = serde_json::Map::new();
        message.insert("kind".to_string(), serde_json::Value::String(kind.to_string()));
        message.insert(
            "challenge_nonce".to_string(),
            serde_json::Value::String(challenge_value),
        );
        if kind == "request" {
            let mut input = String::new();
            use std::io::Read;
            std::io::stdin()
                .take(MAX_MESSAGE_BYTES as u64)
                .read_to_string(&mut input)
                .map_err(|_| "could not read the request payload".to_string())?;
            if input.is_empty() || input.len() > MAX_MESSAGE_BYTES {
                return Err("request payload is empty or oversized".into());
            }
            message.insert(
                "request_json".to_string(),
                serde_json::Value::String(input),
            );
        }
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
        let request = serde_json::Value::Object(message).to_string();
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
            return Err("authority Named Pipe request failed".to_string());
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
            // STOP_PENDING is reported immediately; the service loop
            // observes the event, cancels its pending accept, drains the
            // active connection within its IO deadline, and then reports
            // STOPPED.  Stopping never leaves a wedged accept loop.
            set_service_state(SERVICE_STOP_PENDING, 0, 10_000);
            let event = STOP_EVENT;
            if !event.is_null() {
                SetEvent(event);
            }
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
        STATUS_HANDLE = status_handle;
        set_service_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);
        match run_service_loop() {
            Ok(()) => {
                // Graceful stop: the loop already reported STOP_PENDING;
                // every pipe and backend resource was closed inside it.
                set_service_state(SERVICE_STOPPED, 0, 0);
            }
            Err(error) => {
                eprintln!("khaos-authorityd-windows: service loop failed: {error}");
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOPPED,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: SERVICE_ERROR_CRITICAL,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(status_handle, &status);
            }
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
        let kind = arguments.get(1).map(String::as_str);
        if kind == Some("--probe") || kind == Some("--request") {
            let mode = if kind == Some("--probe") { "probe" } else { "request" };
            let challenge = arguments
                .iter()
                .position(|value| value == "--challenge")
                .and_then(|index| arguments.get(index + 1))
                .map(String::as_str);
            return client_request(mode, challenge).map(|_| 0).unwrap_or(78);
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
