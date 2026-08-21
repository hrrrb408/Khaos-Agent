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
    use std::fmt::{Display, Formatter};
    use std::fs;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use sha2::Digest;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG, CRYPT_INTEGER_BLOB,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenGroups, TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
        FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_ERROR_CRITICAL, SERVICE_RUNNING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
        WaitForMultipleObjects, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    const MAX_MESSAGE_BYTES: usize = 64 * 1024;
    const SERVICE_NAME: &str = "KhaosAuthorityD";
    const ERROR_OPERATION_ABORTED: u32 = 995;
    const ERROR_IO_INCOMPLETE: u32 = 996;

    #[derive(Debug)]
    struct OverlappedIoError {
        message: String,
        terminal: bool,
    }

    impl OverlappedIoError {
        fn terminal(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
                terminal: true,
            }
        }

        fn active(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
                terminal: false,
            }
        }
    }

    impl Display for OverlappedIoError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn required(name: &str) -> Result<String, String> {
        env::var(name).map_err(|_| format!("{name} is missing"))
    }

    unsafe fn cancel_and_reap(
        handle: HANDLE,
        event: HANDLE,
        overlapped: &mut OVERLAPPED,
        operation: &str,
    ) -> Result<(), OverlappedIoError> {
        // CancelIoEx only requests cancellation.  Keep the OVERLAPPED
        // storage and event alive until the kernel reports terminal state.
        CancelIoEx(handle, overlapped);
        let wait = WaitForSingleObject(event, 5_000);
        if wait != WAIT_OBJECT_0 {
            return Err(OverlappedIoError::active(format!(
                "{operation} cancellation did not reach terminal completion"
            )));
        }
        let mut transferred = 0_u32;
        if GetOverlappedResult(handle, overlapped, &mut transferred, 0) != 0 {
            return Ok(());
        }
        let error = GetLastError();
        if error == ERROR_OPERATION_ABORTED {
            return Ok(());
        }
        Err(OverlappedIoError::active(format!(
            "{operation} cancellation completion failed: {error}"
        )))
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
        // Must stay byte-identical to the installer's Protect entropy in
        // packaging/windows/install-khaos-authorityd.ps1: DPAPI refuses to
        // decrypt when the optional entropy does not match, so a mismatch
        // here made every provisioned marker undecryptable.
        let entropy_bytes: &[u8] = b"khaos-authorityd-key-marker";
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: entropy_bytes.len() as u32,
            pbData: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(&input, null_mut(), &entropy, null(), null(), 0, &mut output)
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
        // Process-lifetime instance identity, mirroring the macOS XPC
        // frontend: generated once per process from the system CSPRNG and
        // stable until restart.  Recomputing it per request changed the id
        // between the adapter's probe and its first real request, tripping
        // the "service instance changed mid-session" verifier on every
        // session.  A CSPRNG failure is fatal (exit 78): never degrade to a
        // guessable time-derived id.
        static INSTANCE: OnceLock<String> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                let mut entropy = [0u8; 16];
                let status = unsafe {
                    BCryptGenRandom(
                        null_mut(),
                        entropy.as_mut_ptr(),
                        entropy.len() as u32,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    )
                };
                if status != 0 {
                    std::process::exit(78);
                }
                format!("{:x}", sha2::Sha256::digest(entropy))[..32].to_string()
            })
            .clone()
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
        value.len() == 64
            && value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }

    // Keep backend readiness below the Python probe's five-second native
    // client budget; a client deadline must never leave the service waiting
    // on a pipe that the caller has already abandoned.
    const BACKEND_CONNECT_TIMEOUT_MS: u32 = 4_000;

    fn frontend_error(code: &str, message: impl Into<String>) -> String {
        serde_json::json!({
            "ok": false,
            "error_code": code,
            "error": message.into(),
        })
        .to_string()
    }

    /// Open the backend pipe within one bounded startup/readiness window.
    ///
    /// The backend is hosted by a separate SCM service.  SCM reports that
    /// host as running immediately after its Python child is spawned, while
    /// the child still has to load the staged interpreter and create its
    /// Named Pipe.  A single CreateFileW therefore made a clean deployment
    /// fail as a startup race.  WaitNamedPipeW is only a readiness hint, so
    /// CreateFileW is retried until the same hard deadline expires.
    unsafe fn open_backend_pipe(backend: &[u16]) -> Result<HANDLE, String> {
        let deadline = Instant::now() + Duration::from_millis(BACKEND_CONNECT_TIMEOUT_MS as u64);
        let mut last_error;
        loop {
            let handle = CreateFileW(
                backend.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                null_mut(),
            );
            if handle != INVALID_HANDLE_VALUE {
                return Ok(handle);
            }
            last_error = GetLastError();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "authority backend pipe is unavailable: Win32 error {last_error}"
                ));
            }
            let wait_milliseconds = remaining.as_millis().min(250).max(1) as u32;
            if WaitNamedPipeW(backend.as_ptr(), wait_milliseconds) == 0 {
                // ERROR_FILE_NOT_FOUND means the backend has not created its
                // first instance yet.  Keep the bounded retry alive rather
                // than turning normal child startup into a false failure.
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }

    /// Handle one client message: parse kind/challenge/request, wrap the
    /// request into a backend `attest` envelope, forward it, and merge the
    /// backend response with the transport binding for the client.
    fn service_request(
        input: &[u8],
        service_sid: &str,
        peer_identity: &str,
    ) -> Result<String, OverlappedIoError> {
        let message: serde_json::Value = match serde_json::from_slice(input) {
            Ok(value) => value,
            Err(_) => {
                return Ok(frontend_error(
                    "native_request_malformed",
                    "native pipe message is malformed JSON",
                ))
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
            return Ok(frontend_error(
                "native_request_malformed",
                "native pipe challenge is missing or malformed",
            ));
        }
        let request_bytes: Vec<u8> = if kind == Some("probe") {
            PROBE_INNER_REQUEST.as_bytes().to_vec()
        } else {
            match message.get("request_json").and_then(|value| value.as_str()) {
                Some(request) => request.as_bytes().to_vec(),
                None => {
                    return Ok(frontend_error(
                        "native_request_malformed",
                        "native pipe request body is missing",
                    ))
                }
            }
        };
        if request_bytes.is_empty() || request_bytes.len() > MAX_MESSAGE_BYTES / 2 {
            return Ok(frontend_error(
                "native_request_out_of_bounds",
                "native pipe request is out of bounds",
            ));
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
                return Ok(frontend_error(
                    "authority_backend_unavailable",
                    "authority backend pipe is not configured",
                ))
            }
        };
        // Open the backend pipe overlapped so a wedged backend cannot
        // block the authority frontend forever: every operation carries
        // a hard deadline and is cancelled on expiry.
        let handle = match unsafe { open_backend_pipe(&backend) } {
            Ok(handle) => handle,
            Err(error) => {
                return Ok(frontend_error("authority_backend_unavailable", error));
            }
        };
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
            return Ok(frontend_error(
                "authority_backend_unavailable",
                "authority backend pipe identity is not the authority Service SID",
            ));
        }
        let payload = serde_json::to_vec(&attest_request).unwrap_or_default();
        if payload.len() > MAX_MESSAGE_BYTES {
            unsafe { CloseHandle(handle) };
            return Ok(frontend_error(
                "authority_backend_unavailable",
                "authority backend request is out of bounds",
            ));
        }
        let backend_bytes = unsafe {
            write_message_deadline(handle, &payload, BACKEND_IO_TIMEOUT_MS).and_then(|()| {
                let mut response = vec![0_u8; MAX_MESSAGE_BYTES];
                read_message_deadline(handle, &mut response, BACKEND_IO_TIMEOUT_MS)
            })
        };
        let backend_bytes = match backend_bytes {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE_BYTES => {
                unsafe { CloseHandle(handle) };
                bytes
            }
            Ok(_) => {
                unsafe { CloseHandle(handle) };
                return Ok(frontend_error(
                    "authority_backend_unavailable",
                    "authority backend returned no bounded response",
                ));
            }
            Err(error) => {
                if error.terminal {
                    unsafe { CloseHandle(handle) };
                    return Ok(frontend_error(
                        "authority_backend_unavailable",
                        format!("authority backend IO deadline: {error}"),
                    ));
                }
                return Err(error);
            }
        };
        let backend_body: serde_json::Value = match serde_json::from_slice(&backend_bytes) {
            Ok(value) => value,
            Err(_) => {
                return Ok(frontend_error(
                    "authority_backend_malformed",
                    "authority backend returned malformed JSON",
                ))
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
                if key != "native_transport" && key != "proof_digest" {
                    wrapper.insert(key, value);
                }
            }
        } else {
            return Ok(frontend_error(
                "authority_backend_malformed",
                "authority backend returned a non-object response",
            ));
        }
        Ok(serde_json::Value::Object(wrapper).to_string())
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
    unsafe fn read_message_deadline(
        handle: HANDLE,
        buffer: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Vec<u8>, OverlappedIoError> {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        let event = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
        if event.is_null() {
            return Err(OverlappedIoError::terminal("CreateEventW failed"));
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
            return Err(OverlappedIoError::terminal(format!(
                "ReadFile failed: {last_error}"
            )));
        }
        if pending == 0 {
            let wait = WaitForSingleObject(event, timeout_ms);
            if wait == WAIT_TIMEOUT {
                return match cancel_and_reap(handle, event, &mut overlapped, "read") {
                    Ok(()) => {
                        CloseHandle(event);
                        Err(OverlappedIoError::terminal("read deadline exceeded"))
                    }
                    Err(error) => Err(error),
                };
            }
            if wait != WAIT_OBJECT_0 {
                return match cancel_and_reap(handle, event, &mut overlapped, "read") {
                    Ok(()) => {
                        CloseHandle(event);
                        Err(OverlappedIoError::terminal(format!(
                            "read wait failed: {wait}"
                        )))
                    }
                    Err(error) => Err(error),
                };
            }
            // The overlapped result carries the byte count.
            if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0) == 0 {
                let error = GetLastError();
                if error == ERROR_IO_INCOMPLETE {
                    return Err(OverlappedIoError::active("read completion is not terminal"));
                }
                CloseHandle(event);
                return Err(OverlappedIoError::terminal(format!(
                    "GetOverlappedResult failed: {error}"
                )));
            }
        }
        CloseHandle(event);
        if transferred == 0 || transferred as usize > buffer.len() {
            return Err(OverlappedIoError::terminal("empty or oversized message"));
        }
        Ok(buffer[..transferred as usize].to_vec())
    }

    /// Overlapped write of one bounded message with a hard deadline.
    unsafe fn write_message_deadline(
        handle: HANDLE,
        payload: &[u8],
        timeout_ms: u32,
    ) -> Result<(), OverlappedIoError> {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        let event = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
        if event.is_null() {
            return Err(OverlappedIoError::terminal("CreateEventW failed"));
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
            return Err(OverlappedIoError::terminal(format!(
                "WriteFile failed: {last_error}"
            )));
        }
        if pending == 0 {
            let wait = WaitForSingleObject(event, timeout_ms);
            if wait == WAIT_TIMEOUT {
                return match cancel_and_reap(handle, event, &mut overlapped, "write") {
                    Ok(()) => {
                        CloseHandle(event);
                        Err(OverlappedIoError::terminal("write deadline exceeded"))
                    }
                    Err(error) => Err(error),
                };
            }
            if wait != WAIT_OBJECT_0 {
                return match cancel_and_reap(handle, event, &mut overlapped, "write") {
                    Ok(()) => {
                        CloseHandle(event);
                        Err(OverlappedIoError::terminal(format!(
                            "write wait failed: {wait}"
                        )))
                    }
                    Err(error) => Err(error),
                };
            }
            if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0) == 0 {
                let error = GetLastError();
                if error == ERROR_IO_INCOMPLETE {
                    return Err(OverlappedIoError::active(
                        "write completion is not terminal",
                    ));
                }
                CloseHandle(event);
                return Err(OverlappedIoError::terminal(format!(
                    "GetOverlappedResult failed: {error}"
                )));
            }
        }
        CloseHandle(event);
        if transferred as usize != payload.len() {
            return Err(OverlappedIoError::terminal("incomplete write"));
        }
        Ok(())
    }

    unsafe fn finish_client_connection(
        handle: HANDLE,
        connect_event: HANDLE,
        response: &str,
    ) -> Result<(), String> {
        match write_message_deadline(handle, response.as_bytes(), CLIENT_IO_TIMEOUT_MS) {
            Ok(()) => {
                // A deterministic terminal state for the connection even
                // when stop arrives mid-request: the response is flushed
                // before disconnecting and releasing the pipe handle.
                DisconnectNamedPipe(handle);
                CloseHandle(connect_event);
                CloseHandle(handle);
                Ok(())
            }
            Err(error) if error.terminal => {
                DisconnectNamedPipe(handle);
                CloseHandle(connect_event);
                CloseHandle(handle);
                Err(error.to_string())
            }
            Err(error) => {
                // The connect event is already terminal, but the pipe write
                // is not.  Do not close the pipe handle while the kernel can
                // still complete the write; the process supervisor owns the
                // remaining cleanup path.
                CloseHandle(connect_event);
                Err(error.to_string())
            }
        }
    }

    fn run_service_loop() -> Result<(), String> {
        let service_sid = service_sid_present()?;
        protected_key_marker()?;
        let pipe = pipe_name()?;
        let (_descriptor, attributes) = build_pipe_security()?;
        let pipe_w = wide(&pipe);
        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            unsafe { LocalFree(attributes.lpSecurityDescriptor.cast()) };
            return Err("CreateEventW failed for the stop event".to_string());
        }
        unsafe { STOP_EVENT = stop_event };
        let result = (|| -> Result<(), String> {
            loop {
                // The pipe is opened overlapped so the blocking accept can
                // be interrupted by SERVICE_CONTROL_STOP.
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
                let connect_event =
                    unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
                if connect_event.is_null() {
                    unsafe { CloseHandle(handle) };
                    return Err("CreateEventW failed for the connect event".to_string());
                }
                overlapped.hEvent = connect_event;
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
                    let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if wait == WAIT_OBJECT_0 {
                        // Stop requested: cancel the pending accept, drain,
                        // and report STOP_PENDING before releasing resources.
                        unsafe {
                            cancel_and_reap(handle, connect_event, &mut overlapped, "connect")
                                .map_err(|error| error.to_string())?;
                            set_service_state(SERVICE_STOP_PENDING, 0, 10_000);
                            CloseHandle(connect_event);
                            DisconnectNamedPipe(handle);
                            CloseHandle(handle);
                        }
                        return Ok(());
                    }
                    if wait == WAIT_OBJECT_0 + 1 {
                        let mut transferred = 0_u32;
                        unsafe {
                            if GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0)
                                == 0
                            {
                                let error = GetLastError();
                                if error == ERROR_IO_INCOMPLETE {
                                    return Err(
                                        "connect completion proof is not terminal".to_string()
                                    );
                                }
                                CloseHandle(connect_event);
                                CloseHandle(handle);
                                return Err(format!("connect completion proof failed: {error}"));
                            }
                            true
                        }
                    } else {
                        unsafe {
                            cancel_and_reap(handle, connect_event, &mut overlapped, "connect")
                                .map_err(|error| error.to_string())?;
                            CloseHandle(connect_event);
                            CloseHandle(handle);
                        }
                        continue;
                    }
                } else {
                    false
                };
                if !connected {
                    unsafe {
                        CloseHandle(connect_event);
                        CloseHandle(handle);
                    }
                    continue;
                }

                unsafe {
                    let mut peer_pid = 0_u32;
                    let peer_process_ok =
                        GetNamedPipeClientProcessId(handle, &mut peer_pid) != 0 && peer_pid > 0;
                    let peer_identity = if peer_process_ok {
                        peer_sid(peer_pid).ok()
                    } else {
                        None
                    };
                    let expected_agent_sid = env::var("KHAOS_AGENT_SID").unwrap_or_default();
                    let peer_ok = peer_identity.as_deref() == Some(expected_agent_sid.as_str());
                    if peer_ok {
                        let mut buffer = vec![0_u8; MAX_MESSAGE_BYTES];
                        let message = match read_message_deadline(
                            handle,
                            &mut buffer,
                            CLIENT_IO_TIMEOUT_MS,
                        ) {
                            Ok(message) => message,
                            Err(error) if error.terminal => {
                                DisconnectNamedPipe(handle);
                                CloseHandle(connect_event);
                                CloseHandle(handle);
                                continue;
                            }
                            Err(error) => {
                                // The pending read is still live; preserve
                                // the handle and let the process supervisor
                                // terminate the service domain.
                                CloseHandle(connect_event);
                                return Err(error.to_string());
                            }
                        };
                        let response = match service_request(
                            &message,
                            &service_sid,
                            peer_identity.as_deref().unwrap_or("unknown"),
                        ) {
                            Ok(response) => response,
                            Err(error) => {
                                // The frontend read has completed, so its
                                // handle is safe to close.  The backend handle
                                // is intentionally retained by service_request
                                // when its overlapped completion is unproven.
                                DisconnectNamedPipe(handle);
                                CloseHandle(connect_event);
                                CloseHandle(handle);
                                return Err(error.to_string());
                            }
                        };
                        finish_client_connection(handle, connect_event, &response)?;
                    } else {
                        let response = frontend_error(
                            "native_peer_identity_mismatch",
                            "Named Pipe peer proof failed",
                        );
                        finish_client_connection(handle, connect_event, &response)?;
                    }
                }
            }
        })();
        unsafe {
            STOP_EVENT = null_mut();
            CloseHandle(stop_event);
            LocalFree(attributes.lpSecurityDescriptor.cast());
        }
        result
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
        message.insert(
            "kind".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
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
            message.insert("request_json".to_string(), serde_json::Value::String(input));
        }
        let pipe = wide(&pipe_name()?);
        let handle = unsafe {
            CreateFileW(
                pipe.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err("authority Named Pipe is unavailable".to_string());
        }
        let request = serde_json::Value::Object(message).to_string();
        let response = unsafe {
            write_message_deadline(handle, request.as_bytes(), CLIENT_IO_TIMEOUT_MS).and_then(
                |_| {
                    let mut response = vec![0_u8; MAX_MESSAGE_BYTES];
                    read_message_deadline(handle, &mut response, CLIENT_IO_TIMEOUT_MS)
                },
            )
        };
        match response {
            Ok(response) => {
                unsafe { CloseHandle(handle) };
                println!("{}", String::from_utf8_lossy(&response));
                Ok(())
            }
            Err(error) if error.terminal => {
                unsafe { CloseHandle(handle) };
                Err(error.to_string())
            }
            Err(error) => Err(error.to_string()),
        }
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
            let mode = if kind == Some("--probe") {
                "probe"
            } else {
                "request"
            };
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
