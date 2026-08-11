//! Windows execution TCB for Khaos.
//!
//! The Python layer never creates the child directly on Windows.  This
//! launcher creates a restricted primary token, places the child in a
//! kill-on-close Job Object, and keeps the job alive until the child exits.
//! The surrounding Python backend only reports the backend as available after
//! this binary proves its native primitives and its WFP-backed firewall
//! transaction can be created and removed.

#![cfg_attr(not(windows), allow(dead_code))]

// KHAOS-PRIVILEGED-SPAWN owner=WindowsSandboxTCB threat-model=restricted-token-job-acl-wfp boundary=windows-sandbox

#[cfg(windows)]
mod windows_backend {
    use std::env;
    use std::ffi::{c_void, OsStr, OsString};
    use std::io::{ErrorKind, Read};
    use std::iter::once;
    use std::mem::{size_of, zeroed};
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::{self, TryRecvError};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, HANDLE,
        HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, CopySid, CreateRestrictedToken, CreateWellKnownSid, GetLengthSid,
        GetTokenInformation, IsTokenRestricted, LookupPrivilegeValueW, SetTokenInformation,
        TokenDefaultDacl, TokenGroups, WinRestrictedCodeSid, WinWorldSid, DISABLE_MAX_PRIVILEGE,
        LUA_TOKEN, LUID_AND_ATTRIBUTES, PSID, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED,
        SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY, WRITE_RESTRICTED,
    };
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_TIME,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        ResumeThread, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    const FIREWALL_PREFIX: &str = "KhaosWindowsSandbox";
    // Windows Firewall application rules are image-scoped. A descendant can
    // otherwise switch to another executable and bypass the parent's rule.
    // Until a job-wide WFP/AppContainer policy is available, the only
    // deterministic fail-closed containment is one process per sandbox.
    // Commands that need to spawn children therefore fail inside the native
    // boundary instead of silently escaping the network policy.
    const MAX_ACTIVE_PROCESSES: u32 = 1;

    pub enum ExecutionOutcome {
        Completed,
        TimedOut,
        Cancelled,
    }

    struct Handle(HANDLE);

    #[repr(C)]
    struct TokenDefaultDaclInfo {
        default_dacl: *mut windows_sys::Win32::Security::ACL,
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != null_mut() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub fn run() -> Result<ExecutionOutcome, String> {
        let args: Vec<OsString> = env::args_os().skip(1).collect();
        if args.first().is_some_and(|arg| arg == "--probe") {
            probe()?;
            return Ok(ExecutionOutcome::Completed);
        }
        if args.first().is_some_and(|arg| arg == "--probe-child") {
            probe_child(&args[1..])?;
            return Ok(ExecutionOutcome::Completed);
        }
        let options = Options::parse(&args)?;
        validate_paths(&options)?;
        let executable = resolve_executable(
            options
                .command
                .first()
                .ok_or_else(|| "missing Windows sandbox command".to_string())?,
        )?;
        let workspace = std::fs::canonicalize(&options.workspace)
            .map_err(|e| format!("workspace unavailable: {e}"))?;
        let acl = WorkspaceAcl::apply(&workspace)?;
        let runtime_acl = match RuntimeAcl::apply(&executable) {
            Ok(acl) => acl,
            Err(error) => {
                let restore = acl.restore();
                return Err(match restore {
                    Ok(()) => error,
                    Err(restore_error) => format!("{error}; {restore_error}"),
                });
            }
        };
        let rule = match FirewallRule::install(&options, &executable) {
            Ok(rule) => rule,
            Err(error) => {
                let runtime_restore = runtime_acl.restore();
                let workspace_restore = acl.restore();
                return Err(join_cleanup_errors(
                    error,
                    runtime_restore,
                    workspace_restore,
                ));
            }
        };
        let result = spawn_restricted(&options, &executable);
        let remove_result = rule.remove();
        let runtime_acl_result = runtime_acl.restore();
        let acl_result = acl.restore();
        let mut errors = Vec::new();
        let outcome = match result {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                errors.push(error);
                None
            }
        };
        if let Err(error) = remove_result {
            errors.push(error);
        }
        if let Err(error) = runtime_acl_result {
            errors.push(error);
        }
        if let Err(error) = acl_result {
            errors.push(error);
        }
        if errors.is_empty() {
            match outcome {
                Some(outcome) => Ok(outcome),
                None => Err("Windows sandbox execution outcome is missing".to_string()),
            }
        } else {
            Err(errors.join("; "))
        }
    }

    fn join_cleanup_errors(
        primary: String,
        runtime_restore: Result<(), String>,
        workspace_restore: Result<(), String>,
    ) -> String {
        let mut errors = vec![primary];
        if let Err(error) = runtime_restore {
            errors.push(error);
        }
        if let Err(error) = workspace_restore {
            errors.push(error);
        }
        errors.join("; ")
    }

    fn probe() -> Result<(), String> {
        let token = restricted_token()?;
        if unsafe { IsTokenRestricted(token.0) } == 0 {
            return Err("CreateRestrictedToken did not create a restricted token".to_string());
        }
        drop(token);

        let helper = env::current_exe().map_err(|e| format!("resolve Windows helper: {e}"))?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("create Windows firewall probe listener: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("configure Windows firewall probe listener: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read Windows firewall probe port: {e}"))?
            .port();
        let probe_root = env::temp_dir().join(unique_rule_name("sandbox-probe"));
        let outside = env::temp_dir().join(unique_rule_name("sandbox-outside"));
        std::fs::create_dir(&probe_root)
            .map_err(|e| format!("create sandbox probe directory: {e}"))?;
        let result_path = probe_root.join("probe-result.txt");
        let command = vec![
            helper.as_os_str().to_os_string(),
            OsString::from("--probe-child"),
            OsString::from("--workspace"),
            probe_root.as_os_str().to_os_string(),
            OsString::from("--outside"),
            outside.as_os_str().to_os_string(),
            OsString::from("--port"),
            OsString::from(port.to_string()),
        ];
        let options = Options {
            workspace: probe_root.clone(),
            cwd: probe_root.clone(),
            network: "none".to_string(),
            proxy_port: None,
            memory_bytes: 128 * 1024 * 1024,
            cpu_seconds: 120,
            timeout_seconds: 10,
            command,
        };
        let acl = match WorkspaceAcl::apply(&probe_root) {
            Ok(acl) => acl,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(error);
            }
        };
        let runtime_acl = match RuntimeAcl::apply(&helper) {
            Ok(acl) => acl,
            Err(error) => {
                let _ = acl.restore();
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(error);
            }
        };
        let rule = match FirewallRule::install(&options, &helper) {
            Ok(rule) => rule,
            Err(error) => {
                let _ = runtime_acl.restore();
                let _ = acl.restore();
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(error);
            }
        };
        let result = spawn_restricted(&options, &helper);
        let network_connected = listener_observed_connection(&listener);
        let remove_result = rule.remove();
        let runtime_acl_result = runtime_acl.restore();
        let acl_result = acl.restore();
        let child_report = match result {
            Ok(ExecutionOutcome::Completed) => std::fs::read_to_string(&result_path)
                .map_err(|e| format!("read Windows sandbox capability probe: {e}")),
            Ok(_) => Err("Windows sandbox capability probe child did not complete".to_string()),
            Err(error) => Err(error),
        };
        let mut errors = Vec::new();
        if network_connected {
            errors.push("Windows firewall probe observed a direct network path".to_string());
        }
        match child_report {
            Ok(report) => {
                if !report.contains("network_blocked=true") {
                    errors.push(
                        "Windows firewall probe did not block the child network path".to_string(),
                    );
                }
                if !report.contains("descendant_blocked=true") {
                    errors.push("Windows Job Object allowed an untracked descendant".to_string());
                }
                if !report.contains("outside_denied=true")
                    || !report.contains("inside_written=true")
                {
                    errors.push(
                        "Windows restricted-token ACL probe did not enforce workspace scope"
                            .to_string(),
                    );
                }
            }
            Err(error) => errors.push(error),
        }
        if let Err(error) = remove_result {
            errors.push(error);
        }
        if let Err(error) = runtime_acl_result {
            errors.push(error);
        }
        if let Err(error) = acl_result {
            errors.push(error);
        }
        if let Err(error) = remove_probe_path(&outside) {
            errors.push(error);
        }
        if let Err(error) = std::fs::remove_dir_all(&probe_root) {
            errors.push(format!("remove Windows sandbox capability probe: {error}"));
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        println!(
            "{{\"restricted_token\":true,\"job_object\":true,\"process_tree\":true,\"acl\":true,\"wfp\":true}}"
        );
        Ok(())
    }

    fn listener_observed_connection(listener: &TcpListener) -> bool {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok((_stream, _address)) => return true,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return false,
            }
        }
    }

    fn remove_probe_path(path: &Path) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove Windows sandbox probe path: {error}")),
        }
    }

    fn probe_child(args: &[OsString]) -> Result<(), String> {
        let mut workspace = None;
        let mut outside = None;
        let mut port = None;
        let mut index = 0;
        while index < args.len() {
            let value = args[index].to_string_lossy();
            let next = |index: &mut usize| -> Result<OsString, String> {
                *index += 1;
                args.get(*index)
                    .cloned()
                    .ok_or_else(|| "Windows probe child option is missing a value".to_string())
            };
            match value.as_ref() {
                "--workspace" => workspace = Some(PathBuf::from(next(&mut index)?)),
                "--outside" => outside = Some(PathBuf::from(next(&mut index)?)),
                "--port" => {
                    port = Some(
                        next(&mut index)?
                            .to_string_lossy()
                            .parse::<u16>()
                            .map_err(|_| "invalid Windows probe port".to_string())?,
                    )
                }
                _ => return Err(format!("unknown Windows probe child option: {value}")),
            }
            index += 1;
        }
        let workspace =
            workspace.ok_or_else(|| "Windows probe workspace is missing".to_string())?;
        let outside = outside.ok_or_else(|| "Windows probe outside path is missing".to_string())?;
        let port = port.ok_or_else(|| "Windows probe port is missing".to_string())?;
        let address: std::net::SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|e| format!("invalid probe address: {e}"))?;
        let network_blocked =
            TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_err();
        let cmd = env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("System32").join("cmd.exe"))
            .ok_or_else(|| "SystemRoot is missing for Windows process probe".to_string())?;
        let descendant_blocked = Command::new(cmd)
            .args(["/c", "exit", "0"])
            .status()
            .is_err();
        let inside_written = std::fs::write(workspace.join("inside-probe.txt"), b"ok").is_ok();
        let outside_denied = std::fs::write(outside, b"must-not-write").is_err();
        let report = format!(
            "network_blocked={network_blocked}\ndescendant_blocked={descendant_blocked}\ninside_written={inside_written}\noutside_denied={outside_denied}\n"
        );
        std::fs::write(workspace.join("probe-result.txt"), report)
            .map_err(|e| format!("write Windows sandbox capability probe: {e}"))?;
        Ok(())
    }

    struct Options {
        workspace: PathBuf,
        cwd: PathBuf,
        network: String,
        proxy_port: Option<u16>,
        memory_bytes: u64,
        cpu_seconds: u64,
        timeout_seconds: u64,
        command: Vec<OsString>,
    }

    impl Options {
        fn parse(args: &[OsString]) -> Result<Self, String> {
            let mut workspace = None;
            let mut cwd = None;
            let mut network = "none".to_string();
            let mut proxy_host = None;
            let mut proxy_port = None;
            let mut memory_bytes = 512 * 1024 * 1024;
            let mut cpu_seconds = 120;
            let mut timeout_seconds = 120;
            let mut index = 0;
            while index < args.len() {
                let value = args[index].to_string_lossy();
                if value == "--" {
                    index += 1;
                    break;
                }
                let next = |index: &mut usize| -> Result<OsString, String> {
                    *index += 1;
                    args.get(*index)
                        .cloned()
                        .ok_or_else(|| "Windows sandbox option is missing a value".to_string())
                };
                match value.as_ref() {
                    "--workspace" => workspace = Some(PathBuf::from(next(&mut index)?)),
                    "--cwd" => cwd = Some(PathBuf::from(next(&mut index)?)),
                    "--network" => network = next(&mut index)?.to_string_lossy().to_string(),
                    "--proxy-host" => {
                        proxy_host = Some(next(&mut index)?.to_string_lossy().to_string())
                    }
                    "--proxy-port" => {
                        proxy_port = Some(
                            next(&mut index)?
                                .to_string_lossy()
                                .parse()
                                .map_err(|_| "invalid proxy port".to_string())?,
                        )
                    }
                    "--memory-bytes" => {
                        memory_bytes = next(&mut index)?
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| "invalid memory limit".to_string())?
                    }
                    "--cpu-seconds" => {
                        cpu_seconds = next(&mut index)?
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| "invalid CPU limit".to_string())?
                    }
                    "--timeout-seconds" => {
                        timeout_seconds = next(&mut index)?
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| "invalid timeout".to_string())?
                    }
                    _ => return Err(format!("unknown Windows sandbox option: {value}")),
                }
                index += 1;
            }
            let command = args[index..].to_vec();
            if command.is_empty() {
                return Err("Windows sandbox command is empty".to_string());
            }
            let workspace =
                workspace.ok_or_else(|| "Windows sandbox workspace is missing".to_string())?;
            let cwd = cwd.ok_or_else(|| "Windows sandbox cwd is missing".to_string())?;
            if network != "none" && network != "brokered" {
                return Err("Windows sandbox network policy is unsupported".to_string());
            }
            if network == "brokered" && (proxy_host.is_none() || proxy_port.is_none()) {
                return Err("brokered Windows execution requires a proxy endpoint".to_string());
            }
            if network == "brokered" && proxy_host.as_deref() != Some("127.0.0.1") {
                return Err(
                    "Windows brokered execution only permits the IPv4 loopback proxy".to_string(),
                );
            }
            if timeout_seconds == 0 {
                return Err("Windows sandbox timeout must be positive".to_string());
            }
            Ok(Self {
                workspace,
                cwd,
                network,
                proxy_port,
                memory_bytes,
                cpu_seconds,
                timeout_seconds,
                command,
            })
        }
    }

    fn validate_paths(options: &Options) -> Result<(), String> {
        let workspace = std::fs::canonicalize(&options.workspace)
            .map_err(|e| format!("workspace unavailable: {e}"))?;
        let cwd =
            std::fs::canonicalize(&options.cwd).map_err(|e| format!("cwd unavailable: {e}"))?;
        if cwd != workspace && !cwd.starts_with(&workspace) {
            return Err("cwd is outside the Windows sandbox workspace".to_string());
        }
        if !workspace.is_dir() || !cwd.is_dir() {
            return Err("Windows sandbox workspace/cwd must be directories".to_string());
        }
        Ok(())
    }

    fn restricted_token() -> Result<Handle, String> {
        let restricted_sid = restricted_code_sid()?;
        let mut current: HANDLE = null_mut();
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE
                    | TOKEN_QUERY
                    | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_ADJUST_SESSIONID
                    | TOKEN_ADJUST_PRIVILEGES,
                &mut current as *mut HANDLE,
            )
        };
        if opened == 0 {
            return Err(last_error("OpenProcessToken"));
        }
        let current = Handle(current);
        let logon_sid = token_logon_sid(current.0)?;
        let everyone_sid = world_sid()?;
        let restricted_sid_attributes = [
            SID_AND_ATTRIBUTES {
                Sid: restricted_sid.as_ptr() as PSID,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: logon_sid.as_ptr() as PSID,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: everyone_sid.as_ptr() as PSID,
                Attributes: 0,
            },
        ];
        let mut restricted: HANDLE = null_mut();
        let created = unsafe {
            CreateRestrictedToken(
                current.0,
                DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
                0,
                null(),
                0,
                null(),
                restricted_sid_attributes.len() as u32,
                restricted_sid_attributes.as_ptr(),
                &mut restricted as *mut HANDLE,
            )
        };
        if created == 0 {
            return Err(last_error("CreateRestrictedToken"));
        }
        if let Err(error) = set_default_dacl(
            restricted,
            &[
                logon_sid.as_ptr() as PSID,
                everyone_sid.as_ptr() as PSID,
                restricted_sid.as_ptr() as PSID,
            ],
        ) {
            unsafe { CloseHandle(restricted) };
            return Err(error);
        }
        if let Err(error) = enable_change_notify_privilege(restricted) {
            unsafe { CloseHandle(restricted) };
            return Err(error);
        }
        Ok(Handle(restricted))
    }

    /// Preserve the interactive logon identity as a restricted SID so the
    /// normal Windows runtime can read user-scoped IPC and loader objects.
    fn token_logon_sid(token: HANDLE) -> Result<Vec<u8>, String> {
        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenGroups, null_mut(), 0, &mut required as *mut u32);
        }
        if required == 0 {
            return Err(last_error("GetTokenInformation(TokenGroups size)"));
        }
        let mut buffer = vec![0_u8; required as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenGroups,
                buffer.as_mut_ptr() as *mut c_void,
                required,
                &mut required as *mut u32,
            )
        } == 0
        {
            return Err(last_error("GetTokenInformation(TokenGroups)"));
        }
        if buffer.len() < size_of::<u32>() {
            return Err("TokenGroups response is truncated".to_string());
        }
        let group_count = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const u32) };
        let after_count = buffer.as_ptr() as usize + size_of::<u32>();
        let alignment = std::mem::align_of::<SID_AND_ATTRIBUTES>();
        let groups_address = (after_count + alignment - 1) & !(alignment - 1);
        let groups_offset = groups_address - buffer.as_ptr() as usize;
        let group_size = size_of::<SID_AND_ATTRIBUTES>();
        let group_bytes = (group_count as usize)
            .checked_mul(group_size)
            .ok_or_else(|| "TokenGroups count overflow".to_string())?;
        if groups_offset > buffer.len() || group_bytes > buffer.len() - groups_offset {
            return Err("TokenGroups response has invalid group bounds".to_string());
        }
        let groups = groups_address as *const SID_AND_ATTRIBUTES;
        for index in 0..group_count as usize {
            let entry = unsafe { std::ptr::read_unaligned(groups.add(index)) };
            if entry.Attributes & SE_GROUP_LOGON_ID as u32 == 0 {
                continue;
            }
            if entry.Sid.is_null() {
                return Err("TokenGroups contains a null logon SID".to_string());
            }
            let length = unsafe { GetLengthSid(entry.Sid) };
            if length == 0 {
                return Err(last_error("GetLengthSid(logon SID)"));
            }
            let mut sid = vec![0_u8; length as usize];
            if unsafe { CopySid(length, sid.as_mut_ptr() as PSID, entry.Sid) } == 0 {
                return Err(last_error("CopySid(logon SID)"));
            }
            return Ok(sid);
        }
        Err("interactive logon SID is absent from the current token".to_string())
    }

    /// Give child-created pipes and runtime IPC a narrow, explicit default
    /// DACL.  This does not grant filesystem access; the workspace/runtime
    /// ACL transactions remain the filesystem authority.
    fn set_default_dacl(token: HANDLE, sids: &[PSID]) -> Result<(), String> {
        if sids.is_empty() {
            return Ok(());
        }
        const GENERIC_ALL: u32 = 0x1000_0000;
        let entries: Vec<EXPLICIT_ACCESS_W> = sids
            .iter()
            .map(|sid| EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: 0,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: *sid as *mut u16,
                },
            })
            .collect();
        let mut new_acl: *mut windows_sys::Win32::Security::ACL = null_mut();
        let result = unsafe {
            SetEntriesInAclW(
                entries.len() as u32,
                entries.as_ptr(),
                null(),
                &mut new_acl as *mut *mut windows_sys::Win32::Security::ACL,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(format!("SetEntriesInAclW failed with Win32 error {result}"));
        }
        let mut info = TokenDefaultDaclInfo {
            default_dacl: new_acl,
        };
        let updated = unsafe {
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                &mut info as *mut TokenDefaultDaclInfo as *mut c_void,
                size_of::<TokenDefaultDaclInfo>() as u32,
            )
        };
        let free_result = if new_acl.is_null() {
            None
        } else {
            Some(unsafe { LocalFree(new_acl as HLOCAL) })
        };
        if updated == 0 {
            let mut error = last_error("SetTokenInformation(TokenDefaultDacl)");
            if let Some(free_result) = free_result {
                if !free_result.is_null() {
                    error.push_str("; LocalFree(default DACL) failed");
                }
            }
            return Err(error);
        }
        if free_result.is_some_and(|result| !result.is_null()) {
            return Err("LocalFree(default DACL) failed".to_string());
        }
        Ok(())
    }

    /// Re-enable only directory traversal after creating the restricted token.
    /// WRITE_RESTRICTED keeps the restricted-code SID in the write-access
    /// check while ordinary runtime reads use the normal user SIDs.  This is
    /// the Windows restricted-token shape needed to load public system and
    /// interpreter DLLs without granting the restricted SID broad read access.
    fn enable_change_notify_privilege(token: HANDLE) -> Result<(), String> {
        let mut luid: windows_sys::Win32::Foundation::LUID = unsafe { zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut luid) } == 0 {
            return Err(last_error("LookupPrivilegeValueW(SeChangeNotifyPrivilege)"));
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        if unsafe {
            AdjustTokenPrivileges(
                token,
                0,
                &privileges,
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                null_mut(),
                null_mut(),
            )
        } == 0
        {
            return Err(last_error("AdjustTokenPrivileges(SeChangeNotifyPrivilege)"));
        }
        if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err("SeChangeNotifyPrivilege is unavailable on restricted token".to_string());
        }
        Ok(())
    }

    fn restricted_code_sid() -> Result<Vec<u8>, String> {
        well_known_sid(WinRestrictedCodeSid, "restricted-code SID")
    }

    fn world_sid() -> Result<Vec<u8>, String> {
        well_known_sid(WinWorldSid, "Everyone SID")
    }

    fn well_known_sid(
        sid_type: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        let mut sid = vec![0u8; 68];
        let mut size = sid.len() as u32;
        let created = unsafe {
            CreateWellKnownSid(sid_type, null_mut(), sid.as_mut_ptr() as PSID, &mut size)
        };
        if created == 0 {
            return Err(format!(
                "CreateWellKnownSid({label}): {}",
                last_error("Win32")
            ));
        }
        sid.truncate(size as usize);
        Ok(sid)
    }

    fn configure_job(job: HANDLE, memory_bytes: u64, cpu_seconds: u64) -> Result<(), String> {
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        // A coding execution is intentionally limited to one native process
        // on Windows. Job Objects do not provide an egress policy for unknown
        // descendants; keeping this bound at one is the deterministic
        // containment primitive that closes that WFP discovery race. Commands
        // that need a launcher/child must use a future job-wide network
        // authority instead of silently bypassing the current policy.
        limits.BasicLimitInformation.ActiveProcessLimit = MAX_ACTIVE_PROCESSES;
        limits.ProcessMemoryLimit = memory_bytes as usize;
        limits.BasicLimitInformation.PerJobUserTimeLimit = (cpu_seconds as i64) * 10_000_000;
        let updated = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if updated == 0 {
            return Err(last_error("SetInformationJobObject"));
        }
        Ok(())
    }

    fn spawn_restricted(options: &Options, executable: &Path) -> Result<ExecutionOutcome, String> {
        let token = restricted_token()?;
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job == null_mut() {
            return Err(last_error("CreateJobObjectW"));
        }
        let job = Handle(job);
        configure_job(job.0, options.memory_bytes, options.cpu_seconds)?;
        let mut command = quote_command_line(&options.command);
        let mut application = wide_null(executable.as_os_str());
        let mut current_directory = wide_null(options.cwd.as_os_str());
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESTDHANDLES;
        // Keep the helper's cancellation pipe private.  Passing the same
        // stdin handle to the restricted child would let the command consume
        // the cancellation byte before the helper sees it.
        startup.hStdInput = null_mut();
        startup.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        startup.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        let created = unsafe {
            CreateProcessAsUserW(
                token.0,
                application.as_mut_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                1,
                CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                null_mut(),
                current_directory.as_mut_ptr(),
                &startup,
                &mut information,
            )
        };
        if created == 0 {
            return Err(last_error("CreateProcessAsUserW"));
        }
        let process = Handle(information.hProcess);
        let thread = Handle(information.hThread);
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(process.0, 1) };
            return Err(last_error("AssignProcessToJobObject"));
        }
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(process.0, 1) };
            return Err(last_error("ResumeThread"));
        }
        let (cancel_sender, cancel_receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut input = std::io::stdin();
            let mut byte = [0_u8; 1];
            if matches!(input.read(&mut byte), Ok(count) if count > 0) {
                let _ = cancel_sender.send(());
            }
        });
        let deadline = Instant::now() + Duration::from_secs(options.timeout_seconds);
        let mut outcome = ExecutionOutcome::Completed;
        loop {
            let wait = unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(process.0, 100)
            };
            if wait == WAIT_OBJECT_0 {
                break;
            }
            if wait == WAIT_FAILED {
                return Err(last_error("WaitForSingleObject"));
            }
            if wait != WAIT_TIMEOUT {
                return Err(format!("unexpected process wait result: {wait}"));
            }
            match cancel_receiver.try_recv() {
                Ok(()) => {
                    terminate_job(job.0)?;
                    outcome = ExecutionOutcome::Cancelled;
                    break;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {}
            }
            if Instant::now() >= deadline {
                terminate_job(job.0)?;
                outcome = ExecutionOutcome::TimedOut;
                break;
            }
        }
        let wait = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(process.0, u32::MAX)
        };
        if wait != WAIT_OBJECT_0 {
            return Err(last_error("WaitForSingleObject after job termination"));
        }
        if matches!(outcome, ExecutionOutcome::Completed) {
            let mut exit_code = 0_u32;
            if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
                return Err(last_error("GetExitCodeProcess"));
            }
            if exit_code != 0 {
                return Err(format!(
                    "Windows sandbox child exited with status {exit_code}"
                ));
            }
        }
        Ok(outcome)
    }

    fn terminate_job(job: HANDLE) -> Result<(), String> {
        if unsafe { TerminateJobObject(job, 1) } == 0 {
            return Err(last_error("TerminateJobObject"));
        }
        Ok(())
    }

    /// Temporarily adds the restricted-code SID to the complete worktree ACL.
    ///
    /// A restricted token is still stamped with the interactive user's SID.
    /// Windows access checks for restricted tokens also require a matching
    /// restricted SID ACE, so ordinary user-owned paths without this ACE are
    /// denied while the worktree remains usable.  ``icacls`` is invoked by
    /// absolute path with no shell; the original ACL tree is saved first and
    /// restored before this helper reports success.
    struct WorkspaceAcl {
        workspace: PathBuf,
        backup: PathBuf,
    }

    impl WorkspaceAcl {
        fn apply(workspace: &Path) -> Result<Self, String> {
            let backup = env::temp_dir().join(unique_rule_name("acl"));
            let save = vec![
                workspace.as_os_str().to_os_string(),
                OsString::from("/save"),
                backup.as_os_str().to_os_string(),
                OsString::from("/t"),
                OsString::from("/c"),
            ];
            run_icacls(&save).map_err(|error| format!("save workspace ACL: {error}"))?;
            let grant = vec![
                workspace.as_os_str().to_os_string(),
                OsString::from("/grant:r"),
                OsString::from("*S-1-5-12:(OI)(CI)F"),
                OsString::from("/t"),
                OsString::from("/c"),
            ];
            if let Err(error) = run_icacls(&grant) {
                let restore = vec![
                    workspace.as_os_str().to_os_string(),
                    OsString::from("/restore"),
                    backup.as_os_str().to_os_string(),
                    OsString::from("/c"),
                ];
                let _ = run_icacls(&restore);
                let _ = std::fs::remove_file(&backup);
                return Err(format!("grant restricted workspace ACL: {error}"));
            }
            Ok(Self {
                workspace: workspace.to_path_buf(),
                backup,
            })
        }

        fn restore(self) -> Result<(), String> {
            let restore = vec![
                self.workspace.as_os_str().to_os_string(),
                OsString::from("/restore"),
                self.backup.as_os_str().to_os_string(),
                OsString::from("/c"),
            ];
            let result =
                run_icacls(&restore).map_err(|error| format!("restore workspace ACL: {error}"));
            let remove = std::fs::remove_file(&self.backup)
                .map_err(|error| format!("remove workspace ACL backup: {error}"));
            result.and(remove)
        }
    }

    /// Temporarily grants the restricted-code SID read/execute access to the
    /// resolved native runtime tree.  WRITE_RESTRICTED makes this SID the
    /// authority for writes, so a user-owned runtime that is writable by the
    /// interactive user must still be made explicitly read/execute-only for
    /// the child.  The grant is scoped to the interpreter's parent directory;
    /// only execute/traverse is added to its ancestors.  Every ACL is saved
    /// before mutation and restored before the helper reports success.
    ///
    /// This is deliberately separate from ``WorkspaceAcl``: the child gets
    /// full access only to the task workspace, while the runtime is strictly
    /// read/execute.  Any grant or restore failure aborts the execution and
    /// leaves the helper fail-closed.
    struct RuntimeAcl {
        entries: Vec<RuntimeAclEntry>,
    }

    struct RuntimeAclEntry {
        root: PathBuf,
        backup: PathBuf,
    }

    impl RuntimeAcl {
        fn apply(executable: &Path) -> Result<Self, String> {
            let runtime_root = executable
                .parent()
                .ok_or_else(|| "Windows sandbox executable has no parent directory".to_string())?
                .to_path_buf();
            if !runtime_root.is_dir() {
                return Err(format!(
                    "Windows sandbox runtime directory is unavailable: {}",
                    runtime_root.display()
                ));
            }
            if directory_ancestors(&runtime_root).is_empty() {
                return Err(
                    "Windows sandbox refuses to mutate a volume-root runtime directory".to_string(),
                );
            }
            let mut entries = Vec::new();
            for ancestor in directory_ancestors(&runtime_root) {
                if let Err(error) =
                    apply_runtime_acl(&ancestor, &mut entries, "*S-1-5-12:(X)", false)
                {
                    return Err(join_runtime_acl_error(error, entries));
                }
            }
            if let Err(error) =
                apply_runtime_acl(&runtime_root, &mut entries, "*S-1-5-12:(OI)(CI)RX", true)
            {
                return Err(join_runtime_acl_error(error, entries));
            }
            Ok(Self { entries })
        }

        fn restore(self) -> Result<(), String> {
            restore_runtime_acl_entries(self.entries)
        }
    }

    fn apply_runtime_acl(
        root: &Path,
        entries: &mut Vec<RuntimeAclEntry>,
        permission: &str,
        recursive: bool,
    ) -> Result<(), String> {
        let backup = env::temp_dir().join(unique_rule_name("runtime-acl"));
        let save = vec![
            root.as_os_str().to_os_string(),
            OsString::from("/save"),
            backup.as_os_str().to_os_string(),
            OsString::from("/c"),
        ];
        let mut save = save;
        if recursive {
            save.push(OsString::from("/t"));
        }
        run_icacls(&save).map_err(|error| format!("save runtime ACL: {error}"))?;
        entries.push(RuntimeAclEntry {
            root: root.to_path_buf(),
            backup: backup.clone(),
        });
        let mut grant = vec![
            root.as_os_str().to_os_string(),
            OsString::from("/grant"),
            OsString::from(permission),
        ];
        if recursive {
            grant.extend([OsString::from("/t"), OsString::from("/c")]);
        }
        if let Err(error) = run_icacls(&grant) {
            return Err(format!("grant restricted runtime ACL: {error}"));
        }
        Ok(())
    }

    fn join_runtime_acl_error(primary: String, entries: Vec<RuntimeAclEntry>) -> String {
        let mut errors = vec![primary];
        if let Err(error) = restore_runtime_acl_entries(entries) {
            errors.push(error);
        }
        errors.join("; ")
    }

    fn restore_runtime_acl_entries(mut entries: Vec<RuntimeAclEntry>) -> Result<(), String> {
        let mut errors = Vec::new();
        while let Some(entry) = entries.pop() {
            let restore = vec![
                entry.root.as_os_str().to_os_string(),
                OsString::from("/restore"),
                entry.backup.as_os_str().to_os_string(),
                OsString::from("/c"),
            ];
            if let Err(error) = run_icacls(&restore) {
                errors.push(format!("restore runtime ACL: {error}"));
            }
            if let Err(error) = std::fs::remove_file(&entry.backup) {
                errors.push(format!("remove runtime ACL backup: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn directory_ancestors(path: &Path) -> Vec<PathBuf> {
        let mut ancestors = Vec::new();
        let mut current = path.to_path_buf();
        while let Some(parent) = current.parent() {
            let parent = parent.to_path_buf();
            if parent == current {
                break;
            }
            ancestors.push(parent.clone());
            current = parent;
        }
        ancestors
    }

    fn run_icacls(arguments: &[OsString]) -> Result<(), String> {
        let root = env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
        let path = Path::new(&root).join("System32").join("icacls.exe");
        let result = Command::new(path)
            .args(arguments)
            .output()
            .map_err(|e| format!("icacls unavailable: {e}"))?;
        if !result.status.success() {
            return Err(format!(
                "icacls failed: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            ));
        }
        Ok(())
    }

    struct FirewallRule {
        names: Vec<String>,
    }

    impl FirewallRule {
        fn install(options: &Options, executable: &Path) -> Result<Self, String> {
            let program = executable.to_string_lossy().to_string();
            let mut names = Vec::new();
            let result = if options.network == "brokered" {
                let port = options.proxy_port.unwrap();
                // A broad block rule wins over an allow rule in Windows
                // Firewall.  Therefore brokered mode blocks every address
                // except the exact IPv4 loopback proxy port, then adds an
                // allow rule for that one endpoint.  IPv6 is denied in full.
                let allow_name = unique_rule_name("exec-allow");
                let allow_args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={allow_name}"),
                    "dir=out".to_string(),
                    "action=allow".to_string(),
                    // ``Command`` passes this as one already-isolated argv
                    // element; embedding shell quotes would make the quotes
                    // part of the program path when netsh parses it.
                    format!("program={program}"),
                    "remoteip=127.0.0.1".to_string(),
                    "protocol=TCP".to_string(),
                    format!("remoteport={port}"),
                    "profile=any".to_string(),
                ];
                run_netsh_dynamic(&allow_args)?;
                names.push(allow_name);

                let non_loopback_v4 = unique_rule_name("exec-v4");
                let v4_args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={non_loopback_v4}"),
                    "dir=out".to_string(),
                    "action=block".to_string(),
                    format!("program={program}"),
                    "remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255".to_string(),
                    "profile=any".to_string(),
                ];
                if let Err(error) = run_netsh_dynamic(&v4_args) {
                    remove_firewall_rules(&names);
                    return Err(error);
                }
                names.push(non_loopback_v4);

                let v6_name = unique_rule_name("exec-v6");
                let v6_args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={v6_name}"),
                    "dir=out".to_string(),
                    "action=block".to_string(),
                    format!("program={program}"),
                    "remoteip=::/0".to_string(),
                    "profile=any".to_string(),
                ];
                if let Err(error) = run_netsh_dynamic(&v6_args) {
                    remove_firewall_rules(&names);
                    return Err(error);
                }
                names.push(v6_name);

                for protocol in ["TCP", "UDP"] {
                    for remote_port in excluded_proxy_port_ranges(port) {
                        let name = unique_rule_name("exec-loopback");
                        let args = vec![
                            "advfirewall".to_string(),
                            "firewall".to_string(),
                            "add".to_string(),
                            "rule".to_string(),
                            format!("name={name}"),
                            "dir=out".to_string(),
                            "action=block".to_string(),
                            format!("program={program}"),
                            // Block every IPv4 loopback address except the
                            // exact proxy endpoint covered by the allow rule.
                            "remoteip=127.0.0.0-127.255.255.255".to_string(),
                            format!("protocol={protocol}"),
                            format!("remoteport={remote_port}"),
                            "profile=any".to_string(),
                        ];
                        if let Err(error) = run_netsh_dynamic(&args) {
                            remove_firewall_rules(&names);
                            return Err(error);
                        }
                        names.push(name);
                    }
                }
                Ok(())
            } else {
                let name = unique_rule_name("exec-all");
                let args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={name}"),
                    "dir=out".to_string(),
                    "action=block".to_string(),
                    format!("program={program}"),
                    "profile=any".to_string(),
                ];
                run_netsh_dynamic(&args).map(|()| names.push(name))
            };
            if let Err(error) = result {
                remove_firewall_rules(&names);
                return Err(error);
            }
            Ok(Self { names })
        }

        fn remove(&self) -> Result<(), String> {
            let mut first_error = None;
            for name in &self.names {
                let args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "delete".to_string(),
                    "rule".to_string(),
                    format!("name={name}"),
                ];
                if let Err(error) = run_netsh_dynamic(&args) {
                    first_error.get_or_insert(error);
                }
            }
            first_error.map_or(Ok(()), Err)
        }
    }

    fn remove_firewall_rules(names: &[String]) {
        for name in names {
            let args = vec![
                "advfirewall".to_string(),
                "firewall".to_string(),
                "delete".to_string(),
                "rule".to_string(),
                format!("name={name}"),
            ];
            let _ = run_netsh_dynamic(&args);
        }
    }

    fn excluded_proxy_port_ranges(port: u16) -> Vec<String> {
        let mut ranges = Vec::new();
        if port > 1 {
            ranges.push(format!("1-{}", port - 1));
        }
        if port < u16::MAX {
            ranges.push(format!("{}-65535", port + 1));
        }
        ranges
    }

    fn run_netsh(arguments: &[&str]) -> Result<(), String> {
        let root = env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
        let path = Path::new(&root).join("System32").join("netsh.exe");
        let result = Command::new(path)
            .args(arguments)
            .output()
            .map_err(|e| format!("WFP firewall command unavailable: {e}"))?;
        if !result.status.success() {
            return Err(format!(
                "WFP firewall command failed (status={}): stdout={} stderr={}",
                result.status,
                String::from_utf8_lossy(&result.stdout).trim(),
                String::from_utf8_lossy(&result.stderr).trim(),
            ));
        }
        Ok(())
    }

    fn run_netsh_dynamic(arguments: &[String]) -> Result<(), String> {
        let references: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run_netsh(&references)
    }

    fn resolve_executable(command: &OsStr) -> Result<PathBuf, String> {
        let command_path = Path::new(command);
        let mut candidates = Vec::new();
        if command_path.is_absolute() || command_path.components().count() > 1 {
            candidates.push(command_path.to_path_buf());
        } else {
            let path = env::var_os("PATH").ok_or_else(|| "Windows PATH is missing".to_string())?;
            let extensions: Vec<OsString> = env::var_os("PATHEXT")
                .map(|value| {
                    value
                        .to_string_lossy()
                        .split(';')
                        .map(OsString::from)
                        .collect()
                })
                .unwrap_or_else(|| vec![OsString::from(".COM"), OsString::from(".EXE")]);
            for directory in env::split_paths(&path) {
                candidates.push(directory.join(command_path));
                if command_path.extension().is_none() {
                    for extension in &extensions {
                        let mut with_extension = directory.join(command_path);
                        with_extension
                            .set_extension(extension.to_string_lossy().trim_start_matches('.'));
                        candidates.push(with_extension);
                    }
                }
            }
        }
        for candidate in candidates {
            let resolved = match std::fs::canonicalize(&candidate) {
                Ok(path) if path.is_file() => path,
                _ => continue,
            };
            let extension = resolved
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if extension != "exe" && extension != "com" {
                return Err(format!(
                    "Windows sandbox requires a native executable, got {}",
                    resolved.display()
                ));
            }
            // ``canonicalize`` may return a Win32 extended path such as
            // ``\\?\\C:\\...``.  CreateProcess and icacls accept that form,
            // but the Windows Firewall application filter rejects the
            // ``\\?\\`` prefix as invalid application-path characters.
            return Ok(strip_windows_verbatim_prefix(resolved));
        }
        Err(format!(
            "Windows sandbox executable could not be resolved: {}",
            command.to_string_lossy()
        ))
    }

    fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
        let value = path.to_string_lossy();
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
        path
    }

    fn unique_rule_name(kind: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{FIREWALL_PREFIX}-{kind}-{nanos:x}")
    }

    fn quote_command_line(command: &[OsString]) -> Vec<u16> {
        let mut result = OsString::new();
        for (index, argument) in command.iter().enumerate() {
            if index != 0 {
                result.push(" ");
            }
            let value = argument.to_string_lossy();
            result.push("\"");
            result.push(value.replace('"', "\\\""));
            result.push("\"");
        }
        wide_null(&result)
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(once(0)).collect()
    }

    fn last_error(operation: &str) -> String {
        format!("{operation} failed with Win32 error {}", unsafe {
            GetLastError()
        })
    }
}

#[cfg(windows)]
fn main() {
    match windows_backend::run() {
        Ok(windows_backend::ExecutionOutcome::Completed) => {}
        Ok(windows_backend::ExecutionOutcome::TimedOut) => {
            eprintln!("khaos-windows-sandbox: execution timed out");
            std::process::exit(124);
        }
        Ok(windows_backend::ExecutionOutcome::Cancelled) => {
            eprintln!("khaos-windows-sandbox: execution cancelled");
            std::process::exit(125);
        }
        Err(error) => {
            eprintln!("khaos-windows-sandbox: {error}");
            std::process::exit(126);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("khaos-windows-sandbox is Windows-only");
    std::process::exit(126);
}
