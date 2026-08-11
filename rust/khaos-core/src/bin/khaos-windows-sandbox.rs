//! Windows execution TCB for Khaos.
//!
//! The Python layer never creates the child directly on Windows.  This
//! launcher creates a restricted primary token, places network-none children
//! in an OS-issued AppContainer, adds a kill-on-close Job Object, and keeps
//! the job alive until the child exits.
//! The surrounding Python backend only reports the backend as available after
//! this binary proves its native primitives, AppContainer network isolation,
//! and WFP-backed firewall transaction can be created and removed.

#![cfg_attr(not(windows), allow(dead_code))]

// KHAOS-PRIVILEGED-SPAWN owner=WindowsSandboxTCB threat-model=restricted-token-job-acl-appcontainer-wfp boundary=windows-sandbox

#[cfg(windows)]
mod windows_backend {
    use std::collections::HashSet;
    use std::env;
    use std::ffi::{c_void, OsStr, OsString};
    use std::io::{ErrorKind, Read};
    use std::iter::once;
    use std::mem::{size_of, zeroed};
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::{self, TryRecvError};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED,
        ERROR_SUCCESS, HANDLE, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, CopySid, CreateRestrictedToken, CreateWellKnownSid, FreeSid,
        GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorSacl, GetTokenInformation,
        IsTokenRestricted, LookupPrivilegeValueW, SetTokenInformation, TokenDefaultDacl,
        TokenGroups, TokenIsAppContainer, WinRestrictedCodeSid, WinWorldSid, ACL,
        DISABLE_MAX_PRIVILEGE, LUA_TOKEN, LUID_AND_ATTRIBUTES, PROTECTED_SACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SACL_SECURITY_INFORMATION, SECURITY_CAPABILITIES,
        SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED, SE_SACL_PROTECTED, SE_SECURITY_NAME,
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
        CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
        GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread,
        UpdateProcThreadAttribute, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, STARTUPINFOW,
    };

    const FIREWALL_PREFIX: &str = "KhaosWindowsSandbox";
    // Windows Firewall application rules are image-scoped. A descendant can
    // otherwise switch to another executable and bypass the parent's rule.
    // Windows Firewall application rules are image-scoped, while the
    // AppContainer is the network boundary for network-none executions.
    // The one-process limit still prevents a descendant from switching to an
    // untracked executable before a job-wide policy is available.
    // Commands that need to spawn children therefore fail inside the native
    // boundary instead of silently escaping the network policy.
    const MAX_ACTIVE_PROCESSES: u32 = 1;

    pub enum ExecutionOutcome {
        Completed,
        TimedOut,
        Cancelled,
    }

    struct Handle(HANDLE);

    /// Temporarily enables the TCB's SACL privilege for the integrity-label
    /// transaction.  The child never receives this token: it is created later
    /// from a `DISABLE_MAX_PRIVILEGE` restricted token.  Keeping the privilege
    /// in a small RAII guard prevents the cleanup path from accidentally
    /// leaving the helper process elevated after the ACL transaction.
    struct SecurityPrivilegeGuard {
        token: Handle,
        previous: TOKEN_PRIVILEGES,
        active: bool,
    }

    impl SecurityPrivilegeGuard {
        fn enable() -> Result<Self, String> {
            let mut token: HANDLE = null_mut();
            if unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &mut token,
                )
            } == 0
            {
                return Err(last_error("OpenProcessToken(SeSecurityPrivilege)"));
            }
            let token = Handle(token);
            let mut luid = unsafe { zeroed() };
            if unsafe { LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut luid) } == 0 {
                return Err(last_error("LookupPrivilegeValueW(SeSecurityPrivilege)"));
            }
            let requested = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let mut previous = TOKEN_PRIVILEGES::default();
            let mut returned_length = 0_u32;
            let adjusted = unsafe {
                AdjustTokenPrivileges(
                    token.0,
                    0,
                    &requested,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut previous,
                    &mut returned_length,
                )
            };
            let adjust_error = unsafe { GetLastError() };
            if adjusted == 0 || adjust_error == ERROR_NOT_ALL_ASSIGNED {
                if adjusted != 0 {
                    let _ = unsafe {
                        AdjustTokenPrivileges(
                            token.0,
                            0,
                            &previous,
                            size_of::<TOKEN_PRIVILEGES>() as u32,
                            null_mut(),
                            null_mut(),
                        )
                    };
                }
                if adjusted == 0 {
                    return Err(last_error("AdjustTokenPrivileges(SeSecurityPrivilege)"));
                }
                return Err(
                    "SeSecurityPrivilege is unavailable on the Windows TCB token".to_string(),
                );
            }
            Ok(Self {
                token,
                previous,
                active: true,
            })
        }

        fn restore(mut self) -> Result<(), String> {
            if !self.active {
                return Ok(());
            }
            let restored = unsafe {
                AdjustTokenPrivileges(
                    self.token.0,
                    0,
                    &self.previous,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    null_mut(),
                    null_mut(),
                )
            };
            let restore_error = unsafe { GetLastError() };
            self.active = false;
            if restored == 0 {
                return Err(last_error("restore SeSecurityPrivilege"));
            }
            if restore_error == ERROR_NOT_ALL_ASSIGNED {
                return Err(
                    "restore SeSecurityPrivilege reported ERROR_NOT_ALL_ASSIGNED".to_string(),
                );
            }
            Ok(())
        }
    }

    impl Drop for SecurityPrivilegeGuard {
        fn drop(&mut self) {
            if self.active {
                let _ = unsafe {
                    AdjustTokenPrivileges(
                        self.token.0,
                        0,
                        &self.previous,
                        size_of::<TOKEN_PRIVILEGES>() as u32,
                        null_mut(),
                        null_mut(),
                    )
                };
                self.active = false;
            }
        }
    }

    #[repr(C)]
    struct TokenDefaultDaclInfo {
        default_dacl: *mut windows_sys::Win32::Security::ACL,
    }

    /// Snapshot the complete SACL before lowering a workspace's integrity
    /// label for an AppContainer.  ``icacls /save`` only stores DACLs; without
    /// this separate transaction a failed execution could leave the user's
    /// workspace at low integrity after the helper exits.
    struct IntegritySnapshot {
        path: PathBuf,
        sacl: Option<Vec<u8>>,
        protected: bool,
    }

    struct IntegrityTransaction {
        root: PathBuf,
        snapshots: Vec<IntegritySnapshot>,
        security_privilege: SecurityPrivilegeGuard,
    }

    impl IntegrityTransaction {
        fn capture(root: &Path) -> Result<Self, String> {
            let security_privilege = SecurityPrivilegeGuard::enable().map_err(|error| {
                format!("enable SeSecurityPrivilege for SACL transaction: {error}")
            })?;
            let capture_result = (|| -> Result<Vec<IntegritySnapshot>, String> {
                let mut snapshots = Vec::new();
                for path in filesystem_paths(root)? {
                    snapshots.push(IntegritySnapshot::capture(path)?);
                }
                Ok(snapshots)
            })();
            let snapshots = match capture_result {
                Ok(snapshots) => snapshots,
                Err(error) => {
                    if let Err(restore_error) = security_privilege.restore() {
                        return Err(format!(
                            "{error}; restore SeSecurityPrivilege after failed capture: {restore_error}"
                        ));
                    }
                    return Err(error);
                }
            };
            Ok(Self {
                root: root.to_path_buf(),
                snapshots,
                security_privilege,
            })
        }

        fn restore(self) -> Result<(), String> {
            let Self {
                root,
                snapshots,
                security_privilege,
            } = self;
            let mut errors = Vec::new();
            let known: HashSet<PathBuf> = snapshots
                .iter()
                .map(|snapshot| snapshot.path.clone())
                .collect();
            if let Some(root_snapshot) = snapshots.first() {
                match filesystem_paths(&root) {
                    Ok(paths) => {
                        for path in paths {
                            if !known.contains(&path) {
                                if let Err(error) = root_snapshot.restore_to(&path) {
                                    errors.push(error);
                                }
                            }
                        }
                    }
                    Err(error) => errors.push(error),
                }
            }
            for snapshot in snapshots.into_iter().rev() {
                if let Err(error) = snapshot.restore_to(&snapshot.path) {
                    errors.push(error);
                }
            }
            if let Err(error) = security_privilege.restore() {
                errors.push(error);
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl IntegritySnapshot {
        fn capture(path: PathBuf) -> Result<Self, String> {
            let path_wide = wide_null(path.as_os_str());
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            let mut sacl: *mut ACL = null_mut();
            let result = unsafe {
                GetNamedSecurityInfoW(
                    path_wide.as_ptr(),
                    SE_FILE_OBJECT,
                    SACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut sacl,
                    &mut descriptor,
                )
            };
            if result != ERROR_SUCCESS {
                return Err(format!(
                    "capture Windows integrity SACL for {} failed with Win32 error {result}",
                    path.display()
                ));
            }
            let mut present = 0;
            let mut _defaulted = 0;
            let sacl_read = unsafe {
                GetSecurityDescriptorSacl(descriptor, &mut present, &mut sacl, &mut _defaulted)
            };
            if sacl_read == 0 {
                unsafe { LocalFree(descriptor as HLOCAL) };
                return Err(format!(
                    "read Windows integrity SACL for {} failed: {}",
                    path.display(),
                    last_error("GetSecurityDescriptorSacl")
                ));
            }
            let mut control = 0_u16;
            let mut _revision = 0_u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut _revision) }
                == 0
            {
                unsafe { LocalFree(descriptor as HLOCAL) };
                return Err(format!(
                    "read Windows integrity SACL control for {} failed: {}",
                    path.display(),
                    last_error("GetSecurityDescriptorControl")
                ));
            }
            let sacl_bytes = if present != 0 && !sacl.is_null() {
                let size = unsafe { (*sacl).AclSize as usize };
                if size < size_of::<ACL>() {
                    unsafe { LocalFree(descriptor as HLOCAL) };
                    return Err(format!(
                        "Windows integrity SACL for {} has an invalid size",
                        path.display()
                    ));
                }
                Some(unsafe { std::slice::from_raw_parts(sacl as *const u8, size) }.to_vec())
            } else {
                None
            };
            let free_result = unsafe { LocalFree(descriptor as HLOCAL) };
            if !free_result.is_null() {
                return Err(format!(
                    "free Windows integrity SACL for {} failed",
                    path.display()
                ));
            }
            Ok(Self {
                path,
                sacl: sacl_bytes,
                protected: control & SE_SACL_PROTECTED != 0,
            })
        }

        fn restore_to(&self, path: &Path) -> Result<(), String> {
            let path_wide = wide_null(path.as_os_str());
            let security_info = SACL_SECURITY_INFORMATION
                | if self.protected {
                    PROTECTED_SACL_SECURITY_INFORMATION
                } else {
                    0
                };
            let sacl = self
                .sacl
                .as_ref()
                .map_or(null(), |bytes| bytes.as_ptr() as *const ACL);
            let result = unsafe {
                SetNamedSecurityInfoW(
                    path_wide.as_ptr(),
                    SE_FILE_OBJECT,
                    security_info,
                    null_mut(),
                    null_mut(),
                    null(),
                    sacl,
                )
            };
            if result == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(format!(
                    "restore Windows integrity SACL for {} failed with Win32 error {result}",
                    path.display()
                ))
            }
        }
    }

    fn filesystem_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
        let mut paths = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("inspect Windows integrity path {}: {e}", path.display()))?;
            paths.push(path.clone());
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path).map_err(|e| {
                    format!("enumerate Windows integrity path {}: {e}", path.display())
                })? {
                    let entry = entry.map_err(|e| {
                        format!(
                            "read Windows integrity directory entry {}: {e}",
                            path.display()
                        )
                    })?;
                    pending.push(entry.path());
                }
            }
        }
        Ok(paths)
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// Owns the per-execution AppContainer identity used by network-none
    /// executions.  The profile SID is an OS-issued authority; it is never
    /// accepted from the Python caller or reconstructed from user input.
    struct AppContainerProfile {
        name: Vec<u16>,
        sid: PSID,
        sid_string: String,
        deleted: bool,
    }

    impl AppContainerProfile {
        fn create() -> Result<Self, String> {
            let name = unique_rule_name("appcontainer");
            let name_wide = wide_null(OsStr::new(&name));
            let display = wide_null(OsStr::new("Khaos network-none sandbox"));
            let description = wide_null(OsStr::new(
                "Per-execution Khaos AppContainer with no network capability",
            ));
            let mut sid = null_mut();
            let result = unsafe {
                CreateAppContainerProfile(
                    name_wide.as_ptr(),
                    display.as_ptr(),
                    description.as_ptr(),
                    null(),
                    0,
                    &mut sid,
                )
            };
            if result != 0 {
                return Err(format!(
                    "CreateAppContainerProfile failed with HRESULT 0x{:08x}",
                    result as u32
                ));
            }
            if sid.is_null() {
                let _ = unsafe { DeleteAppContainerProfile(name_wide.as_ptr()) };
                return Err("CreateAppContainerProfile returned a null package SID".to_string());
            }
            let sid_string = match sid_to_string(sid) {
                Ok(value) => value,
                Err(error) => {
                    unsafe { FreeSid(sid) };
                    let _ = unsafe { DeleteAppContainerProfile(name_wide.as_ptr()) };
                    return Err(error);
                }
            };
            Ok(Self {
                name: name_wide,
                sid,
                sid_string,
                deleted: false,
            })
        }

        fn sid(&self) -> PSID {
            self.sid
        }

        fn sid_string(&self) -> &str {
            &self.sid_string
        }

        fn close(mut self) -> Result<(), String> {
            let delete_result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            if delete_result == 0 {
                self.deleted = true;
            }
            let free_result = if self.sid.is_null() {
                null_mut()
            } else {
                let sid = self.sid;
                self.sid = null_mut();
                unsafe { FreeSid(sid) }
            };
            let mut errors = Vec::new();
            if delete_result != 0 {
                errors.push(format!(
                    "DeleteAppContainerProfile failed with HRESULT 0x{:08x}",
                    delete_result as u32
                ));
            }
            if !free_result.is_null() {
                errors.push("FreeSid failed for AppContainer package SID".to_string());
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl Drop for AppContainerProfile {
        fn drop(&mut self) {
            if !self.deleted {
                let _ = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
                self.deleted = true;
            }
            if !self.sid.is_null() {
                unsafe { FreeSid(self.sid) };
                self.sid = null_mut();
            }
        }
    }

    /// Owns the extended startup attribute list that marks a process as an
    /// AppContainer.  The package SID remains owned by AppContainerProfile
    /// for the full lifetime of the created process.
    struct AppContainerAttributes {
        storage: Vec<u8>,
        list: LPPROC_THREAD_ATTRIBUTE_LIST,
        capabilities: SECURITY_CAPABILITIES,
    }

    impl AppContainerAttributes {
        fn create(profile: &AppContainerProfile) -> Result<Self, String> {
            let mut size = 0usize;
            let first = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
            if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
                return Err(last_error("InitializeProcThreadAttributeList(size)"));
            }
            let mut storage = vec![0u8; size];
            let list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
            if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
                return Err(last_error("InitializeProcThreadAttributeList"));
            }
            let capabilities = SECURITY_CAPABILITIES {
                AppContainerSid: profile.sid(),
                Capabilities: null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    &capabilities as *const SECURITY_CAPABILITIES as *const c_void,
                    size_of::<SECURITY_CAPABILITIES>(),
                    null_mut(),
                    null(),
                )
            };
            if updated == 0 {
                unsafe { DeleteProcThreadAttributeList(list) };
                return Err(last_error(
                    "UpdateProcThreadAttribute(security capabilities)",
                ));
            }
            Ok(Self {
                storage,
                list,
                capabilities,
            })
        }
    }

    impl Drop for AppContainerAttributes {
        fn drop(&mut self) {
            if !self.list.is_null() {
                unsafe { DeleteProcThreadAttributeList(self.list) };
                self.list = null_mut();
            }
            // Keep both fields live until the attribute list is destroyed.
            let _ = (&self.storage, &self.capabilities);
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
        let appcontainer = if options.network == "none" {
            Some(AppContainerProfile::create()?)
        } else {
            None
        };
        let acl = match WorkspaceAcl::apply(
            &workspace,
            appcontainer.as_ref().map(AppContainerProfile::sid_string),
        ) {
            Ok(acl) => acl,
            Err(error) => {
                let mut errors = vec![error];
                close_appcontainer(appcontainer, &mut errors);
                return Err(errors.join("; "));
            }
        };
        let runtime_acl = match RuntimeAcl::apply(
            &executable,
            appcontainer.as_ref().map(AppContainerProfile::sid_string),
            &options.runtime_roots,
        ) {
            Ok(acl) => acl,
            Err(error) => {
                let restore = acl.restore();
                let mut errors = vec![error];
                if let Err(restore_error) = restore {
                    errors.push(restore_error);
                }
                close_appcontainer(appcontainer, &mut errors);
                return Err(errors.join("; "));
            }
        };
        let rule = match FirewallRule::install(&options, &executable) {
            Ok(rule) => rule,
            Err(error) => {
                let runtime_restore = runtime_acl.restore();
                let workspace_restore = acl.restore();
                let mut errors = vec![error];
                if let Err(restore_error) = runtime_restore {
                    errors.push(restore_error);
                }
                if let Err(restore_error) = workspace_restore {
                    errors.push(restore_error);
                }
                close_appcontainer(appcontainer, &mut errors);
                return Err(errors.join("; "));
            }
        };
        let result = spawn_restricted(&options, &executable, appcontainer.as_ref());
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
        close_appcontainer(appcontainer, &mut errors);
        if errors.is_empty() {
            match outcome {
                Some(outcome) => Ok(outcome),
                None => Err("Windows sandbox execution outcome is missing".to_string()),
            }
        } else {
            Err(errors.join("; "))
        }
    }

    fn close_appcontainer(profile: Option<AppContainerProfile>, errors: &mut Vec<String>) {
        if let Some(profile) = profile {
            if let Err(error) = profile.close() {
                errors.push(format!("close Windows AppContainer: {error}"));
            }
        }
    }

    fn probe() -> Result<(), String> {
        let token = restricted_token()?;
        if unsafe { IsTokenRestricted(token.0) } == 0 {
            return Err("CreateRestrictedToken did not create a restricted token".to_string());
        }
        drop(token);

        let helper = env::current_exe()
            .map_err(|e| format!("resolve Windows helper: {e}"))
            .and_then(|path| resolve_executable(path.as_os_str()))?;
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
            runtime_roots: Vec::new(),
            command,
        };
        let appcontainer = match AppContainerProfile::create() {
            Ok(profile) => Some(profile),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(error);
            }
        };
        let acl = match WorkspaceAcl::apply(
            &probe_root,
            appcontainer.as_ref().map(AppContainerProfile::sid_string),
        ) {
            Ok(acl) => acl,
            Err(error) => {
                let mut errors = vec![error];
                close_appcontainer(appcontainer, &mut errors);
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(errors.join("; "));
            }
        };
        let runtime_acl = match RuntimeAcl::apply(
            &helper,
            appcontainer.as_ref().map(AppContainerProfile::sid_string),
            &[],
        ) {
            Ok(acl) => acl,
            Err(error) => {
                let mut errors = vec![error];
                if let Err(restore_error) = acl.restore() {
                    errors.push(restore_error);
                }
                close_appcontainer(appcontainer, &mut errors);
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(errors.join("; "));
            }
        };
        let rule = match FirewallRule::install(&options, &helper) {
            Ok(rule) => rule,
            Err(error) => {
                let mut errors = vec![error];
                if let Err(restore_error) = runtime_acl.restore() {
                    errors.push(restore_error);
                }
                if let Err(restore_error) = acl.restore() {
                    errors.push(restore_error);
                }
                close_appcontainer(appcontainer, &mut errors);
                let _ = std::fs::remove_dir_all(&probe_root);
                return Err(errors.join("; "));
            }
        };
        let result = spawn_restricted(&options, &helper, appcontainer.as_ref());
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
                if !report.contains("appcontainer=true") {
                    errors.push(
                        "Windows network-none probe did not enter an AppContainer".to_string(),
                    );
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
        close_appcontainer(appcontainer, &mut errors);
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
            "{{\"restricted_token\":true,\"job_object\":true,\"process_tree\":true,\"acl\":true,\"wfp\":true,\"appcontainer\":true}}"
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
        let appcontainer = running_in_appcontainer()?;
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
            "network_blocked={network_blocked}\ndescendant_blocked={descendant_blocked}\nappcontainer={appcontainer}\ninside_written={inside_written}\noutside_denied={outside_denied}\n"
        );
        std::fs::write(workspace.join("probe-result.txt"), report)
            .map_err(|e| format!("write Windows sandbox capability probe: {e}"))?;
        Ok(())
    }

    fn running_in_appcontainer() -> Result<bool, String> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error("OpenProcessToken(probe child)"));
        }
        let token = Handle(token);
        let mut value = 0u32;
        let mut returned = 0u32;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenIsAppContainer,
                &mut value as *mut u32 as *mut c_void,
                size_of::<u32>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(last_error("GetTokenInformation(TokenIsAppContainer)"));
        }
        Ok(value != 0)
    }

    struct Options {
        workspace: PathBuf,
        cwd: PathBuf,
        network: String,
        proxy_port: Option<u16>,
        memory_bytes: u64,
        cpu_seconds: u64,
        timeout_seconds: u64,
        runtime_roots: Vec<PathBuf>,
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
            let mut runtime_roots = Vec::new();
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
                    "--runtime-root" => runtime_roots.push(PathBuf::from(next(&mut index)?)),
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
                runtime_roots,
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
        for runtime_root in &options.runtime_roots {
            let canonical = std::fs::canonicalize(runtime_root)
                .map_err(|e| format!("Windows sandbox runtime root unavailable: {e}"))?;
            if !canonical.is_dir() {
                return Err("Windows sandbox runtime root must be a directory".to_string());
            }
            if canonical == workspace || canonical.starts_with(&workspace) {
                return Err(
                    "Windows sandbox runtime root cannot be inside the task workspace".to_string(),
                );
            }
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

    fn spawn_restricted(
        options: &Options,
        executable: &Path,
        appcontainer: Option<&AppContainerProfile>,
    ) -> Result<ExecutionOutcome, String> {
        // The AppContainer low-box is created by the normal CreateProcess
        // current-identity path when PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
        // is present. Passing any hToken to that path is rejected by Windows
        // with ERROR_INVALID_PARAMETER. Brokered executions retain the
        // explicit restricted primary-token path below.
        let token = if appcontainer.is_some() {
            None
        } else {
            Some(restricted_token()?)
        };
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(last_error("CreateJobObjectW"));
        }
        let job = Handle(job);
        configure_job(job.0, options.memory_bytes, options.cpu_seconds)?;
        let mut command = quote_command_line(&options.command);
        let mut application = wide_null(executable.as_os_str());
        let mut current_directory = wide_null(options.cwd.as_os_str());
        let appcontainer_attributes = appcontainer
            .map(AppContainerAttributes::create)
            .transpose()?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = if appcontainer_attributes.is_some() {
            size_of::<STARTUPINFOEXW>() as u32
        } else {
            size_of::<STARTUPINFOW>() as u32
        };
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        // Keep the helper's cancellation pipe private.  Passing the same
        // stdin handle to the restricted child would let the command consume
        // the cancellation byte before the helper sees it.
        startup.StartupInfo.hStdInput = null_mut();
        startup.StartupInfo.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        startup.StartupInfo.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        startup.lpAttributeList = appcontainer_attributes
            .as_ref()
            .map_or(null_mut(), |attributes| attributes.list);
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        let creation_flags = CREATE_NEW_PROCESS_GROUP
            | CREATE_SUSPENDED
            | CREATE_UNICODE_ENVIRONMENT
            | if appcontainer_attributes.is_some() {
                EXTENDED_STARTUPINFO_PRESENT
            } else {
                0
            };
        let created = if appcontainer.is_some() {
            unsafe {
                CreateProcessW(
                    application.as_mut_ptr(),
                    command.as_mut_ptr(),
                    null_mut(),
                    null_mut(),
                    1,
                    creation_flags,
                    null_mut(),
                    current_directory.as_mut_ptr(),
                    &startup.StartupInfo,
                    &mut information,
                )
            }
        } else {
            unsafe {
                CreateProcessAsUserW(
                    token.as_ref().map_or(null_mut(), |token| token.0),
                    application.as_mut_ptr(),
                    command.as_mut_ptr(),
                    null_mut(),
                    null_mut(),
                    1,
                    creation_flags,
                    null_mut(),
                    current_directory.as_mut_ptr(),
                    &startup.StartupInfo,
                    &mut information,
                )
            }
        };
        if created == 0 {
            return Err(last_error(if appcontainer.is_some() {
                "CreateProcessW"
            } else {
                "CreateProcessAsUserW"
            }));
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
        integrity: Option<IntegrityTransaction>,
        appcontainer_sid: Option<String>,
    }

    impl WorkspaceAcl {
        fn apply(workspace: &Path, appcontainer_sid: Option<&str>) -> Result<Self, String> {
            let integrity = if appcontainer_sid.is_some() {
                Some(IntegrityTransaction::capture(workspace).map_err(|error| {
                    format!("capture AppContainer workspace integrity: {error}")
                })?)
            } else {
                None
            };
            let backup = env::temp_dir().join(unique_rule_name("acl"));
            let save = vec![
                workspace.as_os_str().to_os_string(),
                OsString::from("/save"),
                backup.as_os_str().to_os_string(),
                OsString::from("/t"),
                OsString::from("/c"),
            ];
            run_icacls(&save).map_err(|error| format!("save workspace ACL: {error}"))?;
            let mut grant = vec![
                workspace.as_os_str().to_os_string(),
                OsString::from("/grant:r"),
                OsString::from("*S-1-5-12:(OI)(CI)F"),
            ];
            if let Some(sid) = appcontainer_sid {
                grant.extend([
                    OsString::from("/grant"),
                    OsString::from(format!("*{sid}:(OI)(CI)F")),
                ]);
                let integrity_args = vec![
                    workspace.as_os_str().to_os_string(),
                    OsString::from("/setintegritylevel"),
                    OsString::from("(OI)(CI)L"),
                    OsString::from("/t"),
                    OsString::from("/c"),
                ];
                if let Err(error) = run_icacls(&integrity_args) {
                    let restore = vec![
                        workspace.as_os_str().to_os_string(),
                        OsString::from("/restore"),
                        backup.as_os_str().to_os_string(),
                        OsString::from("/c"),
                    ];
                    let _ = run_icacls(&restore);
                    let _ = remove_workspace_grants(workspace, appcontainer_sid);
                    if let Some(integrity) = integrity {
                        let _ = integrity.restore();
                    }
                    let _ = std::fs::remove_file(&backup);
                    return Err(format!("set AppContainer workspace integrity: {error}"));
                }
            }
            grant.extend([OsString::from("/t"), OsString::from("/c")]);
            if let Err(error) = run_icacls(&grant) {
                let restore = vec![
                    workspace.as_os_str().to_os_string(),
                    OsString::from("/restore"),
                    backup.as_os_str().to_os_string(),
                    OsString::from("/c"),
                ];
                let _ = run_icacls(&restore);
                let _ = remove_workspace_grants(workspace, appcontainer_sid);
                if let Some(integrity) = integrity {
                    let _ = integrity.restore();
                }
                let _ = std::fs::remove_file(&backup);
                return Err(format!("grant restricted workspace ACL: {error}"));
            }
            Ok(Self {
                workspace: workspace.to_path_buf(),
                backup,
                integrity,
                appcontainer_sid: appcontainer_sid.map(str::to_owned),
            })
        }

        fn restore(self) -> Result<(), String> {
            let restore = vec![
                self.workspace.as_os_str().to_os_string(),
                OsString::from("/restore"),
                self.backup.as_os_str().to_os_string(),
                OsString::from("/c"),
            ];
            let mut errors = Vec::new();
            if let Err(error) =
                remove_workspace_grants(&self.workspace, self.appcontainer_sid.as_deref())
            {
                errors.push(format!("remove temporary workspace ACL grants: {error}"));
            }
            if let Err(error) = run_icacls(&restore) {
                errors.push(format!("restore workspace ACL: {error}"));
            }
            if let Some(integrity) = self.integrity {
                if let Err(error) = integrity.restore() {
                    errors.push(format!("restore workspace integrity: {error}"));
                }
            }
            if let Err(error) = std::fs::remove_file(&self.backup) {
                errors.push(format!("remove workspace ACL backup: {error}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    fn remove_workspace_grants(
        workspace: &Path,
        appcontainer_sid: Option<&str>,
    ) -> Result<(), String> {
        let mut arguments = vec![
            workspace.as_os_str().to_os_string(),
            OsString::from("/remove:g"),
            OsString::from("*S-1-5-12"),
        ];
        if let Some(sid) = appcontainer_sid {
            arguments.push(OsString::from(format!("*{sid}")));
        }
        arguments.extend([OsString::from("/t"), OsString::from("/c")]);
        run_icacls(&arguments)
    }

    /// Temporarily grants the restricted-code SID read/execute access to the
    /// resolved native runtime tree.  WRITE_RESTRICTED makes this SID the
    /// authority for writes, so a user-owned runtime that is writable by the
    /// interactive user must still be made explicitly read/execute-only for
    /// the child.  The executable directory and explicitly trusted runtime
    /// roots receive read/execute access; only execute/traverse is added to
    /// their ancestors. Every ACL is saved before mutation and restored
    /// before the helper reports success.
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
        fn apply(
            executable: &Path,
            appcontainer_sid: Option<&str>,
            additional_roots: &[PathBuf],
        ) -> Result<Self, String> {
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
            let mut roots = vec![runtime_root];
            roots.extend(additional_roots.iter().cloned());
            let mut entries = Vec::new();
            let mut seen_ancestors = HashSet::new();
            let mut seen_recursive = HashSet::new();
            for root in roots {
                let root = std::fs::canonicalize(&root)
                    .map_err(|e| format!("canonicalize Windows runtime root: {e}"))?;
                if !root.is_dir() {
                    return Err(format!(
                        "Windows sandbox runtime root is not a directory: {}",
                        root.display()
                    ));
                }
                if directory_ancestors(&root).is_empty() {
                    return Err(
                        "Windows sandbox refuses a volume-root runtime directory".to_string()
                    );
                }
                for ancestor in directory_ancestors(&root) {
                    if !seen_ancestors.insert(ancestor.clone()) {
                        continue;
                    }
                    if let Err(error) = apply_runtime_acl(
                        &ancestor,
                        &mut entries,
                        "*S-1-5-12:(X)",
                        appcontainer_sid,
                        false,
                    ) {
                        return Err(join_runtime_acl_error(error, entries));
                    }
                }
                // A root may first appear as another root's traversal
                // ancestor (for example venv\Scripts before venv).  That
                // must not suppress the recursive read/execute grant for
                // the root itself.
                if seen_recursive.insert(root.clone()) {
                    if let Err(error) = apply_runtime_acl(
                        &root,
                        &mut entries,
                        "*S-1-5-12:(OI)(CI)RX",
                        appcontainer_sid,
                        true,
                    ) {
                        return Err(join_runtime_acl_error(error, entries));
                    }
                }
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
        appcontainer_sid: Option<&str>,
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
        if let Some(sid) = appcontainer_sid {
            let app_permission = permission.strip_prefix("*S-1-5-12:").unwrap_or(permission);
            grant.extend([
                OsString::from("/grant"),
                OsString::from(format!("*{sid}:{app_permission}")),
            ]);
        }
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
                    program_rule_argument(&program),
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
                    program_rule_argument(&program),
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
                    program_rule_argument(&program),
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
                            program_rule_argument(&program),
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
                    program_rule_argument(&program),
                    "profile=any".to_string(),
                    "enable=yes".to_string(),
                ];
                run_netsh_dynamic(&args).map(|()| names.push(name))
            };
            if let Err(error) = result {
                remove_firewall_rules(&names);
                return Err(error);
            }
            // netsh returns after the policy transaction is accepted, while
            // the WFP provider may still be publishing the filter to the
            // active profile.  Do not spawn the restricted runtime during
            // that small propagation window.
            std::thread::sleep(Duration::from_millis(100));
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

    fn program_rule_argument(program: &str) -> String {
        // netsh's firewall grammar accepts a quoted program value.  Keep the
        // quotes in the single argv element so paths containing spaces are
        // still matched by the normalized application identity.
        format!(r#"program="{program}""#)
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
                "WFP firewall command failed (status={}): args={} stdout={} stderr={}",
                result.status,
                arguments.join(" "),
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
            let mut escaped = String::with_capacity(value.len() + 2);
            escaped.push('"');
            let mut backslashes = 0usize;
            for character in value.chars() {
                match character {
                    '\\' => backslashes += 1,
                    '"' => {
                        escaped.push_str(&"\\".repeat(backslashes * 2 + 1));
                        escaped.push('"');
                        backslashes = 0;
                    }
                    _ => {
                        escaped.push_str(&"\\".repeat(backslashes));
                        escaped.push(character);
                        backslashes = 0;
                    }
                }
            }
            // Backslashes immediately before the closing quote must also be
            // doubled, otherwise Windows removes them while parsing argv.
            escaped.push_str(&"\\".repeat(backslashes * 2));
            escaped.push('"');
            result.push(escaped);
        }
        wide_null(&result)
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(once(0)).collect()
    }

    fn sid_to_string(sid: PSID) -> Result<String, String> {
        let mut raw = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err(last_error("ConvertSidToStringSidW"));
        }
        let value = unsafe {
            let mut length = 0usize;
            while *raw.add(length) != 0 {
                length += 1;
            }
            OsString::from_wide(std::slice::from_raw_parts(raw, length))
        };
        let free_result = unsafe { LocalFree(raw as HLOCAL) };
        if !free_result.is_null() {
            return Err("LocalFree failed for converted SID".to_string());
        }
        value
            .into_string()
            .map_err(|_| "converted AppContainer SID is not valid UTF-16".to_string())
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
