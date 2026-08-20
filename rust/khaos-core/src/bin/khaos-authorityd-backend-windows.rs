//! Native SCM host for the Python authority backend on Windows.
//!
//! The Python daemon owns the authority protocol and signing state, but it is
//! not itself a Windows service executable.  This host is the service TCB: it
//! registers with SCM, starts the daemon with a fixed isolated entry point,
//! owns the child process in a kill-on-close Job Object, and proves terminal
//! child cleanup before reporting the service stopped.

#![cfg_attr(not(windows), allow(dead_code))]

// KHAOS-PRIVILEGED-SPAWN owner=AuthorityBackendServiceHost threat-model=trusted-backend-child-lifecycle boundary=windows-authority-backend-service

#[cfg(not(windows))]
fn main() {
    eprintln!("khaos-authorityd-backend-windows is Windows-only");
    std::process::exit(126);
}

#[cfg(windows)]
mod backend_service {
    use std::collections::BTreeMap;
    use std::env;
    use std::ffi::c_void;
    use std::fs::{self, metadata, symlink_metadata, File, OpenOptions};
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;
    use std::thread;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_ERROR_CRITICAL, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
        SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, SetEvent, WaitForSingleObject, CREATE_NO_WINDOW,
    };

    const SERVICE_NAME: &str = "KhaosAuthorityDBackend";
    const CONFIG_LIMIT_BYTES: u64 = 64 * 1024;
    const CHILD_STOP_TIMEOUT_MS: u32 = 10_000;
    const WAIT_OBJECT_0: u32 = 0;
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    const BACKEND_ENV_KEYS: &[&str] = &[
        "KHAOS_AUTHORITYD_NAMED_PIPE",
        "KHAOS_AUTHORITYD_BACKEND_PIPE",
        "KHAOS_AUTHORITYD_KEY_PATH",
        "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH",
        "KHAOS_TYPED_RESOURCE_CATALOG_PATH",
        "KHAOS_EFFECTIVE_POLICY_DIGEST",
        "KHAOS_AUTHORITYD_SERVICE_SID",
        "KHAOS_AGENT_SID",
        "KHAOS_AUTHORITYD_PROTECTED_KEY_REF",
        "KHAOS_AUDIT_WORM_ENDPOINT",
        "KHAOS_AUDIT_WORM_CA_FILE",
        "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT",
    ];

    static CONFIG: OnceLock<BackendConfig> = OnceLock::new();
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = null_mut();
    static mut STOP_EVENT: HANDLE = null_mut();

    #[derive(Debug)]
    struct BackendConfig {
        python: PathBuf,
        entry: PathBuf,
        log: PathBuf,
        environment: Vec<(String, String)>,
    }

    struct BackendJob(HANDLE);

    impl Drop for BackendJob {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn required(values: &BTreeMap<String, String>, name: &str) -> Result<String, String> {
        values
            .get(name)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("backend service configuration is missing {name}"))
    }

    fn canonical_file(value: &str, name: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(format!("{name} must be an absolute path"));
        }
        let metadata = symlink_metadata(&path).map_err(|_| format!("{name} is unavailable"))?;
        if !metadata.is_file() {
            return Err(format!("{name} must be a regular file"));
        }
        fs::canonicalize(&path).map_err(|_| format!("{name} cannot be canonicalized"))
    }

    fn parse_config(path: &Path) -> Result<BackendConfig, String> {
        let config_metadata = symlink_metadata(path)
            .map_err(|_| "backend service configuration is unavailable".to_string())?;
        if !config_metadata.is_file() || config_metadata.len() > CONFIG_LIMIT_BYTES {
            return Err("backend service configuration is not a bounded regular file".to_string());
        }
        let text = fs::read_to_string(path)
            .map_err(|_| "backend service configuration cannot be read".to_string())?;
        let mut values = BTreeMap::new();
        for (line_number, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                return Err(format!(
                    "backend service configuration line {} is malformed",
                    line_number + 1
                ));
            };
            if name == "KHAOS_AUTHORITYD_BACKEND_PYTHON"
                || name == "KHAOS_AUTHORITYD_BACKEND_ENTRY"
                || name == "KHAOS_AUTHORITYD_BACKEND_LOG"
                || BACKEND_ENV_KEYS.contains(&name)
            {
                if values.insert(name.to_string(), value.to_string()).is_some() {
                    return Err(format!("backend service configuration repeats {name}"));
                }
            } else {
                return Err(format!(
                    "backend service configuration contains unknown field {name}"
                ));
            }
        }

        let python = canonical_file(
            &required(&values, "KHAOS_AUTHORITYD_BACKEND_PYTHON")?,
            "KHAOS_AUTHORITYD_BACKEND_PYTHON",
        )?;
        let entry = canonical_file(
            &required(&values, "KHAOS_AUTHORITYD_BACKEND_ENTRY")?,
            "KHAOS_AUTHORITYD_BACKEND_ENTRY",
        )?;
        let log_value = required(&values, "KHAOS_AUTHORITYD_BACKEND_LOG")?;
        let log = PathBuf::from(log_value);
        if !log.is_absolute() {
            return Err("KHAOS_AUTHORITYD_BACKEND_LOG must be an absolute path".to_string());
        }
        let log_parent = log
            .parent()
            .ok_or_else(|| "KHAOS_AUTHORITYD_BACKEND_LOG has no parent".to_string())?;
        if !metadata(log_parent)
            .map_err(|_| "backend service log directory is unavailable".to_string())?
            .is_dir()
        {
            return Err("backend service log parent is not a directory".to_string());
        }
        if let Ok(log_metadata) = symlink_metadata(&log) {
            if !log_metadata.is_file() {
                return Err("backend service log is not a regular file".to_string());
            }
        }

        let mut environment = Vec::with_capacity(BACKEND_ENV_KEYS.len());
        for name in BACKEND_ENV_KEYS {
            environment.push((name.to_string(), required(&values, name)?));
        }
        Ok(BackendConfig {
            python,
            entry,
            log,
            environment,
        })
    }

    fn open_log(path: &Path) -> Result<(File, File), String> {
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| "backend service log cannot be opened".to_string())?;
        let stderr = stdout
            .try_clone()
            .map_err(|_| "backend service log cannot be duplicated".to_string())?;
        Ok((stdout, stderr))
    }

    fn reap_unowned_child(child: &mut Child) -> Result<(), String> {
        let _ = child.kill();
        child
            .wait()
            .map(|_| ())
            .map_err(|error| format!("unowned authority backend cleanup failed: {error}"))
    }

    fn spawn_backend(config: &BackendConfig) -> Result<(Child, BackendJob), String> {
        let (stdout, stderr) = open_log(&config.log)?;
        let system_root = env::var("SystemRoot")
            .map_err(|_| "SystemRoot is unavailable to the backend service".to_string())?;
        let system_path = format!(r"{system_root}\System32;{system_root}");
        let temp = format!(r"{system_root}\Temp");
        let mut command = Command::new(&config.python);
        command
            .args(["-I", "-S"])
            .arg(&config.entry)
            .current_dir(
                config
                    .entry
                    .parent()
                    .ok_or_else(|| "backend entry point has no parent".to_string())?,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .creation_flags(CREATE_NO_WINDOW)
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("PATH", system_path)
            .env("TEMP", &temp)
            .env("TMP", &temp);
        for (name, value) in &config.environment {
            command.env(name, value);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("authority backend spawn failed: {error}"))?;
        let process = child.as_raw_handle() as HANDLE;
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            let error = format!("CreateJobObjectW failed: {}", unsafe { GetLastError() });
            if let Err(cleanup) = reap_unowned_child(&mut child) {
                return Err(format!("{error}; {cleanup}"));
            }
            return Err(error);
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0;
        if !configured {
            let error = format!("SetInformationJobObject failed: {}", unsafe {
                GetLastError()
            });
            unsafe { CloseHandle(job) };
            if let Err(cleanup) = reap_unowned_child(&mut child) {
                return Err(format!("{error}; {cleanup}"));
            }
            return Err(error);
        }
        if unsafe { AssignProcessToJobObject(job, process) } == 0 {
            let error = format!("AssignProcessToJobObject failed: {}", unsafe {
                GetLastError()
            });
            unsafe {
                TerminateJobObject(job, 1);
                CloseHandle(job);
            }
            if let Err(cleanup) = reap_unowned_child(&mut child) {
                return Err(format!("{error}; {cleanup}"));
            }
            return Err(error);
        }
        Ok((child, BackendJob(job)))
    }

    fn terminate_backend(child: &Child, job: &BackendJob) -> Result<(), String> {
        if unsafe { TerminateJobObject(job.0, 1) } == 0 {
            return Err(format!("TerminateJobObject failed: {}", unsafe {
                GetLastError()
            }));
        }
        let process = child.as_raw_handle() as HANDLE;
        let wait = unsafe { WaitForSingleObject(process, CHILD_STOP_TIMEOUT_MS) };
        if wait != WAIT_OBJECT_0 {
            return Err(format!(
                "authority backend process did not reach terminal state: wait={wait}"
            ));
        }
        let deadline =
            std::time::Instant::now() + Duration::from_millis(CHILD_STOP_TIMEOUT_MS as u64);
        loop {
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            let queried = unsafe {
                QueryInformationJobObject(
                    job.0,
                    JobObjectBasicAccountingInformation,
                    &mut accounting as *mut _ as *mut c_void,
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                )
            } != 0;
            if !queried {
                return Err(format!("QueryInformationJobObject failed: {}", unsafe {
                    GetLastError()
                }));
            }
            if accounting.ActiveProcesses == 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "authority backend process domain is not terminal: active_processes={}",
                    accounting.ActiveProcesses
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    unsafe fn set_service_state(state: u32, controls: u32, wait_hint: u32, error: u32) {
        if STATUS_HANDLE.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: error,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        SetServiceStatus(STATUS_HANDLE, &status);
    }

    fn stop_requested() -> bool {
        let event = unsafe { STOP_EVENT };
        !event.is_null() && unsafe { WaitForSingleObject(event, 0) == WAIT_OBJECT_0 }
    }

    fn run_service(config: &BackendConfig) -> Result<(), String> {
        let (mut child, job) = spawn_backend(config)?;
        unsafe { set_service_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0) };
        loop {
            if stop_requested() {
                unsafe { set_service_state(SERVICE_STOP_PENDING, 0, CHILD_STOP_TIMEOUT_MS, 0) };
                let result = terminate_backend(&child, &job);
                drop(job);
                let process = child.as_raw_handle() as HANDLE;
                let terminal = unsafe { WaitForSingleObject(process, CHILD_STOP_TIMEOUT_MS) };
                if terminal != WAIT_OBJECT_0 {
                    return Err(format!(
                        "authority backend process did not reach terminal state after job close: wait={terminal}"
                    ));
                }
                let _ = child.wait();
                return result;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("authority backend wait failed: {error}"))?
            {
                return Err(format!("authority backend exited unexpectedly: {status:?}"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    unsafe extern "system" fn service_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            set_service_state(SERVICE_STOP_PENDING, 0, CHILD_STOP_TIMEOUT_MS, 0);
            if !STOP_EVENT.is_null() {
                SetEvent(STOP_EVENT);
            }
        }
        0
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let service_name = wide(SERVICE_NAME);
        let status =
            RegisterServiceCtrlHandlerExW(service_name.as_ptr(), Some(service_handler), null_mut());
        if status.is_null() {
            return;
        }
        STATUS_HANDLE = status;
        set_service_state(SERVICE_START_PENDING, 0, CHILD_STOP_TIMEOUT_MS, 0);
        let event = CreateEventW(null(), 1, 0, null());
        if event.is_null() {
            set_service_state(SERVICE_STOPPED, 0, 0, SERVICE_ERROR_CRITICAL);
            return;
        }
        STOP_EVENT = event;
        let result = match CONFIG.get() {
            Some(config) => run_service(config),
            None => Err("backend service configuration was not loaded".to_string()),
        };
        if let Err(error) = result {
            eprintln!("khaos-authorityd-backend-windows: {error}");
            set_service_state(SERVICE_STOPPED, 0, 0, SERVICE_ERROR_CRITICAL);
        } else {
            set_service_state(SERVICE_STOPPED, 0, 0, 0);
        }
        STOP_EVENT = null_mut();
        CloseHandle(event);
        STATUS_HANDLE = null_mut();
    }

    pub fn run() -> i32 {
        let arguments: Vec<String> = env::args().collect();
        if arguments.len() != 3 || arguments[1] != "--config" {
            eprintln!("usage: khaos-authorityd-backend-windows --config <absolute path>");
            return 78;
        }
        let config_path = PathBuf::from(&arguments[2]);
        if !config_path.is_absolute() {
            eprintln!("backend service configuration path must be absolute");
            return 78;
        }
        let config_path = match fs::canonicalize(config_path) {
            Ok(path) => path,
            Err(_) => {
                eprintln!("backend service configuration cannot be canonicalized");
                return 78;
            }
        };
        let config = match parse_config(&config_path) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("{error}");
                return 78;
            }
        };
        if CONFIG.set(config).is_err() {
            eprintln!("backend service configuration was initialized twice");
            return 78;
        }
        let service_name = wide(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            eprintln!("StartServiceCtrlDispatcherW failed: {}", unsafe {
                GetLastError()
            });
            return 78;
        }
        0
    }
}

#[cfg(windows)]
fn main() {
    std::process::exit(backend_service::run());
}
