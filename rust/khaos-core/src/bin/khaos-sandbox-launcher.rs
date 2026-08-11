//! Fail-closed inner launcher for the Linux execution sandbox.

// KHAOS-PRIVILEGED-SPAWN owner=LinuxSandboxLauncher threat-model=seccomp-landlock-bwrap-boundary boundary=linux-sandbox

#[cfg(target_os = "linux")]
mod linux {
    use _khaos_core::browser_kernel_protocol_generated::{
        BrowserKernelOperation as HelperOperation, BrowserKernelRequest as HelperRequest,
        BrowserKernelResponseOwned as HelperResponse, MAX_MESSAGE_BYTES as HELPER_MAX_MESSAGE,
        PROTOCOL_VERSION as HELPER_PROTOCOL_VERSION,
    };
    use std::env;
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const DEFAULT_HELPER_SOCKET: &str = "/run/khaos/browser-kernel-helper.sock";

    // Landlock syscall numbers are stable across the supported Linux
    // architectures.  Keep them local instead of depending on the libc crate
    // exposing a kernel-header version newer than the runner's headers.
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const LANDLOCK_RULE_TYPE_PATH_BENEATH: libc::c_uint = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_MAKE_WATCH: u64 = 1 << 15;
    const LANDLOCK_CREATE_RULESET_VERSION_FLAG: libc::c_uint = 1;
    const O_PATH_FLAG: libc::c_int = 0o10000000;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn landlock_abi() -> io::Result<i32> {
        let result = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<LandlockRulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION_FLAG,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result as i32)
    }

    fn landlock_access_masks(abi: i32) -> io::Result<(u64, u64)> {
        if abi < 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Landlock filesystem ABI is unavailable",
            ));
        }
        let read =
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
        let mut write = LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            write |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            write |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            write |= LANDLOCK_ACCESS_FS_MAKE_WATCH;
        }
        Ok((read, read | write))
    }

    fn landlock_paths(variable: &str) -> io::Result<Vec<String>> {
        let raw = env::var(variable).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{variable} is missing from the sandbox environment"),
            )
        })?;
        let paths: Vec<String> = serde_json::from_str(&raw).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{variable} is not a JSON path list: {error}"),
            )
        })?;
        if paths
            .iter()
            .any(|path| path.is_empty() || !path.starts_with('/') || path.as_bytes().contains(&0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{variable} contains an invalid absolute path"),
            ));
        }
        Ok(paths)
    }

    fn add_landlock_path(ruleset_fd: RawFd, path: &str, access: u64) -> io::Result<()> {
        let c_path = CString::new(path).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Landlock path contained NUL")
        })?;
        let descriptor = unsafe {
            libc::open(
                c_path.as_ptr(),
                O_PATH_FLAG | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "open Landlock allow path {path}: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        let rule = LandlockPathBeneathAttr {
            allowed_access: access,
            parent_fd: descriptor,
        };
        let result = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_TYPE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        let close_result = unsafe { libc::close(descriptor) };
        if close_result != 0 && result >= 0 {
            return Err(io::Error::last_os_error());
        }
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn install_landlock_if_required() -> io::Result<()> {
        if env::var("KHAOS_LANDLOCK_REQUIRED").as_deref() != Ok("1") {
            return Ok(());
        }
        let abi = landlock_abi().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Landlock is required but unavailable: {error}"),
            )
        })?;
        let (read_access, write_access) = landlock_access_masks(abi)?;
        let attr = LandlockRulesetAttr {
            handled_access_fs: write_access,
            handled_access_net: 0,
            scoped: 0,
        };
        let ruleset_fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };
        if ruleset_fd < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!("create Landlock ruleset: {}", io::Error::last_os_error()),
            ));
        }
        let ruleset_fd = ruleset_fd as RawFd;
        let result = (|| {
            for path in landlock_paths("KHAOS_LANDLOCK_READ_ROOTS")? {
                add_landlock_path(ruleset_fd, &path, read_access)?;
            }
            for path in landlock_paths("KHAOS_LANDLOCK_WRITE_ROOTS")? {
                add_landlock_path(ruleset_fd, &path, write_access)?;
            }
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let restricted = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
            if restricted < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        unsafe { libc::close(ruleset_fd) };
        result
    }

    #[cfg(target_arch = "x86_64")]
    fn audit_arch() -> u32 {
        AUDIT_ARCH_X86_64
    }

    #[cfg(target_arch = "aarch64")]
    fn audit_arch() -> u32 {
        AUDIT_ARCH_AARCH64
    }

    fn denied_syscalls() -> &'static [libc::c_long] {
        // Batch 7.6 (round-7 §二十五): io_uring syscalls added to match
        // the Codex restricted-execution model.  io_uring expands the
        // async kernel-I/O attack surface; denying it keeps the sandbox
        // to the classic synchronous syscall set.
        &[
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_open_by_handle_at,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_userfaultfd,
            libc::SYS_perf_event_open,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ]
    }

    fn install_seccomp() -> io::Result<()> {
        let mut filter = vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, 4),
            jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch(), 1, 0),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD | BPF_W | BPF_ABS, 0),
        ];
        for syscall in denied_syscalls() {
            filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *syscall as u32, 0, 1));
            filter.push(stmt(
                BPF_RET | BPF_K,
                SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ));
        }
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        let mut program = libc::sock_fprog {
            len: filter
                .len()
                .try_into()
                .map_err(|_| io::Error::other("filter too large"))?,
            filter: filter.as_mut_ptr(),
        };
        let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if no_new_privs != 0 {
            return Err(io::Error::last_os_error());
        }
        let applied = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &mut program as *mut libc::sock_fprog,
            )
        };
        if applied != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn exec(args: &[std::ffi::OsString]) -> io::Result<()> {
        if args.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command required",
            ));
        }
        let program = CString::new(args[0].as_bytes())?;
        let c_args: Result<Vec<_>, _> = args
            .iter()
            .map(|arg| CString::new(arg.as_bytes()))
            .collect();
        let c_args = c_args?;
        let mut pointers: Vec<_> = c_args.iter().map(|arg| arg.as_ptr()).collect();
        pointers.push(std::ptr::null());
        unsafe { libc::execvp(program.as_ptr(), pointers.as_ptr()) };
        Err(io::Error::last_os_error())
    }

    /// Batch 7.4 (round-7 §十一): close every inherited file descriptor
    /// greater than ``stderr`` before exec'ing the browser, so a
    /// compromised renderer cannot reach privileged fds held by the
    /// launcher (e.g. the netns fd, the cgroup file, library fds).
    /// Uses ``close_range`` when available (Linux 5.9+); falls back to
    /// iterating ``/proc/self/fd``.
    fn sanitize_fds_except(preserved: &[i32]) -> io::Result<()> {
        // Browser pipe transport is deliberately inherited on fd 3/4.
        // close_range cannot express holes, so close the ranges around the
        // small, validated preserve set.
        let mut keep: Vec<u32> = preserved
            .iter()
            .copied()
            .filter(|fd| *fd > 2)
            .map(|fd| fd as u32)
            .collect();
        keep.sort_unstable();
        keep.dedup();
        // Try close_range(3, ~0u, CLOSE_RANGE_UNSHARE).  We do NOT unshare
        // the fd table (the flag is 0) so the launcher's own fds used
        // during setup are already closed by this point.
        const CLOSE_RANGE_FD_MASK: u32 = 0;
        let mut start = 3u32;
        let mut close_range_supported = true;
        for end in keep.iter().copied().chain(std::iter::once(u32::MAX)) {
            if start < end {
                let ret = unsafe {
                    libc::syscall(libc::SYS_close_range, start, end - 1, CLOSE_RANGE_FD_MASK)
                };
                if ret != 0 {
                    close_range_supported = false;
                    break;
                }
            }
            if end == u32::MAX {
                break;
            }
            start = end.saturating_add(1);
        }
        if close_range_supported {
            return Ok(());
        }
        // Fallback: iterate /proc/self/fd.  close_range may be absent on
        // older kernels (ENOSYS) — the errno is checked by the fallback.
        let entries = std::fs::read_dir("/proc/self/fd")
            .map_err(|e| io::Error::new(e.kind(), format!("read /proc/self/fd: {e}")))?;
        // Collect before closing: the iterator itself owns a directory fd.
        let fds: Vec<i32> = entries
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|name| name.parse::<i32>().ok())
            .collect();
        for fd in fds {
            if fd > 2 && !preserved.contains(&fd) {
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    /// Batch 7.4 (round-7 §十一): join a named network namespace by
    /// opening ``/var/run/netns/<name>`` and calling ``setns(fd,
    /// CLONE_NEWNET)``.  Must run BEFORE seccomp installs (the filter
    /// denies ``setns`` so a later-compromised browser cannot escape).
    fn join_netns(name: &str) -> io::Result<()> {
        validate_netns_name(name)?;
        let authority = CString::new("/var/run/netns").map_err(io::Error::other)?;
        let directory = unsafe {
            libc::open(
                authority.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if directory < 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = unsafe { OwnedFd::from_raw_fd(directory) };
        let entry = CString::new(name).map_err(io::Error::other)?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                entry.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        validate_namespace_fd(descriptor.as_raw_fd())?;
        let rc = unsafe { libc::setns(descriptor.as_raw_fd(), libc::CLONE_NEWNET) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn validate_netns_name(name: &str) -> io::Result<()> {
        if name == "."
            || name == ".."
            || name.contains('/')
            || !name.starts_with("khaos-br-")
            || name.len() != 21
            || !name[9..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid managed netns name",
            ));
        }
        Ok(())
    }

    fn validate_namespace_fd(descriptor: RawFd) -> io::Result<()> {
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "network namespace descriptor is not a regular namespace file",
            ));
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(descriptor, &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        const NSFS_MAGIC: libc::c_long = 0x6e736673;
        if filesystem.f_type != NSFS_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "network namespace descriptor is not nsfs",
            ));
        }
        Ok(())
    }

    fn drop_join_capabilities() -> io::Result<()> {
        #[repr(C)]
        struct CapabilityHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapabilityData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        let header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if unsafe { libc::syscall(libc::SYS_capset, &header, &data) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn join_browser_authority(
        principal_id: &str,
        project_id: &str,
        runtime_id: &str,
        task_id: &str,
        token: &str,
    ) -> io::Result<()> {
        validate_authority_identifier(principal_id, "principal_id")?;
        validate_authority_identifier(project_id, "project_id")?;
        validate_authority_identifier(runtime_id, "runtime_id")?;
        validate_authority_identifier(task_id, "task_id")?;
        if token.len() < 32
            || token.len() > 256
            || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sandbox token",
            ));
        }
        let socket_path = env::var("KHAOS_BROWSER_KERNEL_HELPER_SOCKET")
            .unwrap_or_else(|_| DEFAULT_HELPER_SOCKET.to_owned());
        validate_helper_socket(&socket_path)?;
        let client_pid = std::process::id();
        let client_start_time = process_start_time(client_pid)?;
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();

        // Capabilities are bound to the exact launcher PID/start-time.  The
        // Python client's capability therefore cannot be replayed by this
        // child: authorize this peer first, then use the returned capability
        // for the descriptor-bearing join request.
        let authorize_id = format!("authorize-{client_pid}-{client_start_time}");
        let authorize = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: authorize_id.clone(),
            boot_id: boot_id.clone(),
            client_pid,
            client_start_time,
            principal_id: principal_id.to_owned(),
            project_id: project_id.to_owned(),
            runtime_id: runtime_id.to_owned(),
            task_id: task_id.to_owned(),
            sandbox_token: token.to_owned(),
            runtime_capability: None,
            op: HelperOperation::Authorize,
            port: None,
            target_pid: None,
            target_start_time: None,
        };
        let mut authorize_stream = connect_helper(&socket_path)?;
        send_helper_request(&mut authorize_stream, &authorize)?;
        let authorize_response = receive_helper_response(&mut authorize_stream)?;
        validate_helper_response(&authorize_response, &authorize_id)?;
        let capability = authorize_response.runtime_capability.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper runtime capability missing",
            )
        })?;
        if capability.len() != 64 || !capability.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper runtime capability invalid",
            ));
        }

        let request_id = format!("join-{client_pid}-{client_start_time}");
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request_id.clone(),
            boot_id,
            client_pid,
            client_start_time,
            principal_id: principal_id.to_owned(),
            project_id: project_id.to_owned(),
            runtime_id: runtime_id.to_owned(),
            task_id: task_id.to_owned(),
            sandbox_token: token.to_owned(),
            runtime_capability: Some(capability),
            op: HelperOperation::Join,
            port: None,
            target_pid: None,
            target_start_time: None,
        };
        let mut stream = connect_helper(&socket_path)?;
        send_helper_request(&mut stream, &request)?;
        let (response, namespace) = receive_helper_fd(&mut stream)?;
        validate_helper_response(&response, &request_id)?;
        if response.runtime_capability.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "join response leaked a runtime capability",
            ));
        }
        let namespace = namespace.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper namespace descriptor missing",
            )
        })?;
        let status = response
            .status
            .ok_or_else(|| io::Error::other("helper isolation evidence missing"))?;
        if !status.helper_authenticated
            || !status.network_namespace
            || !status.nft_default_deny
            || !status.cgroup_attached
            || !status.process_isolated
            || !status.resource_registry_verified
            || status.quarantined
            || status.proxy_host.parse::<std::net::IpAddr>().is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper returned incomplete or quarantined isolation evidence",
            ));
        }
        validate_namespace_fd(namespace.as_raw_fd())?;
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("join helper-owned network namespace: {error}"),
            ));
        }
        drop_join_capabilities().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("drop launcher join capabilities: {error}"),
            )
        })?;
        Ok(())
    }

    fn validate_authority_identifier(value: &str, label: &str) -> io::Result<()> {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {label}"),
            ));
        }
        Ok(())
    }

    fn validate_helper_socket(path: &str) -> io::Result<()> {
        let path = Path::new(path);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper socket path must be absolute",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("helper socket parent missing"))?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if parent_metadata.uid() != 0 || parent_metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper socket parent is not protected",
            ));
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper socket type or mode invalid",
            ));
        }
        Ok(())
    }

    fn validate_helper_peer(stream: &UnixStream) -> io::Result<()> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if cred.uid != 0 || cred.pid <= 1 || process_start_time(cred.pid as u32)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper peer identity invalid",
            ));
        }
        Ok(())
    }

    fn process_start_time(pid: u32) -> io::Result<u64> {
        let value = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let end = value
            .rfind(')')
            .ok_or_else(|| io::Error::other("invalid proc stat"))?;
        value[end + 2..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::other("missing process start time"))?
            .parse()
            .map_err(io::Error::other)
    }

    fn connect_helper(socket_path: &str) -> io::Result<UnixStream> {
        let stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        validate_helper_peer(&stream)?;
        Ok(stream)
    }

    fn send_helper_request(stream: &mut UnixStream, request: &HelperRequest) -> io::Result<()> {
        let data = serde_json::to_vec(request).map_err(io::Error::other)?;
        if data.is_empty() || data.len() > HELPER_MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper request too large",
            ));
        }
        stream.write_all(&(data.len() as u32).to_be_bytes())?;
        stream.write_all(&data)
    }

    fn validate_helper_response(response: &HelperResponse, request_id: &str) -> io::Result<()> {
        if response.protocol_version != HELPER_PROTOCOL_VERSION || response.request_id != request_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper response identity invalid",
            ));
        }
        if !response.ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                response
                    .error
                    .clone()
                    .unwrap_or_else(|| "helper rejected request".to_owned()),
            ));
        }
        if response.error.is_some() || response.error_code.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "successful helper response carried an error",
            ));
        }
        Ok(())
    }

    fn receive_helper_response(stream: &mut UnixStream) -> io::Result<HelperResponse> {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > HELPER_MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "helper response length invalid",
            ));
        }
        let mut data = vec![0_u8; length];
        stream.read_exact(&mut data)?;
        serde_json::from_slice(&data).map_err(io::Error::other)
    }

    fn receive_helper_fd(stream: &mut UnixStream) -> io::Result<(HelperResponse, Option<OwnedFd>)> {
        let mut data = vec![0_u8; HELPER_MAX_MESSAGE + 4];
        let mut vector = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let control_length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
        let mut control = vec![0_u8; control_length as usize];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received <= 0 {
            return Err(if received < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(io::ErrorKind::UnexpectedEof, "empty helper response")
            });
        }
        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "helper descriptor control data truncated",
            ));
        }
        let mut total = received as usize;
        if total < 4 {
            stream.read_exact(&mut data[total..4])?;
            total = 4;
        }
        let length = u32::from_be_bytes(data[..4].try_into().map_err(io::Error::other)?) as usize;
        let frame_length = length.saturating_add(4);
        if length == 0 || length > HELPER_MAX_MESSAGE || total > frame_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "helper response length invalid",
            ));
        }
        if total < frame_length {
            stream.read_exact(&mut data[total..frame_length])?;
        }
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        let descriptor = if header.is_null() {
            None
        } else {
            if unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
                || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
                || unsafe { (*header).cmsg_len }
                    != unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize }
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "helper namespace descriptor invalid",
                ));
            }
            let descriptor = unsafe { *libc::CMSG_DATA(header).cast::<RawFd>() };
            if descriptor < 0 {
                return Err(io::Error::other("helper namespace descriptor invalid"));
            }
            Some(unsafe { OwnedFd::from_raw_fd(descriptor) })
        };
        let response = serde_json::from_slice::<HelperResponse>(&data[4..4 + length])
            .map_err(io::Error::other)?;
        Ok((response, descriptor))
    }

    /// Move this process into an existing cgroup-v2 leaf without applying
    /// ordinary-file creation or truncation flags to the cgroupfs control
    /// file.  `std::fs::write` uses `File::create`, whose O_CREAT/O_TRUNC
    /// semantics are inappropriate for kernel pseudo-files and can be
    /// rejected with EROFS even when the delegated control file is writable.
    fn join_cgroup(procs: &std::ffi::OsStr) -> io::Result<()> {
        let path = PathBuf::from(procs);
        if path.file_name() != Some(std::ffi::OsStr::new("cgroup.procs"))
            || !path.starts_with("/sys/fs/cgroup")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup target must be an absolute cgroup.procs path",
            ));
        }
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "cgroup path contained NUL")
        })?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("open cgroup.procs: {error}; {}", cgroup_context()),
            ));
        }
        let pid = b"0\n";
        let written = unsafe { libc::write(fd, pid.as_ptr().cast(), pid.len()) };
        let write_error = if written < 0 {
            let error = io::Error::last_os_error();
            Some(io::Error::new(
                error.kind(),
                format!("write cgroup.procs: {error}; {}", cgroup_context()),
            ))
        } else if written as usize != pid.len() {
            Some(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to cgroup.procs",
            ))
        } else {
            None
        };
        let close_result = unsafe { libc::close(fd) };
        if let Some(error) = write_error {
            return Err(error);
        }
        if close_result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn cgroup_context() -> String {
        let membership = std::fs::read_to_string("/proc/self/cgroup")
            .unwrap_or_else(|error| format!("unavailable:{error}"))
            .trim()
            .replace('\n', ",");
        let mount = std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.contains(" - cgroup2 "))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unavailable".to_string());
        format!(
            "euid={} cgroup={} mount={}",
            unsafe { libc::geteuid() },
            membership,
            mount
        )
    }

    fn validate_control_channel(fd: i32, needs_read: bool) -> io::Result<()> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let file_type = stat.st_mode & libc::S_IFMT;
        if file_type != libc::S_IFIFO && file_type != libc::S_IFSOCK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Playwright control fd {fd} is not a pipe/socket channel"),
            ));
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let access = flags & libc::O_ACCMODE;
        let wrong_direction = if needs_read {
            access == libc::O_WRONLY
        } else {
            access == libc::O_RDONLY
        };
        if wrong_direction {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Playwright control fd {fd} has invalid access direction"),
            ));
        }
        Ok(())
    }

    /// Bubblewrap deliberately closes non-stdio descriptors and released
    /// Ubuntu versions do not expose a portable arbitrary-FD preservation
    /// option. Bridge Playwright's read/write pipes across the bwrap exec via
    /// stdin/stdout, which bwrap preserves by contract. The inner launcher
    /// restores the canonical Chromium FD 3/4 layout before installing
    /// seccomp and execing the browser.
    fn bridge_playwright_pipes_to_stdio() -> io::Result<()> {
        validate_control_channel(3, true)?;
        validate_control_channel(4, false)?;
        if unsafe { libc::dup2(3, libc::STDIN_FILENO) } < 0
            || unsafe { libc::dup2(4, libc::STDOUT_FILENO) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn restore_playwright_pipes_from_stdio() -> io::Result<()> {
        if unsafe { libc::dup2(libc::STDIN_FILENO, 3) } < 0
            || unsafe { libc::dup2(libc::STDOUT_FILENO, 4) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        validate_control_channel(3, true)?;
        validate_control_channel(4, false)?;

        let dev_null = CString::new("/dev/null").expect("static path has no NUL");
        let null_fd = unsafe { libc::open(dev_null.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if null_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let redirect_result = if unsafe { libc::dup2(null_fd, libc::STDIN_FILENO) } < 0
            || unsafe { libc::dup2(null_fd, libc::STDOUT_FILENO) } < 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        unsafe { libc::close(null_fd) };
        redirect_result
    }

    pub fn run() -> io::Result<()> {
        let mut args: Vec<_> = env::args_os().skip(1).collect();

        // Round 8: Playwright executes this binary directly.  The immutable
        // launch metadata is child-only environment supplied by
        // BrowserManager; Chromium flags remain in argv exactly as Playwright
        // produced them.  No forwarding shell participates in production.
        if env::var_os("KHAOS_BROWSER_LAUNCH").as_deref() == Some(std::ffi::OsStr::new("1")) {
            let real = env::var_os("KHAOS_BROWSER_REAL_EXECUTABLE").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing browser executable")
            })?;
            if env::var_os("KHAOS_BROWSER_AUTHORITY").as_deref() == Some(std::ffi::OsStr::new("1"))
            {
                let principal_id = env::var("KHAOS_BROWSER_PRINCIPAL_ID")
                    .map_err(|_| io::Error::other("browser principal identity missing"))?;
                let project_id = env::var("KHAOS_BROWSER_PROJECT_ID")
                    .map_err(|_| io::Error::other("browser project identity missing"))?;
                let runtime_id = env::var("KHAOS_BROWSER_RUNTIME_ID")
                    .map_err(|_| io::Error::other("browser runtime identity missing"))?;
                let task_id = env::var("KHAOS_BROWSER_TASK_ID")
                    .map_err(|_| io::Error::other("browser task identity missing"))?;
                let token = env::var("KHAOS_BROWSER_SANDBOX_TOKEN")
                    .map_err(|_| io::Error::other("browser sandbox token missing"))?;
                join_browser_authority(&principal_id, &project_id, &runtime_id, &task_id, &token)?;
            } else {
                if env::var_os("KHAOS_DEV_MODE").as_deref() != Some(std::ffi::OsStr::new("1")) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "legacy browser netns contract is development-only",
                    ));
                }
                let netns = env::var("KHAOS_BROWSER_NETNS").map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing browser netns")
                })?;
                if let Some(procs) = env::var_os("KHAOS_BROWSER_CGROUP_PROCS") {
                    join_cgroup(&procs).map_err(|error| {
                        io::Error::new(error.kind(), format!("join browser cgroup: {error}"))
                    })?;
                }
                join_netns(&netns).map_err(|error| {
                    io::Error::new(error.kind(), format!("join browser netns: {error}"))
                })?;
            }

            let launcher_path = env::current_exe().map_err(|error| {
                io::Error::new(error.kind(), format!("resolve launcher image: {error}"))
            })?;
            let launcher_c_path = CString::new(launcher_path.as_os_str().as_encoded_bytes())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "launcher path contained NUL")
                })?;
            // Intentionally omit O_CLOEXEC: --ro-bind-data consumes this
            // descriptor inside bwrap, allowing the verified running image
            // to cross the user-namespace boundary without reopening a
            // private parent directory by pathname.
            let launcher_fd = unsafe { libc::open(launcher_c_path.as_ptr(), libc::O_RDONLY) };
            if launcher_fd < 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("open launcher image: {error}"),
                ));
            }

            let real_path = PathBuf::from(&real);
            let real_parent = real_path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "browser executable has no parent",
                )
            })?;
            let real_name = real_path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "browser executable has no filename",
                )
            })?;
            let inner_real = PathBuf::from("/run/khaos-browser/runtime").join(real_name);

            // Batch 9.2 (round-9 §十): resolve the REAL host home so we can
            // mask it even when it lives outside /home or /root (e.g.
            // /var/lib/khaos, /srv/khaos).  Python passes the resolved path.
            let host_home = env::var("KHAOS_BROWSER_HOST_HOME")
                .ok()
                .filter(|s| !s.is_empty());
            // Batch 9.3 (round-9 §十二): use the validated absolute bubblewrap
            // Batch 11.3 (round-11 §六): bwrap MUST be supplied by Python
            // via KHAOS_BROWSER_BWRAP_PATH (validated absolute path).  The
            // old fallback to a bare "bwrap" PATH lookup allowed a
            // pre-sandbox attacker to hijack bubblewrap.  Now a missing
            // env var is a hard error (the Python side is responsible for
            // resolving + validating bwrap before launching).
            let bwrap_exe = match env::var_os("KHAOS_BROWSER_BWRAP_PATH") {
                Some(path) if !path.is_empty() => path,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "KHAOS_BROWSER_BWRAP_PATH not set — bubblewrap absolute path required (no PATH fallback)",
                    ));
                }
            };

            // Batch 9.2: sensitive host paths that must NEVER be readable
            // from inside the browser namespace, regardless of the ro-bind
            // of /.  tmpfs overwrites the ro-bind at these mount points.
            let sensitive_host_paths: [&str; 5] =
                ["/workspace", "/srv", "/data", "/mnt", "/var/lib"];

            // Batch 11.5 + 12.6 (round-11 §八 + round-12 §九): EMPTY-ROOT
            // ALLOWLIST with MINIMAL /etc.  Previously /etc was bound as
            // an entire tree, exposing /etc/shadow, application secrets,
            // and machine identity files.  Now /etc is NOT bound as a
            // whole — only the specific files Chromium needs are bound
            // individually.
            let allowlist_ro_binds: [&str; 5] = ["/usr", "/lib", "/lib64", "/bin", "/sbin"];
            // Batch 12.6: minimal /etc files (not the whole tree).
            let etc_files: [&str; 9] = [
                "/etc/hosts",
                "/etc/hostname",
                "/etc/resolv.conf",
                "/etc/nsswitch.conf",
                "/etc/passwd",
                "/etc/localtime",
                "/etc/ssl/certs",
                "/etc/ca-certificates",
                "/etc/machine-id",
            ];

            let mut bwrap_args: Vec<std::ffi::OsString> = vec![
                bwrap_exe,
                "--die-with-parent".into(),
                "--new-session".into(),
                "--unshare-user-try".into(),
                "--unshare-pid".into(),
                "--unshare-ipc".into(),
                "--unshare-uts".into(),
            ];
            // Mount only the allowlisted runtime trees (each must exist).
            for path in allowlist_ro_binds {
                if Path::new(path).is_dir() {
                    bwrap_args.push("--ro-bind".into());
                    bwrap_args.push(path.into());
                    bwrap_args.push(path.into());
                }
            }
            // Batch 12.6: mount only the minimal /etc files (not /etc as
            // a whole tree).  Each file must exist on the host.
            for path in etc_files {
                let p = Path::new(path);
                if p.exists() {
                    bwrap_args.push("--ro-bind".into());
                    bwrap_args.push(path.into());
                    bwrap_args.push(path.into());
                }
            }
            bwrap_args.extend([
                "--dev".into(),
                "/dev".into(),
                "--proc".into(),
                "/proc".into(),
                "--tmpfs".into(),
                "/tmp".into(),
                "--tmpfs".into(),
                "/run".into(),
                "--tmpfs".into(),
                "/home".into(),
                "--tmpfs".into(),
                "/root".into(),
            ]);
            // Mask the resolved real home if it is not already covered by
            // the /home or /root tmpfs above.  Only mask paths that EXIST
            // on the host.
            if let Some(home) = host_home.as_deref() {
                let home_str = home.trim_end_matches('/');
                let already_masked = home_str == "/home"
                    || home_str == "/root"
                    || home_str.starts_with("/home/")
                    || home_str.starts_with("/root/");
                if !already_masked && !home_str.is_empty() && Path::new(home_str).exists() {
                    bwrap_args.push("--tmpfs".into());
                    bwrap_args.push(home_str.into());
                }
            }
            // Batch 11.5: these paths are now default-deny (not in the
            // allowlist) but we still mask them with tmpfs in case a future
            // change re-adds a broader ro-bind.  Belt-and-suspenders.
            for path in sensitive_host_paths {
                if Path::new(path).exists() {
                    bwrap_args.push("--tmpfs".into());
                    bwrap_args.push(path.into());
                }
            }
            bwrap_args.extend([
                "--dir".into(),
                "/run/khaos-browser".into(),
                "--dir".into(),
                "/run/khaos-browser/runtime".into(),
                "--ro-bind".into(),
                real_parent.as_os_str().into(),
                "/run/khaos-browser/runtime".into(),
                "--perms".into(),
                "0500".into(),
                "--ro-bind-data".into(),
                launcher_fd.to_string().into(),
                "/run/khaos-browser/launcher".into(),
                "--dir".into(),
                "/tmp/khaos-home".into(),
                // Batch 9.1 (round-9 §九): --clearenv wipes ALL inherited
                // environment, then we re-set only the minimal benign vars
                // Chromium actually needs.  Provider keys / cloud creds /
                // proxy secrets from the parent are therefore absent.
                "--clearenv".into(),
                "--setenv".into(),
                "HOME".into(),
                "/tmp/khaos-home".into(),
                "--setenv".into(),
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                "--setenv".into(),
                "LANG".into(),
                "C.UTF-8".into(),
                "--chdir".into(),
                "/tmp/khaos-home".into(),
                // The inner image must not re-enter the privileged outer
                // launch branch.  Strip all one-shot authority metadata at
                // the namespace boundary; only the explicit inner argv
                // contract continues into the read-only sandbox.
                "--unsetenv".into(),
                "KHAOS_BROWSER_LAUNCH".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_REAL_EXECUTABLE".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_NETNS".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_CGROUP_PROCS".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_AUTHORITY".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_PRINCIPAL_ID".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_PROJECT_ID".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_RUNTIME_ID".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_TASK_ID".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_SANDBOX_TOKEN".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_KERNEL_HELPER_SOCKET".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_HOST_HOME".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_BWRAP_PATH".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_FS_PROBE".into(),
                "--".into(),
                "/run/khaos-browser/launcher".into(),
            ]);
            // Batch 10.5: if KHAOS_BROWSER_FS_PROBE is set (colon-separated
            // sentinel paths), run the fs-probe inner mode instead of
            // Chromium.  Same bwrap mount args → same mask → the probe
            // observes the SAME mount-namespace view Chromium would.
            let probe_paths = env::var("KHAOS_BROWSER_FS_PROBE").ok();
            if let Some(paths) = probe_paths.as_deref() {
                bwrap_args.push("--browser-fs-probe".into());
                bwrap_args.push("--".into());
                for path in paths.split(':') {
                    if !path.is_empty() {
                        bwrap_args.push(path.into());
                    }
                }
            } else {
                bwrap_args.push("--browser-inner".into());
                bwrap_args.push("--".into());
                bwrap_args.push(inner_real.into_os_string());
            }
            bwrap_args.append(&mut args);
            if bwrap_args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--remote-debugging-pipe")
                && probe_paths.is_none()
            {
                bridge_playwright_pipes_to_stdio().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("bridge Playwright control channels: {error}"),
                    )
                })?;
            }
            return exec(&bwrap_args).map_err(|error| {
                io::Error::new(error.kind(), format!("exec bubblewrap: {error}"))
            });
        }

        if args.first().is_some_and(|arg| arg == "--browser-inner") {
            args.remove(0);
            if args.first().is_some_and(|arg| arg == "--") {
                args.remove(0);
            }
            let remote_debugging_pipe = args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--remote-debugging-pipe");
            let preserved = if remote_debugging_pipe {
                restore_playwright_pipes_from_stdio().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("restore Playwright control channels: {error}"),
                    )
                })?;
                vec![3, 4]
            } else {
                Vec::new()
            };
            for fd in &preserved {
                validate_control_channel(*fd, *fd == 3)?;
            }
            sanitize_fds_except(&preserved).map_err(|error| {
                io::Error::new(error.kind(), format!("sanitize browser fds: {error}"))
            })?;
            install_seccomp().map_err(|error| {
                io::Error::new(error.kind(), format!("install browser seccomp: {error}"))
            })?;
            return exec(&args)
                .map_err(|error| io::Error::new(error.kind(), format!("exec Chromium: {error}")));
        }

        // Batch 10.5 (round-10 §八): filesystem secrecy probe mode.
        //   --browser-fs-probe <sentinel_path> [<sentinel_path> ...]
        // Runs INSIDE bubblewrap (re-exec'd by the outer launch branch
        // with the same mount args that mask /home /root /workspace etc).
        // For each sentinel path, attempts open(2) and reports the
        // outcome on stdout as a line "PATH\tOK" or "PATH\tENOENT" (or
        // the errno name).  Exit code 0 = all probes completed (regardless
        // of readability); non-zero = probe error.  This bypasses
        // Playwright/Route Guard/Web Security entirely — a direct
        // mount-namespace open(2) proof.
        if args.first().is_some_and(|arg| arg == "--browser-fs-probe") {
            args.remove(0);
            if args.first().is_some_and(|arg| arg == "--") {
                args.remove(0);
            }
            let sentinel_paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
            // sanitize fds (no Playwright pipes needed for the probe).
            sanitize_fds_except(&[]).map_err(|error| {
                io::Error::new(error.kind(), format!("sanitize probe fds: {error}"))
            })?;
            install_seccomp().map_err(|error| {
                io::Error::new(error.kind(), format!("install probe seccomp: {error}"))
            })?;
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            for path in &sentinel_paths {
                let path_str = path.to_string_lossy();
                // Batch 11.6 (round-11 §九): use File::open + read 1 byte
                // instead of std::fs::read (which slurps the whole file).
                // The probe only needs to prove reachability — a huge
                // file or special device must not cause memory/IO DoS.
                match std::fs::File::open(path) {
                    Ok(mut file) => {
                        let mut byte = [0u8; 1];
                        // read returns Ok(0) at EOF — for the probe, any
                        // successful open+read (even 0 bytes) proves the
                        // file is reachable.
                        match file.read(&mut byte) {
                            Ok(_n) => {
                                // Any successful read (even 0 bytes at EOF)
                                // proves the file is reachable.
                                let _ = writeln!(handle, "{}\tREADABLE", path_str);
                            }
                            Err(error) => {
                                let kind = error.raw_os_error().unwrap_or(0);
                                let label = match kind {
                                    libc::ENOENT => "ENOENT",
                                    libc::EACCES => "EACCES",
                                    libc::ENOTDIR => "ENOTDIR",
                                    _ => "BLOCKED",
                                };
                                let _ = writeln!(handle, "{}\t{}", path_str, label);
                            }
                        }
                    }
                    Err(error) => {
                        let kind = error.raw_os_error().unwrap_or(0);
                        let label = match kind {
                            libc::ENOENT => "ENOENT",
                            libc::EACCES => "EACCES",
                            libc::ENOTDIR => "ENOTDIR",
                            _ => "BLOCKED",
                        };
                        let _ = writeln!(handle, "{}\t{}", path_str, label);
                    }
                }
            }
            return Ok(());
        }

        // Production browser authority mode.  The launcher receives only the
        // abstract identity tuple; the authenticated helper returns the
        // already-validated namespace descriptor via SCM_RIGHTS and attaches
        // this launcher to the helper-owned cgroup before setns.
        if args.first().is_some_and(|arg| arg == "--browser-authority") {
            args.remove(0);
            if args.first().is_some_and(|arg| arg == "--") {
                args.remove(0);
            }
            let principal_id = env::var("KHAOS_BROWSER_PRINCIPAL_ID")
                .map_err(|_| io::Error::other("browser principal identity missing"))?;
            let project_id = env::var("KHAOS_BROWSER_PROJECT_ID")
                .map_err(|_| io::Error::other("browser project identity missing"))?;
            let runtime_id = env::var("KHAOS_BROWSER_RUNTIME_ID")
                .map_err(|_| io::Error::other("browser runtime identity missing"))?;
            let task_id = env::var("KHAOS_BROWSER_TASK_ID")
                .map_err(|_| io::Error::other("browser task identity missing"))?;
            let token = env::var("KHAOS_BROWSER_SANDBOX_TOKEN")
                .map_err(|_| io::Error::other("browser sandbox token missing"))?;
            env::remove_var("KHAOS_BROWSER_PRINCIPAL_ID");
            env::remove_var("KHAOS_BROWSER_PROJECT_ID");
            env::remove_var("KHAOS_BROWSER_RUNTIME_ID");
            env::remove_var("KHAOS_BROWSER_TASK_ID");
            env::remove_var("KHAOS_BROWSER_SANDBOX_TOKEN");
            join_browser_authority(&principal_id, &project_id, &runtime_id, &task_id, &token)?;
            let remote_debugging_pipe = args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--remote-debugging-pipe");
            let preserved = if remote_debugging_pipe {
                for fd in [3, 4] {
                    validate_control_channel(fd, fd == 3)?;
                }
                vec![3, 4]
            } else {
                Vec::new()
            };
            sanitize_fds_except(&preserved)?;
            install_seccomp()?;
            return exec(&args);
        }

        // Development compatibility browser launcher mode.
        //   --browser --netns <name> --cgroup <procs> -- <chromium> <args>
        // Order: validate → join cgroup → join netns → sanitize fds →
        // no_new_privs → install seccomp (denies setns, so the browser
        // cannot later escape) → execve.  This replaces the shell
        // wrapper that did ``echo $$ > cgroup.procs; nsenter --net=…``.
        if args.first().is_some_and(|arg| arg == "--browser") {
            args.remove(0);
            let mut netns: Option<String> = None;
            let mut cgroup: Option<PathBuf> = None;
            loop {
                match args
                    .first()
                    .map(|s| s.to_string_lossy().into_owned())
                    .as_deref()
                {
                    Some("--netns") => {
                        args.remove(0);
                        netns = Some(
                            args.remove(0)
                                .to_str()
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "--netns value not UTF-8",
                                    )
                                })?
                                .to_string(),
                        );
                    }
                    Some("--cgroup") => {
                        args.remove(0);
                        cgroup = Some(PathBuf::from(args.remove(0)));
                    }
                    Some("--") => {
                        args.remove(0);
                        break;
                    }
                    _ => break,
                }
            }
            // P1-6 (round-13): use the safe join_cgroup (O_NOFOLLOW +
            // path validation) instead of bare std::fs::write.
            if let Some(procs) = cgroup {
                join_cgroup(procs.as_os_str()).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("browser join cgroup {}: {error}", procs.display()),
                    )
                })?;
            }
            // Join the netns BEFORE seccomp (setns is denied after install).
            if let Some(name) = netns {
                join_netns(&name)?;
            }
            let remote_debugging_pipe = args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--remote-debugging-pipe");
            let preserved = if remote_debugging_pipe {
                for fd in [3, 4] {
                    validate_control_channel(fd, fd == 3)?;
                }
                vec![3, 4]
            } else {
                Vec::new()
            };
            sanitize_fds_except(&preserved)?;
            // seccomp: no_new_privs + deny-list.  setns is in the deny
            // list, so Chromium cannot change namespaces after this point.
            install_seccomp()?;
            return exec(&args);
        }

        if args.first().is_some_and(|arg| arg == "--join-cgroup") {
            if args.len() < 4 || args[2] != "--" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected --join-cgroup PATH -- COMMAND",
                ));
            }
            let path = PathBuf::from(args.remove(1));
            args.drain(0..2);
            // P1-6 (round-13): use the safe join_cgroup (O_NOFOLLOW +
            // path validation) instead of bare std::fs::write.
            join_cgroup(path.as_os_str()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("join cgroup {}: {error}", path.display()),
                )
            })?;
            return exec(&args);
        }
        if args.first().is_some_and(|arg| arg == "--") {
            args.remove(0);
        }
        install_landlock_if_required()?;
        install_seccomp()?;
        exec(&args)
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("khaos-sandbox-launcher: {error}");
        std::process::exit(126);
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("khaos-sandbox-launcher is Linux-only");
        std::process::exit(126);
    }
}
