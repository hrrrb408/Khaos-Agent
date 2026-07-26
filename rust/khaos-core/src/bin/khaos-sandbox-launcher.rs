//! Fail-closed inner launcher for the Linux execution sandbox.

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    #[allow(dead_code)] // only used on aarch64 targets
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

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
        let path = format!("/var/run/netns/{}", name);
        let c_path = CString::new(path.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "netns path contained NUL"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
        unsafe { libc::close(fd) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
            // path supplied by Python instead of relying on PATH lookup
            // (which a pre-sandbox attacker could hijack).
            let bwrap_exe = env::var_os("KHAOS_BROWSER_BWRAP_PATH")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "bwrap".into());

            // Batch 9.2: sensitive host paths that must NEVER be readable
            // from inside the browser namespace, regardless of the ro-bind
            // of /.  tmpfs overwrites the ro-bind at these mount points.
            let sensitive_host_paths: [&str; 5] = [
                "/workspace",
                "/srv",
                "/data",
                "/mnt",
                "/var/lib",
            ];

            let mut bwrap_args: Vec<std::ffi::OsString> = vec![
                bwrap_exe,
                "--die-with-parent".into(),
                "--new-session".into(),
                "--unshare-user-try".into(),
                "--unshare-pid".into(),
                "--unshare-ipc".into(),
                "--unshare-uts".into(),
                "--ro-bind".into(),
                "/".into(),
                "/".into(),
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
            ];
            // Mask the resolved real home if it is not already covered by
            // the /home or /root tmpfs above.
            if let Some(home) = host_home.as_deref() {
                let home_str = home.trim_end_matches('/');
                let already_masked = home_str == "/home"
                    || home_str == "/root"
                    || home_str.starts_with("/home/")
                    || home_str.starts_with("/root/");
                if !already_masked && !home_str.is_empty() {
                    bwrap_args.push("--tmpfs".into());
                    bwrap_args.push(home_str.into());
                }
            }
            // Mask the fixed sensitive host paths.
            for path in sensitive_host_paths {
                bwrap_args.push("--tmpfs".into());
                bwrap_args.push(path.into());
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
                // the namespace boundary; only the explicit --browser-inner
                // argv contract continues into the read-only sandbox.
                "--unsetenv".into(),
                "KHAOS_BROWSER_LAUNCH".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_REAL_EXECUTABLE".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_NETNS".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_CGROUP_PROCS".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_HOST_HOME".into(),
                "--unsetenv".into(),
                "KHAOS_BROWSER_BWRAP_PATH".into(),
                "--".into(),
                "/run/khaos-browser/launcher".into(),
                "--browser-inner".into(),
                "--".into(),
                inner_real.into_os_string(),
            ]);
            bwrap_args.append(&mut args);
            if bwrap_args
                .iter()
                .any(|arg| arg.to_string_lossy() == "--remote-debugging-pipe")
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

        // Batch 7.4 (round-7 §十一): browser launcher mode.
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
            // Join cgroup first (write our PID into cgroup.procs).
            if let Some(procs) = cgroup {
                std::fs::write(&procs, b"0").map_err(|error| {
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
            // This stage runs before bubblewrap creates a user namespace.
            // Joining the delegated cgroup from inside that namespace is
            // rejected by the kernel even when cgroup.procs is bind-mounted.
            std::fs::write(&path, b"0").map_err(|error| {
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
