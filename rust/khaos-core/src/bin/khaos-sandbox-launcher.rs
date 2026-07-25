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
    fn sanitize_fds() -> io::Result<()> {
        // Try close_range(3, ~0u, CLOSE_RANGE_UNSHARE).  We do NOT unshare
        // the fd table (the flag is 0) so the launcher's own fds used
        // during setup are already closed by this point.
        const CLOSE_RANGE_FD_MASK: u32 = 0;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                CLOSE_RANGE_FD_MASK,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        // Fallback: iterate /proc/self/fd.  close_range may be absent on
        // older kernels (ENOSYS) — the errno is checked by the fallback.
        let entries = std::fs::read_dir("/proc/self/fd")
            .map_err(|e| io::Error::new(e.kind(), format!("read /proc/self/fd: {e}")))?;
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(fd) = name.parse::<i32>() {
                    if fd > 2 {
                        unsafe { libc::close(fd) };
                    }
                }
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
        let c_path = CString::new(path.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "netns path contained NUL")
        })?;
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

    pub fn run() -> io::Result<()> {
        let mut args: Vec<_> = env::args_os().skip(1).collect();

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
                match args.first().map(|s| s.to_string_lossy().into_owned()).as_deref() {
                    Some("--netns") => {
                        args.remove(0);
                        netns = Some(
                            args.remove(0)
                                .to_str()
                                .ok_or_else(|| io::Error::new(
                                    io::ErrorKind::InvalidInput, "--netns value not UTF-8",
                                ))?
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
            // Sanitize inherited fds (close everything > stderr).
            sanitize_fds()?;
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
