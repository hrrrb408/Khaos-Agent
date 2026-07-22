//! Fail-closed inner launcher for the Linux execution sandbox.

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
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

    pub fn run() -> io::Result<()> {
        let mut args: Vec<_> = env::args_os().skip(1).collect();
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
            std::fs::write(path, b"0")?;
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
