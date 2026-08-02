//! Small fail-closed process boundary for host execution.
//!
//! Python passes validated directory descriptors and resource budgets to this
//! binary.  The launcher verifies the descriptor identities, selects the cwd,
//! applies rlimits, creates the process session, and finally replaces itself
//! with the requested command.  Keeping this sequence outside the Python
//! interpreter removes ``preexec_fn`` from the security boundary.

#[cfg(unix)]
mod unix {
    use std::env;
    use std::io;
    use std::os::fd::RawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    type RlimitResource = libc::__rlimit_resource_t;

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    type RlimitResource = libc::c_int;

    #[derive(Default)]
    struct Options {
        new_session: bool,
        preserve_directory_fds: bool,
        root_fd: Option<RawFd>,
        root_device: Option<u64>,
        root_inode: Option<u64>,
        cwd_fd: Option<RawFd>,
        cwd_device: Option<u64>,
        cwd_inode: Option<u64>,
        rlimit_fsize: Option<u64>,
        rlimit_nofile: Option<u64>,
        rlimit_cpu: Option<u64>,
        rlimit_as: Option<u64>,
    }

    pub fn run() -> io::Result<()> {
        let (options, command) = parse_args(env::args_os().skip(1))?;
        if options.new_session {
            let result = unsafe { libc::setsid() };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        verify_directory(
            options.root_fd,
            options.root_device,
            options.root_inode,
            "workspace root",
        )?;
        verify_directory(
            options.cwd_fd,
            options.cwd_device,
            options.cwd_inode,
            "execution cwd",
        )?;
        if let Some(fd) = options.cwd_fd {
            let result = unsafe { libc::fchdir(fd) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // The directory descriptors are authority capabilities used only for
        // identity verification and fchdir.  Ordinary commands must not
        // retain them.  Bubblewrap is an explicit protocol exception: it
        // resolves the already-validated workspace source through
        // /proc/self/fd before constructing its mount namespace.
        // Default policy: explicit whitelist of 0/1/2; only that protocol can
        // extend it with bound directory FDs.
        let preserved = if options.preserve_directory_fds {
            vec![options.root_fd, options.cwd_fd]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        } else {
            close_authority_fds(options.root_fd, options.cwd_fd);
            Vec::new()
        };
        apply_limit(libc::RLIMIT_FSIZE, options.rlimit_fsize)?;
        apply_limit(libc::RLIMIT_NOFILE, options.rlimit_nofile)?;
        apply_limit(libc::RLIMIT_CPU, options.rlimit_cpu)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        apply_limit(libc::RLIMIT_AS, options.rlimit_as)?;
        #[cfg(target_os = "macos")]
        let _ = options.rlimit_as;

        close_inherited_fds_except(&preserved)?;

        let mut child = Command::new(&command[0]);
        child.args(&command[1..]);
        let error = child.exec();
        Err(error)
    }

    fn parse_args<I>(arguments: I) -> io::Result<(Options, Vec<std::ffi::OsString>)>
    where
        I: IntoIterator<Item = std::ffi::OsString>,
    {
        let values: Vec<_> = arguments.into_iter().collect();
        let mut options = Options::default();
        let mut index = 0;
        while index < values.len() {
            if values[index] == "--" {
                let command = values[index + 1..].to_vec();
                if command.is_empty() {
                    return Err(invalid("command required"));
                }
                validate_identity_pairs(&options)?;
                return Ok((options, command));
            }
            if values[index] == "--new-session" {
                if options.new_session {
                    return Err(invalid("duplicate --new-session"));
                }
                options.new_session = true;
                index += 1;
                continue;
            }
            if values[index] == "--preserve-directory-fds" {
                if options.preserve_directory_fds {
                    return Err(invalid("duplicate --preserve-directory-fds"));
                }
                options.preserve_directory_fds = true;
                index += 1;
                continue;
            }
            let name = values[index]
                .to_str()
                .ok_or_else(|| invalid("launcher option is not UTF-8"))?;
            let key = name
                .strip_prefix("--")
                .ok_or_else(|| invalid("launcher options must precede --"))?;
            if index + 1 >= values.len() {
                return Err(invalid("launcher option value is missing"));
            }
            let number = parse_number(&values[index + 1], key)?;
            match key {
                "root-fd" => set_once(&mut options.root_fd, checked_fd(number), key)?,
                "root-device" => set_once(&mut options.root_device, Some(number), key)?,
                "root-inode" => set_once(&mut options.root_inode, Some(number), key)?,
                "cwd-fd" => set_once(&mut options.cwd_fd, checked_fd(number), key)?,
                "cwd-device" => set_once(&mut options.cwd_device, Some(number), key)?,
                "cwd-inode" => set_once(&mut options.cwd_inode, Some(number), key)?,
                "rlimit-fsize" => set_once(&mut options.rlimit_fsize, Some(number), key)?,
                "rlimit-nofile" => set_once(&mut options.rlimit_nofile, Some(number), key)?,
                "rlimit-cpu" => set_once(&mut options.rlimit_cpu, Some(number), key)?,
                "rlimit-as" => set_once(&mut options.rlimit_as, Some(number), key)?,
                _ => return Err(invalid(&format!("unknown launcher option: --{key}"))),
            }
            index += 2;
        }
        Err(invalid("launcher command separator is required"))
    }

    fn validate_identity_pairs(options: &Options) -> io::Result<()> {
        for (fd, device, inode, label) in [
            (
                options.root_fd,
                options.root_device,
                options.root_inode,
                "root",
            ),
            (options.cwd_fd, options.cwd_device, options.cwd_inode, "cwd"),
        ] {
            if fd.is_some() != (device.is_some() && inode.is_some()) {
                return Err(invalid(&format!("incomplete {label} identity")));
            }
        }
        if options.preserve_directory_fds && (options.root_fd.is_none() || options.cwd_fd.is_none())
        {
            return Err(invalid(
                "preserving directory descriptors requires root and cwd bindings",
            ));
        }
        Ok(())
    }

    fn set_once<T>(slot: &mut Option<T>, value: Option<T>, key: &str) -> io::Result<()> {
        if slot.is_some() || value.is_none() {
            return Err(invalid(&format!("duplicate or invalid --{key}")));
        }
        *slot = value;
        Ok(())
    }

    fn parse_number(value: &std::ffi::OsString, key: &str) -> io::Result<u64> {
        let text = value
            .to_str()
            .ok_or_else(|| invalid(&format!("--{key} is not UTF-8")))?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid(&format!("--{key} must be an unsigned decimal")));
        }
        text.parse::<u64>()
            .map_err(|_| invalid(&format!("--{key} is out of range")))
    }

    fn checked_fd(value: u64) -> Option<RawFd> {
        if value <= i32::MAX as u64 {
            Some(value as RawFd)
        } else {
            None
        }
    }

    fn verify_directory(
        fd: Option<RawFd>,
        device: Option<u64>,
        inode: Option<u64>,
        label: &str,
    ) -> io::Result<()> {
        let (Some(fd), Some(device), Some(inode)) = (fd, device, inode) else {
            return Ok(());
        };
        let mut info = unsafe { std::mem::zeroed::<libc::stat>() };
        let result = unsafe { libc::fstat(fd, &mut info) };
        if result < 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} descriptor is unavailable"),
            ));
        }
        if info.st_dev as u64 != device || info.st_ino as u64 != inode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} identity changed before exec"),
            ));
        }
        Ok(())
    }

    fn close_authority_fds(root_fd: Option<RawFd>, cwd_fd: Option<RawFd>) {
        let mut closed = [RawFd::MIN; 2];
        let mut count = 0;
        for fd in [root_fd, cwd_fd].into_iter().flatten() {
            if fd > 2 && !closed[..count].contains(&fd) {
                unsafe { libc::close(fd) };
                closed[count] = fd;
                count += 1;
            }
        }
    }

    /// Close every descriptor except stdin/stdout/stderr and explicit protocol FDs.
    ///
    /// Linux uses the atomic close_range syscall when available.  The
    /// bounded fallback is retained for older kernels and macOS; neither
    /// path preserves arbitrary inherited descriptors.
    fn close_inherited_fds_except(preserved: &[RawFd]) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut fds = preserved
                .iter()
                .copied()
                .filter(|fd| *fd > 2)
                .collect::<Vec<_>>();
            fds.sort_unstable();
            fds.dedup();
            let mut start = 3_u32;
            let mut supported = true;
            for fd in fds {
                let end = fd as u32 - 1;
                if start > end {
                    start = fd as u32 + 1;
                    continue;
                }
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_close_range,
                        start as libc::c_uint,
                        end as libc::c_uint,
                        0 as libc::c_uint,
                    )
                };
                if result != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ENOSYS)
                        || error.raw_os_error() == Some(libc::EINVAL)
                    {
                        supported = false;
                        break;
                    }
                    return Err(error);
                }
                start = fd as u32 + 1;
            }
            if supported {
                if start <= u32::MAX {
                    let result = unsafe {
                        libc::syscall(
                            libc::SYS_close_range,
                            start as libc::c_uint,
                            u32::MAX as libc::c_uint,
                            0 as libc::c_uint,
                        )
                    };
                    if result == 0 {
                        return Ok(());
                    }
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ENOSYS)
                        && error.raw_os_error() != Some(libc::EINVAL)
                    {
                        return Err(error);
                    }
                } else {
                    return Ok(());
                }
            }
        }

        let maximum = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        if maximum <= 3 {
            return Ok(());
        }
        for fd in 3..maximum {
            if preserved.contains(&(fd as RawFd)) {
                continue;
            }
            unsafe { libc::close(fd as RawFd) };
        }
        Ok(())
    }

    fn apply_limit(resource: RlimitResource, requested: Option<u64>) -> io::Result<()> {
        let Some(requested) = requested else {
            return Ok(());
        };
        let mut current = unsafe { std::mem::zeroed::<libc::rlimit>() };
        if unsafe { libc::getrlimit(resource, &mut current) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let effective = if current.rlim_max == libc::RLIM_INFINITY {
            requested as libc::rlim_t
        } else {
            std::cmp::min(requested as libc::rlim_t, current.rlim_max)
        };
        let limits = libc::rlimit {
            rlim_cur: effective,
            rlim_max: effective,
        };
        if unsafe { libc::setrlimit(resource, &limits) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = unix::run() {
        eprintln!("khaos-exec-launcher: {error}");
        std::process::exit(126);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("khaos-exec-launcher: unsupported platform");
    std::process::exit(126);
}
