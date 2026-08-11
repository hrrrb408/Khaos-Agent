//! Small fail-closed process boundary for host execution.
//!
//! Python passes validated directory descriptors and resource budgets to this
//! binary.  The launcher verifies the descriptor identities, selects the cwd,
//! applies rlimits, creates the process session, and finally replaces itself
//! with the requested command.  Keeping this sequence outside the Python
//! interpreter removes ``preexec_fn`` from the security boundary.

// KHAOS-PRIVILEGED-SPAWN owner=NativeExecLauncher threat-model=fd-bound-executable-authority boundary=native-launcher

#[cfg(unix)]
mod unix {
    use sha2::{Digest, Sha256};
    use std::env;
    #[cfg(not(target_os = "linux"))]
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom};
    #[cfg(not(target_os = "linux"))]
    use std::os::fd::AsRawFd;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    #[cfg(not(target_os = "linux"))]
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;
    #[cfg(not(target_os = "linux"))]
    use std::path::{Path, PathBuf};
    use std::process::Command;
    #[cfg(target_os = "macos")]
    use std::process::Stdio;

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
        exec_fd: Option<RawFd>,
        exec_digest: Option<String>,
        interpreter_fd: Option<RawFd>,
        interpreter_digest: Option<String>,
        interpreter_argv0: Option<OsString>,
        interpreter_args: Vec<OsString>,
    }

    #[cfg(not(target_os = "linux"))]
    struct StagedExec {
        executable_path: PathBuf,
        interpreter_path: Option<PathBuf>,
        interpreter_argv0: Option<OsString>,
        interpreter_args: Vec<OsString>,
        command: Vec<OsString>,
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
        #[cfg(not(target_os = "linux"))]
        let staged_exec = if let Some(exec_fd) = options.exec_fd {
            verify_executable_fd(exec_fd, options.exec_digest.as_deref(), "executable")?;
            if let Some(interpreter_fd) = options.interpreter_fd {
                verify_executable_fd(
                    interpreter_fd,
                    options.interpreter_digest.as_deref(),
                    "interpreter",
                )?;
            }
            Some(stage_exec(
                exec_fd,
                options.interpreter_fd,
                options.interpreter_argv0.as_ref(),
                &command,
                &options.interpreter_args,
            )?)
        } else {
            None
        };
        apply_limit(libc::RLIMIT_FSIZE, options.rlimit_fsize)?;
        apply_limit(libc::RLIMIT_NOFILE, options.rlimit_nofile)?;
        apply_limit(libc::RLIMIT_CPU, options.rlimit_cpu)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        apply_limit(libc::RLIMIT_AS, options.rlimit_as)?;
        #[cfg(target_os = "macos")]
        let _ = options.rlimit_as;

        let mut preserved = preserved;
        preserved.extend(options.exec_fd.iter().copied());
        preserved.extend(options.interpreter_fd.iter().copied());
        close_inherited_fds_except(&preserved)?;

        #[cfg(not(target_os = "linux"))]
        if let Some(staged_exec) = staged_exec {
            return exec_from_staged(staged_exec);
        }

        if let Some(exec_fd) = options.exec_fd {
            verify_executable_fd(exec_fd, options.exec_digest.as_deref(), "executable")?;
            if let Some(interpreter_fd) = options.interpreter_fd {
                verify_executable_fd(
                    interpreter_fd,
                    options.interpreter_digest.as_deref(),
                    "interpreter",
                )?;
                exec_from_fd(
                    interpreter_fd,
                    exec_fd,
                    options.interpreter_argv0.as_ref(),
                    &command,
                    &options.interpreter_args,
                )
            } else {
                exec_from_fd(exec_fd, exec_fd, None, &command, &[])
            }
        } else {
            let mut child = Command::new(&command[0]);
            child.args(&command[1..]);
            let error = child.exec();
            Err(error)
        }
    }

    fn verify_executable_fd(
        fd: RawFd,
        expected_digest: Option<&str>,
        label: &str,
    ) -> io::Result<()> {
        let mut info = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut info) } < 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} authority descriptor is unavailable"),
            ));
        }
        if (info.st_mode & libc::S_IFMT) != libc::S_IFREG || (info.st_mode & 0o111) == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} authority descriptor is not executable"),
            ));
        }
        let expected = expected_digest.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} authority digest is missing"),
            )
        })?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} authority digest is invalid"),
            ));
        }
        if digest_fd(fd)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} authority content changed before exec"),
            ));
        }
        Ok(())
    }

    fn digest_fd(fd: RawFd) -> io::Result<String> {
        let duplicated = unsafe { libc::dup(fd) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(duplicated) };
        file.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    fn exec_from_fd(
        interpreter_fd: RawFd,
        script_fd: RawFd,
        interpreter_argv0: Option<&OsString>,
        command: &[OsString],
        interpreter_args: &[OsString],
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let script_path = format!("/proc/self/fd/{script_fd}");
            let mut args = if interpreter_fd == script_fd {
                command.to_vec()
            } else {
                // The approved script descriptor is opened O_CLOEXEC. It
                // must survive the one exec into the approved interpreter so
                // the interpreter can reopen /proc/self/fd/<N>.
                set_fd_inheritable(script_fd)?;
                let mut values = vec![interpreter_argv0
                    .cloned()
                    .unwrap_or_else(|| OsString::from(format!("/proc/self/fd/{interpreter_fd}")))];
                values.extend(interpreter_args.iter().cloned());
                values.push(OsString::from(script_path));
                values.extend(command.iter().skip(1).cloned());
                values
            };
            let program_fd = if interpreter_fd == script_fd {
                script_fd
            } else {
                interpreter_fd
            };
            execveat_fd(program_fd, &mut args)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Darwin does not provide Linux's execveat(AT_EMPTY_PATH), and
            // execve(/dev/fd/N) is not an executable-object API there.  Copy
            // the already-hashed descriptor into a private O_EXCL staging
            // file and execute that immutable generation.  The staged
            // interpreter is used for shebang payloads as well, so neither
            // the script nor its interpreter is reopened by pathname.
            let script_path = stage_fd(script_fd, "script", &command[0])?;
            let executable_path = if interpreter_fd == script_fd {
                script_path.clone()
            } else {
                let interpreter_name = interpreter_argv0
                    .map(|value| value.as_os_str())
                    .unwrap_or_else(|| OsStr::new("interpreter"));
                stage_fd(interpreter_fd, "interpreter", interpreter_name)?
            };
            let mut child = Command::new(executable_path);
            if interpreter_fd == script_fd {
                child.arg0(&command[0]);
                child.args(&command[1..]);
            } else {
                if let Some(interpreter_argv0) = interpreter_argv0 {
                    child.arg0(interpreter_argv0);
                }
                child.args(interpreter_args);
                child.arg(script_path);
                child.args(&command[1..]);
            }
            let error = child.exec();
            Err(error)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn stage_exec(
        executable_fd: RawFd,
        interpreter_fd: Option<RawFd>,
        interpreter_argv0: Option<&OsString>,
        command: &[OsString],
        interpreter_args: &[OsString],
    ) -> io::Result<StagedExec> {
        let executable_path = stage_fd(executable_fd, "executable", &command[0])?;
        let interpreter_path = match interpreter_fd {
            Some(fd) => {
                let interpreter_name = interpreter_argv0
                    .map(|value| value.as_os_str())
                    .unwrap_or_else(|| OsStr::new("interpreter"));
                match stage_fd(fd, "interpreter", interpreter_name) {
                    Ok(path) => Some(path),
                    Err(error) => {
                        remove_staged_path(&executable_path);
                        return Err(error);
                    }
                }
            }
            None => None,
        };
        Ok(StagedExec {
            executable_path,
            interpreter_path,
            interpreter_argv0: interpreter_argv0.cloned(),
            interpreter_args: interpreter_args.to_vec(),
            command: command.to_vec(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn exec_from_staged(staged: StagedExec) -> io::Result<()> {
        let mut child = if let Some(interpreter_path) = &staged.interpreter_path {
            let mut child = Command::new(interpreter_path);
            if let Some(interpreter_argv0) = &staged.interpreter_argv0 {
                child.arg0(interpreter_argv0);
            }
            child.args(&staged.interpreter_args);
            child.arg(&staged.executable_path);
            child.args(staged.command.iter().skip(1));
            child
        } else {
            let mut child = Command::new(&staged.executable_path);
            child.arg0(&staged.command[0]);
            child.args(staged.command.iter().skip(1));
            child
        };
        let error = child.exec();
        remove_staged_path(&staged.executable_path);
        if let Some(interpreter_path) = staged.interpreter_path {
            remove_staged_path(&interpreter_path);
        }
        Err(error)
    }

    #[cfg(not(target_os = "linux"))]
    fn stage_fd(fd: RawFd, label: &str, preferred_name: &OsStr) -> io::Result<PathBuf> {
        let temp_dir = env::temp_dir();
        let dir_template = temp_dir.join(format!("khaos-{label}-XXXXXX"));
        let template_c =
            std::ffi::CString::new(dir_template.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "staging path contained NUL")
            })?;
        let directory_ptr = unsafe { libc::mkdtemp(template_c.as_ptr() as *mut libc::c_char) };
        if directory_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        let staging_directory = PathBuf::from(OsString::from_vec(unsafe {
            std::ffi::CStr::from_ptr(template_c.as_ptr())
                .to_bytes()
                .to_vec()
        }));
        let file_name = Path::new(preferred_name)
            .file_name()
            .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
            .unwrap_or_else(|| OsStr::new(label));
        let staged_path = staging_directory.join(file_name);
        let staged_c = match std::ffi::CString::new(staged_path.as_os_str().as_bytes()) {
            Ok(value) => value,
            Err(error) => {
                let _ = std::fs::remove_dir(&staging_directory);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("staging path contained NUL: {error}"),
                ));
            }
        };
        let staged_fd = unsafe {
            libc::open(
                staged_c.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                0o700,
            )
        };
        if staged_fd < 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_dir(&staging_directory);
            return Err(error);
        }
        let mut source = {
            let duplicated = unsafe { libc::dup(fd) };
            if duplicated < 0 {
                unsafe { libc::close(staged_fd) };
                remove_staged_path(&staged_path);
                return Err(io::Error::last_os_error());
            }
            unsafe { File::from_raw_fd(duplicated) }
        };
        let mut staged = unsafe { File::from_raw_fd(staged_fd) };
        let copy_result = (|| -> io::Result<()> {
            source.seek(SeekFrom::Start(0))?;
            staged.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut source, &mut staged)?;
            staged.sync_data()?;
            if unsafe { libc::fchmod(staged.as_raw_fd(), 0o700) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if let Err(error) = copy_result {
            drop(staged);
            remove_staged_path(&staged_path);
            return Err(error);
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = sign_staged_file(&staged_path) {
            drop(staged);
            remove_staged_path(&staged_path);
            return Err(error);
        }
        Ok(staged_path)
    }

    #[cfg(not(target_os = "linux"))]
    fn remove_staged_path(path: &Path) {
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[cfg(target_os = "macos")]
    fn sign_staged_file(path: &std::path::Path) -> io::Result<()> {
        // Preserve an embedded platform CodeDirectory when the source already
        // has one.  Replacing the signature on a platform binary such as
        // /bin/cat with an ad-hoc signature can make macOS AMFI terminate the
        // staged process with SIGKILL even though its bytes and digest are
        // unchanged.  Unsigned objects still receive an ad-hoc signature;
        // failure remains hard failure rather than a pathname fallback.
        let existing = Command::new("/usr/bin/codesign")
            .args(["-d", "--verbose=4"])
            .arg(path)
            .output()?;
        if existing.status.success() {
            return Ok(());
        }
        let status = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS rejected ad-hoc signing of staged executable",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn execveat_fd(fd: RawFd, args: &mut [OsString]) -> io::Result<()> {
        let c_args: Result<Vec<_>, _> = args
            .iter()
            .map(|arg| std::ffi::CString::new(arg.as_bytes()))
            .collect();
        let c_args = c_args.map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "exec argument contained NUL")
        })?;
        let mut argv: Vec<_> = c_args.iter().map(|arg| arg.as_ptr()).collect();
        argv.push(std::ptr::null());
        let env_args: Result<Vec<_>, _> = env::vars_os()
            .map(|(key, value)| {
                let mut bytes = key.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend(value.as_bytes());
                std::ffi::CString::new(bytes)
            })
            .collect();
        let env_args = env_args.map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "environment contained NUL")
        })?;
        let mut envp: Vec<_> = env_args.iter().map(|arg| arg.as_ptr()).collect();
        envp.push(std::ptr::null());
        let empty = std::ffi::CString::new("").expect("empty CString");
        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::other("execveat returned unexpectedly"))
        }
    }

    #[cfg(target_os = "linux")]
    fn set_fd_inheritable(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
            if key == "exec-digest" || key == "interpreter-digest" {
                let digest = values[index + 1]
                    .to_str()
                    .ok_or_else(|| invalid("launcher digest is not UTF-8"))?
                    .to_string();
                if key == "exec-digest" {
                    set_once(&mut options.exec_digest, Some(digest), key)?;
                } else {
                    set_once(&mut options.interpreter_digest, Some(digest), key)?;
                }
                index += 2;
                continue;
            }
            if key == "interpreter-argv0" {
                if values[index + 1].is_empty() {
                    return Err(invalid("interpreter argv0 is empty"));
                }
                set_once(
                    &mut options.interpreter_argv0,
                    Some(values[index + 1].clone()),
                    key,
                )?;
                index += 2;
                continue;
            }
            if key == "interpreter-arg" {
                options.interpreter_args.push(values[index + 1].clone());
                index += 2;
                continue;
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
                "exec-fd" => set_once(&mut options.exec_fd, checked_fd(number), key)?,
                "interpreter-fd" => set_once(&mut options.interpreter_fd, checked_fd(number), key)?,
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
        if options.exec_fd.is_some() != options.exec_digest.is_some() {
            return Err(invalid("incomplete executable authority"));
        }
        if options.interpreter_fd.is_some() != options.interpreter_digest.is_some()
            || options.interpreter_fd.is_some() && options.exec_fd.is_none()
            || options.interpreter_argv0.is_some() && options.interpreter_fd.is_none()
            || (!options.interpreter_args.is_empty() && options.interpreter_fd.is_none())
        {
            return Err(invalid("incomplete interpreter authority"));
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
