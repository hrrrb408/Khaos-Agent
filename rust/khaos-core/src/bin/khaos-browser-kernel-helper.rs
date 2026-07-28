//! Privileged browser kernel authority.
//!
//! The protocol is a closed, length-prefixed serde contract.  Callers provide
//! only project/runtime identity plus an opaque sandbox token; every kernel
//! resource name is derived inside this helper with a protected HMAC key.

#[cfg(target_os = "linux")]
mod linux {
    use hmac::{Hmac, Mac};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    type HmacSha256 = Hmac<Sha256>;

    const PROTOCOL_VERSION: u16 = 1;
    const MAX_MESSAGE: usize = 8192;
    const MAX_CONNECTIONS: usize = 32;
    const MAX_REPLAY_IDS: usize = 4096;
    const DEFAULT_SOCKET: &str = "/run/khaos/browser-kernel-helper.sock";
    const DEFAULT_SECRET: &str = "/var/lib/khaos/browser-helper.secret";
    const DEFAULT_JOURNAL: &str = "/run/khaos/browser-helper";
    const IP_PATH: &str = "/usr/sbin/ip";
    const NFT_PATH: &str = "/usr/sbin/nft";

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        protocol_version: u16,
        request_id: String,
        boot_id: String,
        client_pid: u32,
        client_start_time: u64,
        project_id: String,
        runtime_id: String,
        sandbox_token: String,
        op: Operation,
        port: Option<u16>,
        target_pid: Option<u32>,
        target_start_time: Option<u64>,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Operation {
        Setup,
        AllowProxy,
        RevokeProxy,
        AttachProcess,
        Join,
        Teardown,
        Status,
    }

    #[derive(Serialize)]
    struct Response<'a> {
        protocol_version: u16,
        request_id: &'a str,
        ok: bool,
        error: Option<String>,
        status: Option<IsolationStatus>,
    }

    #[derive(Clone, Default, Serialize)]
    struct IsolationStatus {
        helper_authenticated: bool,
        network_namespace: bool,
        nft_default_deny: bool,
        cgroup_attached: bool,
        process_isolated: bool,
        resource_registry_verified: bool,
        quarantined: bool,
        proxy_host: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct ResourceIdentity {
        project_id: String,
        runtime_id: String,
        sandbox_token: String,
    }

    #[derive(Clone)]
    struct ResourceRecord {
        identity: ResourceIdentity,
        names: ResourceNames,
        ports: HashSet<u16>,
        status: IsolationStatus,
    }

    #[derive(Clone)]
    struct ResourceNames {
        key: String,
        netns: String,
        veth_host: String,
        veth_peer: String,
        nft_table: String,
        cgroup: PathBuf,
        host_ip: String,
        namespace_ip: String,
    }

    #[derive(Deserialize, Serialize)]
    struct JournalEnvelope {
        identity: ResourceIdentity,
        stage: String,
        mac: String,
    }

    struct TrustedBinary {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    struct State {
        secret: Vec<u8>,
        boot_id: String,
        journal_root: PathBuf,
        resources: Mutex<HashMap<String, ResourceRecord>>,
        replay: Mutex<(HashSet<String>, VecDeque<String>)>,
        ip: TrustedBinary,
        nft: TrustedBinary,
    }

    #[derive(Clone, Copy)]
    struct PeerCred {
        pid: u32,
        uid: u32,
    }

    impl State {
        fn derive(&self, identity: &ResourceIdentity) -> io::Result<ResourceNames> {
            let input = format!(
                "{}\0{}\0{}\0{}",
                self.boot_id, identity.project_id, identity.runtime_id, identity.sandbox_token
            );
            let digest = hmac_hex(&self.secret, input.as_bytes())?;
            let octet = u8::from_str_radix(&digest[0..2], 16).unwrap_or(1).max(1);
            let subnet = (octet % 250).max(1);
            Ok(ResourceNames {
                key: digest.clone(),
                netns: format!("khaos-br-{}", &digest[..12]),
                veth_host: format!("kh{}", &digest[..12]),
                veth_peer: format!("kn{}", &digest[..12]),
                nft_table: format!("khaos_browser_{}", &digest[..32]),
                cgroup: Path::new("/sys/fs/cgroup/khaos-browser").join(&digest[..32]),
                host_ip: format!("10.203.{subnet}.1"),
                namespace_ip: format!("10.203.{subnet}.2"),
            })
        }

        fn accept_request_id(&self, request_id: &str) -> io::Result<()> {
            validate_identifier(request_id, 8, 128, "request_id")?;
            let mut replay = self
                .replay
                .lock()
                .map_err(|_| io::Error::other("replay lock poisoned"))?;
            if !replay.0.insert(request_id.to_owned()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "request replayed",
                ));
            }
            replay.1.push_back(request_id.to_owned());
            while replay.1.len() > MAX_REPLAY_IDS {
                if let Some(old) = replay.1.pop_front() {
                    replay.0.remove(&old);
                }
            }
            Ok(())
        }

        fn journal(&self, identity: &ResourceIdentity, stage: &str) -> io::Result<()> {
            fs::create_dir_all(&self.journal_root)?;
            fs::set_permissions(&self.journal_root, fs::Permissions::from_mode(0o700))?;
            let body = serde_json::to_vec(&(identity, stage)).map_err(io::Error::other)?;
            let envelope = JournalEnvelope {
                identity: identity.clone(),
                stage: stage.to_owned(),
                mac: hmac_hex(&self.secret, &body)?,
            };
            let names = self.derive(identity)?;
            let path = self.journal_root.join(format!("{}.json", names.key));
            let temporary = self.journal_root.join(format!(".{}.tmp", names.key));
            let data = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&data)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(&self.journal_root)?.sync_all()?;
            Ok(())
        }

        fn remove_journal(&self, identity: &ResourceIdentity) -> io::Result<()> {
            let path = self
                .journal_root
                .join(format!("{}.json", self.derive(identity)?.key));
            match fs::remove_file(path) {
                Ok(()) => File::open(&self.journal_root)?.sync_all(),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }

    fn validate_request(request: &Request, peer: PeerCred, state: &State) -> io::Result<()> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported protocol version",
            ));
        }
        if request.boot_id != state.boot_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "boot id mismatch",
            ));
        }
        if request.client_pid != peer.pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer pid mismatch",
            ));
        }
        if process_start_time(peer.pid)? != request.client_start_time {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer pid start time mismatch",
            ));
        }
        validate_identifier(&request.project_id, 1, 128, "project_id")?;
        validate_identifier(&request.runtime_id, 1, 128, "runtime_id")?;
        validate_hex(&request.sandbox_token, 16, 128, "sandbox_token")?;
        state.accept_request_id(&request.request_id)
    }

    fn dispatch(request: &Request, state: &State) -> io::Result<IsolationStatus> {
        let identity = ResourceIdentity {
            project_id: request.project_id.clone(),
            runtime_id: request.runtime_id.clone(),
            sandbox_token: request.sandbox_token.clone(),
        };
        let names = state.derive(&identity)?;
        match request.op {
            Operation::Setup => setup(state, identity, names),
            Operation::AllowProxy => update_proxy(state, &names.key, request.port, true),
            Operation::RevokeProxy => update_proxy(state, &names.key, request.port, false),
            Operation::AttachProcess => attach_process(
                state,
                &names.key,
                request
                    .target_pid
                    .ok_or_else(|| io::Error::other("target_pid required"))?,
                request
                    .target_start_time
                    .ok_or_else(|| io::Error::other("target_start_time required"))?,
                request.client_pid,
            ),
            Operation::Join => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "join requires descriptor response",
            )),
            Operation::Teardown => teardown_key(state, &names.key),
            Operation::Status => {
                let resources = state
                    .resources
                    .lock()
                    .map_err(|_| io::Error::other("resource lock poisoned"))?;
                resources
                    .get(&names.key)
                    .map(|record| record.status.clone())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))
            }
        }
    }

    fn setup(
        state: &State,
        identity: ResourceIdentity,
        names: ResourceNames,
    ) -> io::Result<IsolationStatus> {
        {
            let resources = state
                .resources
                .lock()
                .map_err(|_| io::Error::other("resource lock poisoned"))?;
            if resources.contains_key(&names.key) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "sandbox already exists",
                ));
            }
        }
        state.journal(&identity, "intent")?;
        let result = (|| {
            run_ip(state, &["netns", "add", &names.netns])?;
            state.journal(&identity, "netns")?;
            run_ip(
                state,
                &[
                    "link",
                    "add",
                    &names.veth_host,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &names.veth_peer,
                ],
            )?;
            run_ip(
                state,
                &["link", "set", &names.veth_peer, "netns", &names.netns],
            )?;
            run_ip(
                state,
                &[
                    "addr",
                    "add",
                    &format!("{}/30", names.host_ip),
                    "dev",
                    &names.veth_host,
                ],
            )?;
            run_ip(state, &["link", "set", &names.veth_host, "up"])?;
            run_ip(
                state,
                &[
                    "-n",
                    &names.netns,
                    "addr",
                    "add",
                    &format!("{}/30", names.namespace_ip),
                    "dev",
                    &names.veth_peer,
                ],
            )?;
            run_ip(
                state,
                &["-n", &names.netns, "link", "set", &names.veth_peer, "up"],
            )?;
            run_ip(state, &["-n", &names.netns, "link", "set", "lo", "up"])?;
            run_ip(
                state,
                &[
                    "-n",
                    &names.netns,
                    "route",
                    "add",
                    "default",
                    "via",
                    &names.host_ip,
                ],
            )?;
            state.journal(&identity, "veth")?;
            create_cgroup(&names.cgroup)?;
            state.journal(&identity, "cgroup")?;
            apply_nft(state, &names, &HashSet::new(), false)?;
            state.journal(&identity, "active")?;
            Ok(())
        })();
        if let Err(error) = result {
            let mut record = ResourceRecord {
                identity: identity.clone(),
                names: names.clone(),
                ports: HashSet::new(),
                status: IsolationStatus {
                    quarantined: true,
                    ..IsolationStatus::default()
                },
            };
            let _ = teardown_record(state, &mut record);
            let _ = state.journal(&identity, "quarantined");
            return Err(error);
        }
        let status = IsolationStatus {
            helper_authenticated: true,
            network_namespace: true,
            nft_default_deny: true,
            cgroup_attached: true,
            process_isolated: false,
            resource_registry_verified: true,
            quarantined: false,
            proxy_host: names.host_ip.clone(),
        };
        state
            .resources
            .lock()
            .map_err(|_| io::Error::other("resource lock poisoned"))?
            .insert(
                names.key.clone(),
                ResourceRecord {
                    identity,
                    names,
                    ports: HashSet::new(),
                    status: status.clone(),
                },
            );
        Ok(status)
    }

    fn update_proxy(
        state: &State,
        key: &str,
        port: Option<u16>,
        add: bool,
    ) -> io::Result<IsolationStatus> {
        let port =
            port.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "port required"))?;
        if port == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid port"));
        }
        let mut resources = state
            .resources
            .lock()
            .map_err(|_| io::Error::other("resource lock poisoned"))?;
        let record = resources
            .get_mut(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))?;
        let mut desired = record.ports.clone();
        if add {
            desired.insert(port);
        } else {
            desired.remove(&port);
        }
        apply_nft(state, &record.names, &desired, true)?;
        record.ports = desired;
        Ok(record.status.clone())
    }

    fn join_authority(
        state: &State,
        key: &str,
        peer: PeerCred,
    ) -> io::Result<(IsolationStatus, OwnedFd)> {
        let mut resources = state
            .resources
            .lock()
            .map_err(|_| io::Error::other("resource lock poisoned"))?;
        let record = resources
            .get_mut(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))?;
        fs::write(
            record.names.cgroup.join("cgroup.procs"),
            peer.pid.to_string(),
        )?;
        let namespace = open_managed_netns(&record.names.netns)?;
        record.status.process_isolated = true;
        Ok((record.status.clone(), namespace))
    }

    fn attach_process(
        state: &State,
        key: &str,
        pid: u32,
        start_time: u64,
        ancestor: u32,
    ) -> io::Result<IsolationStatus> {
        if process_start_time(pid)? != start_time || !is_descendant(pid, ancestor)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target process identity is invalid",
            ));
        }
        let mut resources = state
            .resources
            .lock()
            .map_err(|_| io::Error::other("resource lock poisoned"))?;
        let record = resources
            .get_mut(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))?;
        fs::write(record.names.cgroup.join("cgroup.procs"), pid.to_string())?;
        record.status.process_isolated = true;
        Ok(record.status.clone())
    }

    fn teardown_key(state: &State, key: &str) -> io::Result<IsolationStatus> {
        let mut record = state
            .resources
            .lock()
            .map_err(|_| io::Error::other("resource lock poisoned"))?
            .remove(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))?;
        match teardown_record(state, &mut record) {
            Ok(()) => {
                state.remove_journal(&record.identity)?;
                Ok(IsolationStatus {
                    helper_authenticated: true,
                    resource_registry_verified: true,
                    ..IsolationStatus::default()
                })
            }
            Err(error) => {
                record.status.quarantined = true;
                state.journal(&record.identity, "quarantined")?;
                state
                    .resources
                    .lock()
                    .map_err(|_| io::Error::other("resource lock poisoned"))?
                    .insert(key.to_owned(), record);
                Err(error)
            }
        }
    }

    fn teardown_record(state: &State, record: &mut ResourceRecord) -> io::Result<()> {
        let mut errors = Vec::new();
        if let Err(error) = remove_cgroup(&record.names.cgroup) {
            errors.push(error.to_string());
        }
        if let Err(error) = run_nft(
            state,
            &["delete", "table", "inet", &record.names.nft_table],
            None,
        ) {
            if !error.to_string().contains("No such") {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = run_ip(state, &["link", "del", &record.names.veth_host]) {
            if !error.to_string().contains("Cannot find") {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = run_ip(state, &["netns", "del", &record.names.netns]) {
            if !error.to_string().contains("No such") && !error.to_string().contains("Cannot") {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    fn create_cgroup(path: &Path) -> io::Result<()> {
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| io::Error::other("cgroup parent missing"))?,
        )?;
        fs::create_dir(path)?;
        for (name, value) in [
            ("pids.max", "256"),
            ("memory.max", "1073741824"),
            ("memory.swap.max", "0"),
        ] {
            fs::write(path.join(name), value)?;
        }
        Ok(())
    }

    fn remove_cgroup(path: &Path) -> io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let kill = path.join("cgroup.kill");
        if kill.exists() {
            fs::write(kill, "1")?;
        }
        for _ in 0..50 {
            let events = fs::read_to_string(path.join("cgroup.events")).unwrap_or_default();
            if events.contains("populated 0") {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        fs::remove_dir(path)
    }

    fn apply_nft(
        state: &State,
        names: &ResourceNames,
        ports: &HashSet<u16>,
        replace: bool,
    ) -> io::Result<()> {
        let mut sorted: Vec<u16> = ports.iter().copied().collect();
        sorted.sort_unstable();
        let prefix = if replace {
            format!("delete table inet {}\n", names.nft_table)
        } else {
            String::new()
        };
        let mut script = format!(
            "{prefix}add table inet {0}\nadd chain inet {0} khaos_input {{ type filter hook input priority -150; policy accept; }}\nadd chain inet {0} khaos_forward {{ type filter hook forward priority -150; policy accept; }}\n",
            names.nft_table
        );
        for port in sorted {
            script.push_str(&format!(
                "add rule inet {} khaos_input iifname \"{}\" ip daddr {} tcp dport {} accept\n",
                names.nft_table, names.veth_host, names.host_ip, port
            ));
        }
        script.push_str(&format!("add rule inet {} khaos_input iifname \"{}\" drop\nadd rule inet {} khaos_forward iifname \"{}\" drop\n", names.nft_table, names.veth_host, names.nft_table, names.veth_host));
        run_nft(state, &["-f", "-"], Some(script.as_bytes()))
    }

    fn open_managed_netns(name: &str) -> io::Result<OwnedFd> {
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
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed netns target is not a namespace file",
            ));
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(descriptor.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        const NSFS_MAGIC: libc::c_long = 0x6e736673;
        if filesystem.f_type != NSFS_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed netns target is outside nsfs authority",
            ));
        }
        Ok(descriptor)
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

    fn run_ip(state: &State, args: &[&str]) -> io::Result<()> {
        run_trusted(&state.ip, args, None)
    }
    fn run_nft(state: &State, args: &[&str], stdin: Option<&[u8]>) -> io::Result<()> {
        run_trusted(&state.nft, args, stdin)
    }

    fn run_trusted(binary: &TrustedBinary, args: &[&str], stdin: Option<&[u8]>) -> io::Result<()> {
        let executable = binary.open_for_exec()?;
        let executable_path = format!("/proc/self/fd/{}", executable.as_raw_fd());
        let mut command = Command::new(&executable_path);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn()?;
        if let (Some(data), Some(mut writer)) = (stdin, child.stdin.take()) {
            writer.write_all(data)?;
        }
        let output = child.wait_with_output()?;
        binary.open_for_exec()?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "{} failed: {}",
            binary.path.display(),
            String::from_utf8_lossy(&output.stderr)
        )))
    }

    impl TrustedBinary {
        fn open(path: &'static str) -> io::Result<Self> {
            let configured_path = Path::new(path);
            if !configured_path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCB binary path must be absolute",
                ));
            }
            validate_parent_chain(configured_path)?;
            let configured_metadata = fs::symlink_metadata(configured_path)?;
            if configured_metadata.uid() != 0 || configured_metadata.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCB binary link ownership or mode invalid",
                ));
            }
            // usrmerge distributions expose package-managed tools through
            // root-owned symlinks (for example /usr/sbin/ip -> /usr/bin/ip).
            // Resolve that immutable link first, then apply O_NOFOLLOW,
            // owner/mode and device/inode checks to the actual executable.
            let resolved_path = fs::canonicalize(configured_path)?;
            validate_parent_chain(&resolved_path)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&resolved_path)?;
            let metadata = file.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCB binary ownership or mode invalid",
                ));
            }
            Ok(Self {
                path: resolved_path,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        fn open_for_exec(&self) -> io::Result<File> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&self.path)?;
            let metadata = file.metadata()?;
            if metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCB binary identity changed",
                ));
            }
            Ok(file)
        }
    }

    fn validate_parent_chain(path: &Path) -> io::Result<()> {
        let mut current = path.parent();
        while let Some(parent) = current {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCB parent directory is mutable",
                ));
            }
            current = parent.parent();
        }
        Ok(())
    }

    fn handle_connection(
        mut stream: UnixStream,
        allowed_uid: u32,
        state: Arc<State>,
    ) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let peer = peer_cred(&stream)?;
        if peer.uid != allowed_uid {
            return write_error(&mut stream, "", "peer uid not allowed");
        }
        let request = read_request(&mut stream)?;
        let request_id = request.request_id.clone();
        validate_request(&request, peer, &state)?;
        if request.op == Operation::Join {
            let identity = ResourceIdentity {
                project_id: request.project_id.clone(),
                runtime_id: request.runtime_id.clone(),
                sandbox_token: request.sandbox_token.clone(),
            };
            let names = state.derive(&identity)?;
            let (status, namespace) = join_authority(&state, &names.key, peer)?;
            let response = Response {
                protocol_version: PROTOCOL_VERSION,
                request_id: &request_id,
                ok: true,
                error: None,
                status: Some(status),
            };
            return write_response_with_fd(&stream, &response, namespace.as_raw_fd());
        }
        let result = dispatch(&request, &state);
        let response = match result {
            Ok(status) => Response {
                protocol_version: PROTOCOL_VERSION,
                request_id: &request_id,
                ok: true,
                error: None,
                status: Some(status),
            },
            Err(error) => Response {
                protocol_version: PROTOCOL_VERSION,
                request_id: &request_id,
                ok: false,
                error: Some(error.to_string()),
                status: None,
            },
        };
        write_response(&mut stream, &response)
    }

    fn read_request(stream: &mut UnixStream) -> io::Result<Request> {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request length invalid",
            ));
        }
        let mut data = vec![0_u8; length];
        stream.read_exact(&mut data)?;
        serde_json::from_slice(&data).map_err(io::Error::other)
    }

    fn write_response(stream: &mut UnixStream, response: &Response<'_>) -> io::Result<()> {
        let data = serde_json::to_vec(response).map_err(io::Error::other)?;
        stream.write_all(&(data.len() as u32).to_be_bytes())?;
        stream.write_all(&data)
    }

    fn write_response_with_fd(
        stream: &UnixStream,
        response: &Response<'_>,
        descriptor: RawFd,
    ) -> io::Result<()> {
        let data = serde_json::to_vec(response).map_err(io::Error::other)?;
        let length = (data.len() as u32).to_be_bytes();
        let vectors = [
            libc::iovec {
                iov_base: length.as_ptr().cast_mut().cast(),
                iov_len: length.len(),
            },
            libc::iovec {
                iov_base: data.as_ptr().cast_mut().cast(),
                iov_len: data.len(),
            },
        ];
        let control_length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
        let mut control = vec![0_u8; control_length as usize];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = vectors.as_ptr().cast_mut();
        message.msg_iovlen = vectors.len();
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::other("SCM_RIGHTS header unavailable"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
            std::ptr::copy_nonoverlapping(&descriptor, libc::CMSG_DATA(header).cast::<RawFd>(), 1);
            message.msg_controllen = (*header).cmsg_len;
            let sent = libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            if sent as usize != length.len() + data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short descriptor response",
                ));
            }
        }
        Ok(())
    }
    fn write_error(stream: &mut UnixStream, request_id: &str, error: &str) -> io::Result<()> {
        write_response(
            stream,
            &Response {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                ok: false,
                error: Some(error.to_owned()),
                status: None,
            },
        )
    }

    fn peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PeerCred {
            pid: cred.pid as u32,
            uid: cred.uid,
        })
    }

    fn process_start_time(pid: u32) -> io::Result<u64> {
        let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
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

    fn is_descendant(mut pid: u32, ancestor: u32) -> io::Result<bool> {
        for _ in 0..128 {
            if pid == ancestor {
                return Ok(true);
            }
            if pid <= 1 {
                return Ok(false);
            }
            let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            let end = value
                .rfind(')')
                .ok_or_else(|| io::Error::other("invalid proc stat"))?;
            pid = value[end + 2..]
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| io::Error::other("missing ppid"))?
                .parse()
                .map_err(io::Error::other)?;
        }
        Ok(false)
    }

    fn read_secret(path: &Path) -> io::Result<Vec<u8>> {
        validate_parent_chain(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper secret ownership or mode invalid",
            ));
        }
        let mut secret = Vec::new();
        file.take(128).read_to_end(&mut secret)?;
        if secret.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "helper secret too short",
            ));
        }
        Ok(secret)
    }

    fn hmac_hex(secret: &[u8], input: &[u8]) -> io::Result<String> {
        let mut mac = HmacSha256::new_from_slice(secret).map_err(io::Error::other)?;
        mac.update(input);
        Ok(mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
    fn validate_identifier(value: &str, min: usize, max: usize, label: &str) -> io::Result<()> {
        if value.len() < min
            || value.len() > max
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
    fn validate_hex(value: &str, min: usize, max: usize, label: &str) -> io::Result<()> {
        if value.len() < min
            || value.len() > max
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {label}"),
            ));
        }
        Ok(())
    }

    fn recover(state: &Arc<State>) -> io::Result<()> {
        fs::create_dir_all(&state.journal_root)?;
        for entry in fs::read_dir(&state.journal_root)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read(entry.path())?;
            let envelope: JournalEnvelope = match serde_json::from_slice(&data) {
                Ok(value) => value,
                Err(_) => {
                    fs::rename(entry.path(), entry.path().with_extension("quarantine"))?;
                    continue;
                }
            };
            let body = serde_json::to_vec(&(&envelope.identity, &envelope.stage))
                .map_err(io::Error::other)?;
            if hmac_hex(&state.secret, &body)? != envelope.mac {
                fs::rename(entry.path(), entry.path().with_extension("quarantine"))?;
                continue;
            }
            let names = state.derive(&envelope.identity)?;
            let mut record = ResourceRecord {
                identity: envelope.identity,
                names: names.clone(),
                ports: HashSet::new(),
                status: IsolationStatus {
                    quarantined: true,
                    ..IsolationStatus::default()
                },
            };
            if teardown_record(state, &mut record).is_ok() {
                let _ = fs::remove_file(entry.path());
            } else {
                state
                    .resources
                    .lock()
                    .map_err(|_| io::Error::other("resource lock poisoned"))?
                    .insert(names.key, record);
            }
        }
        Ok(())
    }

    pub fn main() -> io::Result<()> {
        let socket_path = std::env::var("KHAOS_BROWSER_KERNEL_HELPER_SOCKET")
            .unwrap_or_else(|_| DEFAULT_SOCKET.to_owned());
        let allowed_uid = std::env::var("KHAOS_BROWSER_KERNEL_HELPER_UID")
            .map_err(|_| io::Error::other("allowed helper uid is required"))?
            .parse::<u32>()
            .map_err(io::Error::other)?;
        if allowed_uid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "browser client uid must be non-root",
            ));
        }
        let secret_path = PathBuf::from(
            std::env::var("KHAOS_BROWSER_HELPER_SECRET_FILE")
                .unwrap_or_else(|_| DEFAULT_SECRET.to_owned()),
        );
        let journal_root = PathBuf::from(
            std::env::var("KHAOS_BROWSER_HELPER_JOURNAL_ROOT")
                .unwrap_or_else(|_| DEFAULT_JOURNAL.to_owned()),
        );
        let state = Arc::new(State {
            secret: read_secret(&secret_path)?,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
            journal_root,
            resources: Mutex::new(HashMap::new()),
            replay: Mutex::new((HashSet::new(), VecDeque::new())),
            ip: TrustedBinary::open(IP_PATH)?,
            nft: TrustedBinary::open(NFT_PATH)?,
        });
        recover(&state)?;
        if let Some(parent) = Path::new(&socket_path).parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        let socket_c = CString::new(socket_path.clone()).map_err(io::Error::other)?;
        if unsafe { libc::chown(socket_c.as_ptr(), allowed_uid, u32::MAX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let active = Arc::new(AtomicUsize::new(0));
        for incoming in listener.incoming() {
            let stream = incoming?;
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::AcqRel);
                drop(stream);
                continue;
            }
            let state = Arc::clone(&state);
            let active = Arc::clone(&active);
            thread::spawn(move || {
                let _ = handle_connection(stream, allowed_uid, state);
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn request_json(extra: &str) -> String {
            format!(
                r#"{{"protocol_version":1,"request_id":"request-123","boot_id":"boot","client_pid":42,"client_start_time":99,"project_id":"project","runtime_id":"runtime","sandbox_token":"0123456789abcdef0123456789abcdef","op":"status","port":null,"target_pid":null,"target_start_time":null{extra}}}"#
            )
        }

        #[test]
        fn request_rejects_unknown_fields() {
            let error = serde_json::from_str::<Request>(&request_json(",\"argv\":[\"ip\"]"))
                .expect_err("unknown helper fields must fail");
            assert!(error.to_string().contains("unknown field"));
        }

        #[test]
        fn request_rejects_unknown_operations() {
            let invalid = request_json("").replace("\"status\"", "\"run_command\"");
            assert!(serde_json::from_str::<Request>(&invalid).is_err());
        }

        #[test]
        fn managed_netns_names_are_strict() {
            assert!(validate_netns_name("khaos-br-0123456789ab").is_ok());
            for invalid in [
                "../host",
                ".",
                "..",
                "khaos-br-0123456789a/",
                "other-0123456789abcdef",
            ] {
                assert!(validate_netns_name(invalid).is_err(), "accepted {invalid}");
            }
        }

        #[test]
        fn resource_identity_is_bound_to_boot_and_principal_scope() {
            let secret = [0x5a_u8; 32];
            let first = hmac_hex(&secret, b"boot-a\0project\0runtime\0token").unwrap();
            let same = hmac_hex(&secret, b"boot-a\0project\0runtime\0token").unwrap();
            let other_boot = hmac_hex(&secret, b"boot-b\0project\0runtime\0token").unwrap();
            let other_project = hmac_hex(&secret, b"boot-a\0other\0runtime\0token").unwrap();
            assert_eq!(first, same);
            assert_ne!(first, other_boot);
            assert_ne!(first, other_project);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::main() {
        eprintln!("khaos-browser-kernel-helper: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("khaos-browser-kernel-helper: Linux-only");
    std::process::exit(126);
}
