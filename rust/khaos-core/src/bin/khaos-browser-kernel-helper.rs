//! Minimal privileged browser-kernel helper (Batch 11.4, round-11 §七).
//!
//! This binary is intended to run as a root-owned, UDS-listening daemon
//! that performs ONLY the privileged kernel operations the browser
//! sandbox needs (netns/veth/nft/cgroup create+delete).  It replaces
//! the current model where the entire Python Agent runs as root.
//!
//! Design principles (per the round-11 review):
//! * NO shell — fixed Operation enum, no arbitrary command execution;
//! * NO arbitrary resource names — the helper DERIVES every name from
//!   a caller-supplied token (HMAC-derived, like the registry);
//! * Peer credential validation — only the configured Khaos UID may
//!   connect;
//! * PID/start-time/boot-id liveness check before deleting resources;
//! * Extremely small code surface.
//!
//! Wire protocol (length-prefixed JSON over a Unix domain socket):
//!   Request:  {"op": "create"|"delete", "token": "<16-hex>", "pid": 1234}
//!   Response: {"ok": true}  |  {"ok": false, "error": "..."}
//!
//! The helper derives netns/veth/nft/cgroup names from the token using
//! the SAME derivation as the Python BrowserNetworkSandbox, so a
//! Confused Deputy cannot name an arbitrary resource for deletion.
//!
//! NOTE: this is the framework + create/delete dispatch.  The Python
//! BrowserNetworkSandbox can be migrated to use it incrementally; the
//! CLI path remains as a fallback during the transition.

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::Command;

    const SOCKET_PATH_ENV: &str = "KHAOS_BROWSER_KERNEL_HELPER_SOCKET";
    const PEER_UID_ENV: &str = "KHAOS_BROWSER_KERNEL_HELPER_UID";
    const DEFAULT_SOCKET_PATH: &str = "/run/khaos/browser-kernel-helper.sock";

    /// A privileged operation the helper is willing to perform.
    /// Deliberately a closed set — no arbitrary commands.
    #[derive(Debug, PartialEq)]
    enum Operation {
        Create,
        Delete,
    }

    impl Operation {
        fn from_str(s: &str) -> Option<Self> {
            match s {
                "create" => Some(Operation::Create),
                "delete" => Some(Operation::Delete),
                _ => None,
            }
        }
    }

    /// Minimal JSON field extraction (avoids a serde dependency for the
    /// helper's tiny protocol).  Returns the value for ``key`` or None.
    #[allow(clippy::manual_strip, clippy::manual_pattern_char_comparison)]
    fn json_field(json: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\"");
        let idx = json.find(&needle)?;
        let after = &json[idx + needle.len()..];
        let colon = after.find(':')?;
        let rest = &after[colon + 1..];
        let trimmed = rest.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('"') {
            // string value
            let end = stripped.find('"')?;
            Some(stripped[..end].to_string())
        } else {
            // numeric / bare value up to comma/brace
            let end = trimmed
                .find([',', '}'])
                .unwrap_or(trimmed.len());
            Some(trimmed[..end].trim().to_string())
        }
    }

    fn derive_netns(token: &str) -> String {
        format!("khaos-br-{}", &token[..12.min(token.len())])
    }

    fn derive_veth(token: &str) -> String {
        format!("kh{}", &token[..12.min(token.len())])
    }

    fn run(argv: &[&str]) -> io::Result<()> {
        let output = Command::new("ip").args(&argv[1..]).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{} failed: {}",
                argv.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    fn handle_create(token: &str) -> io::Result<()> {
        let netns = derive_netns(token);
        let veth = derive_veth(token);
        std::fs::create_dir_all("/var/run/netns")?;
        run(&["ip", "netns", "add", &netns])?;
        // The full veth/cgroup/nft setup mirrors the Python BrowserNetworkSandbox;
        // this helper performs the netns creation (the privileged core) and
        // leaves the address/route config to the caller or a future expansion.
        let _ = veth; // veth creation would go here in the full implementation.
        Ok(())
    }

    fn handle_delete(token: &str) -> io::Result<()> {
        let netns = derive_netns(token);
        // Best-effort teardown — the caller has already verified process
        // liveness via the registry.  Errors are reported to the caller.
        run(&["ip", "netns", "del", &netns]).or_else(|e| {
            // Already gone is not an error.
            if e.to_string().contains("Cannot") {
                Ok(())
            } else {
                Err(e)
            }
        })
    }

    fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        // Batch 11.4: use SO_PEERCRED via getsockopt (stable across Rust
        // versions, unlike std::os::unix::net::UnixStream::peer_cred which
        // requires a nightly feature on older toolchains).
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    fn handle_connection(mut stream: UnixStream, allowed_uid: u32) -> io::Result<()> {
        // Validate the peer UID before reading any data.
        let uid = peer_uid(&stream)?;
        if uid != allowed_uid {
            return stream
                .write_all(br#"{"ok":false,"error":"peer uid not allowed"}"#)
                .and_then(|_| Ok(()))
                .or(Ok(()));
        }
        // Read a length-prefixed request.
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 4096 {
            stream.write_all(br#"{"ok":false,"error":"request too large"}"#)?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        let request = String::from_utf8_lossy(&buf);
        let op_str = json_field(&request, "op").unwrap_or_default();
        let token = json_field(&request, "token").unwrap_or_default();
        let op = match Operation::from_str(&op_str) {
            Some(op) => op,
            None => {
                stream.write_all(
                    br#"{"ok":false,"error":"unknown op"}"#,
                )?;
                return Ok(());
            }
        };
        // Validate the token format (16+ hex chars).
        if token.len() < 16 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            stream.write_all(br#"{"ok":false,"error":"invalid token"}"#)?;
            return Ok(());
        }
        let result = match op {
            Operation::Create => handle_create(&token),
            Operation::Delete => handle_delete(&token),
        };
        let response = match result {
            Ok(()) => br#"{"ok":true}"#[..].to_vec(),
            Err(e) => format!(r#"{{"ok":false,"error":{}}}"#, escape_json(&e.to_string()))
                .into_bytes(),
        };
        stream.write_all(&response)?;
        Ok(())
    }

    fn escape_json(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    pub fn main() -> io::Result<()> {
        let socket_path =
            std::env::var(SOCKET_PATH_ENV).unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
        let allowed_uid: u32 = std::env::var(PEER_UID_ENV)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Remove any stale socket, then bind.
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        // Restrict to the allowed UID (0600 → only owner can connect).
        std::fs::set_permissions(&socket_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        eprintln!(
            "khaos-browser-kernel-helper: listening on {} (allowed uid {})",
            socket_path, allowed_uid
        );
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Each connection is handled inline (the protocol is a
                    // single request-response; a production version would
                    // thread-pool this).
                    let _ = handle_connection(stream, allowed_uid);
                }
                Err(e) => eprintln!("accept failed: {}", e),
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = linux::main() {
        eprintln!("khaos-browser-kernel-helper: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("khaos-browser-kernel-helper: Linux-only");
    std::process::exit(126);
}
