# Browser Threat Model (Round 8 closure)

## Enforced authority boundary

A runtime-owned `BrowserManager` generation owns one Chromium process tree.
Its kernel resources are owned exclusively by the root Rust helper and keyed
by principal/project/task/runtime identity plus an opaque sandbox token. Python never chooses
netns, veth, nft or cgroup names. A manager is injected into one runtime; it is
not stored in a mutable module-global holder.

This single-principal lease is intentional. A `BrowserContext` is an API state
boundary, not a containment boundary for a compromised Chromium process. A
multi-user service must therefore allocate a distinct `BrowserManager` process
generation per principal/project authority domain; it may not share this
singleton between principals.

| Layer | Scope | Enforced guarantee |
|---|---|---|
| Chromium process tree | one principal per generation | a second principal is denied |
| Linux mount namespace (`bwrap`) | process generation | `/home`, `/root` and host temp are hidden; synthetic HOME/tmp only |
| Network namespace + nftables | process generation | default deny; only authenticated proxy ports are pinned |
| cgroup v2 | process generation | pids, memory, CPU and I/O budget |
| `BrowserContext` | per session/runtime key | cookie, DOM and storage separation within one principal |
| Egress proxy | per context | credentialed relay plus DNS/IP revalidation |

## Launch and teardown transaction

Production Python must run with effective UID other than zero and without
`CAP_NET_ADMIN` or `CAP_SYS_ADMIN`. A root-owned helper authenticates the
non-root client over a protected UDS using an explicitly configured daemon PID,
UID, PID start time and boot identity. The daemon first obtains a secret-backed,
principal/project/task/runtime-bound capability; all later operations must present
that capability and cannot be issued by another process that merely shares the UID.
Production launch is permitted only after helper-authenticated
netns, cgroup, nftables, trusted Rust launcher, FD sanitization and filesystem
sandbox enforcement have been established. Helper unavailability or partial
setup poisons the generation; no CLI or Host fallback is reachable.

On Linux, the root-owned Rust launcher carries only the file capability
`CAP_SYS_ADMIN=ep` needed for the single `setns` into the namespace descriptor
returned by the authenticated helper. It validates the helper peer, protocol
response, isolation evidence and nsfs descriptor before joining, then clears
all effective, permitted and inheritable capabilities and sets `no_new_privs`
before invoking bubblewrap or Chromium. Python and Chromium never receive that
capability.

The Rust launcher preserves only Playwright's
FD 3/4 pipes, closes unrelated descriptors, joins cgroup/netns, enters the
mount sandbox, installs `no_new_privs` and seccomp, then execs Chromium.
The Chromium runtime itself must be installed in a root-owned, read-only path
traversable by the launcher user namespace (for example
`/opt/khaos-playwright`); a browser cache under a private user Home is rejected
rather than weakening Home directory permissions.

Context teardown removes its nft port while the authenticated proxy still owns
the socket, closes the proxy, and finally closes the context. Generation
teardown removes wrappers, kills and removes the cgroup, then removes nft/netns
resources. Partial cleanup remains registered and makes shutdown fail until a
retry succeeds; it is never reported as closed.

Helper journal entries contain boot and lifecycle identity plus the allocated
subnet lease. Resource names are derived as HMAC(helper secret, boot ID,
principal ID, project ID, runtime ID, task ID, sandbox token). Address allocation
uses an active in-memory and authenticated-journal lease registry with collision
probing; two live sandboxes never receive the same `/30` merely because their
digest prefixes collide. The allocator covers 262,143 `/30` leases in
`10.192.0.0/12`, persists the selected lease in the authenticated journal, and
fails closed on actual pool exhaustion instead of aliasing a live subnet.
The Browser
mount namespace cannot access that secret. Corrupt or unauthenticated entries
are quarantined rather than trusted by the reaper.

## Claims and deployment rule

Safe claim: on the Linux workflow proven by the current commit's required
gate, Khaos enforces a runtime-owned Chromium generation with
kernel-default-deny egress, filesystem hiding, cgroup limits, descriptor
sanitization and retryable fail-closed teardown on supported Linux hosts.

Not a safe claim: absolute containment, or support on an OS without a passing
real-kernel gate. Windows remains explicitly unsupported and fail-closed.
