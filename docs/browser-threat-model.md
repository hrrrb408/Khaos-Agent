# Browser Threat Model (Round 8 closure)

## Enforced authority boundary

A `BrowserManager` generation owns one Chromium process tree, network
namespace, cgroup, nftables table and registry record. That generation is
leased to exactly one authenticated principal. Sessions and runtimes for that
principal may use separate `BrowserContext` objects, but a second principal is
rejected fail-closed for the lifetime of the process generation.

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

Production launch is permitted only after netns, cgroup, nftables, trusted
Rust launcher, FD sanitization and filesystem sandbox enforcement have all
been established. Sandbox setup failure poisons the generation; retry cannot
fall through to direct Chromium. The Rust launcher preserves only Playwright's
FD 3/4 pipes, closes unrelated descriptors, joins cgroup/netns, enters the
mount sandbox, installs `no_new_privs` and seccomp, then execs Chromium.

Context teardown removes its nft port while the authenticated proxy still owns
the socket, closes the proxy, and finally closes the context. Generation
teardown removes wrappers, kills and removes the cgroup, then removes nft/netns
resources. Partial cleanup remains registered and makes shutdown fail until a
retry succeeds; it is never reported as closed.

Registry entries contain owner PID/start-time, boot ID, lifecycle stage and an
HMAC. Resource names are derived from the same per-install secret. The Browser
mount namespace cannot access that secret. Corrupt or unauthenticated entries
are quarantined rather than trusted by the reaper.

## Claims and deployment rule

Safe claim: Khaos enforces a single-principal Chromium generation with
kernel-default-deny egress, filesystem hiding, cgroup limits, descriptor
sanitization and retryable fail-closed teardown on supported Linux hosts.

Not a safe claim: one `BrowserManager` can safely serve several principals.
Multi-user deployments must instantiate independent generations; if they do
not, the built-in principal lease rejects the second principal.
