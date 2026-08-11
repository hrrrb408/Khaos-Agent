# Authority and Network Effect Boundaries

This document records the three local execution boundaries that must remain
separate from model input and ordinary Python data classes.

## Authority context versus effect capability

`AuthorityEnvelope` identifies the principal, project, runtime, task,
workspace generation, policy digest and resource context. It is suitable for
audit and approval binding, but it is not accepted by an effect runner.

`AuthorityBroker` is a spawned control-plane process. It owns the HMAC secret,
capability registry, expiry and revocation state. `EffectCapability` objects
can only be created through the broker client; effect boundaries still ask the
broker to validate the live token, operation prefix, resource digest,
generation, epoch and expiry. Derivation narrows the operation label and does
not mint an independently transferable authority.

This protects against accidental or model-controlled construction of an
authority object. It does not claim protection against a hostile process that
already runs as the same OS user and can interfere with the trusted control
plane.

## Managed terminal egress

`NetworkBroker` is the generic HTTP/HTTPS egress broker for Coding tools and
terminal subprocesses. Its protocol is intentionally narrow:

- HTTP uses absolute-form requests; HTTPS uses CONNECT followed by a checked
  TLS ClientHello/SNI.
- The broker, not the worker, performs DNS resolution and connects to the
  selected pinned address. Non-public results are rejected unless the target
  was explicitly registered as a local test endpoint.
- Domain, blocklist, port and protocol policy is checked before connect.
- Proxy authentication, bounded concurrent connections, idle timeout, upload
  and download ceilings, and allow/deny audit events are mandatory.
- The returned `NetworkLease` is bound to the exact endpoint and policy by a
  second broker-issued capability. Backends validate that lease before launch
  and the broker revalidates it for every connection, so expiry/revocation
  closes new egress.

On macOS and Windows, a brokered worker may use the exact loopback proxy
endpoint. On Linux, a loopback proxy combined with `bwrap --unshare-net` is
not a valid design because the worker's loopback is a different namespace.
Linux therefore requires `NetworkBroker(linux_namespace=True)`, an
authenticated kernel-helper namespace/veth contract, and `--share-net` inside
the final bubblewrap namespace. The outer Rust launcher consumes the join
contract; model-controlled environment values never authorize the join.

## Windows native backend

`WindowsSandboxBackend` has no Host fallback. The Rust helper must prove before
execution:

1. a restricted primary token with the restricted-code SID;
2. a kill-on-close Job Object with resource limits and active-process limit one;
3. a transactionally granted/restored restricted-code workspace ACL;
4. a WFP-backed Windows Firewall transaction; and
5. exact resolution to a native `.exe`/`.com`, never a shell script.

The active-process limit is deliberate: Windows program firewall rules cannot
reliably authorize unknown descendants during a process-discovery race. A
command that needs a child process is refused by the Job Object rather than
being allowed an ungoverned network tree. Windows brokered egress is limited
to IPv4 loopback and the exact broker port; all other IPv4/IPv6 paths are
blocked.

The helper probe and native execution job run on Windows hosted CI. A missing
helper or any incomplete probe returns infrastructure-unsupported and keeps
the fail-closed behavior.
