# ADR-020: Native macOS and Windows Authority Transports

**Status:** Accepted for M6 implementation

## Context

The Linux authority daemon already has a distinct UID and private Unix-socket
contract. A Python process running beside the Agent cannot provide the same
boundary on macOS or Windows. In particular, a same-UID mock, a Unix-socket
substitute, or an environment variable claiming a service identity would not
prove the peer or protect the signing key.

## Decision

macOS production uses a launchd-owned Mach service with an XPC client and
service. The service checks the incoming audit token, the Agent code-signing
identity, its own signed identity, and a Keychain item in the authority access
group before forwarding a bounded request to the authority backend. The
backend socket is authority-owned and is never opened by the Agent client.

Windows production uses a Service-SID-owned native service and an ACL-bound
Named Pipe. The service must prove its Service SID and pipe client identity,
and unlock only a DPAPI/CNG-protected authority key inside the service. The
Python client talks to a native pipe client; it never changes to TCP, a Unix
socket, or an in-process broker.

The Python `NativeAuthorityProof` is an admission record, not a self-issued
claim. A native executable must return the exact proof fields, and the client
rejects missing fields, stale proof digests, incorrect transport, and
unverified key/peer state. Platform jobs report missing signed deployment
inputs as unavailable; they do not convert that state into production success.

## Consequences

- Local Linux and unit tests can validate fail-closed parsing and wiring but
  cannot produce macOS/Windows native closure evidence.
- A release deployment must install and sign the native service artifacts and
  provision the protected key in the platform security domain.
- The existing Linux authority path remains unchanged; this decision does not
  turn development brokers into production authorities.
