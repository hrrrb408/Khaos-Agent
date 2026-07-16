# Verification Write Authority Security Boundary

## Database open-path audit

| Location | Mode/path control | Verification write authority exposure |
|---|---|---|
| `approval.store.open_store()` | Legacy `sqlite3.connect(path)` read/write; caller chooses path | Not an authority factory. Production `ApprovalRuntime` must receive this store only from trusted bootstrap and never expose it to Agent/plugin code. |
| `ApprovalRuntime._configure_trusted_verification_internal()` | Uses the already-open trusted approval connection | Creates the only production `VerificationExecutionStore`, starts the boot-scoped authority, and binds the store before Runner construction. |
| `TrustedVerificationRunner.__init__()` | Does not open a production DB | Reuses the Runtime-bound store. A production backend without write authority is rejected. |
| `VerificationExecutionStore.open_readonly()` | No caller path/factory | Returns a fixed-query `VerificationReadHandle` over the authority-owned EXCLUSIVE connection; it exposes no SQL API and cannot close the owner handle. |
| Approval/verification startup recovery | Same Runtime-owned store | No independent connection or caller path. Success requires current authority evidence. |
| CLI/TUI `Database` | Application `khaos.db` selected by CLI | General application persistence, not a Verification Authority API. It is not passed to Sandbox/project code. |
| `IndexStore` and repository intelligence | Separate caller/store connection | Code intelligence data only; cannot establish trusted verification success. |
| Tests under `python/tests/coding` | Explicit file or in-memory SQLite | Test-only construction. Direct `VerificationExecutionStore(store)` without authority is unsafe-test compatibility and is not accepted by the production Runner. |

No production Verification path uses `aiosqlite`, SQLAlchemy, a caller-provided
connection factory, or a caller-selected verification database path.

## Writable principals

- Trusted Runtime bootstrap owns the original approval SQLite connection.
- The boot-scoped `VerificationWriteAuthority` pins that writer and the
  DB/WAL/SHM/parent identities.
- A dedicated authority subprocess is the sole writer of the authoritative
  CleanupProof/success ledger. It receives commands only over an inherited
  anonymous pipe.
- Runner and Scheduler call typed store methods; they do not receive the IPC
  pipe, capability, ledger path, or authority database connection.
- CLI/TUI, plugins, Agent tools, Sandbox project code and Verification
  Workspace code receive neither a writable connection nor an authority API.
- Test helpers can deliberately construct an unsafe store, but production
  Runner construction rejects an unbound store.

The general approval connection remains writable inside the trusted Runtime
process because Batch 2/3 mutation and lease state share the file. Its
`passed/verified` columns are caches, not sufficient trusted success evidence.
A trusted success read additionally requires immutable persisted evidence and
confirmation from the live authority subprocess ledger.

## Authority IPC and lifecycle

The Runtime creates one authority per `(runtime_id, boot_id)`. Direct class
construction and duplicate issuance are rejected. The authority creates an
anonymous `multiprocessing.Pipe` and a 256-bit capability before spawning its
ledger process. The capability is never placed in SQLite, argv, environment,
repository files, logs or Sandbox mounts. Every request carries a strictly
monotonic sequence; wrong capability, wrong sequence and replay fail closed.

Supported authority commands are deliberately narrow:

- authorize/require canonical CleanupProof binding;
- record/require canonical final-success binding;
- shutdown.

There is no `passed=True`, `verified=True` or `proof_valid=True` command. The
main Runtime still reloads and revalidates CleanupProof, Artifact, Sandbox,
Disposable Workspace and canonical Workspace evidence before asking the
authority to record the canonical binding. An authority crash invalidates the
pipe and makes proof persistence/finalization fail. A new boot does not inherit
the prior in-memory/ledger authority.

## SQLite and filesystem responsibilities

SQLite triggers enforce state-machine prerequisites, existence of a
CleanupProof and immutable evidence. They do not identify a trusted
connection. The former connection-local UDF is absent from production code.

After schema migration, Runtime switches SQLite to WAL + EXCLUSIVE locking,
commits a bootstrap write, retains the resulting OS lock for the authority
lifetime, pins the schema/trigger digest and opens the
database parent chain with `O_DIRECTORY | O_NOFOLLOW`. It records
dev/inode/uid/gid/mode for parent, DB, WAL and SHM when present; an SHM omitted
by SQLite's exclusive-WAL mode is pinned as absent. DB/WAL/SHM directory entries
are set to `0o400` while the authority connection remains active. A connection
opened before activation but not holding a transaction is still denied by the
retained SQLite lock; an already-active writer makes authority startup fail
closed. Independent `mode=rw`/`mode=rwc` writers therefore cannot rely on a
pre-open descriptor to bypass later chmod.
Every authority operation checks directory entries against the fixed FDs and
checks the schema digest. Database, WAL, SHM or parent replacement fails
closed. Shutdown restores owner write permission through the fixed FDs, not
through replaceable path strings.

Each boot creates the child authority ledger with `O_CREAT | O_EXCL | O_NOFOLLOW`
inside a random server-selected directory under the verification storage parent.
The directory is owner-only `0o700`; the initial ledger must be a regular,
single-link, owner-held `0o600` file. Before reporting ready, the child switches
the ledger to WAL plus `locking_mode=EXCLUSIVE`, forces and retains the exclusive
lock, then fixes DB/WAL/SHM dev/inode/owner/mode/nlink identities. Existing
writers either lose the race to the retained lock or make startup fail closed.
Directory-entry replacement, symlink/FIFO precreation, hardlink creation and
sidecar appearance are rejected. The fixed DB/WAL/SHM entries are `0o400` while
the already-open child writer remains active. Each boot ledger remains on disk
for audit, but proof/success capability is never reused across boot ledgers.

## Migration and historical success

Startup drops the old UDF-dependent success triggers and recreates consistency
triggers without connection authentication. It creates immutable
`verification_success_evidence`. Existing duplicated CleanupProofs still stop
migration.

`PASSED` or `VERIFIED` records from an earlier boot cannot be anchored to the
new ephemeral authority ledger. They are atomically changed to
`ERRORED/VERIFICATION_ERROR` with
`historical-success-requires-audit`; Khaos never guesses that they passed.
This deliberately sacrifices automatic reuse of historical success until a
future durable, separately owned signing ledger is introduced.

## Threat model

Covered:

- plugins limited to public Khaos APIs;
- components that know a state ID but have no Runtime authority;
- components that can read the ordinary database path but cannot change file
  permissions;
- independent local processes attempting ordinary SQLite writes, UDF spoofing,
  trigger removal, forged CleanupProof insertion or state updates during an
  active Runtime;
- DB/WAL/SHM inode replacement, unexpected sidecar creation and parent rename/symlink swap, which are
  detected and fail closed;
- Sandbox and repository code, which never receives the database, pipe or
  capability.

Not covered:

- malicious Python already executing inside the trusted Khaos Runtime process;
- a same-UID attacker that deliberately changes owner-controlled permissions,
  debugs the Runtime or steals its inherited descriptors;
- root/administrator compromise, kernel compromise or physical rollback of all
  Runtime storage.

Those attackers cross the documented OS/process authority boundary. SQLite
triggers are not claimed to defend them. Defending a hostile same-UID process
requires running the complete state writer under a separate OS identity and
authenticating a Unix socket with peer credentials; the implementation must
fail closed rather than silently downgrade when that deployment mode is added.
