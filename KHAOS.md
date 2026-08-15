# Khaos Project Instructions

This is the root instruction file for the Khaos repository.

Agents working in this repository must read and follow `AGENTS.md` before
modifying code, tests, Docker files, or documentation. The active project
layout is Python Agent logic, Go API gateway, Rust security-critical TCB
launchers/helpers plus performance modules, and SQLite-backed local storage.
The machine-readable security boundary is `docs/security_facts.yaml`.
The production Docker composition must receive host-reviewed, hash-pinned
outer seccomp, AppArmor, and system-path profile declarations through the
required
`KHAOS_DOCKER_SECCOMP_OPT`, `KHAOS_DOCKER_APPARMOR_OPT`, and
`KHAOS_DOCKER_SYSTEMPATHS_OPT` variables. `compose.prod.yaml` fails closed when
any is missing. Before production startup, the exact values must pass
`scripts/validate_docker_outer_profiles.py --manifest <manifest>`; the
manifest hashes the seccomp/AppArmor source files and pins `systempaths=default`.
Docker uses `name=value` syntax. The disposable composition probe may use
explicit `unconfined` values for its temporary CI host, but that test setup is
not a production default. It must not replace the inner boundary with
`SYS_ADMIN` on the Python Agent or a Host-execution fallback.
The disposable production composition probe now runs the exact
`ExecutionService -> ProcessSupervisor -> native launcher -> bwrap` path with
`network=none`; its external `/proc` oracle proves the configured job mapping.
The production Agent also requires a separate, host-reviewed delegated cgroup
v2 subtree through `KHAOS_EXECUTION_CGROUP_SOURCE`, mounted only at
`/run/khaos-execution-cgroup` and fixed as `KHAOS_CGROUP_ROOT`; the backend
confirms the destination is a real cgroup2 mount. The browser helper's cgroup
subtree is independent. Missing or incomplete execution delegation fails
closed.
The independent real-kernel network gate remains the authority for broader
network-isolation coverage.
