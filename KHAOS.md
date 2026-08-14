# Khaos Project Instructions

This is the root instruction file for the Khaos repository.

Agents working in this repository must read and follow `AGENTS.md` before
modifying code, tests, Docker files, or documentation. The active project
layout is Python Agent logic, Go API gateway, Rust security-critical TCB
launchers/helpers plus performance modules, and SQLite-backed local storage.
The machine-readable security boundary is `docs/security_facts.yaml`.
The production Docker composition must receive host-reviewed outer seccomp,
AppArmor, and system-path profiles through the required
`KHAOS_DOCKER_SECCOMP_OPT`, `KHAOS_DOCKER_APPARMOR_OPT`, and
`KHAOS_DOCKER_SYSTEMPATHS_OPT` variables. `compose.prod.yaml` fails closed when
any is missing. Docker uses `name=value` syntax; the disposable composition
probe may use explicit `unconfined` values for its temporary CI host, but that
test setup is not a production default. It must not replace the inner boundary
with `SYS_ADMIN` on the Python Agent or a Host-execution fallback.
