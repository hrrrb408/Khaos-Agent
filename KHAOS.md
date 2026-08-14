# Khaos Project Instructions

This is the root instruction file for the Khaos repository.

Agents working in this repository must read and follow `AGENTS.md` before
modifying code, tests, Docker files, or documentation. The active project
layout is Python Agent logic, Go API gateway, Rust security-critical TCB
launchers/helpers plus performance modules, and SQLite-backed local storage.
The machine-readable security boundary is `docs/security_facts.yaml`.
The production Docker composition must preserve the documented outer
`seccomp:unconfined`, `apparmor:unconfined`, and `systempaths:unconfined`
compatibility settings for the non-root bubblewrap namespace/mount boundary;
it must not replace them with `SYS_ADMIN` on the Python Agent or a
Host-execution fallback.
