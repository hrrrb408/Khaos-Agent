# Khaos Project Instructions

This is the root instruction file for the Khaos repository.

Agents working in this repository must read and follow `AGENTS.md` before
modifying code, tests, Docker files, or documentation. The active project
layout is Python Agent logic, Go API gateway, Rust security-critical TCB
launchers/helpers plus performance modules, and SQLite-backed local storage.
The machine-readable security boundary is `docs/security_facts.yaml`.
The production Docker composition must preserve the documented outer
`seccomp:unconfined` compatibility setting for the non-root bubblewrap user
namespace; it must not replace that setting with `SYS_ADMIN` on the Python
Agent or a Host-execution fallback.
