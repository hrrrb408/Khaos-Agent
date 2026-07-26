# Supply-chain Lockfile Status (Round 8 closure)

## Python dependency authority

`uv.lock` is the canonical resolution for the project and every CI install
uses `uv sync --frozen` with the job's required extras. The committed
`python/requirements-lock.txt` is generated from that frozen resolution and
contains hashes for the audit/install artifact set.

The supply-chain workflow regenerates the export from `uv.lock`, fails on any
diff, and runs `pip-audit --require-hashes` against that exact export. This
prevents CI from resolving a graph different from the graph being audited.

## Audit tool pins

The workflow pins its bootstrap tools rather than installing floating latest
versions:

- `uv==0.11.9`
- `pip-audit==2.10.0`
- `cargo-audit==0.22.2`
- `govulncheck@v1.6.0`

The Go vulnerability job also pins the standard-library toolchain to
`go1.26.5`; this avoids reintroducing GO-2026-5856 from Go 1.26.4.

Rust remains governed by `Cargo.lock`; web installs use `npm ci` and
`package-lock.json`; Go vulnerability analysis runs against the checked-in Go
module graph.

## Update procedure

Change `pyproject.toml`, run `uv lock`, regenerate
`python/requirements-lock.txt` using the same frozen export command encoded in
`.github/workflows/supply-chain-audit.yml`, and commit both files atomically.
CI rejects a stale or manually edited companion export.
