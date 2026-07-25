# Supply-chain Lockfile Status (Batch 7.6, round-7 §二十四)

## Current state

`python/requirements-lock.txt` pins versions but does NOT pin hashes, and
CI installs from `pyproject.toml` (``pip install -e '.[test]'``), not from
the lockfile.  This means the dependency graph ``pip-audit`` scans is NOT
necessarily the one CI actually builds.

## Known gap (review §二十四)

- ``pyproject.toml`` uses loose lower bounds (``aiosqlite>=0.19`` etc.).
- CI resolves the full transitive graph fresh on each run, so two CI runs
  a week apart may build against different transitive versions.
- ``pip-audit`` scans ``requirements-lock.txt`` (a separate, hand-maintained
  pin set) — not the resolved graph from ``pyproject.toml``.

## Recommended end state (future work)

1. Adopt ``uv.lock`` (or ``pip-tools``) — a single lockfile covering ALL
   extras (test/browser/tui) with every transitive dependency pinned.
2. Generate a ``--require-hashes`` companion so installs verify byte-for-byte.
3. CI + Release install ONLY from the lock (``uv sync --frozen`` or
   ``pip install --require-hashes -r requirements-lock.txt``).
4. Add a "lock-in-sync-with-pyproject" CI check that fails when the lock
   drifts (the equivalent of ``cargo update --dry-run`` / ``npm ci``).
5. Pin the audit tools themselves (``pip-audit``, ``cargo-audit``,
   ``govulncheck``) to exact versions in the lock.

This is tracked as future work — it is a build-pipeline migration, not a
code fix, and is sized as its own batch.
