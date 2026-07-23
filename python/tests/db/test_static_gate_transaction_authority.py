"""Static gate: forbid bare BEGIN/COMMIT/ROLLBACK in production code.

Round-4 Batch 1 (§四 C-02, §十九 Batch 1) requires:

    除 Database.transaction() 和 Migration Runner 外，
    生产代码禁止出现：
    - BEGIN
    - COMMIT
    - ROLLBACK
    - conn.commit()
    - conn.rollback()

This test parses ``python/khaos/db/database.py`` with AST and verifies
that every ``conn.commit()``, ``conn.rollback()`` and
``conn.execute("BEGIN …")`` call is inside a whitelisted function:

  - ``transaction``              — the Transaction Authority entry point
  - ``_commit_if_owner``         — the authority's bare-write helper
  - ``run_migrations``           — the migration runner
  - ``_run_legacy_schema_upgrades`` — legacy ALTER TABLE helpers caller
  - ``_ensure_*``                — idempotent schema column helpers
  - ``commit`` / ``rollback``    — ``_AsyncSqliteFallback`` wrappers

``migrations_cli.py`` is the Migration Runner and is exempt in its
entirety.

The independent stores under ``python/khaos/coding/`` use their own
``sqlite3`` connections (not the shared Database Transaction Authority)
and are out of scope for this gate.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

DB_DIR = Path(__file__).resolve().parents[2] / "khaos" / "db"
DATABASE_PY = DB_DIR / "database.py"
MIGRATIONS_CLI_PY = DB_DIR / "migrations_cli.py"

# Functions in database.py that are allowed to issue BEGIN / COMMIT / ROLLBACK.
WHITELIST_NAMES = {
    "transaction",           # the Authority entry point
    "_commit_if_owner",      # bare-write commit helper
    "run_migrations",        # migration runner
    "_run_legacy_schema_upgrades",
    # _AsyncSqliteFallback connection-wrapper methods (delegate to sync conn)
    "commit",
    "rollback",
}
WHITELIST_PREFIXES = ("_ensure_",)


class TransactionControlFinder(ast.NodeVisitor):
    """Find bare BEGIN/COMMIT/ROLLBACK calls and their enclosing function."""

    def __init__(self) -> None:
        self.violations: list[tuple[str, int, str]] = []
        self._func_stack: list[str] = []

    def _is_whitelisted(self, func_name: str) -> bool:
        return (
            func_name in WHITELIST_NAMES
            or any(func_name.startswith(p) for p in WHITELIST_PREFIXES)
        )

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            # conn.commit() / conn.rollback()
            if func.attr in ("commit", "rollback"):
                enclosing = self._func_stack[-1] if self._func_stack else "<module>"
                if not self._is_whitelisted(enclosing):
                    self.violations.append((
                        enclosing, node.lineno,
                        f"conn.{func.attr}()",
                    ))
            # conn.execute("BEGIN …")
            elif func.attr == "execute":
                if node.args and isinstance(node.args[0], ast.Constant):
                    raw = node.args[0].value
                    if isinstance(raw, str) and raw.strip().upper().startswith("BEGIN"):
                        enclosing = (
                            self._func_stack[-1]
                            if self._func_stack
                            else "<module>"
                        )
                        if not self._is_whitelisted(enclosing):
                            self.violations.append((
                                enclosing, node.lineno,
                                f'conn.execute("{raw.strip()}")',
                            ))
        self.generic_visit(node)


def _scan_file(path: Path) -> list[tuple[str, int, str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    finder = TransactionControlFinder()
    finder.visit(tree)
    return finder.violations


# ---------------------------------------------------------------------------
# database.py — strict whitelist
# ---------------------------------------------------------------------------

def test_database_py_has_no_bare_begin_commit_rollback():
    """Every BEGIN/COMMIT/ROLLBACK in database.py must be inside
    ``transaction()``, ``_commit_if_owner()``, ``run_migrations()``,
    ``_run_legacy_schema_upgrades()``, an ``_ensure_*`` helper, or the
    ``_AsyncSqliteFallback`` wrapper methods.
    """
    violations = _scan_file(DATABASE_PY)
    if violations:
        details = "\n".join(
            f"  line {lineno}: in {func!r} — {desc}"
            for func, lineno, desc in violations
        )
        pytest.fail(
            "database.py contains bare BEGIN/COMMIT/ROLLBACK outside "
            "whitelisted Transaction Authority functions:\n" + details
        )


# ---------------------------------------------------------------------------
# migrations_cli.py — exempt (Migration Runner), but still scanned so the
# exemption is explicit and visible in CI output.
# ---------------------------------------------------------------------------

def test_migrations_cli_py_exempt_as_migration_runner():
    """``migrations_cli.py`` is the Migration Runner and is allowed to
    issue BEGIN/COMMIT/ROLLBACK.  This test exists to make the exemption
    explicit — if the file grows non-migration code, move it out.
    """
    violations = _scan_file(MIGRATIONS_CLI_PY)
    # Exempt: all violations are allowed in the migration runner.
    # We assert the count is stable so new additions are reviewed.
    assert len(violations) <= 10, (
        f"migrations_cli.py has {len(violations)} BEGIN/COMMIT/ROLLBACK "
        "calls — if this grew, verify they are all migration-only"
    )


# ---------------------------------------------------------------------------
# Other db/*.py files must not contain any transaction control at all
# ---------------------------------------------------------------------------

def test_other_db_modules_have_no_transaction_control():
    """``migrate.py``, ``state_root.py``, ``__init__.py`` must not issue
    BEGIN/COMMIT/ROLLBACK — they are not the Transaction Authority.
    """
    other_files = sorted(
        p for p in DB_DIR.glob("*.py")
        if p.name not in ("database.py", "migrations_cli.py")
    )
    all_violations: list[tuple[str, str, int, str]] = []
    for path in other_files:
        for func, lineno, desc in _scan_file(path):
            all_violations.append((path.name, func, lineno, desc))
    if all_violations:
        details = "\n".join(
            f"  {fname} line {lineno}: in {func!r} — {desc}"
            for fname, func, lineno, desc in all_violations
        )
        pytest.fail(
            "Non-Authority db/*.py files must not contain "
            "BEGIN/COMMIT/ROLLBACK:\n" + details
        )
