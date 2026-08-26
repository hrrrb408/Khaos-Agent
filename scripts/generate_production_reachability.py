#!/usr/bin/env python3
"""Generate a machine-checked production Python reachability inventory.

The graph follows imports from the production composition roots and resolves
the repository's explicit lazy-export maps.  It is intentionally conservative:
an unresolved internal import or a forbidden development/host execution edge
is a CI failure, not a reason to assume that the edge is unused.
"""

from __future__ import annotations

import argparse
import ast
from collections import deque
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "python"
OUTPUT = ROOT / "docs" / "generated" / "production-reachability.md"

PRODUCTION_ROOTS = (
    ("khaos.rpc.agent_service", "AgentService"),
    ("khaos.grpc_server", "_dispatch"),
    ("khaos.runtime.factory", "build_production_runtime"),
    ("khaos.tools.scheduler", "ToolScheduler"),
    ("khaos.coding.execution.service", "ExecutionService"),
)

# These are explicit forbidden production paths.  The graph must not rely on
# a human saying that a compatibility backend is "not called".
FORBIDDEN_MODULES = (
    "khaos.coding.execution.host",
    "khaos.coding.verification.pipeline",
    "khaos.runtime.testing",
    "khaos.security.mock_authority",
    "khaos.coding.execution.testing_sandbox",
)
FORBIDDEN_SYMBOLS = {
    ("khaos.coding.execution.host", "HostExecutionBackend"),
    ("khaos.coding.execution.host", "HostBackend"),
    ("khaos.coding.verification.pipeline", "HostExecutionBackend"),
    ("khaos.security.mock_authority", "MockAuthority"),
    ("khaos.coding.execution.testing_sandbox", "TestingSandbox"),
}
LEGACY_RUNTIME_PROFILE_MODULE = "khaos.runtime_profile"


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    target: str
    symbol: str
    line: int


@dataclass(frozen=True, slots=True)
class ModuleInfo:
    name: str
    path: Path
    tree: ast.Module
    lazy_exports: dict[str, str]


def module_path(module: str) -> Path | None:
    relative = PYTHON_ROOT.joinpath(*module.split("."))
    package = relative / "__init__.py"
    if package.is_file():
        return package
    source = relative.with_suffix(".py")
    return source if source.is_file() else None


def load_module(module: str) -> ModuleInfo | None:
    path = module_path(module)
    if path is None:
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return None
    return ModuleInfo(module, path, tree, _lazy_exports(tree))


def _lazy_exports(tree: ast.Module) -> dict[str, str]:
    for statement in tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "_LAZY_EXPORTS" for target in statement.targets):
            continue
        try:
            value = ast.literal_eval(statement.value)
        except (ValueError, TypeError):
            return {}
        if not isinstance(value, dict):
            return {}
        result: dict[str, str] = {}
        for key, target in value.items():
            if not isinstance(key, str) or not isinstance(target, tuple) or not target:
                continue
            if isinstance(target[0], str) and target[0].startswith("khaos."):
                result[key] = target[0]
        return result
    return {}


def resolve_relative(module: str, level: int, imported: str | None) -> str:
    package_parts = module.split(".")[:-1]
    if level > len(package_parts) + 1:
        return ""
    prefix = package_parts[: len(package_parts) - level + 1]
    if imported:
        prefix.append(imported)
    return ".".join(prefix)


def import_edges(info: ModuleInfo) -> tuple[tuple[Edge, ...], tuple[str, ...]]:
    edges: list[Edge] = []
    unresolved: list[str] = []
    constants = _constant_strings(info.tree)
    for node in ast.walk(info.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("khaos.") or alias.name == "khaos":
                    edges.append(Edge(info.name, alias.name, alias.asname or alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            target_module = (
                resolve_relative(info.name, node.level, node.module)
                if node.level
                else (node.module or "")
            )
            if not target_module.startswith("khaos"):
                continue
            for alias in node.names:
                if alias.name == "*":
                    edges.append(Edge(info.name, target_module, "*", node.lineno))
                    continue
                resolved = info.lazy_exports.get(alias.name)
                edges.append(
                    Edge(
                        info.name,
                        resolved or target_module,
                        alias.name,
                        node.lineno,
                    )
                )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                value = _static_string(node.args[0], constants) if node.args else None
                if value is not None:
                    if value.startswith("khaos"):
                        edges.append(Edge(info.name, value, "dynamic-import", node.lineno))
                elif info.lazy_exports:
                    # The package's __getattr__ implementation is covered by
                    # its explicit literal lazy-export map.
                    continue
                else:
                    unresolved.append(f"{info.name}:{node.lineno}: unresolved dynamic import")
            elif isinstance(node.func, ast.Name) and node.func.id == "__import__":
                value = _static_string(node.args[0], constants) if node.args else None
                if value is not None:
                    if value.startswith("khaos"):
                        edges.append(Edge(info.name, value, "dynamic-import", node.lineno))
                else:
                    unresolved.append(f"{info.name}:{node.lineno}: unresolved __import__")
    return tuple(edges), tuple(unresolved)


def _constant_strings(tree: ast.Module) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            values[target.id] = node.value.value
    return values


def _static_string(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def build_graph() -> tuple[set[str], tuple[Edge, ...], tuple[str, ...]]:
    queue: deque[str] = deque(module for module, _symbol in PRODUCTION_ROOTS)
    seen: set[str] = set()
    edges: list[Edge] = []
    unresolved: list[str] = []
    while queue:
        module = queue.popleft()
        if module in seen:
            continue
        seen.add(module)
        info = load_module(module)
        if info is None:
            unresolved.append(f"{module}: missing or unparsable internal module")
            continue
        module_edges, module_unresolved = import_edges(info)
        edges.extend(module_edges)
        unresolved.extend(module_unresolved)
        for edge in module_edges:
            if edge.target.startswith("khaos.") and edge.target not in seen:
                queue.append(edge.target)
    return seen, tuple(sorted(edges, key=lambda edge: (edge.source, edge.line, edge.target, edge.symbol))), tuple(sorted(set(unresolved)))


def forbidden_edges(modules: set[str], edges: tuple[Edge, ...]) -> tuple[str, ...]:
    findings: set[str] = set()
    for module in sorted(modules):
        if module in FORBIDDEN_MODULES:
            findings.add(f"reachable forbidden module: {module}")
    for edge in edges:
        if edge.target in FORBIDDEN_MODULES or (edge.target, edge.symbol) in FORBIDDEN_SYMBOLS:
            findings.add(
                f"{edge.source}:{edge.line} -> {edge.target}.{edge.symbol}"
            )
    # The environment switch is retained only in the isolated compatibility
    # resolver.  Any production-reachable security module that reads it is a
    # real ambient-authority edge, even if the import graph otherwise looks
    # safe.
    for module in sorted(modules):
        if module == LEGACY_RUNTIME_PROFILE_MODULE:
            continue
        info = load_module(module)
        if info is None:
            continue
        for node in ast.walk(info.tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            if not (
                isinstance(function, ast.Attribute)
                and function.attr == "get"
                and isinstance(function.value, ast.Attribute)
                and function.value.attr == "environ"
                and isinstance(function.value.value, ast.Name)
                and function.value.value.id == "os"
            ):
                continue
            first_argument = node.args[0]
            if (
                isinstance(first_argument, ast.Constant)
                and first_argument.value == "KHAOS_DEV_MODE"
            ):
                findings.add(
                    f"{module}:{node.lineno}: ambient KHAOS_DEV_MODE read"
                )
    return tuple(sorted(findings))


def render() -> str:
    modules, edges, unresolved = build_graph()
    forbidden = forbidden_edges(modules, edges)
    lines = [
        "# Generated Production Import Reachability Inventory",
        "",
        "> Generated by `scripts/generate_production_reachability.py`; do not edit manually.",
        "> This is a **static production import graph**, not a whole-program runtime",
        "> reachability proof and not a claim that local tests are native evidence.",
        "> Runtime composition is proven separately by",
        "> `scripts/verify_production_composition.py`; kernel/native properties are",
        "> proven by the platform CI jobs.",
        "",
        "## Production composition roots",
        "",
    ]
    lines.extend(f"- `{module}:{symbol}`" for module, symbol in PRODUCTION_ROOTS)
    lines.extend(
        [
            "",
            "## Import reachability result",
            "",
            f"- Reachable repository modules: `{len(modules)}`.",
            f"- Resolved import edges: `{len(edges)}`.",
            f"- Forbidden production edges: `{len(forbidden)}`.",
            f"- Unresolved internal edges: `{len(unresolved)}`.",
            "",
            "### Forbidden targets",
            "",
        ]
    )
    lines.extend(f"- `{finding}`" for finding in forbidden or ("none",))
    lines.extend(["", "### Unresolved targets", ""])
    lines.extend(f"- `{finding}`" for finding in unresolved or ("none",))
    lines.extend(["", "## Reachable modules", ""])
    lines.extend(f"- `{module}`" for module in sorted(modules))
    lines.extend(
        [
            "",
            "## Gate",
            "",
            "The CI check fails if a forbidden host/dev/compatibility execution path or an unresolved internal import appears in this graph.",
            "",
            "## Evidence scope",
            "",
            "Layer 1 (this document): static import reachability from production roots.",
            "Layer 2: runtime composition manifest (exact component types, forbidden",
            "component absence) generated by `scripts/verify_production_composition.py`.",
            "Layer 3: kernel/native proofs (real-kernel, Docker, launchd/XPC,",
            "Windows Service-SID) from the platform CI jobs.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    rendered = render()
    modules, edges, unresolved = build_graph()
    forbidden = forbidden_edges(modules, edges)
    if forbidden or unresolved:
        for finding in (*forbidden, *unresolved):
            print(finding)
        return 1
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale production reachability inventory: {output}")
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
