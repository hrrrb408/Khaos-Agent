"""Source parser helpers for coding mode."""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CodeParser:
    """Extract lightweight code intelligence from source files."""

    def parse_symbols(self, file_path: Path) -> list[dict[str, Any]]:
        """Extract Python class, function, method, and async function symbols."""
        path = file_path.expanduser().resolve()
        if path.suffix != ".py":
            return []

        try:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            logger.warning("Unable to parse symbols: path=%s error=%s", path, exc)
            return []

        return self._symbols_from_module(module)

    def _symbols_from_module(self, module: ast.Module) -> list[dict[str, Any]]:
        symbols: list[dict[str, Any]] = []
        for node in ast.walk(module):
            if isinstance(node, ast.ClassDef):
                symbols.append(
                    {
                        "name": node.name,
                        "kind": "class",
                        "line": node.lineno,
                        "signature": self._class_signature(node),
                    }
                )
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols.append(self._function_symbol(child, parent=node.name))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_method(node, module):
                    continue
                symbols.append(self._function_symbol(node))

        symbols.sort(key=lambda item: int(item["line"]))
        return symbols

    def parse_symbols_from_source(self, source: str) -> list[dict[str, Any]]:
        module = ast.parse(source)
        return self._symbols_from_module(module)

    def parse_imports_from_source(self, source: str) -> list[str]:
        module = ast.parse(source)
        imports: list[str] = []
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append("." * node.level + (node.module or ""))
        return sorted(set(imports))

    def parse_imports(self, file_path: Path) -> list[str]:
        """Extract import statements from a Python file."""
        path = file_path.expanduser().resolve()
        if path.suffix != ".py":
            return []

        try:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            logger.warning("Unable to parse imports: path=%s error=%s", path, exc)
            return []

        imports: list[str] = []
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module_name = "." * node.level + (node.module or "")
                imports.append(module_name)
        return sorted(set(imports))

    def build_symbol_table(
        self,
        project_root: Path,
        files: list[Path],
    ) -> dict[str, list[dict[str, Any]]]:
        """Build a project-wide symbol table keyed by relative file path."""
        root = project_root.expanduser().resolve()
        symbol_table: dict[str, list[dict[str, Any]]] = {}
        for file_path in files:
            path = file_path.expanduser().resolve()
            if path.suffix != ".py":
                continue
            symbols = self.parse_symbols(path)
            if not symbols:
                continue
            try:
                key = str(path.relative_to(root))
            except ValueError:
                key = str(path)
            symbol_table[key] = symbols
        return symbol_table

    def _function_symbol(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent: str | None = None,
    ) -> dict[str, Any]:
        prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
        name = f"{parent}.{node.name}" if parent else node.name
        kind = "method" if parent else "async_function" if prefix else "function"
        if parent and prefix:
            kind = "async_method"
        return {
            "name": name,
            "kind": kind,
            "line": node.lineno,
            "signature": f"{prefix}def {node.name}{self._arguments_signature(node.args)}",
        }

    def _class_signature(self, node: ast.ClassDef) -> str:
        bases = [self._unparse(base) for base in node.bases]
        if not bases:
            return f"class {node.name}"
        return f"class {node.name}({', '.join(bases)})"

    def _arguments_signature(self, args: ast.arguments) -> str:
        values = [arg.arg for arg in args.posonlyargs + args.args]
        if args.vararg is not None:
            values.append(f"*{args.vararg.arg}")
        values.extend(arg.arg for arg in args.kwonlyargs)
        if args.kwarg is not None:
            values.append(f"**{args.kwarg.arg}")
        return f"({', '.join(values)})"

    def _unparse(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except AttributeError:
            return node.__class__.__name__

    def _is_method(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
        module: ast.Module,
    ) -> bool:
        for class_node in (
            node for node in ast.walk(module) if isinstance(node, ast.ClassDef)
        ):
            if function_node in class_node.body:
                return True
        return False


# ---------------------------------------------------------------------------
# Call-graph and dependency-graph builders (module-level helpers).
# ---------------------------------------------------------------------------


def build_call_graph(
    project_root: Path, file_paths: list[Path]
) -> dict[str, set[str]]:
    """Build a Python inter-procedural call graph.

    Walks each ``.py`` file in ``file_paths`` with the AST and records, for
    every function/method defined there, the set of bare-name function calls
    it makes. The keys are fully-qualified names (``Class.method`` or
    ``function``) so callers can distinguish methods from free functions.

    Only Python is supported — non-``.py`` files are skipped and contribute
    nothing, matching the contract that Go/Rust return an empty mapping.

    Args:
        project_root: Repository root used only for diagnostics; paths in
            ``file_paths`` are resolved independently.
        file_paths: Python files to analyse.

    Returns:
        ``{callable_name: {called_name, ...}}``. Calls to builtins or to
        names not defined as functions in the scanned files are still
        recorded — the caller decides whether to filter.
    """
    root = project_root.expanduser().resolve()
    graph: dict[str, set[str]] = {}

    for file_path in file_paths:
        path = file_path.expanduser().resolve()
        if path.suffix in {".go", ".rs"}:
            _build_regex_call_graph(path, graph)
            continue
        if path.suffix != ".py":
            continue
        try:
            source = path.read_text(encoding="utf-8")
            module = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            logger.warning("call-graph parse failed: path=%s error=%s", path, exc)
            continue

        # First pass: collect every function/method name defined in this file
        # so we can attribute calls to the enclosing definition. Nested defs
        # (functions defined inside other functions) are registered too, so a
        # call made by a nested function is attributed to that nested key.
        for class_node in (n for n in module.body if isinstance(n, ast.ClassDef)):
            for child in class_node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualified = f"{class_node.name}.{child.name}"
                    graph.setdefault(qualified, set())
                    _collect_calls(child, graph[qualified])
        for node in module.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _register_function_calls(node, node.name, graph)

    _ = root  # kept for logging parity with the dependency graph builder
    return graph


def _build_regex_call_graph(path: Path, graph: dict[str, set[str]]) -> None:
    """Extract useful Go/Rust call edges without external parser dependencies."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    if path.suffix == ".go":
        definitions = re.finditer(r"(?m)^\s*func\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:\([^)]*\)|[^\s{]+)?\s*\{", source)
    else:
        definitions = re.finditer(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{", source)
    matches = list(definitions)
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        body = source[match.end():end]
        calls = set(re.findall(r"\b([A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)*)\s*[!(]", body))
        calls -= {"if", "for", "while", "switch", "match", "return", "go", "defer"}
        graph.setdefault(match.group(1), set()).update(calls)


def _register_function_calls(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    name: str,
    graph: dict[str, set[str]],
) -> None:
    """Register ``name`` and its direct calls, then recurse into nested defs.

    A function's *own* call set excludes bodies of nested function defs (those
    are attributed to the nested def itself), so we walk with
    :func:`_collect_calls` for the current function and separately recurse
    into any nested ``FunctionDef``/``AsyncFunctionDef`` we encounter.
    """
    graph.setdefault(name, set())
    _collect_calls(func_node, graph[name])
    for child in ast.iter_child_nodes(func_node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _register_function_calls(child, child.name, graph)


def _collect_calls(func_node: ast.AST, sink: set[str]) -> None:
    """Append every bare-name call target inside ``func_node`` to ``sink``.

    Walks the function body *without* descending into nested function/method
    definitions, so calls made by a nested ``def`` are attributed to that
    nested def (once it's scanned as its own key), not to the outer function.

    Class-level attribute calls (``self.foo()``) are recorded as ``self.foo``
    so method-to-method edges are still visible.
    """
    for child in _walk_skipping_nested_funcs(func_node):
        if isinstance(child, ast.Call):
            callee = _callee_name(child.func)
            if callee:
                sink.add(callee)


def _walk_skipping_nested_funcs(node: ast.AST):
    """Yield descendants of ``node`` without entering nested function defs.

    Unlike :func:`ast.walk`, this stops the recursion at any
    ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` boundary below the top
    node, so each function's call set reflects only its *own* body.
    """
    stack: list[ast.AST] = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested def: skip its body; it is handled as its own key.
            continue
        yield current
        stack.extend(ast.iter_child_nodes(current))


def _callee_name(node: ast.AST) -> str:
    """Best-effort extraction of a callable name from a Call.func node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callee_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def build_dependency_graph(
    project_root: Path, file_paths: list[Path]
) -> dict[Path, set[Path]]:
    """Build an inter-file import dependency graph.

    Resolves each Python file's ``import``/``from ... import`` statements to
    the concrete ``.py`` files they reference (relative to ``project_root``)
    and records the resulting ``Path → {Path}`` edges.

    Resolution rules:

    * ``import a.b.c`` → ``<root>/a/b/c.py`` and ``<root>/a/b/__init__.py``
      (the package init, if present).
    * ``from a.b import c`` → ``<root>/a/b/c.py`` (a submodule) *or*
      ``<root>/a/b.py`` (``c`` is just a name inside module ``a.b``). Both
      candidates are checked against the filesystem.

    Non-``.py`` files (Go/Rust) are skipped and produce no edges, matching
    the contract that they return an empty entry.

    Args:
        project_root: Repository root imports are resolved against.
        file_paths: Files to analyse.

    Returns:
        ``{file_path: {imported_file_path, ...}}`` keyed by resolved absolute
        paths. Files with no resolvable imports map to an empty set.
    """
    root = project_root.expanduser().resolve()
    graph: dict[Path, set[Path]] = {}

    for file_path in file_paths:
        path = file_path.expanduser().resolve()
        if path.suffix in {".go", ".rs"}:
            graph[path] = _regex_dependencies(root, path)
            continue
        if path.suffix != ".py":
            graph[path] = set()
            continue
        graph.setdefault(path, set())

        try:
            source = path.read_text(encoding="utf-8")
            module = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            logger.warning("dependency-graph parse failed: path=%s error=%s", path, exc)
            continue

        for node in ast.walk(module):
            targets: list[Path] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    targets.extend(_resolve_import(root, alias.name, None))
            elif isinstance(node, ast.ImportFrom):
                module_name = "." * node.level + (node.module or "")
                # Relative imports can't be resolved without package context;
                # only absolute imports are resolved here.
                if module_name and not module_name.startswith("."):
                    for alias in node.names:
                        targets.extend(_resolve_import(root, module_name, alias.name))
            for target in targets:
                if target != path:
                    graph[path].add(target)

    return graph


def _regex_dependencies(root: Path, path: Path) -> set[Path]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    targets: set[Path] = set()
    if path.suffix == ".go":
        imports = re.findall(r'(?m)(?:^\s*import\s+|^\s*)"([^"]+)"', source)
        for imported in imports:
            suffix = Path(imported)
            for candidate in (root / suffix, root / "go" / suffix, path.parent / suffix.name):
                if candidate.is_dir():
                    targets.update(item.resolve() for item in candidate.glob("*.go") if item.resolve() != path)
    else:
        modules = re.findall(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;", source)
        modules += re.findall(r"(?m)^\s*use\s+(?:crate|self|super)::([A-Za-z_]\w*)", source)
        for module in modules:
            for candidate in (path.parent / f"{module}.rs", path.parent / module / "mod.rs"):
                if candidate.is_file() and candidate.resolve() != path:
                    targets.add(candidate.resolve())
    return targets


def _resolve_import(
    root: Path, module_name: str, attr: str | None
) -> list[Path]:
    """Resolve a dotted module path to existing ``.py`` files under ``root``.

    Returns every candidate that exists on disk. For ``import a.b.c`` this is
    ``a/b/c.py`` plus the package ``__init__.py`` files. For
    ``from a.b import c`` it tries both ``a/b/c.py`` (submodule) and
    ``a/b.py`` (attribute of the package).
    """
    if not module_name:
        return []
    parts = module_name.split(".")
    base = root.joinpath(*parts)
    candidates: list[Path] = []

    if attr:
        # from <module> import <attr>: attr could be a submodule (module/attr.py)
        # or just a name defined inside module.py.
        candidates.append(base / f"{attr}.py")
        candidates.append(base.with_suffix(".py"))
    else:
        # import <module>: the module file itself.
        candidates.append(base.with_suffix(".py"))
        # ... plus any package __init__.py along the path.
        accumulated = root
        for part in parts:
            accumulated = accumulated / part
            candidates.append(accumulated / "__init__.py")

    return [candidate.resolve() for candidate in candidates if candidate.is_file()]
