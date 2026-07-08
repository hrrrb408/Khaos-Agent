"""Source parser helpers for coding mode."""

from __future__ import annotations

import ast
import logging
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
