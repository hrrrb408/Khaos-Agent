"""Conservative JavaScript/TypeScript/TSX import/call/reference resolution.

Resolves only static relative module imports within the repository:
  - ./x, ../x, explicit extensions, .js/.jsx/.ts/.tsx/.d.ts completion
  - directory index.* resolution
  - default import, named import, namespace import
  - re-export chains (conservative)

External npm packages, tsconfig path aliases, dynamic import, CommonJS require,
and runtime property dispatch remain external/unresolved/dynamic.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from khaos.coding.intelligence.resolution.ids import call_edge_id, reference_edge_id
from khaos.coding.intelligence.resolution.models import (
    ResolutionStatus,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
)
from khaos.coding.intelligence.resolution.symbol_table import RepositorySymbolTable

_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".d.ts", ".mjs", ".cjs")
_INDEX_NAMES = ("index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs", "index.cjs")


def resolve_javascript_imports(
    source_file: str,
    imports: list[dict[str, Any]],
    table: RepositorySymbolTable,
    generation: int,
) -> list[ResolvedImport]:
    results: list[ResolvedImport] = []
    for imp in imports:
        module: str = imp.get("module", "")
        names: tuple[str, ...] = tuple(imp.get("imported_names", ()))
        alias: str | None = imp.get("alias")
        metadata: dict[str, Any] = imp.get("metadata", {})
        is_relative = module.startswith(".") or module.startswith("/")

        if not is_relative:
            # External npm package
            for name in (names or ("",)):
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.EXTERNAL,
                    None, None, 0.9, "external-npm-package",
                    (), {"import_kind": metadata.get("import_kind", "import"), "external": True},
                ))
            continue

        target_file = _resolve_relative_js_path(module, source_file, table)
        if target_file is None:
            for name in (names or ("",)):
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.UNRESOLVED,
                    None, None, 0.6, "relative-module-not-found",
                    (), {"import_kind": metadata.get("import_kind", "import"), "relative": True},
                ))
            continue

        # Module resolved — now resolve specific imported names
        if not names:
            # Side-effect import or whole-module
            results.append(ResolvedImport(
                source_file, module, "", alias, ResolutionStatus.RESOLVED,
                target_file, None, 0.93, "js-relative-module-path",
                (target_file,), {"import_kind": metadata.get("import_kind", "import")},
            ))
            table.register_reverse_dep(source_file, target_file)
            continue

        for name in names:
            if name == "*":
                # Namespace import — module is resolved, name is the namespace
                results.append(ResolvedImport(
                    source_file, module, "*", alias, ResolutionStatus.RESOLVED,
                    target_file, None, 0.92, "js-namespace-import",
                    (target_file,), {"import_kind": "import", "namespace": True},
                ))
                table.register_reverse_dep(source_file, target_file)
                continue

            if name == "default":
                # Default import — look for default export symbol
                target_symbols = table.symbols_by_file(target_file)
                default_syms = [s for s in target_symbols if s.name == "default" or s.kind == "default_export"]
                if len(default_syms) == 1:
                    results.append(ResolvedImport(
                        source_file, module, "default", alias, ResolutionStatus.RESOLVED,
                        target_file, default_syms[0].symbol_id, 0.92, "js-default-import",
                        (target_file,), {"import_kind": "import", "default": True},
                    ))
                else:
                    # Can't pinpoint default export symbol, but module is resolved
                    results.append(ResolvedImport(
                        source_file, module, "default", alias, ResolutionStatus.RESOLVED,
                        target_file, None, 0.88, "js-default-import-module-resolved",
                        (target_file,), {"import_kind": "import", "default": True},
                    ))
                table.register_reverse_dep(source_file, target_file)
                continue

            # Named import
            target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == name]
            if len(target_symbols) == 1:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.RESOLVED,
                    target_file, target_symbols[0].symbol_id, 0.93, "js-named-import",
                    (target_file,), {"import_kind": "import"},
                ))
            elif len(target_symbols) > 1:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.AMBIGUOUS,
                    target_file, None, 0.4, "js-named-import-multiple",
                    tuple(s.symbol_id for s in target_symbols), {"import_kind": "import", "count": len(target_symbols)},
                ))
            else:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.UNRESOLVED,
                    target_file, None, 0.6, "js-named-import-not-found",
                    (target_file,), {"import_kind": "import"},
                ))
            table.register_reverse_dep(source_file, target_file)

    return results


def resolve_javascript_calls(
    repository_id: str,
    source_file: str,
    calls: list[dict[str, Any]],
    table: RepositorySymbolTable,
    resolved_imports: list[ResolvedImport],
    generation: int,
) -> list[ResolvedCallEdge]:
    results: list[ResolvedCallEdge] = []
    import_map: dict[str, tuple[str | None, str | None]] = {}
    for ri in resolved_imports:
        if ri.status not in (ResolutionStatus.RESOLVED, ResolutionStatus.AMBIGUOUS):
            continue
        key = ri.alias or ri.imported_name
        if key:
            import_map[key] = (ri.target_file, ri.target_symbol_id)

    for call in calls:
        callee: str = call.get("callee", "")
        caller: str | None = call.get("caller")
        metadata: dict[str, Any] = call.get("metadata", {})
        callee_form: str = metadata.get("callee_form", "identifier")
        location = call.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = call_edge_id(repository_id, source_file, callee, byte_start, byte_end, generation)
        caller_sym_id = _find_caller_symbol_id(source_file, caller, table)

        if callee_form == "identifier":
            same_file = [s for s in table.symbols_by_file(source_file) if s.name == callee and s.kind in ("function", "async_function", "class", "method")]
            if len(same_file) == 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                    same_file[0].stable_symbol_id, same_file[0].path, 0.95, "same-file-unique-function", None, metadata))
                continue
            if len(same_file) > 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                    None, source_file, 0.4, "same-file-multiple", f"{len(same_file)} candidates", metadata))
                continue
            if callee in import_map:
                target_file, target_sym_id = import_map[callee]
                if target_sym_id:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_sym_id, target_file, 0.93, "imported-function-call", None, metadata))
                elif target_file:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, target_file, 0.6, "imported-but-symbol-not-resolved", None, metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                        None, None, 0.85, "external-import", None, metadata))
                continue
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.5, "no-candidate", None, metadata))
            continue

        if callee_form == "member":
            receiver: str | None = metadata.get("receiver")
            if not receiver:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                    None, None, 0.3, "no-receiver", None, metadata))
                continue
            if receiver in import_map:
                target_file, _ = import_map[receiver]
                if target_file is None:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                        None, None, 0.85, "external-module-attribute", None, metadata))
                    continue
                member_name = callee.split(".", 1)[-1] if "." in callee else callee
                target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == member_name]
                if len(target_symbols) == 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_symbols[0].stable_symbol_id, target_file, 0.92, "namespace-member-call", None, metadata))
                elif len(target_symbols) > 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                        None, target_file, 0.4, "namespace-member-multiple", f"{len(target_symbols)} candidates", metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, target_file, 0.6, "namespace-member-not-found", None, metadata))
                continue
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                None, None, 0.3, "instance-method-dispatch", "receiver type unknown", metadata))
            continue

        results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
            None, None, 0.5, "unsupported-callee-form", None, metadata))

    return results


def resolve_javascript_references(
    repository_id: str,
    source_file: str,
    references: list[dict[str, Any]],
    table: RepositorySymbolTable,
    resolved_imports: list[ResolvedImport],
    generation: int,
) -> list[ResolvedReferenceEdge]:
    results: list[ResolvedReferenceEdge] = []
    import_names: dict[str, tuple[str | None, str | None]] = {}
    for ri in resolved_imports:
        if ri.status not in (ResolutionStatus.RESOLVED, ResolutionStatus.AMBIGUOUS):
            continue
        key = ri.alias or ri.imported_name
        if key:
            import_names[key] = (ri.target_file, ri.target_symbol_id)

    for ref in references:
        name: str = ref.get("name", "")
        ref_kind: str = ref.get("reference_kind", "read")
        metadata: dict[str, Any] = ref.get("metadata", {})
        location = ref.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = reference_edge_id(repository_id, source_file, name, ref_kind, byte_start, byte_end, generation)

        same_file = [s for s in table.symbols_by_file(source_file) if s.name == name]
        if len(same_file) == 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                same_file[0].stable_symbol_id, same_file[0].path, 0.92, "same-file-symbol", metadata))
            continue
        if len(same_file) > 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.AMBIGUOUS,
                None, source_file, 0.4, "same-file-multiple", metadata))
            continue
        if name in import_names:
            target_file, target_sym_id = import_names[name]
            if target_sym_id:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                    target_sym_id, target_file, 0.90, "imported-symbol-reference", metadata))
            elif target_file:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
                    None, target_file, 0.6, "imported-module-reference", metadata))
            else:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.EXTERNAL,
                    None, None, 0.85, "external-reference", metadata))
            continue
        results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
            None, None, 0.4, "no-candidate", metadata))

    return results


def _resolve_relative_js_path(module: str, source_file: str, table: RepositorySymbolTable) -> str | None:
    """Resolve a relative JS/TS module path to a file in the repository."""
    source_dir = PurePosixPath(source_file).parent
    target = source_dir / module
    target_str = str(target)

    # Try exact path
    if table.has_file(target_str):
        return target_str

    # Try with extensions
    for ext in _JS_EXTENSIONS:
        candidate = target_str + ext
        if table.has_file(candidate):
            return candidate

    # Try directory index
    for index_name in _INDEX_NAMES:
        candidate = f"{target_str}/{index_name}"
        if table.has_file(candidate):
            return candidate

    return None


def _find_caller_symbol_id(source_file: str, caller_qualified_name: str | None, table: RepositorySymbolTable) -> str | None:
    if not caller_qualified_name:
        return None
    syms = table.symbols_by_qualified_name(caller_qualified_name)
    return syms[0].symbol_id if syms else None
