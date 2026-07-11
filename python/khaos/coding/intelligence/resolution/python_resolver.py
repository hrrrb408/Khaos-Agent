"""Conservative Python import/call/reference resolution.

Resolves only deterministic intra-repository targets:
  - import module / import module as alias
  - from module import name / from module import name as alias
  - relative imports (. / .. / .module)
  - package __init__.py
  - module.function() where module is a proven import
  - same-file top-level function calls

Dynamic scenarios (monkey patch, attribute chains, __import__, wildcard)
remain unresolved/dynamic/external — never falsely resolved.
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


def resolve_python_imports(
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
        is_relative = metadata.get("relative", module.startswith("."))

        # Whole-module import: import module [as alias] (no imported_names)
        if not names:
            target_file = _resolve_python_module_path(module, source_file, table)
            if target_file:
                results.append(ResolvedImport(
                    source_file, module, "", alias, ResolutionStatus.RESOLVED,
                    target_file, None, 0.95, "python-module-path",
                    (target_file,), {"import_kind": "import"},
                ))
                table.register_reverse_dep(source_file, target_file)
            else:
                results.append(ResolvedImport(
                    source_file, module, "", alias, ResolutionStatus.EXTERNAL,
                    None, None, 0.9, "module-not-in-repository",
                    (), {"import_kind": "import"},
                ))
            continue

        # from module import name(s)
        for name in names:
            if name == "*":
                # Wildcard import: ambiguous unless module is external
                target_file = _resolve_python_module_path(module, source_file, table, relative=is_relative)
                if target_file:
                    results.append(ResolvedImport(
                        source_file, module, "*", alias, ResolutionStatus.AMBIGUOUS,
                        target_file, None, 0.5, "wildcard-import-cannot-determine-names",
                        (target_file,), {"import_kind": "from", "glob": True},
                    ))
                else:
                    results.append(ResolvedImport(
                        source_file, module, "*", alias, ResolutionStatus.EXTERNAL,
                        None, None, 0.9, "wildcard-external-module",
                        (), {"import_kind": "from", "glob": True},
                    ))
                continue

            target_file = _resolve_python_module_path(module, source_file, table, relative=is_relative)
            if target_file is None:
                status = ResolutionStatus.UNRESOLVED if is_relative else ResolutionStatus.EXTERNAL
                results.append(ResolvedImport(
                    source_file, module, name, alias, status,
                    None, None, 0.9 if status == ResolutionStatus.EXTERNAL else 0.7,
                    "module-not-found" if is_relative else "external-module",
                    (), {"import_kind": "from", "relative": is_relative},
                ))
                continue

            # Find the name in the target file's symbols
            target_symbols = table.symbols_by_file(target_file)
            matching = [s for s in target_symbols if s.name == name]
            # Also check if the name is itself a submodule (e.g. from package import submodule)
            if not matching:
                submodule_path = _resolve_python_submodule(module, name, source_file, table, relative=is_relative)
                if submodule_path:
                    results.append(ResolvedImport(
                        source_file, module, name, alias, ResolutionStatus.RESOLVED,
                        submodule_path, None, 0.92, "python-submodule-import",
                        (submodule_path,), {"import_kind": "from"},
                    ))
                    table.register_reverse_dep(source_file, submodule_path)
                    continue
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.UNRESOLVED,
                    target_file, None, 0.7, "name-not-found-in-module",
                    (target_file,), {"import_kind": "from"},
                ))
                continue

            if len(matching) == 1:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.RESOLVED,
                    target_file, matching[0].symbol_id, 0.95, "python-from-import",
                    (target_file,), {"import_kind": "from"},
                ))
                table.register_reverse_dep(source_file, target_file)
            else:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.AMBIGUOUS,
                    target_file, None, 0.5, f"multiple-symbols-named-{name}",
                    tuple(s.symbol_id for s in matching), {"import_kind": "from", "count": len(matching)},
                ))
                table.register_reverse_dep(source_file, target_file)

    return results


def resolve_python_calls(
    source_file: str,
    calls: list[dict[str, Any]],
    table: RepositorySymbolTable,
    resolved_imports: list[ResolvedImport],
    generation: int,
) -> list[ResolvedCallEdge]:
    results: list[ResolvedCallEdge] = []
    # Build import alias map: alias/name → (target_file, target_symbol_id)
    import_map: dict[str, tuple[str | None, str | None]] = {}
    for ri in resolved_imports:
        if ri.status not in (ResolutionStatus.RESOLVED, ResolutionStatus.AMBIGUOUS):
            continue
        key = ri.alias or ri.imported_name or ri.import_module.split(".")[-1]
        if ri.imported_name and ri.imported_name != "*":
            import_map[ri.alias or ri.imported_name] = (ri.target_file, ri.target_symbol_id)
        elif ri.alias:
            import_map[ri.alias] = (ri.target_file, ri.target_symbol_id)
        # For `import a.b.c`, the usable name is `a`
        if not ri.imported_name and ri.import_module:
            top_name = ri.import_module.split(".")[0]
            if top_name not in import_map:
                import_map[top_name] = (ri.target_file, None)

    for call in calls:
        callee: str = call.get("callee", "")
        caller: str | None = call.get("caller")
        metadata: dict[str, Any] = call.get("metadata", {})
        callee_form: str = metadata.get("callee_form", "identifier")
        location = call.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = call_edge_id(source_file, callee, byte_start, byte_end, generation)
        caller_sym_id = _find_caller_symbol_id(source_file, caller, table)

        if callee_form == "identifier":
            # Same-file lookup first
            same_file = [s for s in table.symbols_by_file(source_file) if s.name == callee and s.kind in ("function", "async_function", "method", "class")]
            if len(same_file) == 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                    same_file[0].symbol_id, same_file[0].path, 0.95, "same-file-unique-function", None, metadata))
                continue
            if len(same_file) > 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                    None, source_file, 0.4, "same-file-multiple", f"{len(same_file)} candidates", metadata))
                continue
            # Check imports
            if callee in import_map:
                target_file, target_sym_id = import_map[callee]
                if target_sym_id:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_sym_id, target_file, 0.93, "imported-unique-symbol", None, metadata))
                elif target_file:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, target_file, 0.7, "imported-module-name-not-bound", "module imported but specific symbol not resolved", metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                        None, None, 0.85, "external-import", None, metadata))
                continue
            # Not found anywhere
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.5, "no-candidate-found", None, metadata))
            continue

        if callee_form == "member":
            receiver: str | None = metadata.get("receiver")
            if not receiver:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                    None, None, 0.3, "no-receiver", None, metadata))
                continue
            # Check if receiver is an imported module
            if receiver in import_map:
                target_file, _ = import_map[receiver]
                if target_file is None:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                        None, None, 0.85, "external-module-attribute", None, metadata))
                    continue
                # Find the attribute in the target file
                attr_name = callee.split(".")[-1] if "." in callee else callee
                # The callee for member calls is the full "receiver.method"
                member_name = callee.split(".", 1)[-1] if "." in callee else callee
                target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == member_name]
                if len(target_symbols) == 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_symbols[0].symbol_id, target_file, 0.92, "module-attribute-call", None, metadata))
                elif len(target_symbols) > 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                        None, target_file, 0.4, "module-attribute-multiple", f"{len(target_symbols)} candidates", metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, target_file, 0.6, "module-attribute-not-found", None, metadata))
                continue
            # Receiver is not a proven import → dynamic
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                None, None, 0.3, "instance-method-dispatch", "receiver type unknown", metadata))
            continue

        # path or other forms → unresolved
        results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
            None, None, 0.5, "unsupported-callee-form", None, metadata))

    return results


def resolve_python_references(
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
        key = ri.alias or ri.imported_name or ri.import_module.split(".")[-1]
        import_names[key] = (ri.target_file, ri.target_symbol_id)
        if not ri.imported_name and ri.import_module:
            top = ri.import_module.split(".")[0]
            if top not in import_names:
                import_names[top] = (ri.target_file, None)

    for ref in references:
        name: str = ref.get("name", "")
        ref_kind: str = ref.get("reference_kind", "read")
        metadata: dict[str, Any] = ref.get("metadata", {})
        location = ref.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = reference_edge_id(source_file, name, ref_kind, byte_start, byte_end, generation)

        # Same-file symbol
        same_file = [s for s in table.symbols_by_file(source_file) if s.name == name]
        if len(same_file) == 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                same_file[0].symbol_id, same_file[0].path, 0.92, "same-file-symbol", metadata))
            continue
        if len(same_file) > 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.AMBIGUOUS,
                None, source_file, 0.4, "same-file-multiple-symbols", metadata))
            continue
        # Imported name
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
        # Not found
        results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
            None, None, 0.4, "no-candidate", metadata))

    return results


def _resolve_python_module_path(module: str, source_file: str, table: RepositorySymbolTable, *, relative: bool = False) -> str | None:
    """Resolve a Python module name to a file path in the repository."""
    if not module:
        return None
    # Direct lookup in module_to_file
    direct = table.module_to_file(module)
    if direct:
        return direct
    # Try relative resolution
    if relative or module.startswith("."):
        return _resolve_relative_python_module(module, source_file, table)
    # Try as a file path
    candidates = [
        module.replace(".", "/") + ".py",
        module.replace(".", "/") + "/__init__.py",
    ]
    for candidate in candidates:
        if table.has_file(candidate):
            return candidate
    return None


def _resolve_python_submodule(parent_module: str, name: str, source_file: str, table: RepositorySymbolTable, *, relative: bool = False) -> str | None:
    """Resolve `from parent_module import name` where name is a submodule."""
    full_module = f"{parent_module}.{name}" if not parent_module.startswith(".") else f"{parent_module}.{name}"
    # Strip leading dots for path resolution
    clean = full_module.lstrip(".")
    direct = table.module_to_file(clean)
    if direct:
        return direct
    candidates = [
        clean.replace(".", "/") + ".py",
        clean.replace(".", "/") + "/__init__.py",
    ]
    for candidate in candidates:
        if table.has_file(candidate):
            return candidate
    return None


def _resolve_relative_python_module(module: str, source_file: str, table: RepositorySymbolTable) -> str | None:
    """Resolve a relative Python import (e.g. '.mod', '..', '.mod.name')."""
    level = len(module) - len(module.lstrip("."))
    remaining = module[level:]
    source_parts = list(PurePosixPath(source_file).parts)
    # Navigate up `level` directories from source file's directory
    if source_parts[-1] == "__init__.py":
        base_parts = source_parts[:-1]
    else:
        base_parts = source_parts[:-1]
    # Go up level-1 directories (level=1 means current package)
    for _ in range(level - 1):
        if base_parts:
            base_parts.pop()
    if remaining:
        full_parts = base_parts + remaining.split(".")
    else:
        full_parts = base_parts
    # Try as module
    module_name = ".".join(p.removesuffix(".py").removesuffix("/__init__") for p in full_parts)
    direct = table.module_to_file(module_name)
    if direct:
        return direct
    # Try as file paths
    base_path = "/".join(full_parts)
    candidates = [base_path + ".py", base_path + "/__init__.py"]
    for candidate in candidates:
        if table.has_file(candidate):
            return candidate
    return None


def _find_caller_symbol_id(source_file: str, caller_qualified_name: str | None, table: RepositorySymbolTable) -> str | None:
    if not caller_qualified_name:
        return None
    syms = table.symbols_by_qualified_name(caller_qualified_name)
    return syms[0].symbol_id if syms else None
