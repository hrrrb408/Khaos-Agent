"""Conservative Rust import/call/reference resolution.

Resolves only crate-local paths:
  - crate::, self::, super::
  - use declarations (including alias and glob when unique)
  - mod declarations
  - explicit path calls (e.g. crate::util::run())

External crates, trait method dispatch, macro expansion, and proc macros
remain unresolved/external.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from khaos.coding.intelligence.resolution.ids import call_edge_id, reference_edge_id
from khaos.coding.intelligence.resolution.models import (
    RepositorySymbol,
    ResolutionStatus,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
)
from khaos.coding.intelligence.resolution.symbol_table import RepositorySymbolTable


def resolve_rust_imports(
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
        import_kind = metadata.get("import_kind", "use")

        # Determine if this is a crate-local or external path
        is_external = _is_external_rust_path(module)
        if is_external:
            results.append(ResolvedImport(
                source_file, module, "", alias, ResolutionStatus.EXTERNAL,
                None, None, 0.9, "rust-external-crate",
                (), {"import_kind": import_kind, "external": True},
            ))
            continue

        # Resolve the use path to a target file/module
        target_file = _resolve_rust_path(module, source_file, table)
        if target_file is None:
            results.append(ResolvedImport(
                source_file, module, "", alias, ResolutionStatus.UNRESOLVED,
                None, None, 0.6, "rust-path-not-found",
                (), {"import_kind": import_kind},
            ))
            continue

        # Handle glob imports
        if "*" in names:
            # Glob: ambiguous unless we can prove uniqueness (conservative: always ambiguous)
            results.append(ResolvedImport(
                source_file, module, "*", alias, ResolutionStatus.AMBIGUOUS,
                target_file, None, 0.5, "rust-glob-import-ambiguous",
                (target_file,), {"import_kind": import_kind, "glob": True},
            ))
            table.register_reverse_dep(source_file, target_file)
            continue

        # Resolve the specific imported name
        if not names:
            # Whole path use (e.g. `use crate::mod;`)
            results.append(ResolvedImport(
                source_file, module, "", alias, ResolutionStatus.RESOLVED,
                target_file, None, 0.92, "rust-use-path",
                (target_file,), {"import_kind": import_kind},
            ))
            table.register_reverse_dep(source_file, target_file)
            continue

        for name in names:
            if name == "*":
                results.append(ResolvedImport(
                    source_file, module, "*", alias, ResolutionStatus.AMBIGUOUS,
                    target_file, None, 0.5, "rust-glob-import-ambiguous",
                    (target_file,), {"import_kind": import_kind, "glob": True},
                ))
                continue

            # Look for name in target file symbols
            target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == name]
            if len(target_symbols) == 1:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.RESOLVED,
                    target_file, target_symbols[0].symbol_id, 0.93, "rust-use-named",
                    (target_file,), {"import_kind": import_kind},
                ))
            elif len(target_symbols) > 1:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.AMBIGUOUS,
                    target_file, None, 0.4, "rust-use-multiple",
                    tuple(s.symbol_id for s in target_symbols), {"import_kind": import_kind, "count": len(target_symbols)},
                ))
            else:
                results.append(ResolvedImport(
                    source_file, module, name, alias, ResolutionStatus.UNRESOLVED,
                    target_file, None, 0.6, "rust-use-name-not-found",
                    (target_file,), {"import_kind": import_kind},
                ))
            table.register_reverse_dep(source_file, target_file)

    return results


def resolve_rust_calls(
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

    source_dir = str(PurePosixPath(source_file).parent)

    for call in calls:
        callee: str = call.get("callee", "")
        caller: str | None = call.get("caller")
        metadata: dict[str, Any] = call.get("metadata", {})
        callee_form: str = metadata.get("callee_form", "identifier")
        call_kind: str = metadata.get("call_kind", "call")
        location = call.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = call_edge_id(source_file, callee, byte_start, byte_end, generation)
        caller_sym_id = _find_caller_symbol_id(source_file, caller, table)

        if callee_form == "identifier":
            # Same-module function lookup
            same_mod_files = _same_module_files(source_file, table)
            candidates = []
            for mod_file in same_mod_files:
                candidates.extend(s for s in table.symbols_by_file(mod_file) if s.name == callee and s.kind in ("function", "method"))
            # Also check imports
            if callee in import_map:
                target_file, target_sym_id = import_map[callee]
                if target_sym_id:
                    candidates.append(RepositorySymbol(target_sym_id, table.repository_id, target_file or "", "rust", "function", callee, callee, 0, 0, 0, 0))

            if len(candidates) == 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                    candidates[0].symbol_id, candidates[0].path, 0.93, "rust-same-module-function", None, metadata))
                continue
            if len(candidates) > 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                    None, None, 0.4, "rust-same-module-multiple", f"{len(candidates)} candidates", metadata))
                continue
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.5, "no-candidate", None, metadata))
            continue

        if callee_form == "path":
            # Explicit path call: crate::util::run() or Type::method()
            # Try to resolve the full path
            target_file = _resolve_rust_path(callee.rsplit("::", 1)[0] if "::" in callee else callee, source_file, table)
            func_name = callee.rsplit("::", 1)[-1] if "::" in callee else callee
            if target_file:
                target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == func_name and s.kind in ("function", "method")]
                if len(target_symbols) == 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_symbols[0].symbol_id, target_file, 0.92, "rust-path-call", None, metadata))
                    continue
                if len(target_symbols) > 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                        None, target_file, 0.4, "rust-path-call-multiple", f"{len(target_symbols)} candidates", metadata))
                    continue
            # Check if it's an imported path
            if callee in import_map:
                target_file, target_sym_id = import_map[callee]
                if target_sym_id:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_sym_id, target_file, 0.92, "rust-imported-path-call", None, metadata))
                    continue
            # Check if it starts with an external crate
            top_crate = callee.split("::")[0]
            if top_crate not in ("crate", "self", "super") and top_crate not in import_map:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                    None, None, 0.85, "rust-external-crate-call", None, metadata))
                continue
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.5, "rust-path-not-resolved", None, metadata))
            continue

        if callee_form == "member":
            receiver: str | None = metadata.get("receiver")
            if not receiver:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                    None, None, 0.3, "no-receiver", None, metadata))
                continue
            # Check if receiver is an imported name
            if receiver in import_map:
                target_file, _ = import_map[receiver]
                if target_file is None:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.EXTERNAL,
                        None, None, 0.85, "rust-external-attribute", None, metadata))
                    continue
                member_name = callee.split(".", 1)[-1] if "." in callee else callee
                target_symbols = [s for s in table.symbols_by_file(target_file) if s.name == member_name]
                if len(target_symbols) == 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        target_symbols[0].symbol_id, target_file, 0.92, "rust-module-attribute-call", None, metadata))
                elif len(target_symbols) > 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                        None, target_file, 0.4, "rust-module-attribute-multiple", None, metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, target_file, 0.6, "rust-module-attribute-not-found", None, metadata))
                continue
            # Value receiver → trait dispatch, can't resolve
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.DYNAMIC,
                None, None, 0.3, "rust-trait-dispatch", "receiver dynamic type unknown", metadata))
            continue

        results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
            None, None, 0.5, "unsupported-callee-form", None, metadata))

    return results


def resolve_rust_references(
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

    same_mod_files = _same_module_files(source_file, table)

    for ref in references:
        name: str = ref.get("name", "")
        ref_kind: str = ref.get("reference_kind", "read")
        metadata: dict[str, Any] = ref.get("metadata", {})
        location = ref.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = reference_edge_id(source_file, name, ref_kind, byte_start, byte_end, generation)

        # Same-module symbol lookup
        candidates = []
        for mod_file in same_mod_files:
            candidates.extend(s for s in table.symbols_by_file(mod_file) if s.name == name)
        if len(candidates) == 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                candidates[0].symbol_id, candidates[0].path, 0.90, "rust-same-module-symbol", metadata))
            continue
        if len(candidates) > 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.AMBIGUOUS,
                None, None, 0.4, "rust-same-module-multiple", metadata))
            continue
        # Imported name
        if name in import_names:
            target_file, target_sym_id = import_names[name]
            if target_sym_id:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                    target_sym_id, target_file, 0.88, "rust-imported-reference", metadata))
            elif target_file:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
                    None, target_file, 0.6, "rust-imported-module-reference", metadata))
            else:
                results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.EXTERNAL,
                    None, None, 0.85, "rust-external-reference", metadata))
            continue
        results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
            None, None, 0.4, "no-candidate", metadata))

    return results


def _is_external_rust_path(path: str) -> bool:
    """Determine if a Rust use path is external (starts with an external crate name)."""
    if not path:
        return False
    first = path.split("::")[0]
    # crate, self, super are local
    if first in ("crate", "self", "super"):
        return False
    # Paths starting with :: are absolute (could be external)
    if path.startswith("::"):
        return True
    # Otherwise, it's likely an external crate name (e.g. std, serde, tokio)
    # We can't know for sure without Cargo.toml, so treat short names as external
    # if they don't contain crate/self/super
    return True


def _resolve_rust_path(path: str, source_file: str, table: RepositorySymbolTable) -> str | None:
    """Resolve a Rust path (crate::mod::item) to a file in the repository."""
    if not path:
        return None

    # Handle crate:: prefix
    if path.startswith("crate::"):
        remaining = path[7:]
        return _resolve_rust_module_parts(remaining.split("::"), table)

    if path.startswith("self::"):
        remaining = path[6:]
        # self refers to current module
        source_module = _get_source_module(source_file)
        parts = source_module.split("::") if source_module else []
        parts.extend(remaining.split("::"))
        return _resolve_rust_module_parts(parts, table)

    if path.startswith("super::"):
        remaining = path[7:]
        source_module = _get_source_module(source_file)
        parts = source_module.split("::") if source_module else []
        if parts:
            parts = parts[:-1]  # Go up one level
        parts.extend(remaining.split("::"))
        return _resolve_rust_module_parts(parts, table)

    # Try direct module lookup
    direct = table.module_to_file(path)
    if direct:
        return direct

    return None


def _resolve_rust_module_parts(parts: list[str], table: RepositorySymbolTable) -> str | None:
    """Resolve Rust module parts to a file path."""
    if not parts:
        return None
    # Try as module identity
    module = "::".join(parts)
    direct = table.module_to_file(module)
    if direct:
        return direct
    # Try as file paths
    candidates = [
        "src/" + "/".join(parts) + ".rs",
        "/".join(parts) + ".rs",
        "src/" + "/".join(parts) + "/mod.rs",
        "/".join(parts) + "/mod.rs",
    ]
    for candidate in candidates:
        if table.has_file(candidate):
            return candidate
    return None


def _get_source_module(source_file: str) -> str | None:
    """Get the module identity of the source file."""
    from khaos.coding.intelligence.resolution.symbol_table import rust_file_to_module
    return rust_file_to_module(source_file)


def _same_module_files(source_file: str, table: RepositorySymbolTable) -> list[str]:
    """Get all files in the same Rust module (same directory + mod.rs)."""
    source_dir = str(PurePosixPath(source_file).parent)
    result = sorted(p for p in table.indexed_paths() if str(PurePosixPath(p).parent) == source_dir and p.endswith(".rs"))
    if source_file not in result:
        result.append(source_file)
    return result


def _find_caller_symbol_id(source_file: str, caller_qualified_name: str | None, table: RepositorySymbolTable) -> str | None:
    if not caller_qualified_name:
        return None
    syms = table.symbols_by_qualified_name(caller_qualified_name)
    return syms[0].symbol_id if syms else None
