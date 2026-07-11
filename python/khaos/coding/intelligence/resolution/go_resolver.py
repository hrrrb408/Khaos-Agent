"""Conservative Go import/call/reference resolution.

Reads go.mod for module path but does NOT run `go list` or download dependencies.
Resolves only current-module imports and same-package top-level symbols.

External modules, interface dispatch, and receiver dynamic types remain unresolved/external.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.intelligence.resolution.ids import call_edge_id, reference_edge_id
from khaos.coding.intelligence.resolution.models import (
    ResolutionStatus,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
)
from khaos.coding.intelligence.resolution.symbol_table import RepositorySymbolTable


def resolve_go_imports(
    source_file: str,
    imports: list[dict[str, Any]],
    table: RepositorySymbolTable,
    generation: int,
    module_path: str | None = None,
) -> list[ResolvedImport]:
    results: list[ResolvedImport] = []
    for imp in imports:
        module: str = imp.get("module", "")
        alias: str | None = imp.get("alias")
        metadata: dict[str, Any] = imp.get("metadata", {})

        if module_path and module.startswith(module_path):
            # Intra-module import — resolve to directory
            relative = module[len(module_path):].lstrip("/")
            if relative:
                # All .go files in this directory are part of the package
                target_files = sorted(p for p in table.indexed_paths() if p.startswith(relative + "/") and p.endswith(".go"))
                if target_files:
                    results.append(ResolvedImport(
                        source_file, module, "", alias, ResolutionStatus.RESOLVED,
                        target_files[0], None, 0.92, "go-intra-module-package",
                        tuple(target_files), {"import_kind": "import", "package_dir": relative},
                    ))
                    for tf in target_files:
                        table.register_reverse_dep(source_file, tf)
                else:
                    results.append(ResolvedImport(
                        source_file, module, "", alias, ResolutionStatus.UNRESOLVED,
                        None, None, 0.6, "go-package-directory-not-found",
                        (), {"import_kind": "import"},
                    ))
            else:
                # Root package
                root_files = sorted(p for p in table.indexed_paths() if "/" not in p and p.endswith(".go"))
                if root_files:
                    results.append(ResolvedImport(
                        source_file, module, "", alias, ResolutionStatus.RESOLVED,
                        root_files[0], None, 0.92, "go-root-package",
                        tuple(root_files), {"import_kind": "import"},
                    ))
                    for rf in root_files:
                        table.register_reverse_dep(source_file, rf)
                else:
                    results.append(ResolvedImport(
                        source_file, module, "", alias, ResolutionStatus.UNRESOLVED,
                        None, None, 0.6, "go-root-package-empty",
                        (), {"import_kind": "import"},
                    ))
        else:
            # External module
            results.append(ResolvedImport(
                source_file, module, "", alias, ResolutionStatus.EXTERNAL,
                None, None, 0.9, "go-external-module",
                (), {"import_kind": "import", "external": True},
            ))

    return results


def resolve_go_calls(
    repository_id: str,
    source_file: str,
    calls: list[dict[str, Any]],
    table: RepositorySymbolTable,
    resolved_imports: list[ResolvedImport],
    generation: int,
) -> list[ResolvedCallEdge]:
    results: list[ResolvedCallEdge] = []
    # Build package alias map: alias/package_name → set of target files
    package_map: dict[str, list[str]] = {}
    for ri in resolved_imports:
        if ri.status not in (ResolutionStatus.RESOLVED, ResolutionStatus.AMBIGUOUS):
            continue
        if ri.target_file is None:
            continue
        # Package name is the last component of the module path, or alias
        pkg_name = ri.alias or ri.import_module.rsplit("/", 1)[-1]
        candidate_targets = list(ri.candidate_targets) if ri.candidate_targets else [ri.target_file]
        if pkg_name not in package_map:
            package_map[pkg_name] = []
        package_map[pkg_name].extend(candidate_targets)

    source_dir = str(PurePosixPath(source_file).parent)

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
            # Same-package function — look in all .go files in the same directory
            same_pkg_files = sorted(p for p in table.indexed_paths() if str(PurePosixPath(p).parent) == source_dir and p.endswith(".go"))
            candidates = []
            for pkg_file in same_pkg_files:
                candidates.extend(s for s in table.symbols_by_file(pkg_file) if s.name == callee and s.kind in ("function", "type", "method"))
            if len(candidates) == 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                    candidates[0].stable_symbol_id, candidates[0].path, 0.93, "go-same-package-function", None, metadata))
                continue
            if len(candidates) > 1:
                results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                    None, None, 0.4, "go-same-package-multiple", f"{len(candidates)} candidates", metadata))
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
            # Check if receiver is an imported package
            if receiver in package_map:
                target_files = package_map[receiver]
                member_name = callee.split(".", 1)[-1] if "." in callee else callee
                candidates = []
                for tf in target_files:
                    candidates.extend(s for s in table.symbols_by_file(tf) if s.name == member_name and s.kind in ("function", "type", "method"))
                if len(candidates) == 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.RESOLVED,
                        candidates[0].stable_symbol_id, candidates[0].path, 0.92, "go-package-selector-call", None, metadata))
                elif len(candidates) > 1:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.AMBIGUOUS,
                        None, None, 0.4, "go-package-selector-multiple", f"{len(candidates)} candidates", metadata))
                else:
                    results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                        None, None, 0.6, "go-package-symbol-not-found", None, metadata))
                continue
            # Receiver is a value → unresolved (interface dispatch)
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.3, "go-interface-dispatch", "receiver dynamic type unknown", metadata))
            continue

        if callee_form == "path":
            # Go doesn't use path-form calls, but handle gracefully
            results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
                None, None, 0.5, "unsupported-callee-form", None, metadata))
            continue

        results.append(ResolvedCallEdge(eid, source_file, caller_sym_id, callee, ResolutionStatus.UNRESOLVED,
            None, None, 0.5, "unsupported-callee-form", None, metadata))

    return results


def resolve_go_references(
    repository_id: str,
    source_file: str,
    references: list[dict[str, Any]],
    table: RepositorySymbolTable,
    resolved_imports: list[ResolvedImport],
    generation: int,
) -> list[ResolvedReferenceEdge]:
    results: list[ResolvedReferenceEdge] = []
    source_dir = str(PurePosixPath(source_file).parent)

    for ref in references:
        name: str = ref.get("name", "")
        ref_kind: str = ref.get("reference_kind", "read")
        metadata: dict[str, Any] = ref.get("metadata", {})
        location = ref.get("location", {})
        byte_start = location.get("byte_start", 0)
        byte_end = location.get("byte_end", 0)
        eid = reference_edge_id(repository_id, source_file, name, ref_kind, byte_start, byte_end, generation)

        # Same-package symbol lookup
        same_pkg_files = sorted(p for p in table.indexed_paths() if str(PurePosixPath(p).parent) == source_dir and p.endswith(".go"))
        candidates = []
        for pkg_file in same_pkg_files:
            candidates.extend(s for s in table.symbols_by_file(pkg_file) if s.name == name)
        if len(candidates) == 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.RESOLVED,
                candidates[0].stable_symbol_id, candidates[0].path, 0.90, "go-same-package-symbol", metadata))
            continue
        if len(candidates) > 1:
            results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.AMBIGUOUS,
                None, None, 0.4, "go-same-package-multiple", metadata))
            continue
        results.append(ResolvedReferenceEdge(eid, source_file, name, ref_kind, ResolutionStatus.UNRESOLVED,
            None, None, 0.4, "no-candidate", metadata))

    return results


def read_go_module_path(root: Path | None) -> str | None:
    """Read the module path from go.mod. Returns None if not found."""
    if root is None:
        return None
    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return None
    try:
        for line in go_mod.read_text(encoding="utf-8").splitlines():
            if line.startswith("module "):
                return line.split(None, 1)[1].strip()
    except (OSError, UnicodeDecodeError):
        pass
    return None


def _find_caller_symbol_id(source_file: str, caller_qualified_name: str | None, table: RepositorySymbolTable) -> str | None:
    if not caller_qualified_name:
        return None
    syms = table.symbols_by_qualified_name(caller_qualified_name)
    return syms[0].symbol_id if syms else None
