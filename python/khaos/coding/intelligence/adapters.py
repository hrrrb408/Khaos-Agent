"""Offline fallback adapters and locked Tree-sitter grammar integration."""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.metadata
import importlib.resources
import re
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from khaos.coding.intelligence.models import ImportReference, ParseDiagnostic, ParseResult, ParserMetadata, ParseState, SourceLocation, Symbol


@dataclass(frozen=True)
class AdapterAvailability:
    available: bool
    code: str
    message: str
    version: str = "unknown"


@dataclass(frozen=True)
class GrammarSpec:
    language: str
    dialect: str
    extensions: frozenset[str]
    module: str
    distribution: str
    loader_name: str
    expected_package_version: str
    query_resource_path: str
    query_version: str


GRAMMARS = {
    "python": GrammarSpec("python", "python", frozenset({".py"}), "tree_sitter_python", "tree-sitter-python", "language", "0.25.0", "queries/python", "v1"),
    "javascript": GrammarSpec("javascript", "javascript", frozenset({".js", ".jsx"}), "tree_sitter_javascript", "tree-sitter-javascript", "language", "0.25.0", "queries/javascript", "v1"),
    "typescript": GrammarSpec("typescript", "typescript", frozenset({".ts"}), "tree_sitter_typescript", "tree-sitter-typescript", "language_typescript", "0.23.2", "queries/typescript", "v1"),
    "tsx": GrammarSpec("typescript", "tsx", frozenset({".tsx"}), "tree_sitter_typescript", "tree-sitter-typescript", "language_tsx", "0.23.2", "queries/tsx", "v1"),
    "go": GrammarSpec("go", "go", frozenset({".go"}), "tree_sitter_go", "tree-sitter-go", "language", "0.25.0", "queries/go", "v1"),
    "rust": GrammarSpec("rust", "rust", frozenset({".rs"}), "tree_sitter_rust", "tree-sitter-rust", "language", "0.24.2", "queries/rust", "v1"),
}


class ParseAdapter(Protocol):
    language: str
    source_name: str
    supports_incremental: bool
    version: str
    extensions: frozenset[str]
    def availability(self, file_path: str | None = None) -> AdapterAvailability: ...
    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult: ...


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _point_column(content: bytes, byte_offset: int) -> tuple[int, int]:
    before = content[:byte_offset]
    line = before.count(b"\n")
    line_bytes = before.rsplit(b"\n", 1)[-1]
    return line, len(line_bytes.decode("utf-8"))


def _node_location(file_path: str, content: bytes, node: Any) -> SourceLocation:
    start_line, start_column = _point_column(content, node.start_byte)
    end_line, end_column = _point_column(content, node.end_byte)
    return SourceLocation(file_path, start_line, start_column, end_line, end_column, node.start_byte, node.end_byte)


class TreeSitterAdapter:
    source_name = "tree-sitter"
    supports_incremental = False

    def __init__(self, language: str, extensions: frozenset[str]) -> None:
        self.language = self.language_id = language
        self.extensions = extensions
        self._lock = threading.RLock()
        self._initialized: dict[str, tuple[Any, Any, Any, GrammarSpec]] = {}
        try:
            self.version = importlib.metadata.version("tree-sitter")
        except importlib.metadata.PackageNotFoundError:
            self.version = "unavailable"

    def _spec(self, file_path: str | None) -> GrammarSpec:
        if self.language == "typescript" and file_path and Path(file_path).suffix.lower() == ".tsx":
            return GRAMMARS["tsx"]
        return GRAMMARS[self.language]

    def availability(self, file_path: str | None = None) -> AdapterAvailability:
        try:
            self._initialize(self._spec(file_path))
            return AdapterAvailability(True, "available", "locked grammar and queries initialized", self.version)
        except ModuleNotFoundError as exc:
            code = "dependency-missing" if exc.name == "tree_sitter" else "grammar-missing"
            return AdapterAvailability(False, code, str(exc), self.version)
        except importlib.metadata.PackageNotFoundError as exc:
            return AdapterAvailability(False, "grammar-missing", str(exc), self.version)
        except AttributeError as exc:
            return AdapterAvailability(False, "grammar-loader-missing", str(exc), self.version)
        except GrammarVersionError as exc:
            return AdapterAvailability(False, "grammar-version-mismatch", str(exc), self.version)
        except GrammarAbiError as exc:
            return AdapterAvailability(False, "grammar-abi-incompatible", str(exc), self.version)
        except QueryLoadError as exc:
            return AdapterAvailability(False, "query-invalid", str(exc), self.version)
        except (ImportError, RuntimeError, TypeError, ValueError) as exc:
            return AdapterAvailability(False, "parser-initialization-failed", str(exc), self.version)

    def _initialize(self, spec: GrammarSpec) -> tuple[Any, Any, Any, GrammarSpec]:
        with self._lock:
            if spec.dialect in self._initialized:
                return self._initialized[spec.dialect]
            tree_sitter = importlib.import_module("tree_sitter")
            module = importlib.import_module(spec.module)
            version = importlib.metadata.version(spec.distribution)
            if version != spec.expected_package_version:
                raise GrammarVersionError(f"{spec.distribution} {version} != locked {spec.expected_package_version}")
            loader = getattr(module, spec.loader_name)
            language = tree_sitter.Language(loader())
            if not tree_sitter.MIN_COMPATIBLE_LANGUAGE_VERSION <= language.abi_version <= tree_sitter.LANGUAGE_VERSION:
                raise GrammarAbiError(f"grammar ABI {language.abi_version} outside {tree_sitter.MIN_COMPATIBLE_LANGUAGE_VERSION}..{tree_sitter.LANGUAGE_VERSION}")
            try:
                symbols_query = tree_sitter.Query(language, _query_text(spec, "symbols.scm"))
                imports_query = tree_sitter.Query(language, _query_text(spec, "imports.scm"))
                tree_sitter.QueryCursor(symbols_query)
                tree_sitter.QueryCursor(imports_query)
            except tree_sitter.QueryError as exc:
                raise QueryLoadError(str(exc)) from exc
            parser = tree_sitter.Parser(language)
            if parser.parse(_minimum_source(spec.dialect)).root_node is None:
                raise RuntimeError("minimum grammar parse returned no root")
            value = (language, symbols_query, imports_query, spec)
            self._initialized[spec.dialect] = value
            return value

    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult:
        del previous_state
        started = time.perf_counter()
        language, symbols_query, imports_query, spec = self._initialize(self._spec(file_path))
        tree_sitter = importlib.import_module("tree_sitter")
        tree = tree_sitter.Parser(language).parse(content)
        all_nodes = list(_walk(tree.root_node))
        error_nodes = [node for node in all_nodes if node.type == "ERROR" or node.is_missing]
        symbol_matches = tree_sitter.QueryCursor(symbols_query).matches(tree.root_node)
        import_matches = tree_sitter.QueryCursor(imports_query).matches(tree.root_node)
        symbols = _extract_symbols(spec, symbol_matches, content, file_path, error_nodes)
        imports = _extract_imports(spec, import_matches, content, file_path, error_nodes)
        diagnostics: list[ParseDiagnostic] = []
        if tree.root_node.has_error:
            node = error_nodes[0] if error_nodes else tree.root_node
            diagnostics.append(ParseDiagnostic("parse-error", "warning", "Tree-sitter recovered from syntax error", _node_location(file_path, content, node), True, self.source_name))
        metadata = ParserMetadata(spec.module, importlib.metadata.version(spec.distribution), language.abi_version, spec.dialect, spec.query_version, len(error_nodes), len(all_nodes), len(symbol_matches), len(import_matches))
        return ParseResult(spec.language, file_path, tuple(symbols), tuple(imports), (), (), tuple(diagnostics), self.source_name, self.version, _hash(content), (time.perf_counter() - started) * 1000, metadata)


class GrammarVersionError(RuntimeError): pass
class GrammarAbiError(RuntimeError): pass
class QueryLoadError(RuntimeError): pass


def _query_text(spec: GrammarSpec, name: str) -> str:
    resource = importlib.resources.files("khaos.coding.intelligence").joinpath(spec.query_resource_path, name)
    if not resource.is_file():
        raise QueryLoadError(f"missing packaged query: {spec.query_resource_path}/{name}")
    return resource.read_text(encoding="utf-8")


def _minimum_source(dialect: str) -> bytes:
    return {"python": b"pass\n", "javascript": b"const x = 1;", "typescript": b"const x: number = 1;", "tsx": b"const X = () => <div />;", "go": b"package p\n", "rust": b"fn main() {}"}[dialect]


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _error_nodes(root: Any) -> list[Any]:
    return [node for node in _walk(root) if node.type == "ERROR" or node.is_missing]


def _overlaps(node: Any, errors: list[Any]) -> bool:
    return any(node.start_byte < error.end_byte and error.start_byte < node.end_byte for error in errors)


def _text(content: bytes, node: Any | None) -> str:
    return content[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _first_capture(captures: dict[str, list[Any]], name: str) -> Any | None:
    nodes = captures.get(name, ())
    return nodes[0] if nodes else None


def _extract_symbols(spec: GrammarSpec, matches: list[tuple[int, dict[str, list[Any]]]], content: bytes, file_path: str, errors: list[Any]) -> list[Symbol]:
    found: dict[tuple[int, int, str, str], Symbol] = {}
    kind_priority = {"type": 0, "function": 1, "class": 2, "interface": 2, "struct": 2, "method": 3}
    for pattern_index, captures in matches:
        definition_capture = next((name for name in captures if name.startswith("definition.")), None)
        definition = _first_capture(captures, definition_capture) if definition_capture else None
        name_node = _first_capture(captures, "name")
        if definition is None or name_node is None:
            continue
        kind = definition_capture.removeprefix("definition.")
        if kind == "type":
            kind = "type_alias" if spec.dialect in {"typescript", "tsx", "rust"} else "named_type"
        if spec.dialect == "python" and kind == "function":
            parent = definition.parent
            container = parent.parent if parent is not None and parent.type == "block" else None
            if container is not None and container.type == "class_definition":
                kind = "method"
            elif _text(content, definition).lstrip().startswith("async "):
                kind = "async_function"
        if spec.dialect == "rust" and kind == "function":
            ancestor = definition.parent
            while ancestor is not None:
                if ancestor.type == "impl_item":
                    kind = "method"
                    break
                ancestor = ancestor.parent
        name = _text(content, name_node)
        if not name:
            continue
        owner_names: list[str] = []
        parent = definition.parent
        while parent is not None:
            if parent.type in {"class_definition", "class_declaration", "impl_item", "internal_module", "mod_item", "function_definition", "function_declaration", "method_definition"}:
                owner = parent.child_by_field_name("name") or parent.child_by_field_name("type")
                owner_text = _text(content, owner)
                if owner_text:
                    owner_names.append(owner_text)
            parent = parent.parent
        qualified = ".".join([*reversed(owner_names), name])
        confidence = 0.5 if _overlaps(definition, errors) else 0.98
        location = _node_location(file_path, content, name_node)
        symbol = Symbol(name, kind, qualified, location, spec.language, "tree-sitter", confidence, {"dialect": spec.dialect, "node_type": definition.type, "query_pattern": pattern_index, "definition_byte_start": definition.start_byte, "definition_byte_end": definition.end_byte})
        key = (location.byte_start, location.byte_end, kind, name)
        competing = next((item for item in found if item[0] == key[0] and item[1] == key[1] and item[3] == name), None)
        if competing is None or kind_priority.get(kind, 1) > kind_priority.get(competing[2], 1):
            if competing is not None:
                found.pop(competing)
            found[key] = symbol
    return sorted(found.values(), key=lambda item: (item.location.byte_start, item.location.byte_end, item.kind, item.name))


def _extract_imports(spec: GrammarSpec, matches: list[tuple[int, dict[str, list[Any]]]], content: bytes, file_path: str, errors: list[Any]) -> list[ImportReference]:
    found: dict[tuple[int, int, str, str | None], ImportReference] = {}
    for pattern_index, captures in matches:
        statement = _first_capture(captures, "import.statement") or _first_capture(captures, "import.reexport")
        if statement is None or _overlaps(statement, errors):
            continue
        if spec.dialect == "python":
            items = _python_imports(statement, content)
        elif spec.dialect in {"javascript", "typescript", "tsx"}:
            items = _javascript_imports(statement, content, reexport="import.reexport" in captures)
        elif spec.dialect == "go":
            items = _go_imports(statement, content)
        else:
            items = _rust_imports(statement, content)
        location = _node_location(file_path, content, statement)
        for module, names, alias, metadata in items:
            if not module:
                continue
            metadata.update({"dialect": spec.dialect, "query_pattern": pattern_index, "statement_byte_start": statement.start_byte, "statement_byte_end": statement.end_byte})
            item = ImportReference(module, tuple(names), alias, location, "tree-sitter", 0.98, metadata)
            found[(location.byte_start, location.byte_end, module, alias)] = item
    return sorted(found.values(), key=lambda item: (item.location.byte_start, int(item.metadata.get("item_byte_start", item.location.byte_start)), item.module, item.alias or ""))


def _python_imports(statement: Any, content: bytes) -> list[tuple[str, list[str], str | None, dict[str, Any]]]:
    if statement.type == "import_statement":
        result = []
        for child in statement.named_children:
            name = child.child_by_field_name("name") if child.type == "aliased_import" else child
            alias = child.child_by_field_name("alias") if child.type == "aliased_import" else None
            result.append((_text(content, name), [], _text(content, alias) or None, {"import_kind": "import", "item_byte_start": child.start_byte}))
        return result
    module_node = statement.child_by_field_name("module_name")
    module = _text(content, module_node)
    result = []
    for child in statement.named_children:
        if child == module_node:
            continue
        if child.type == "wildcard_import":
            result.append((module, ["*"], None, {"import_kind": "from", "glob": True, "item_byte_start": child.start_byte}))
        elif child.type in {"dotted_name", "aliased_import"}:
            name = child.child_by_field_name("name") if child.type == "aliased_import" else child
            alias = child.child_by_field_name("alias") if child.type == "aliased_import" else None
            result.append((module, [_text(content, name)], _text(content, alias) or None, {"import_kind": "from", "relative": module.startswith("."), "item_byte_start": child.start_byte}))
    return result


def _javascript_imports(statement: Any, content: bytes, *, reexport: bool) -> list[tuple[str, list[str], str | None, dict[str, Any]]]:
    source = statement.child_by_field_name("source")
    module = _text(content, source).strip("\"'")
    base = {"import_kind": "reexport" if reexport else "import", "reexport": reexport}
    clause = next((child for child in statement.named_children if child.type in {"import_clause", "export_clause", "namespace_export"}), None)
    if clause is None:
        return [(module, [], None, {**base, "side_effect": not reexport})]
    type_only = any(child.type == "type" for child in statement.children)
    result = []
    for child in _walk(clause):
        if child.type == "import_specifier" or child.type == "export_specifier":
            name = child.child_by_field_name("name")
            alias = child.child_by_field_name("alias")
            result.append((module, [_text(content, name)], _text(content, alias) or None, {**base, "type_only": type_only}))
        elif child.type == "namespace_import":
            name = next((node for node in child.named_children if node.type == "identifier"), None)
            result.append((module, ["*"], _text(content, name) or None, {**base, "namespace": True, "type_only": type_only}))
    direct = [child for child in clause.named_children if child.type == "identifier"]
    if direct:
        result.insert(0, (module, ["default"], _text(content, direct[0]), {**base, "default": True, "type_only": type_only}))
    return result or [(module, [], None, {**base, "type_only": type_only})]


def _go_imports(statement: Any, content: bytes) -> list[tuple[str, list[str], str | None, dict[str, Any]]]:
    path = statement.child_by_field_name("path")
    name = statement.child_by_field_name("name")
    module = _text(content, path).strip("\"")
    alias = _text(content, name) or None
    return [(module, [], alias, {"import_kind": "import", "blank": alias == "_", "dot": alias == "."})]


def _rust_imports(statement: Any, content: bytes) -> list[tuple[str, list[str], str | None, dict[str, Any]]]:
    if statement.type == "extern_crate_declaration":
        name = statement.child_by_field_name("name")
        return [(_text(content, name), [], None, {"import_kind": "extern_crate"})]
    argument = statement.child_by_field_name("argument")
    return _expand_rust_use(argument, content, "")


def _expand_rust_use(node: Any, content: bytes, prefix: str) -> list[tuple[str, list[str], str | None, dict[str, Any]]]:
    if node.type == "scoped_use_list":
        path = _text(content, node.child_by_field_name("path"))
        base = f"{prefix}::{path}" if prefix else path
        use_list = node.child_by_field_name("list") or next((child for child in node.named_children if child.type == "use_list"), None)
        result = []
        for child in use_list.named_children if use_list is not None else ():
            result.extend(_expand_rust_use(child, content, base))
        return result
    if node.type == "use_as_clause":
        path = node.child_by_field_name("path")
        alias = node.child_by_field_name("alias")
        module = _text(content, path)
        if prefix:
            module = f"{prefix}::{module}"
        return [(module, [], _text(content, alias) or None, {"import_kind": "use", "alias": True})]
    if node.type == "use_wildcard":
        parts = [_text(content, child) for child in node.named_children]
        module = "::".join(part for part in parts if part)
        if prefix:
            module = f"{prefix}::{module}"
        return [(module, ["*"], None, {"import_kind": "use", "glob": True})]
    module = _text(content, node)
    if prefix:
        module = f"{prefix}::{module}"
    return [(module, [], None, {"import_kind": "use"})]


# Existing offline adapters remain dependency-free.
class PythonAstAdapter:
    language = language_id = "python"; source_name = "python-ast"; supports_incremental = False; version = "stdlib-ast"; extensions = frozenset({".py"})
    def availability(self, file_path: str | None = None) -> AdapterAvailability: return AdapterAvailability(True, "available", "Python stdlib ast is available", self.version)
    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult:
        del previous_state
        started=time.perf_counter(); text=content.decode(); tree=ast.parse(text, filename=file_path); symbols=[]; imports=[]
        parents={child:parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
                parent=parents.get(node); owner=parent.name if isinstance(parent,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) else None; kind="class" if isinstance(node,ast.ClassDef) else "method" if isinstance(parent,ast.ClassDef) else "async_function" if isinstance(node,ast.AsyncFunctionDef) else "function"; line=node.lineno-1; col=text.splitlines()[line].find(node.name,node.col_offset); start=sum(len(x.encode()) for x in text.splitlines(keepends=True)[:line])+len(text.splitlines(keepends=True)[line][:col].encode()); loc=SourceLocation(file_path,line,col,line,col+len(node.name),start,start+len(node.name.encode())); symbols.append(Symbol(node.name,kind,f"{owner}.{node.name}" if owner else node.name,loc,"python",self.source_name,1.0,{}))
            elif isinstance(node,(ast.Import,ast.ImportFrom)):
                line=node.lineno-1; start=sum(len(x.encode()) for x in text.splitlines(keepends=True)[:line]); loc=SourceLocation(file_path,line,0,line,len(text.splitlines()[line]),start,start+len(text.splitlines()[line].encode()));
                if isinstance(node,ast.Import):
                    imports.extend(ImportReference(a.name,(),a.asname,loc,self.source_name,1.0) for a in node.names)
                else: imports.append(ImportReference("."*node.level+(node.module or ""),tuple(a.name for a in node.names),node.names[0].asname if len(node.names)==1 else None,loc,self.source_name,1.0))
        return ParseResult("python",file_path,tuple(symbols),tuple(imports),parser_source=self.source_name,parser_version=self.version,content_hash=_hash(content),parse_duration_ms=(time.perf_counter()-started)*1000)


class LegacyRegexAdapter:
    source_name="legacy-regex"; supports_incremental=False; version="legacy-v2"
    def __init__(self,language:str,extensions:frozenset[str])->None: self.language=self.language_id=language; self.extensions=extensions
    def availability(self,file_path:str|None=None)->AdapterAvailability: return AdapterAvailability(True,"available","bundled offline fallback",self.version)
    def parse(self,path:Path|None=None,content:bytes=b"",*,file_path:str|None=None,previous_state:ParseState|None=None)->ParseResult:
        del previous_state
        actual=file_path or str(path); text=content.decode(); patterns={"python":r"(?m)^\s*(?:async\s+)?(class|def)\s+([^\W\d]\w*)","javascript":r"(?m)^\s*(?:export\s+)?(?:async\s+)?(class|function)\s+([^\W\d]\w*)","typescript":r"(?m)^\s*(?:export\s+)?(?:async\s+)?(class|interface|function)\s+([^\W\d]\w*)","go":r"(?m)^\s*(type|func)\s+(?:\([^)]*\)\s*)?([^\W\d]\w*)","rust":r"(?m)^\s*(?:pub\s+)?(struct|trait|fn)\s+([^\W\d]\w*)"}; symbols=[]
        for match in re.finditer(patterns[self.language],text):
            start=match.start(2); line=text.count("\n",0,start); col=start-(text.rfind("\n",0,start)+1); loc=SourceLocation(actual,line,col,line,col+len(match.group(2)),len(text[:start].encode()),len(text[:match.end(2)].encode())); symbols.append(Symbol(match.group(2),match.group(1),match.group(2),loc,self.language,self.source_name,.55,{}))
        diagnostic=() if all(text.count(a)==text.count(b) for a,b in (("(",")"),("{","}"),("[","]"))) else (ParseDiagnostic("syntax-error","warning","unbalanced delimiters",None,True,self.source_name),)
        return ParseResult(self.language,actual,tuple(symbols),diagnostics=diagnostic,parser_source=self.source_name,parser_version=self.version,content_hash=_hash(content))
