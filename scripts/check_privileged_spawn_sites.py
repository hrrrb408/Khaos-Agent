#!/usr/bin/env python3
"""Require an owner and threat model for every detected runtime host-spawn site.

The gate intentionally scans source syntax rather than grep text, so comments
and documentation cannot hide a new privileged spawn.  Each production source
file containing a spawn must carry a file-level declaration:

``KHAOS-PRIVILEGED-SPAWN owner=... threat-model=... boundary=...```

The generated inventory is an auditable snapshot of all discovered call sites;
adding a new site or moving one changes the generated artifact and therefore
requires an explicit security review in the same change.  The scanner also
follows simple assignment aliases (``launch = subprocess.Popen``,
``spawn := exec.Command``, and ``let spawn = Command::new``); indirect or
dynamic dispatch remains forbidden in security-critical host-spawn code.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "generated" / "privileged-spawn-inventory.md"
DECLARATION = re.compile(
    r"KHAOS-PRIVILEGED-SPAWN\s+owner=(?P<owner>[A-Za-z0-9_.-]+)\s+"
    r"threat-model=(?P<threat>[A-Za-z0-9_.-]+)\s+"
    r"boundary=(?P<boundary>[A-Za-z0-9_.-]+)"
)
RUST_CALL = re.compile(r"\b(?:Command::new|execvp|execveat|execve|execvpe)\b")
GO_CALLS = {
    "os/exec": ("Command", "CommandContext", "Cmd"),
    "os": ("StartProcess", "StartProcessAsUser", "FindProcess", "ForkExec"),
    "syscall": ("Exec", "Execve", "Execveat", "ForkExec"),
    "golang.org/x/sys/unix": ("Exec", "Execve", "Execveat", "ForkExec"),
}
PYTHON_EXACT_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.check_returncode",
        "subprocess.call",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.system",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.fork",
        "os.forkpty",
        "pty.spawn",
    }
)


@dataclass(frozen=True)
class SpawnSite:
    path: str
    line: int
    symbol: str
    function: str
    owner: str
    threat_model: str
    boundary: str


def _declaration(path: Path) -> tuple[str, str, str] | None:
    for line in path.read_text(encoding="utf-8").splitlines()[:100]:
        match = DECLARATION.search(line)
        if match:
            return match.group("owner"), match.group("threat"), match.group("boundary")
    return None


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _python_sites(path: Path) -> list[tuple[int, str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    sites: list[tuple[int, str, str]] = []
    stack: list[str] = ["<module>"]
    module_aliases: dict[str, str] = {}
    symbol_aliases: dict[str, str] = {}
    assignment_aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                local = alias.asname or module.split(".", 1)[0]
                if module in {"subprocess", "asyncio", "os", "pty"}:
                    module_aliases[local] = module
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "subprocess",
            "asyncio",
            "os",
            "pty",
        }:
            for alias in node.names:
                local = alias.asname or alias.name
                symbol_aliases[local] = f"{node.module}.{alias.name}"

    def resolve(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return assignment_aliases.get(
                node.id,
                symbol_aliases.get(node.id, module_aliases.get(node.id, node.id)),
            )
        if isinstance(node, ast.Attribute):
            left = resolve(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        return _dotted(node)

    def is_spawn_call(name: str) -> bool:
        if name in PYTHON_EXACT_CALLS:
            return True
        if name.startswith("subprocess.") and name.split(".", 1)[1] in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }:
            return True
        return name.startswith(("os.exec", "os.spawn"))

    class AliasCollector(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            resolved = resolve(node.value)
            if is_spawn_call(resolved):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignment_aliases[target.id] = resolved
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            resolved = resolve(node.value) if node.value is not None else ""
            if is_spawn_call(resolved) and isinstance(node.target, ast.Name):
                assignment_aliases[node.target.id] = resolved
            self.generic_visit(node)

    AliasCollector().visit(tree)

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node: ast.Call) -> None:
            name = resolve(node.func)
            if is_spawn_call(name):
                sites.append((node.lineno, name, ".".join(stack)))
            self.generic_visit(node)

    Visitor().visit(tree)
    return sites


def _rust_sites(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    aliases = {"Command"}
    for match in re.finditer(
        r"use\s+std::process::Command\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)",
        source,
    ):
        aliases.add(match.group("alias"))
    assigned_aliases = {
        match.group("alias")
        for match in re.finditer(
            r"\blet\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            rf"(?:{'|'.join(re.escape(alias) for alias in sorted(aliases))})::new\b",
            source,
        )
    }
    sites: list[tuple[int, str, str]] = []
    call = re.compile(
        rf"\b(?:{'|'.join(re.escape(alias) for alias in sorted(aliases))})::new\b"
        r"|\b(?:execvp|execveat|execve|execvpe)\b"
    )
    for line_number, line in enumerate(source.splitlines(), 1):
        code = line.split("//", 1)[0]
        match = call.search(code) or RUST_CALL.search(code)
        if match is None and assigned_aliases:
            alias_call = re.search(
                rf"\b(?:{'|'.join(re.escape(alias) for alias in sorted(assigned_aliases))})\s*\(",
                code,
            )
            match = alias_call
        if match:
            symbol = match.group(0).rstrip("(").strip()
            sites.append((line_number, symbol, "rust::entrypoint"))
    return sites


def _strip_go_comments_and_strings(source: str) -> str:
    """Blank Go comments/strings while preserving line and column positions."""
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if quote is None:
            if char == "/" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                while index < len(source) and source[index] != "\n":
                    output.append(" ")
                    index += 1
                continue
            if char == "/" and next_char == "*":
                output.extend((" ", " "))
                index += 2
                while index < len(source):
                    if source[index] == "*" and index + 1 < len(source) and source[index + 1] == "/":
                        output.extend((" ", " "))
                        index += 2
                        break
                    output.append("\n" if source[index] == "\n" else " ")
                    index += 1
                continue
            if char in {'"', "'", "`"}:
                quote = char
                output.append(" ")
                index += 1
                continue
            output.append(char)
            index += 1
            continue
        if char == "\\" and quote != "`" and index + 1 < len(source):
            output.extend((" ", " "))
            index += 2
            continue
        if char == quote:
            quote = None
        output.append("\n" if char == "\n" else " ")
        index += 1
    return "".join(output)


def _go_import_aliases(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    import_re = re.compile(
        r"(?:import\s*\(\s*(?P<block>.*?)\s*\)|import\s+(?P<single>[^\n]+))",
        re.DOTALL,
    )
    for match in import_re.finditer(source):
        block = match.group("block") or match.group("single") or ""
        for line in block.splitlines():
            item = line.strip().split("//", 1)[0].strip()
            imported = re.search(
                r'(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"(?P<path>[^"]+)"',
                item,
            )
            if imported is None:
                continue
            package = imported.group("path")
            if package not in GO_CALLS:
                continue
            alias = imported.group("alias")
            if alias is None:
                alias = package.rsplit("/", 1)[-1]
            aliases[alias] = package
    return aliases


def _go_sites(path: Path) -> list[tuple[int, str, str]]:
    source = path.read_text(encoding="utf-8")
    code = _strip_go_comments_and_strings(source)
    aliases = _go_import_aliases(source)
    sites: list[tuple[int, str, str]] = []
    assignment_aliases: dict[str, str] = {}
    for alias, package in aliases.items():
        if alias == ".":
            continue
        functions = "|".join(
            re.escape(function) for function in GO_CALLS[package]
        )
        assignment = re.compile(
            rf"\b(?P<local>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*"
            rf"{re.escape(alias)}\.(?P<function>{functions})\b"
        )
        for match in assignment.finditer(code):
            assignment_aliases[match.group("local")] = (
                f"{package.rsplit('/', 1)[-1]}.{match.group('function')}"
            )
    for alias, package in aliases.items():
        functions = GO_CALLS[package]
        for function in functions:
            pattern = re.compile(
                rf"\b{re.escape(alias)}\.{re.escape(function)}\s*(?:\(|\{{)"
            )
            for match in pattern.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                sites.append((line, f"{package.rsplit('/', 1)[-1]}.{function}", "go::function"))
    if "." in aliases:
        for package in {value for key, value in aliases.items() if key == "."}:
            for function in GO_CALLS[package]:
                pattern = re.compile(rf"\b{re.escape(function)}\s*(?:\(|\{{)")
                for match in pattern.finditer(code):
                    line = code.count("\n", 0, match.start()) + 1
                    sites.append((line, f"{package.rsplit('/', 1)[-1]}.{function}", "go::function"))
    for local, symbol in assignment_aliases.items():
        for match in re.finditer(rf"\b{re.escape(local)}\s*\(", code):
            line = code.count("\n", 0, match.start()) + 1
            sites.append((line, symbol, "go::function"))
    return sorted(set(sites))


def discover() -> list[SpawnSite]:
    files: list[Path] = []
    files.extend(sorted((ROOT / "python" / "khaos").rglob("*.py")))
    files.extend(sorted((ROOT / "rust" / "khaos-core" / "src").rglob("*.rs")))
    files.extend(sorted((ROOT / "go").rglob("*.go")))
    discovered: list[SpawnSite] = []
    errors: list[str] = []
    for path in files:
        if any(part in {"tests", "__pycache__", "target"} for part in path.parts):
            continue
        # Finder-style copies such as ``module 2.py`` are not importable
        # Python modules or Cargo source targets.  They can remain in a
        # developer worktree without becoming part of the releasable runtime
        # graph; do not let preserved local copies poison the generated
        # release inventory.
        if " " in path.name:
            continue
        relative = path.relative_to(ROOT).as_posix()
        try:
            raw_sites = (
                _python_sites(path)
                if path.suffix == ".py"
                else _rust_sites(path)
                if path.suffix == ".rs"
                else _go_sites(path)
            )
        except (OSError, SyntaxError) as exc:
            errors.append(f"{relative}: cannot parse source: {exc}")
            continue
        if not raw_sites:
            continue
        declaration = _declaration(path)
        if declaration is None:
            errors.append(
                f"{relative}: missing KHAOS-PRIVILEGED-SPAWN owner/threat-model/boundary declaration"
            )
            continue
        owner, threat, boundary = declaration
        discovered.extend(
            SpawnSite(relative, line, symbol, function, owner, threat, boundary)
            for line, symbol, function in raw_sites
        )
    if errors:
        raise SystemExit("\n".join(errors))
    return discovered


def render() -> str:
    sites = discover()
    lines = [
        "# Generated Privileged Spawn Inventory",
        "",
        "> Generated by `scripts/check_privileged_spawn_sites.py`; do not edit manually.",
        "> Every host-spawn primitive detected by this enforced static verifier must have an owner, threat model, and enforcement boundary. Indirect or dynamic dispatch is not proven by this inventory.",
        "",
    ]
    for site in sites:
        lines.append(
            f"- `{site.path}:{site.line}` `{site.symbol}` in `{site.function}` "
            f"owner=`{site.owner}` threat-model=`{site.threat_model}` boundary=`{site.boundary}`"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    rendered = render()
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale privileged spawn inventory: {output}", file=sys.stderr)
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
