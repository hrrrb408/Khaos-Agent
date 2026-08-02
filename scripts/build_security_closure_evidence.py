#!/usr/bin/env python3
"""Build and validate the M4 Security Closure evidence artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TESTS = (
    "workspace_escape",
    "approval_replay",
    "schema_injection",
    "browser_direct_ip",
    "browser_dns_rebinding",
    "helper_confused_deputy",
    "process_tree_escape",
)


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _cap_eff() -> str:
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith("CapEff:"):
            return line.split()[1].lower()
    raise RuntimeError("CapEff evidence unavailable")


def _schema_digest() -> str:
    from khaos.tools.registry import create_runtime_registry

    registry = create_runtime_registry()
    digest = hashlib.sha256()
    for name in sorted(registry.names()):
        tool = registry.get(name)
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(tool.schema_digest.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _policy_digest() -> str:
    from khaos.security.effective_policy import load_effective_policy

    return load_effective_policy(ROOT).digest


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _provenance_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_fragment(args: argparse.Namespace) -> None:
    if args.test not in REQUIRED_TESTS:
        raise RuntimeError("unknown security evidence test")
    if args.result != "blocked":
        raise RuntimeError("security evidence result must be blocked")
    environment = {
        "runner_os": args.runner_os,
        "production_mode": args.production_mode == "true",
    }
    payload: dict[str, object] = {
        "commit": args.commit,
        "run_id": args.run_id,
        "job": args.job,
        "test": args.test,
        "result": args.result,
        "environment": environment,
    }
    payload["digest"] = _provenance_digest(payload)
    _write(Path(args.output), payload)


def browser_fragment(args: argparse.Namespace) -> None:
    uid = os.geteuid()
    cap_eff = _cap_eff()
    if uid == 0 or int(cap_eff, 16) != 0:
        raise RuntimeError("production Python browser evidence is privileged")
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        raise RuntimeError("development mode cannot emit production evidence")
    socket_path = Path(args.helper_socket)
    if not socket_path.is_socket() or socket_path.stat().st_uid != uid:
        raise RuntimeError("authenticated helper socket evidence unavailable")
    _write(
        Path(args.output),
        {
            "commit": args.commit,
            "run_id": args.run_id,
            "job": args.job,
            "production_mode": True,
            "python_uid": uid,
            "python_cap_eff": cap_eff,
            "host_fallback": False,
            "browser_helper_authenticated": True,
            "policy_digest": _policy_digest(),
            "schema_digest": _schema_digest(),
            "launcher_digest": _digest(Path(args.launcher)),
            "helper_digest": _digest(Path(args.helper)),
        },
    )


def final_artifact(args: argparse.Namespace) -> None:
    fragment = json.loads(Path(args.fragment).read_text(encoding="utf-8"))
    exact_fields = {
        "production_mode",
        "python_uid",
        "python_cap_eff",
        "host_fallback",
        "browser_helper_authenticated",
        "policy_digest",
        "schema_digest",
        "launcher_digest",
        "helper_digest",
        "commit",
        "run_id",
        "job",
    }
    if set(fragment) != exact_fields:
        raise RuntimeError("browser evidence fragment contract invalid")
    if (
        fragment["commit"] != args.commit
        or not fragment["run_id"]
        or not fragment["job"]
        or
        fragment["production_mode"] is not True
        or fragment["host_fallback"] is not False
        or fragment["browser_helper_authenticated"] is not True
        or type(fragment["python_uid"]) is not int
        or fragment["python_uid"] == 0
        or int(fragment["python_cap_eff"], 16) != 0
    ):
        raise RuntimeError("browser production evidence is not fail-closed")
    for digest_name in (
        "policy_digest",
        "schema_digest",
        "launcher_digest",
        "helper_digest",
    ):
        value = fragment[digest_name]
        if type(value) is not str or len(value) != 64:
            raise RuntimeError(f"{digest_name} is invalid")
    evidence_by_test: dict[str, dict[str, object]] = {}
    for path in sorted(Path(args.fragments_dir).rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        exact = {
            "commit", "run_id", "job", "test", "result", "digest", "environment"
        }
        if not isinstance(payload, dict) or set(payload) != exact:
            raise RuntimeError(f"test evidence contract invalid: {path}")
        digest = payload.pop("digest")
        if (
            payload["commit"] != args.commit
            or payload["test"] not in REQUIRED_TESTS
            or payload["result"] != "blocked"
            or not payload["run_id"]
            or not payload["job"]
            or not isinstance(payload["environment"], dict)
            or payload["environment"].get("production_mode") is not True
            or digest != _provenance_digest(payload)
        ):
            raise RuntimeError(f"test evidence provenance invalid: {path}")
        test_name = str(payload["test"])
        if test_name in evidence_by_test:
            raise RuntimeError(f"duplicate test evidence: {test_name}")
        payload["digest"] = digest
        evidence_by_test[test_name] = payload
    missing = set(REQUIRED_TESTS) - set(evidence_by_test)
    if missing:
        raise RuntimeError(f"missing test evidence: {', '.join(sorted(missing))}")
    artifact = {
        "commit": args.commit,
        **fragment,
        "tests": {
            name: evidence_by_test[name] for name in REQUIRED_TESTS
        },
    }
    _write(Path(args.output), artifact)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    fragment = subparsers.add_parser("browser-fragment")
    fragment.add_argument("--launcher", required=True)
    fragment.add_argument("--helper", required=True)
    fragment.add_argument("--helper-socket", required=True)
    fragment.add_argument("--output", required=True)
    fragment.add_argument("--commit", required=True)
    fragment.add_argument("--run-id", required=True)
    fragment.add_argument("--job", required=True)
    fragment.set_defaults(handler=browser_fragment)
    final = subparsers.add_parser("final")
    final.add_argument("--fragment", required=True)
    final.add_argument("--fragments-dir", required=True)
    final.add_argument("--commit", required=True)
    final.add_argument("--output", required=True)
    final.set_defaults(handler=final_artifact)
    test = subparsers.add_parser("test-fragment")
    test.add_argument("--commit", required=True)
    test.add_argument("--run-id", required=True)
    test.add_argument("--job", required=True)
    test.add_argument("--test", required=True)
    test.add_argument("--result", default="blocked")
    test.add_argument("--runner-os", required=True)
    test.add_argument("--production-mode", choices=("true", "false"), default="true")
    test.add_argument("--output", required=True)
    test.set_defaults(handler=test_fragment)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
