#!/usr/bin/env python3
"""Run the full native authority transaction E2E.

Unlike ``run_native_authority_identity_probe.py`` (which proves only the
transport identity chain), this script proves a complete authority
transaction through the native transport on the deployed backend:

  grant -> prepare -> claim -> execute bounded test effect -> complete(success)

plus the fail-closed negative paths:

  grant -> revoke -> subsequent prepare rejected
  prepare -> claim -> complete -> replayed claim rejected
  prepare -> revoke -> validate rejected
  (--expect-unavailable) backend absent -> UNKNOWN, never SUCCESS

The script is a client of the deployed authority; it has no mock mode and
never bypasses the native transport.  Every failure exits non-zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

from khaos.security.authority_context import AuthorityContextV1
from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    AuthorityDaemonClient,
    AuthorizationIntent,
    RemoteAuditUnavailableError,
    UnknownExecutionError,
)
from khaos.security.identity_isolation import read_contract_from_environment
from khaos.security.native_authority import build_native_authority_adapter
from khaos.security.principals import transport_root_delegation_digest
from khaos.security.resource_scope import ExecutionScope, TypedResourcePartialOrder

E2E_WORKSPACE = "native-e2e-workspace"
E2E_OPERATION = "exec.native-e2e"
E2E_EXECUTABLE = "/bin/echo"
E2E_ARGV = ("khaos-native-e2e",)
E2E_CWD = "/"
E2E_PRINCIPAL_ID = "native-e2e"
E2E_PRINCIPAL_KIND = "human"
E2E_PARENT_PRINCIPAL_ID = "human:native-e2e"
E2E_PROJECT_ID = "native-e2e"
E2E_SESSION_ID = "native-e2e-session"
E2E_SOURCE_TRANSPORT = "cli"


def e2e_execution_scope() -> ExecutionScope:
    """The single bounded effect this E2E is authorized to describe."""
    return ExecutionScope(
        workspace_id=E2E_WORKSPACE,
        executable=E2E_EXECUTABLE,
        argv_prefix=E2E_ARGV,
        cwd=E2E_CWD,
        operations=frozenset({"native-e2e"}),
        argv_exact=True,
    )


def e2e_resource_catalog(policy_digest: str) -> TypedResourcePartialOrder:
    """Build the canonical one-scope catalog consumed by the native E2E."""
    scope = e2e_execution_scope()
    return TypedResourcePartialOrder(
        {scope.digest(): scope},
        policy_digest=policy_digest,
    )


def write_e2e_catalog(output: Path, policy_digest: str) -> TypedResourcePartialOrder:
    """Write an immutable canonical catalog without platform JSON re-encoding."""
    catalog = e2e_resource_catalog(policy_digest)
    output = output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise SystemExit(f"refusing to overwrite existing catalog: {output}")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            catalog.manifest(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    output.chmod(0o444)
    return catalog


def _build_client() -> AuthorityDaemonClient:
    contract = read_contract_from_environment()
    adapter = build_native_authority_adapter(production=True, contract=contract)
    return AuthorityDaemonClient(
        expected_authority_uid=contract.authority_uid,
        native_adapter=adapter,
    )


def _delegation_digest(runtime_id: str, policy_digest: str) -> str:
    """Return the canonical identity commitment used by the native E2E."""
    return transport_root_delegation_digest(
        principal_id=E2E_PRINCIPAL_ID,
        principal_kind=E2E_PRINCIPAL_KIND,
        parent_principal_id=E2E_PARENT_PRINCIPAL_ID,
        project_id=E2E_PROJECT_ID,
        session_id=E2E_SESSION_ID,
        runtime_id=runtime_id,
        source_transport=E2E_SOURCE_TRANSPORT,
        policy_digest=policy_digest,
    )


def _context_digest(runtime_id: str, task_id: str, policy_digest: str) -> str:
    """Return the exact grant context digest sent back in prepare."""
    return AuthorityContextV1(
        principal_id=E2E_PRINCIPAL_ID,
        principal_kind=E2E_PRINCIPAL_KIND,
        parent_principal_id=E2E_PARENT_PRINCIPAL_ID,
        project_id=E2E_PROJECT_ID,
        session_id=E2E_SESSION_ID,
        runtime_id=runtime_id,
        source_transport=E2E_SOURCE_TRANSPORT,
        task_id=task_id,
        workspace_id=E2E_WORKSPACE,
        workspace_generation=1,
        policy_digest=policy_digest,
        authorization_epoch=0,
        delegation_digest=_delegation_digest(runtime_id, policy_digest),
    ).digest()


def _intent(
    nonce: str,
    policy_digest: str,
    grant_id: str | None,
    *,
    runtime_id: str,
    task_id: str,
) -> AuthorizationIntent:
    return AuthorizationIntent(
        principal_id=E2E_PRINCIPAL_ID,
        project_id=E2E_PROJECT_ID,
        runtime_id=runtime_id,
        task_id=task_id,
        workspace_id=E2E_WORKSPACE,
        operation=E2E_OPERATION,
        resource_digest=e2e_execution_scope().digest(),
        policy_digest=policy_digest,
        nonce=nonce,
        authorization_epoch=0,
        workspace_generation=1,
        grant_id=grant_id,
        grant_context_digest=(
            _context_digest(runtime_id, task_id, policy_digest)
            if grant_id is not None
            else None
        ),
        principal_kind=E2E_PRINCIPAL_KIND,
        parent_principal_id=E2E_PARENT_PRINCIPAL_ID,
        session_id=E2E_SESSION_ID,
        delegation_digest=_delegation_digest(runtime_id, policy_digest),
        source_transport=E2E_SOURCE_TRANSPORT,
    )


def _grant(
    client: AuthorityDaemonClient,
    *,
    policy_digest: str,
    runtime_id: str,
    task_id: str,
) -> tuple[str, float]:
    """Issue a grant and bind every later intent to its exact owner context."""
    return client.grant(
        principal_id=E2E_PRINCIPAL_ID,
        project_id=E2E_PROJECT_ID,
        runtime_id=runtime_id,
        task_id=task_id,
        workspace_id=E2E_WORKSPACE,
        workspace_generation=1,
        policy_digest=policy_digest,
        operation_class=E2E_OPERATION,
        resource_digest=e2e_execution_scope().digest(),
        authorization_epoch=0,
        principal_kind=E2E_PRINCIPAL_KIND,
        parent_principal_id=E2E_PARENT_PRINCIPAL_ID,
        session_id=E2E_SESSION_ID,
        delegation_digest=_delegation_digest(runtime_id, policy_digest),
        source_transport=E2E_SOURCE_TRANSPORT,
    )


def _require(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        print(f"native authority E2E requires {name}", file=sys.stderr)
        raise SystemExit(78)
    return value


def _expect_rejected(call, label: str) -> dict[str, str]:
    try:
        call()
    except (AuthorityControlPlaneError, UnknownExecutionError) as exc:
        return {"scenario": label, "rejected": True, "error": str(exc)[:256]}
    print(
        f"native authority E2E FAILED: {label} was accepted (fail-open)",
        file=sys.stderr,
    )
    raise SystemExit(1)


def run_e2e(*, expect_unavailable: bool) -> dict[str, object]:
    policy_digest = _require("KHAOS_EFFECTIVE_POLICY_DIGEST")
    evidence: dict[str, object] = {
        "schema_version": 1,
        "proof_type": "native-authority-full-transaction",
        "platform": sys.platform,
        "github_sha": os.environ.get("GITHUB_SHA", ""),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "policy_digest": policy_digest,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenarios": [],
    }
    client = _build_client()

    if expect_unavailable:
        # The backend is deliberately absent.  The only acceptable result is
        # an explicit unavailable/UNKNOWN error; success would be fail-open.
        try:
            _grant(
                client,
                policy_digest=policy_digest,
                runtime_id="e2e-unavailable",
                task_id="e2e-unavailable",
            )
        except (RemoteAuditUnavailableError, AuthorityControlPlaneError) as exc:
            evidence["scenarios"].append(
                {
                    "scenario": "backend-unavailable",
                    "outcome": "UNKNOWN",
                    "error": str(exc)[:256],
                }
            )
            return evidence
        print(
            "native authority E2E FAILED: request succeeded with no backend",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Scenario 1: full transaction with a bounded test effect.
    grant_id, _expires = _grant(
        client,
        policy_digest=policy_digest,
        runtime_id="e2e-runtime",
        task_id="e2e-task",
    )
    receipt = client.prepare(
        _intent(
            uuid.uuid4().hex,
            policy_digest,
            grant_id,
            runtime_id="e2e-runtime",
            task_id="e2e-task",
        )
    )
    client.claim(receipt)
    effect_root = Path(
        os.environ.get("KHAOS_NATIVE_E2E_EFFECT_ROOT") or tempfile.mkdtemp(
            prefix="khaos-native-e2e-"
        )
    )
    effect_path = effect_root / f"effect-{receipt.nonce}.bin"
    payload = f"khaos-native-e2e:{receipt.nonce}".encode()
    if len(payload) > 64:
        raise SystemExit("native authority E2E effect payload exceeded its bound")
    effect_path.write_bytes(payload)
    result_digest = hashlib.sha256(payload).hexdigest()
    client.complete(receipt, result="success", result_digest=result_digest)
    evidence["scenarios"].append(
        {
            "scenario": "grant-prepare-claim-effect-complete",
            "outcome": "SUCCESS",
            "grant_id": grant_id,
            "receipt_nonce": receipt.nonce,
            "result_digest": result_digest,
        }
    )

    # Scenario 2: revoked grant invalidates subsequent prepares.
    revoked_grant, _ = _grant(
        client,
        policy_digest=policy_digest,
        runtime_id="e2e-runtime",
        task_id="e2e-task-revoke",
    )
    client.revoke_grant(revoked_grant)
    evidence["scenarios"].append(
        _expect_rejected(
            lambda: client.prepare(
                _intent(
                    uuid.uuid4().hex,
                    policy_digest,
                    revoked_grant,
                    runtime_id="e2e-runtime",
                    task_id="e2e-task-revoke",
                )
            ),
            "prepare-after-grant-revoke",
        )
    )

    # Scenario 3: one-shot receipt replay is rejected after completion.
    replay_grant, _ = _grant(
        client,
        policy_digest=policy_digest,
        runtime_id="e2e-runtime",
        task_id="e2e-task-replay",
    )
    replay_receipt = client.prepare(
        _intent(
            uuid.uuid4().hex,
            policy_digest,
            replay_grant,
            runtime_id="e2e-runtime",
            task_id="e2e-task-replay",
        )
    )
    client.claim(replay_receipt)
    client.complete(
        replay_receipt,
        result="success",
        result_digest=hashlib.sha256(b"replay-probe").hexdigest(),
    )
    evidence["scenarios"].append(
        _expect_rejected(
            lambda: client.claim(replay_receipt),
            "claim-replay-after-complete",
        )
    )

    # Scenario 4: revoked receipt no longer validates.
    stale_grant, _ = _grant(
        client,
        policy_digest=policy_digest,
        runtime_id="e2e-runtime",
        task_id="e2e-task-stale",
    )
    stale_receipt = client.prepare(
        _intent(
            uuid.uuid4().hex,
            policy_digest,
            stale_grant,
            runtime_id="e2e-runtime",
            task_id="e2e-task-stale",
        )
    )
    client.revoke(stale_receipt)
    evidence["scenarios"].append(
        _expect_rejected(
            lambda: client.validate(stale_receipt, expected_operation=E2E_OPERATION),
            "validate-after-revoke",
        )
    )
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-unavailable", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--emit-catalog",
        action="store_true",
        help="emit the typed resource catalog entry this E2E requires",
    )
    parser.add_argument(
        "--catalog-output",
        type=Path,
        help="write the canonical typed resource catalog for this E2E",
    )
    args = parser.parse_args(argv)
    if args.emit_catalog and args.catalog_output is not None:
        parser.error("--emit-catalog and --catalog-output are mutually exclusive")
    if args.catalog_output is not None:
        catalog = write_e2e_catalog(
            args.catalog_output,
            _require("KHAOS_EFFECTIVE_POLICY_DIGEST"),
        )
        print(catalog.catalog_digest)
        return 0
    if args.emit_catalog:
        scope = e2e_execution_scope()
        print(
            json.dumps(
                {"digest": scope.digest(), **scope.manifest()},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    evidence = run_e2e(expect_unavailable=args.expect_unavailable)
    rendered = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
