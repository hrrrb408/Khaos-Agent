"""Fail-closed tests for the machine-generated production import graph."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "generate_production_reachability.py"


def _reachability_module():
    spec = importlib.util.spec_from_file_location("khaos_production_reachability", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_production_graph_has_no_unresolved_or_forbidden_edges():
    module = _reachability_module()
    modules, edges, unresolved = module.build_graph()

    assert modules
    assert not unresolved
    assert not module.forbidden_edges(modules, edges)
    assert "khaos.coding.execution.host" not in modules
    assert "khaos.coding.verification.pipeline" not in modules


def test_generated_inventory_is_fresh_and_fail_closed():
    module = _reachability_module()
    modules, edges, unresolved = module.build_graph()
    assert not unresolved
    assert not module.forbidden_edges(modules, edges)
    assert module.OUTPUT.read_text(encoding="utf-8") == module.render()


def test_forbidden_module_is_rejected_even_when_seen_as_an_edge():
    module = _reachability_module()
    edge = module.Edge(
        source="khaos.runtime.factory",
        target="khaos.coding.execution.host",
        symbol="HostExecutionBackend",
        line=1,
    )
    findings = module.forbidden_edges({"khaos.coding.execution.host"}, (edge,))
    assert findings


def test_testing_composition_and_mock_authority_are_forbidden_edges():
    module = _reachability_module()
    edges = (
        module.Edge(
            source="khaos.runtime.factory",
            target="khaos.runtime.testing",
            symbol="TestingRuntimeComposition",
            line=2,
        ),
        module.Edge(
            source="khaos.runtime.factory",
            target="khaos.security.mock_authority",
            symbol="MockAuthority",
            line=3,
        ),
        module.Edge(
            source="khaos.runtime.factory",
            target="khaos.coding.execution.testing_sandbox",
            symbol="TestingSandbox",
            line=4,
        ),
        module.Edge(
            source="khaos.runtime.factory",
            target="khaos.coding.execution.host",
            symbol="HostBackend",
            line=5,
        ),
    )

    findings = module.forbidden_edges(
        {
            "khaos.runtime.testing",
            "khaos.security.mock_authority",
            "khaos.coding.execution.testing_sandbox",
            "khaos.coding.execution.host",
        },
        edges,
    )
    assert len(findings) == 8
