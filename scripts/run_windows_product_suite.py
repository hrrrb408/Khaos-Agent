"""Run the applicable Windows product suite in isolated pytest processes.

The Windows job intentionally executes every test selected by its marker
expression.  It is split into deterministic shards only to give each shard a
fresh asyncio/Winsock/process state and to prevent one leaked native resource
from starving the rest of the product suite.  This is not a coverage filter:
the parent collection is the source of truth and every collected node id is
assigned to exactly one child process.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

DEFAULT_MARKER = (
    "not browser_real and not docker_sandbox_real and "
    "not production_sandbox_real and not kernel_real and "
    "not platform_sandbox_real and not posix_host"
)
TEST_ROOT = "python/tests/"


class _CollectionCapture:
    """Capture the final marker-filtered collection without running tests."""

    def __init__(self) -> None:
        self.nodeids: tuple[str, ...] = ()

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.nodeids = tuple(item.nodeid for item in session.items)


class _ShardSelection:
    """Keep exactly one manifest's node ids in a child pytest process."""

    def __init__(self, nodeids: set[str]) -> None:
        self.nodeids = nodeids

    def pytest_collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]) -> None:
        selected = [item for item in items if item.nodeid in self.nodeids]
        deselected = [item for item in items if item.nodeid not in self.nodeids]
        items[:] = selected
        if deselected:
            config.hook.pytest_deselected(items=deselected)


def _collect(marker: str) -> tuple[str, ...]:
    capture = _CollectionCapture()
    exit_code = pytest.main(
        [TEST_ROOT, "-m", marker, "--collect-only", "-q", "--disable-warnings"],
        plugins=[capture],
    )
    if exit_code != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {int(exit_code)}")
    return capture.nodeids


def _manifest_path(directory: Path, index: int, nodeids: list[str]) -> Path:
    path = directory / f"shard-{index}.txt"
    path.write_text("\n".join(nodeids) + "\n", encoding="utf-8")
    return path


def _run_shard(manifest: Path, marker: str) -> int:
    nodeids = {
        line.strip() for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if not nodeids:
        print(f"Windows product shard {manifest.name} is empty", flush=True)
        return 0
    print(
        f"Windows product shard {manifest.name}: {len(nodeids)} test node(s)",
        flush=True,
    )
    return int(
        pytest.main(
            [TEST_ROOT, "-vv", "-m", marker],
            plugins=[_ShardSelection(nodeids)],
        )
    )


def _run_parent(shards: int, marker: str) -> int:
    nodeids = _collect(marker)
    if not nodeids:
        raise RuntimeError("Windows product suite collected no applicable tests")
    buckets: list[list[str]] = [[] for _ in range(shards)]
    # Stable hashing keeps the same node in the same shard across retries,
    # while distributing parametrized and directory-grouped tests.
    for nodeid in nodeids:
        digest = hashlib.sha256(nodeid.encode("utf-8")).digest()
        buckets[int.from_bytes(digest[:4], "big") % shards].append(nodeid)

    print(
        f"Windows product suite: {len(nodeids)} applicable test node(s) "
        f"across {shards} isolated shard(s)",
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="khaos-windows-suite-") as raw_directory:
        directory = Path(raw_directory)
        manifests = [
            _manifest_path(directory, index, sorted(bucket))
            for index, bucket in enumerate(buckets, 1)
        ]
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        processes: list[tuple[int, subprocess.Popen[bytes]]] = []
        for index, manifest in enumerate(manifests, 1):
            print(
                f"Starting Windows product shard {index}/{shards} "
                f"({len(buckets[index - 1])} node(s))",
                flush=True,
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--run-shard",
                    str(manifest),
                    "--marker",
                    marker,
                ],
                env=environment,
            )
            processes.append((index, process))

        results: list[tuple[int, int]] = []
        for index, process in processes:
            results.append((index, process.wait()))
        failures = [(index, code) for index, code in results if code != 0]
        if failures:
            print(f"Windows product shards failed: {failures}", flush=True)
            return 1
    print("Windows product suite: all isolated shards passed", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    parser.add_argument("--run-shard", type=Path)
    args = parser.parse_args(argv)
    if args.run_shard is not None:
        return _run_shard(args.run_shard, args.marker)
    if args.shards < 1 or args.shards > 8:
        parser.error("--shards must be between 1 and 8")
    return _run_parent(args.shards, args.marker)


if __name__ == "__main__":
    raise SystemExit(main())
