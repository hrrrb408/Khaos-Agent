# KHAOS-PRIVILEGED-SPAWN owner=EvidenceProvenanceFetcher threat-model=untrusted-gh-cli-output boundary=evidence-provenance-lookup
"""GitHub-API provenance fetchers for closure evidence re-verification.

The closure builder must not trust a local ``VERIFIED`` bundle: every
manifest is re-resolved through the GitHub Actions API (via the ``gh``
CLI, mirroring ``scripts/fetch_security_evidence.py``) before a CLOSED
claim is possible.  Any HTTP error, missing object, or digest mismatch
fails closed.
"""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable


class EvidenceProvenanceError(RuntimeError):
    """A GitHub API lookup for evidence provenance failed."""


_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _qualified_api_endpoint(repository: str, endpoint: str) -> str:
    """Bind one GitHub API endpoint to the requested repository.

    The bundled ``gh`` CLI accepts the endpoint as its first positional
    argument and does not expose the newer ``--repo`` flag.  Qualifying the
    endpoint itself keeps the repository binding explicit for both JSON and
    artifact requests without relying on ambient repository state.
    """
    if not _REPOSITORY_RE.fullmatch(repository):
        raise EvidenceProvenanceError("GitHub repository must be owner/name")
    if not endpoint or endpoint.startswith("-"):
        raise EvidenceProvenanceError("GitHub API endpoint is required")
    return f"repos/{repository}/{endpoint.lstrip('/')}"


def _kill_process_domain(process: subprocess.Popen[bytes]) -> None:
    """Terminate the CLI and its owned process group before pipe teardown."""
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _bounded_process(
    argv: list[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[bytes, bytes]:
    """Run one untrusted CLI with bounded output and a hard deadline."""
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise ValueError("process limits must be positive")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name != "nt"),
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            ),
        )
    except OSError as exc:
        raise EvidenceProvenanceError(f"cannot start {' '.join(argv[:2])}: {exc}") from exc
    events: queue.Queue[tuple[str, bytes]] = queue.Queue(maxsize=8)
    stop_readers = threading.Event()

    def drain(stream_name: str, stream) -> None:
        def enqueue(chunk: bytes) -> None:
            while not stop_readers.is_set():
                try:
                    events.put((stream_name, chunk), timeout=0.1)
                    return
                except queue.Full:
                    continue

        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                enqueue(chunk)
                if stop_readers.is_set():
                    return
        finally:
            enqueue(b"")

    threads = [
        threading.Thread(
            target=drain,
            args=(name, stream),
            daemon=True,
            name=f"khaos-evidence-{name}",
        )
        for name, stream in (
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        )
        if stream is not None
    ]
    for thread in threads:
        thread.start()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    finished: set[str] = set()
    deadline = time.monotonic() + timeout_seconds
    failure: EvidenceProvenanceError | None = None
    try:
        while len(finished) < len(threads):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = EvidenceProvenanceError("gh api timed out")
                break
            try:
                stream_name, chunk = events.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                continue
            if not chunk:
                finished.add(stream_name)
                continue
            buffer = buffers[stream_name]
            if len(buffer) + len(chunk) > max_output_bytes:
                failure = EvidenceProvenanceError(
                    f"gh api {stream_name} output exceeds the limit"
                )
                break
            if sum(len(value) for value in buffers.values()) + len(chunk) > max_output_bytes:
                failure = EvidenceProvenanceError("gh api combined output exceeds the limit")
                break
            buffer.extend(chunk)
    finally:
        stop_readers.set()
        if failure is not None or process.poll() is None:
            _kill_process_domain(process)
        try:
            return_code = process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            _kill_process_domain(process)
            return_code = process.wait(timeout=2.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in threads:
            thread.join(timeout=1.0)
    if failure is not None:
        raise failure
    if return_code != 0:
        detail = bytes(buffers["stderr"]).decode("utf-8", errors="replace").strip()
        raise EvidenceProvenanceError(
            f"gh api {' '.join(argv[3:])} failed ({return_code}): {detail[:400]}"
        )
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def gh_api_bytes(
    repository: str,
    *args: str,
    timeout_seconds: float = 30.0,
    max_output_bytes: int = 8 * 1024 * 1024,
) -> bytes:
    """Fetch bounded raw bytes from GitHub through the ``gh`` CLI."""
    if not args:
        raise EvidenceProvenanceError("GitHub API endpoint is required")
    endpoint = _qualified_api_endpoint(repository, args[0])
    stdout, _ = _bounded_process(
        ["gh", "api", endpoint, *args[1:]],
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    return stdout


def gh_fetch_json(repository: str) -> Callable[[str], object]:
    """Return a ``fetch_json(api_path)`` closure backed by ``gh api``."""

    def fetch_json(path: str) -> object:
        try:
            return json.loads(gh_api_bytes(repository, path).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceProvenanceError("gh api returned malformed JSON") from exc

    return fetch_json


def gh_fetch_artifact(repository: str) -> Callable[[str], bytes]:
    """Return a ``fetch_artifact(artifact_id)`` closure backed by ``gh api``.

    The artifact zip is downloaded and streamed through memory once; its
    SHA256 is what the caller compares, so the transfer must be the exact
    artifact bytes.
    """

    def fetch_artifact(artifact_id: str) -> bytes:
        if not artifact_id.isdigit():
            raise EvidenceProvenanceError("artifact id must be numeric")
        return gh_api_bytes(
            repository,
            f"actions/artifacts/{artifact_id}/zip",
            timeout_seconds=60.0,
            max_output_bytes=64 * 1024 * 1024,
        )

    return fetch_artifact


__all__ = [
    "EvidenceProvenanceError",
    "gh_api_bytes",
    "gh_fetch_artifact",
    "gh_fetch_json",
]
