"""Evidence-bound platform sandbox capability cache."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CapabilityEvidence:
    """System and TCB identity to which a capability probe is bound."""

    boot_id: str
    uid: int
    mount_namespace_inode: int | None
    user_namespace_inode: int | None
    binary_device: int
    binary_inode: int
    binary_digest: str
    cgroup_root_device: int | None
    cgroup_root_inode: int | None
    probe_timestamp: float

    @property
    def identity(self) -> tuple[object, ...]:
        """Stable evidence fields; timestamp is freshness metadata only."""
        return (
            self.boot_id,
            self.uid,
            self.mount_namespace_inode,
            self.user_namespace_inode,
            self.binary_device,
            self.binary_inode,
            self.binary_digest,
            self.cgroup_root_device,
            self.cgroup_root_inode,
        )


@dataclass(frozen=True)
class BackendAvailability:
    name: str
    available: bool
    network_enforced: bool
    reason: str = ""
    evidence: CapabilityEvidence | None = None


@dataclass(frozen=True)
class _CapabilityCacheEntry:
    availability: BackendAvailability
    evidence: CapabilityEvidence


_CAPABILITY_CACHE_TTL_SECONDS = 60.0


def _cached_availability(
    entry: _CapabilityCacheEntry | None,
    current: CapabilityEvidence,
) -> BackendAvailability | None:
    if entry is None or entry.evidence.identity != current.identity:
        return None
    if time.time() - entry.evidence.probe_timestamp > _CAPABILITY_CACHE_TTL_SECONDS:
        return None
    return entry.availability


def _capability_evidence(
    binaries: tuple[Path, ...],
    *,
    cgroup_root: Path | None = None,
) -> CapabilityEvidence:
    if not binaries:
        raise RuntimeError("capability evidence requires a TCB binary")
    digest = hashlib.sha256()
    primary = binaries[0].resolve(strict=True)
    primary_stat = primary.stat()
    for binary in binaries:
        canonical = binary.resolve(strict=True)
        metadata = canonical.stat()
        digest.update(str(canonical).encode("utf-8"))
        digest.update(metadata.st_dev.to_bytes(8, "big", signed=False))
        digest.update(metadata.st_ino.to_bytes(8, "big", signed=False))
        with canonical.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    boot_id_path = Path("/proc/sys/kernel/random/boot_id")
    if boot_id_path.is_file():
        boot_id = boot_id_path.read_text(encoding="ascii").strip()
    elif sys.platform == "darwin":
        boot = subprocess.run(
            ("/usr/sbin/sysctl", "-n", "kern.boottime"),
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        boot_id = boot.stdout.strip()
    else:
        boot_id = "unsupported"
    cgroup_device: int | None = None
    cgroup_inode: int | None = None
    if cgroup_root is not None:
        cgroup_stat = cgroup_root.resolve(strict=True).stat()
        cgroup_device = cgroup_stat.st_dev
        cgroup_inode = cgroup_stat.st_ino
    return CapabilityEvidence(
        boot_id=boot_id,
        uid=os.getuid() if hasattr(os, "getuid") else -1,
        mount_namespace_inode=_namespace_inode("/proc/self/ns/mnt"),
        user_namespace_inode=_namespace_inode("/proc/self/ns/user"),
        binary_device=primary_stat.st_dev,
        binary_inode=primary_stat.st_ino,
        binary_digest=digest.hexdigest(),
        cgroup_root_device=cgroup_device,
        cgroup_root_inode=cgroup_inode,
        probe_timestamp=time.time(),
    )


def _namespace_inode(path: str) -> int | None:
    try:
        return Path(path).stat().st_ino
    except OSError:
        return None

