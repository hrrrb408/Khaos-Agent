from __future__ import annotations

from pathlib import Path

from khaos.coding.verification.models import DetectedProject


class ProjectDetector:
    """Detect ecosystems using trusted manifests only; never executes scripts."""

    def detect(self, root: Path) -> DetectedProject:
        root = root.expanduser().resolve()
        if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists():
            return DetectedProject(root, "python", (), 1.0, ("pyproject.toml/pytest.ini",))
        if (root / "package.json").exists():
            return DetectedProject(root, "node", (), 1.0, ("package.json",))
        if (root / "go.mod").exists():
            return DetectedProject(root, "go", (), 1.0, ("go.mod",))
        if (root / "Cargo.toml").exists():
            return DetectedProject(root, "rust", (), 1.0, ("Cargo.toml",))
        return DetectedProject(root, "generic", (), 0.0, ())
