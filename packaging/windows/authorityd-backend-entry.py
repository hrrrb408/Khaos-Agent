"""Run the authority backend from its staged, authority-owned site tree.

The native Windows service host starts this file with ``python -I -S``.  The
entry point deliberately adds only the sibling site tree that the installer
staged; it never consumes an inherited import path, the current working
directory, or user site packages.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    """Load the staged Khaos package and transfer control to the daemon."""
    site_root = Path(__file__).resolve().parent / "backend-site"
    package_root = site_root / "khaos"
    if not site_root.is_dir() or not package_root.is_dir():
        raise SystemExit("authority backend site tree is unavailable")
    sys.path.insert(0, str(site_root))
    runpy.run_module("khaos.security.authorityd_main", run_name="__main__")


if __name__ == "__main__":
    main()
