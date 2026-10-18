#!/usr/bin/env python3
"""Validate and create the static deployment tree for Pages hosting."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
DIST = ROOT / "dist"


def main() -> None:
    for validator in ("validate_public_data.py", "validate_public_tracker.py"):
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / validator)],
            cwd=ROOT,
            check=True,
        )
    if DIST.exists():
        shutil.rmtree(DIST)
    shutil.copytree(PUBLIC, DIST)
    print(f"PASS: deployment tree written to {DIST}")


if __name__ == "__main__":
    main()
