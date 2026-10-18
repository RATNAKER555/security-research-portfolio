#!/usr/bin/env python3
"""Create a local-only dashboard containing the ignored report ledger."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
PRIVATE_DATA = ROOT / "private" / "report-tracker.json"
OUTPUT = ROOT / "dist-private"


def main() -> None:
    for validator in (
        "validate_public_data.py",
        "validate_public_tracker.py",
        "validate_private_tracker.py",
    ):
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / validator)],
            cwd=ROOT,
            check=True,
        )
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    shutil.copytree(PUBLIC, OUTPUT)
    target = OUTPUT / "data" / "private-tracker.json"
    shutil.copy2(PRIVATE_DATA, target)
    index = OUTPUT / "index.html"
    source = index.read_text(encoding="utf-8")
    marker = '<body data-private-tracker="">'
    if source.count(marker) != 1:
        raise SystemExit("PRIVATE BUILD FAILED: body marker is missing or ambiguous")
    index.write_text(
        source.replace(marker, '<body data-private-tracker="data/private-tracker.json">'),
        encoding="utf-8",
    )
    print(f"PASS: local private dashboard written to {OUTPUT}")


if __name__ == "__main__":
    main()
