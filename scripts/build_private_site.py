#!/usr/bin/env python3
"""Create an access-controlled dashboard containing the private report ledger."""

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
    replacements = {
        marker: '<body data-private-tracker="data/private-tracker.json">',
        "<title>Ratnaker Gautam · Security Research</title>":
            "<title>Ratnaker Gautam · Private Research Operations</title>",
        '<p class="eyebrow">Local build only</p>':
            '<p class="eyebrow">Authenticated research dashboard</p>',
        "This view is generated from the ignored local tracker. It is never copied into the GitLab Pages artifact.":
            "This operational ledger is available only through the access-controlled KU Leuven GitLab Pages deployment.",
    }
    for original, replacement in replacements.items():
        if source.count(original) != 1:
            raise SystemExit(
                "PRIVATE BUILD FAILED: expected exactly one private-view marker: "
                + original
            )
        source = source.replace(original, replacement)
    index.write_text(source, encoding="utf-8")
    (OUTPUT / "robots.txt").write_text(
        "User-agent: *\nDisallow: /\n", encoding="utf-8"
    )
    print(f"PASS: local private dashboard written to {OUTPUT}")


if __name__ == "__main__":
    main()
