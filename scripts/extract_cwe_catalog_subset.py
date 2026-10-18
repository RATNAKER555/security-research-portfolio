#!/usr/bin/env python3
"""Extract the CWE entries used by the public ledger from the pinned MITRE catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "public" / "data" / "findings.json"
DEFAULT_OUTPUT = ROOT / "vendor" / "cwe" / "cwe-4.20-subset.json"
CATALOG_VERSION = "4.20"
CATALOG_DATE = "2026-04-30"
CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
CATALOG_SHA256 = "3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50"
NAMESPACE = {"cwe": "http://cwe.mitre.org/cwe-7"}


def fail(message: str) -> None:
    raise SystemExit(f"CWE EXTRACTION FAILED: {message}")


def mapped_ids() -> set[str]:
    payload = json.loads(FINDINGS.read_text(encoding="utf-8"))
    identifiers: set[str] = set()
    for entry in payload["publicEntries"]:
        mapping = entry.get("weakness", {})
        if mapping.get("status") != "mapped":
            continue
        identifiers.add(mapping["primary"]["id"])
        identifiers.update(item["id"] for item in mapping["consequences"])
    return identifiers


def extract(archive: Path) -> dict[str, object]:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != CATALOG_SHA256:
        fail(f"archive SHA-256 is {digest}; expected {CATALOG_SHA256}")

    with ZipFile(archive) as bundle:
        members = bundle.namelist()
        if members != [f"cwec_v{CATALOG_VERSION}.xml"]:
            fail(f"unexpected archive members: {members}")
        root = ET.fromstring(bundle.read(members[0]))

    if root.attrib.get("Version") != CATALOG_VERSION:
        fail(f"catalog version is {root.attrib.get('Version')!r}")
    if root.attrib.get("Date") != CATALOG_DATE:
        fail(f"catalog date is {root.attrib.get('Date')!r}")

    wanted = mapped_ids()
    selected: dict[str, dict[str, str]] = {}
    for weakness in root.findall("./cwe:Weaknesses/cwe:Weakness", NAMESPACE):
        identifier = f"CWE-{weakness.attrib['ID']}"
        if identifier not in wanted:
            continue
        usage = weakness.find("cwe:Mapping_Notes/cwe:Usage", NAMESPACE)
        if usage is None or not usage.text:
            fail(f"{identifier} has no mapping-usage value")
        selected[identifier] = {
            "name": weakness.attrib["Name"],
            "abstraction": weakness.attrib["Abstraction"],
            "status": weakness.attrib["Status"],
            "mappingUsage": usage.text,
        }

    missing = wanted - set(selected)
    if missing:
        fail(f"catalog does not contain mapped IDs: {sorted(missing)}")

    return {
        "catalog": {
            "name": root.attrib["Name"],
            "version": root.attrib["Version"],
            "published": root.attrib["Date"],
            "source": CATALOG_URL,
            "archiveSha256": CATALOG_SHA256,
        },
        "weaknesses": dict(sorted(selected.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="path to cwec_v4.20.xml.zip")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = extract(args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"PASS: extracted {len(payload['weaknesses'])} mapped entries "
        f"from CWE {CATALOG_VERSION} to {args.output}"
    )


if __name__ == "__main__":
    main()
