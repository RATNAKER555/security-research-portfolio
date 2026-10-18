#!/usr/bin/env python3
"""Validate the ignored local report ledger and its public aggregate counts."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import date
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT / "private" / "report-tracker.json"
FINDINGS = ROOT / "public" / "data" / "findings.json"
STATES = {
    "reported",
    "patch-review",
    "fix-queued",
    "fixed-upstream",
    "ready-to-report",
    "held",
    "duplicate",
}
VISIBILITIES = {"embargoed", "private", "public"}


def fail(message: str) -> None:
    raise SystemExit(f"PRIVATE TRACKER INVALID: {message}")


def load(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(payload, dict):
        fail(f"{path} must contain an object")
    return payload


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def require_date(value: object, label: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    raw = require_string(value, label)
    try:
        date.fromisoformat(raw)
    except ValueError:
        fail(f"{label} must use YYYY-MM-DD")
    return raw


def require_public_url(value: object, label: str, nullable: bool) -> str | None:
    if value is None and nullable:
        return None
    raw = require_string(value, label)
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"{label} must be a credential-free HTTPS URL")
    return raw


def validate_ignored() -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", str(TRACKER.relative_to(ROOT))],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        fail("private/report-tracker.json is not covered by .gitignore")
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(TRACKER.relative_to(ROOT))],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode == 0:
        fail("private/report-tracker.json is tracked by git")


def main() -> None:
    validate_ignored()
    data = load(TRACKER)
    findings = load(FINDINGS)
    if set(data) != {"schemaVersion", "updated", "counts", "records"}:
        fail("top-level fields must be schemaVersion, updated, counts, and records")
    if data["schemaVersion"] != 1:
        fail("unsupported schema version")
    require_date(data["updated"], "updated")
    if not isinstance(data["counts"], dict) or set(data["counts"]) != {
        "underCoordination",
        "researchQueue",
    }:
        fail("counts must contain underCoordination and researchQueue")
    for key, value in data["counts"].items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            fail(f"counts.{key} must be a non-negative integer")

    required = {
        "id",
        "project",
        "title",
        "visibility",
        "state",
        "reportedOn",
        "lastActivityOn",
        "followUpOn",
        "nextAction",
        "publicUrl",
        "source",
    }
    records = data["records"]
    if not isinstance(records, list) or not records:
        fail("records must be a non-empty list")
    seen: set[str] = set()
    for index, record in enumerate(records):
        label = f"records[{index}]"
        if not isinstance(record, dict) or set(record) != required:
            fail(f"{label} must contain exactly {sorted(required)}")
        identifier = require_string(record["id"], f"{label}.id")
        if identifier in seen:
            fail(f"duplicate record id {identifier}")
        seen.add(identifier)
        for field in ("project", "title", "nextAction", "source"):
            require_string(record[field], f"{identifier}.{field}")
        if record["visibility"] not in VISIBILITIES:
            fail(f"{identifier}.visibility is unsupported")
        if record["state"] not in STATES:
            fail(f"{identifier}.state is unsupported")
        require_date(record["reportedOn"], f"{identifier}.reportedOn", nullable=True)
        require_date(record["lastActivityOn"], f"{identifier}.lastActivityOn")
        require_date(record["followUpOn"], f"{identifier}.followUpOn", nullable=True)
        require_public_url(
            record["publicUrl"],
            f"{identifier}.publicUrl",
            nullable=record["visibility"] != "public",
        )
        if record["state"] == "reported" and record["reportedOn"] is None:
            fail(f"{identifier}: reported records need a report date")

    reported = sum(record["state"] == "reported" for record in records)
    queued = sum(record["state"] in {"held", "ready-to-report"} for record in records)
    if reported != data["counts"]["underCoordination"]:
        fail(
            f"underCoordination is {data['counts']['underCoordination']}; "
            f"the ledger contains {reported} reported records"
        )
    if queued != data["counts"]["researchQueue"]:
        fail(
            f"researchQueue is {data['counts']['researchQueue']}; "
            f"the ledger contains {queued} held or ready-to-report records"
        )

    aggregates = {entry["status"]: entry["count"] for entry in findings["privateEntries"]}
    if aggregates.get("under-coordination") != data["counts"]["underCoordination"]:
        fail("public under-coordination count differs from the private ledger")
    if aggregates.get("queued") != data["counts"]["researchQueue"]:
        fail("public research-queue count differs from the private ledger")

    public_ids = {entry["recordId"] for entry in findings["publicEntries"]}
    local_public_ids = {
        record["id"] for record in records if record["visibility"] == "public"
    }
    if not public_ids.issubset(local_public_ids):
        fail(f"local tracker is missing public records {sorted(public_ids - local_public_ids)}")
    print(
        "PASS: private tracker contains "
        f"{len(records)} records, {reported} active reports, and "
        f"{len(local_public_ids)} public records"
    )


if __name__ == "__main__":
    main()
