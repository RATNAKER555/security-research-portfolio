#!/usr/bin/env python3
"""Validate the public ledger and fail closed on disclosure or credit mistakes."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "public" / "data" / "findings.json"

PUBLIC_STATUSES = {
    "cve-assigned",
    "publicly-disclosed",
    "engineering-bug",
    "independent-validation",
}
PRIVATE_STATUSES = {"under-coordination", "queued"}
PRIVATE_FIELDS = {
    "id",
    "title",
    "project",
    "status",
    "date",
    "summary",
    "tags",
    "count",
}
PUBLIC_REQUIRED_FIELDS = {
    "id",
    "recordId",
    "title",
    "project",
    "status",
    "date",
    "summary",
    "evidence",
    "credit",
    "tags",
    "links",
}
EVIDENCE_FIELDS = {"primitive", "validation", "boundary"}
SUMMARY_FIELDS = {
    "assignedCves",
    "publicOriginalContributions",
    "underCoordination",
    "validatedDistinctFindings",
    "independentValidations",
    "researchQueue",
    "investigatedPackages",
}

FORBIDDEN_GLOBAL_PATTERNS = [
    re.compile(r"(?:^|[\s\"'])/home/", re.I),
    re.compile(r"file://", re.I),
    re.compile(r"BEGIN (?:OPENSSH )?PRIVATE KEY", re.I),
]
FORBIDDEN_PRIVATE_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d+", re.I),
    re.compile(r"https?://", re.I),
    re.compile(r"\b(?:\.c|\.cc|\.cpp|\.h):\d+\b"),
    re.compile(r"\b(?:commit|bugzilla|reproducer|proof.?of.?concept|PoC)\b", re.I),
    re.compile(r"\b[0-9a-f]{12,64}\b", re.I),
    re.compile(r"\b(?:affected version|root cause|trigger sequence|source line)\b", re.I),
]


def fail(message: str) -> None:
    raise SystemExit(f"PUBLICATION BLOCKED: {message}")


def require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def require_date(value: object, label: str) -> date:
    raw = require_nonempty_string(value, label)
    try:
        return date.fromisoformat(raw)
    except ValueError:
        fail(f"{label} must use YYYY-MM-DD")


def require_https(value: object, label: str) -> str:
    raw = require_nonempty_string(value, label)
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"{label} must be a credential-free HTTPS URL")
    return raw


def require_tags(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty list")
    for index, item in enumerate(value):
        require_nonempty_string(item, f"{label}[{index}]")
    return value


def validate_public_entry(entry: object, index: int, seen: set[str]) -> None:
    if not isinstance(entry, dict):
        fail(f"publicEntries[{index}] is not an object")
    missing = PUBLIC_REQUIRED_FIELDS - set(entry)
    if missing:
        fail(f"publicEntries[{index}] is missing {sorted(missing)}")

    entry_id = require_nonempty_string(entry.get("id"), f"publicEntries[{index}].id")
    if entry_id in seen:
        fail(f"duplicate record id {entry_id}")
    seen.add(entry_id)

    status = entry.get("status")
    if status not in PUBLIC_STATUSES:
        fail(f"{entry_id}: status {status!r} cannot appear in the public ledger")

    require_nonempty_string(entry.get("recordId"), f"{entry_id}.recordId")
    require_nonempty_string(entry.get("title"), f"{entry_id}.title")
    require_nonempty_string(entry.get("project"), f"{entry_id}.project")
    require_nonempty_string(entry.get("summary"), f"{entry_id}.summary")
    require_nonempty_string(entry.get("credit"), f"{entry_id}.credit")
    require_date(entry.get("date"), f"{entry_id}.date")
    require_tags(entry.get("tags"), f"{entry_id}.tags")

    evidence = entry.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
        fail(f"{entry_id}: evidence must contain exactly {sorted(EVIDENCE_FIELDS)}")
    for key in EVIDENCE_FIELDS:
        require_nonempty_string(evidence.get(key), f"{entry_id}.evidence.{key}")

    links = entry.get("links")
    if not isinstance(links, list) or not links:
        fail(f"{entry_id}: every public claim needs at least one public source")
    for link_index, link in enumerate(links):
        if not isinstance(link, dict) or set(link) != {"label", "url"}:
            fail(f"{entry_id}.links[{link_index}] must contain label and url")
        require_nonempty_string(link.get("label"), f"{entry_id}.links[{link_index}].label")
        require_https(link.get("url"), f"{entry_id}.links[{link_index}].url")

    if status == "cve-assigned":
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(entry.get("cve", ""))):
            fail(f"{entry_id}: CVE-assigned records need a valid public CVE identifier")
    elif "cve" in entry:
        fail(f"{entry_id}: a CVE field is allowed only after assignment")

    if status == "independent-validation" and not entry_id.startswith("validation-"):
        fail(f"{entry_id}: validation records need a validation- id")


def validate_private_entry(entry: object, index: int, seen: set[str]) -> None:
    if not isinstance(entry, dict):
        fail(f"privateEntries[{index}] is not an object")
    if set(entry) != PRIVATE_FIELDS:
        fail(
            f"privateEntries[{index}] must contain exactly the aggregate fields "
            f"{sorted(PRIVATE_FIELDS)}"
        )

    entry_id = require_nonempty_string(entry.get("id"), f"privateEntries[{index}].id")
    if entry_id in seen:
        fail(f"duplicate record id {entry_id}")
    seen.add(entry_id)

    status = entry.get("status")
    if status not in PRIVATE_STATUSES:
        fail(f"{entry_id}: private aggregate has unsupported status {status!r}")
    if entry.get("project") not in {"Private", "Multiple projects"}:
        fail(f"{entry_id}: project identity must remain generic")
    require_date(entry.get("date"), f"{entry_id}.date")
    require_nonempty_string(entry.get("title"), f"{entry_id}.title")
    require_nonempty_string(entry.get("summary"), f"{entry_id}.summary")
    require_tags(entry.get("tags"), f"{entry_id}.tags")

    count = entry.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        fail(f"{entry_id}: count must be a non-negative integer")

    rendered = json.dumps(entry, sort_keys=True)
    for pattern in FORBIDDEN_PRIVATE_PATTERNS:
        if pattern.search(rendered):
            fail(f"{entry_id}: aggregate text matches forbidden pattern {pattern.pattern!r}")


def validate_summary(
    summary: object,
    public_entries: list[dict],
    private_entries: list[dict],
) -> None:
    if not isinstance(summary, dict) or set(summary) != SUMMARY_FIELDS:
        fail(f"summary must contain exactly {sorted(SUMMARY_FIELDS)}")
    for key, value in summary.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            fail(f"summary.{key} must be a non-negative integer")

    status_count = lambda wanted: sum(1 for entry in public_entries if entry["status"] in wanted)
    private_count = lambda wanted: sum(
        entry["count"] for entry in private_entries if entry["status"] == wanted
    )
    expected = {
        "assignedCves": status_count({"cve-assigned"}),
        "publicOriginalContributions": status_count(
            {"cve-assigned", "publicly-disclosed", "engineering-bug"}
        ),
        "underCoordination": private_count("under-coordination"),
        "independentValidations": status_count({"independent-validation"}),
        "researchQueue": private_count("queued"),
    }
    expected["validatedDistinctFindings"] = (
        expected["publicOriginalContributions"]
        + expected["underCoordination"]
        + expected["researchQueue"]
    )
    expected["investigatedPackages"] = (
        expected["validatedDistinctFindings"] + expected["independentValidations"]
    )
    for key, value in expected.items():
        if summary.get(key) != value:
            fail(f"summary.{key} is {summary.get(key)!r}; derived value is {value}")


def main() -> None:
    try:
        raw = DATA.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read valid JSON from {DATA}: {error}")

    if not isinstance(payload, dict):
        fail("top-level data must be an object")
    for pattern in FORBIDDEN_GLOBAL_PATTERNS:
        if pattern.search(raw):
            fail(f"dataset contains forbidden local or secret material: {pattern.pattern!r}")

    updated = require_date(payload.get("updated"), "updated")
    profile = payload.get("profile")
    if not isinstance(profile, dict):
        fail("profile must be an object")
    for key in ("name", "role", "affiliation"):
        require_nonempty_string(profile.get(key), f"profile.{key}")
    for key in ("github", "gitlab"):
        require_https(profile.get(key), f"profile.{key}")

    public_entries = payload.get("publicEntries")
    private_entries = payload.get("privateEntries")
    if not isinstance(public_entries, list) or not isinstance(private_entries, list):
        fail("publicEntries and privateEntries must be lists")

    seen: set[str] = set()
    for index, entry in enumerate(public_entries):
        validate_public_entry(entry, index, seen)
        if require_date(entry["date"], f"{entry['id']}.date") > updated:
            fail(f"{entry['id']}: record date is later than dataset update date")
    for index, entry in enumerate(private_entries):
        validate_private_entry(entry, index, seen)
        if require_date(entry["date"], f"{entry['id']}.date") > updated:
            fail(f"{entry['id']}: record date is later than dataset update date")

    validate_summary(payload.get("summary"), public_entries, private_entries)
    print(
        "PASS: "
        f"{len(public_entries)} public records and {len(private_entries)} redacted aggregates "
        f"validated from {DATA}"
    )


if __name__ == "__main__":
    main()
