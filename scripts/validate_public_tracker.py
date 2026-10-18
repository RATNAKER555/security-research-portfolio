#!/usr/bin/env python3
"""Fail closed when the published workflow tracker crosses its public boundary."""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tracker" / "public-monitor.json"
OUTPUT = ROOT / "public" / "data" / "tracker.json"
FINDINGS = ROOT / "public" / "data" / "findings.json"
PUBLIC_INDEX = ROOT / "public" / "index.html"
FORBIDDEN_PRIVATE_OUTPUT = ROOT / "public" / "data" / "private-tracker.json"

STAGES = {
    "patch-review",
    "public-commit",
    "fix-queued",
    "integration",
    "fixed-upstream",
    "closed",
}
CHECK_STATES = {"verified", "check-error"}
CREDIT_STATES = {"confirmed", "missing", "pending"}
FOLLOW_UP_STATES = {"none", "scheduled", "due-soon", "due", "overdue"}
MONITOR_KINDS = {"github-commit", "forgejo-pull", "gitiles-commit"}
DISCOVERY_KINDS = {"github-log", "forgejo-log", "gitiles-log"}
FORBIDDEN = [
    re.compile(r"(?:^|[\s\"'])/home/", re.I),
    re.compile(r"file://", re.I),
    re.compile(r"BEGIN (?:OPENSSH )?PRIVATE KEY", re.I),
    re.compile(r"(?:private|confidential)[-_ ](?:zip|reproducer|issue)", re.I),
]


def fail(message: str) -> None:
    raise SystemExit(f"PUBLIC TRACKER BLOCKED: {message}")


def load(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")
    if not isinstance(payload, dict):
        fail(f"{path} must contain an object")
    for pattern in FORBIDDEN:
        if pattern.search(raw):
            fail(f"{path} matches forbidden pattern {pattern.pattern!r}")
    return payload


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def require_date(value: object, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    raw = require_string(value, label)
    try:
        date.fromisoformat(raw)
    except ValueError:
        fail(f"{label} must use YYYY-MM-DD")
    return raw


def require_https(value: object, label: str) -> str:
    raw = require_string(value, label)
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        fail(f"{label} must be a credential-free HTTPS URL")
    return raw


def require_sha(value: object, label: str) -> str:
    raw = require_string(value, label)
    if not re.fullmatch(r"[0-9a-f]{40,64}", raw):
        fail(f"{label} must be a full hexadecimal commit ID")
    return raw


def require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        fail(f"{label} must be a list")
    for index, item in enumerate(value):
        require_string(item, f"{label}[{index}]")
    return value


def validate_config(config: dict, public_entries: dict[str, dict]) -> None:
    if set(config) != {
        "schemaVersion",
        "updated",
        "reporter",
        "records",
        "discoverySources",
    }:
        fail("public monitor config has unexpected top-level fields")
    if config["schemaVersion"] != 1:
        fail("unsupported public monitor schema")
    require_date(config["updated"], "config.updated")

    reporter = config["reporter"]
    if not isinstance(reporter, dict) or set(reporter) != {"name", "emails"}:
        fail("config.reporter must contain name and emails")
    require_string(reporter["name"], "config.reporter.name")
    emails = require_string_list(reporter["emails"], "config.reporter.emails")
    if not emails or any("@" not in email for email in emails):
        fail("config.reporter.emails must contain valid-looking addresses")

    records = config["records"]
    if not isinstance(records, list) or not records:
        fail("config.records must be a non-empty list")
    seen: set[str] = set()
    linked: set[str] = set()
    required = {
        "id",
        "findingId",
        "project",
        "title",
        "reportedOn",
        "lastPublicActivityOn",
        "followUpOn",
        "nextAction",
        "sourceUrl",
        "stage",
        "monitor",
        "baseline",
    }
    for index, record in enumerate(records):
        label = f"config.records[{index}]"
        if not isinstance(record, dict) or set(record) != required:
            fail(f"{label} must contain exactly {sorted(required)}")
        identifier = require_string(record["id"], f"{label}.id")
        if identifier in seen:
            fail(f"duplicate tracker id {identifier}")
        seen.add(identifier)
        finding_id = require_string(record["findingId"], f"{label}.findingId")
        if finding_id in linked:
            fail(f"public finding {finding_id} is tracked more than once")
        linked.add(finding_id)
        finding = public_entries.get(finding_id)
        if finding is None or finding["status"] == "independent-validation":
            fail(f"{identifier} does not reference a public original contribution")
        if record["project"] != finding["project"] or record["title"] != finding["title"]:
            fail(f"{identifier} project/title differs from the public finding")
        require_date(record["reportedOn"], f"{identifier}.reportedOn")
        require_date(record["lastPublicActivityOn"], f"{identifier}.lastPublicActivityOn")
        require_date(record["followUpOn"], f"{identifier}.followUpOn", nullable=True)
        require_string(record["nextAction"], f"{identifier}.nextAction")
        source_url = require_https(record["sourceUrl"], f"{identifier}.sourceUrl")
        if source_url not in {item["url"] for item in finding["links"]}:
            fail(f"{identifier}.sourceUrl is not a reviewed finding link")
        if record["stage"] not in STAGES:
            fail(f"{identifier}.stage is unsupported")

        monitor = record["monitor"]
        if not isinstance(monitor, dict) or monitor.get("kind") not in MONITOR_KINDS:
            fail(f"{identifier}.monitor kind is unsupported")
        require_sha(monitor.get("commit"), f"{identifier}.monitor.commit")
        expected = monitor.get("expectedCredit")
        if not isinstance(expected, dict) or set(expected) != {"kind", "patterns"}:
            fail(f"{identifier}.monitor.expectedCredit has an invalid schema")
        patterns = require_string_list(
            expected["patterns"], f"{identifier}.monitor.expectedCredit.patterns"
        )
        if not patterns or not all(reporter["name"].casefold() in item.casefold() for item in patterns):
            fail(f"{identifier} credit patterns must identify the reporter")
        require_string_list(monitor.get("cveKeywords"), f"{identifier}.monitor.cveKeywords")
        if monitor["kind"] == "github-commit":
            require_string(monitor.get("repository"), f"{identifier}.monitor.repository")
            related = monitor.get("relatedCommits", [])
            if not isinstance(related, list):
                fail(f"{identifier}.monitor.relatedCommits must be a list")
            for related_index, source in enumerate(related):
                source_label = f"{identifier}.monitor.relatedCommits[{related_index}]"
                if not isinstance(source, dict) or set(source) != {
                    "commit",
                    "url",
                    "expectedCredit",
                    "baseline",
                }:
                    fail(f"{source_label} has an invalid schema")
                require_sha(source["commit"], f"{source_label}.commit")
                require_https(source["url"], f"{source_label}.url")
                related_expected = source["expectedCredit"]
                if not isinstance(related_expected, dict) or set(related_expected) != {
                    "kind",
                    "patterns",
                }:
                    fail(f"{source_label}.expectedCredit has an invalid schema")
                related_patterns = require_string_list(
                    related_expected["patterns"], f"{source_label}.expectedCredit.patterns"
                )
                if not related_patterns or not all(
                    reporter["name"].casefold() in item.casefold()
                    for item in related_patterns
                ):
                    fail(f"{source_label} credit patterns must identify the reporter")
                related_baseline = source["baseline"]
                if not isinstance(related_baseline, dict) or set(related_baseline) != {
                    "checkedOn",
                    "creditState",
                    "creditEvidence",
                }:
                    fail(f"{source_label}.baseline has an invalid schema")
                require_date(related_baseline["checkedOn"], f"{source_label}.baseline.checkedOn")
                if related_baseline["creditState"] not in CREDIT_STATES:
                    fail(f"{source_label}.baseline.creditState is unsupported")
                require_string(
                    related_baseline["creditEvidence"],
                    f"{source_label}.baseline.creditEvidence",
                )
        elif monitor["kind"] == "forgejo-pull":
            require_https(monitor.get("apiBase"), f"{identifier}.monitor.apiBase")
            require_string(monitor.get("repository"), f"{identifier}.monitor.repository")
            if not isinstance(monitor.get("pull"), int) or monitor["pull"] <= 0:
                fail(f"{identifier}.monitor.pull must be positive")
        else:
            require_https(monitor.get("repositoryUrl"), f"{identifier}.monitor.repositoryUrl")
            require_string_list(monitor.get("branches"), f"{identifier}.monitor.branches")
            if not isinstance(monitor.get("scanLimit"), int) or not 1 <= monitor["scanLimit"] <= 1000:
                fail(f"{identifier}.monitor.scanLimit is outside 1..1000")
            probe = monitor.get("branchProbe")
            if probe is not None:
                if not isinstance(probe, dict) or set(probe) != {"path", "contains"}:
                    fail(f"{identifier}.monitor.branchProbe has an invalid schema")
                path = require_string(probe["path"], f"{identifier}.monitor.branchProbe.path")
                if path.startswith("/") or ".." in Path(path).parts:
                    fail(f"{identifier}.monitor.branchProbe.path must be repository-relative")
                patterns = require_string_list(
                    probe["contains"], f"{identifier}.monitor.branchProbe.contains"
                )
                if not patterns:
                    fail(f"{identifier}.monitor.branchProbe.contains cannot be empty")

        baseline = record["baseline"]
        expected_baseline = {
            "checkedOn",
            "checkState",
            "creditState",
            "creditEvidence",
            "upstreamState",
            "locations",
            "cves",
        }
        if not isinstance(baseline, dict) or set(baseline) != expected_baseline:
            fail(f"{identifier}.baseline has an invalid schema")
        require_date(baseline["checkedOn"], f"{identifier}.baseline.checkedOn")
        if baseline["checkState"] not in CHECK_STATES:
            fail(f"{identifier}.baseline.checkState is unsupported")
        if baseline["creditState"] not in CREDIT_STATES:
            fail(f"{identifier}.baseline.creditState is unsupported")
        require_string(baseline["creditEvidence"], f"{identifier}.baseline.creditEvidence")
        if baseline["upstreamState"] not in STAGES:
            fail(f"{identifier}.baseline.upstreamState is unsupported")
        require_string_list(baseline["locations"], f"{identifier}.baseline.locations")
        validate_cves(baseline["cves"], f"{identifier}.baseline.cves")

    sources = config["discoverySources"]
    if not isinstance(sources, list):
        fail("config.discoverySources must be a list")
    for index, source in enumerate(sources):
        label = f"config.discoverySources[{index}]"
        if not isinstance(source, dict) or source.get("kind") not in DISCOVERY_KINDS:
            fail(f"{label} kind is unsupported")
        require_string(source.get("label"), f"{label}.label")
        limit = source.get("scanLimit")
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            fail(f"{label}.scanLimit is outside 1..1000")
        if source["kind"] == "gitiles-log":
            require_https(source.get("repositoryUrl"), f"{label}.repositoryUrl")
            require_string_list(source.get("branches"), f"{label}.branches")
        else:
            require_string(source.get("repository"), f"{label}.repository")
            require_string(source.get("branch"), f"{label}.branch")
            if source["kind"] == "forgejo-log":
                require_https(source.get("apiBase"), f"{label}.apiBase")


def validate_cves(value: object, label: str) -> list[str]:
    values = require_string_list(value, label)
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", item) for item in values):
        fail(f"{label} contains an invalid CVE identifier")
    if len(values) != len(set(values)):
        fail(f"{label} contains duplicate identifiers")
    return values


def validate_output(output: dict, config_ids: set[str]) -> None:
    if set(output) != {
        "schemaVersion",
        "generatedAt",
        "dataDate",
        "mode",
        "summary",
        "records",
        "discoveries",
        "discoveryErrors",
    }:
        fail("tracker output has unexpected top-level fields")
    if output["schemaVersion"] != 1 or output["mode"] not in {"baseline", "live"}:
        fail("tracker output has an unsupported schema or mode")
    try:
        datetime.fromisoformat(require_string(output["generatedAt"], "generatedAt").replace("Z", "+00:00"))
    except ValueError:
        fail("generatedAt must be an ISO-8601 datetime")
    require_date(output["dataDate"], "dataDate")
    records = output["records"]
    if not isinstance(records, list) or {item.get("id") for item in records} != config_ids:
        fail("tracker output records do not match configured public records")
    for record in records:
        identifier = record["id"]
        for field in (
            "findingId",
            "project",
            "title",
            "nextAction",
            "checkDetail",
            "creditEvidence",
        ):
            require_string(record.get(field), f"{identifier}.{field}")
        for field in ("reportedOn", "lastPublicActivityOn"):
            require_date(record.get(field), f"{identifier}.{field}")
        require_date(record.get("followUpOn"), f"{identifier}.followUpOn", nullable=True)
        require_https(record.get("sourceUrl"), f"{identifier}.sourceUrl")
        require_sha(record.get("commit"), f"{identifier}.commit")
        if record.get("stage") not in STAGES or record.get("upstreamState") not in STAGES:
            fail(f"{identifier} has an unsupported stage")
        if record.get("checkState") not in CHECK_STATES:
            fail(f"{identifier}.checkState is unsupported")
        if record.get("creditState") not in CREDIT_STATES:
            fail(f"{identifier}.creditState is unsupported")
        if record.get("followUpState") not in FOLLOW_UP_STATES:
            fail(f"{identifier}.followUpState is unsupported")
        require_string_list(record.get("locations"), f"{identifier}.locations")
        related_sources = record.get("relatedSources")
        if not isinstance(related_sources, list):
            fail(f"{identifier}.relatedSources must be a list")
        for source_index, source in enumerate(related_sources):
            source_label = f"{identifier}.relatedSources[{source_index}]"
            if not isinstance(source, dict) or set(source) != {
                "commit",
                "url",
                "creditState",
                "creditEvidence",
                "checkedOn",
            }:
                fail(f"{source_label} has an invalid schema")
            require_sha(source["commit"], f"{source_label}.commit")
            require_https(source["url"], f"{source_label}.url")
            if source["creditState"] not in CREDIT_STATES:
                fail(f"{source_label}.creditState is unsupported")
            require_string(source["creditEvidence"], f"{source_label}.creditEvidence")
            require_date(source["checkedOn"], f"{source_label}.checkedOn")
        validate_cves(record.get("cves"), f"{identifier}.cves")
        if record.get("cveCheckState") not in {"not-run", "verified", "check-error"}:
            fail(f"{identifier}.cveCheckState is unsupported")

    discoveries = output["discoveries"]
    if not isinstance(discoveries, list):
        fail("discoveries must be a list")
    discovery_commits: set[str] = set()
    for index, item in enumerate(discoveries):
        label = f"discoveries[{index}]"
        sha = require_sha(item.get("commit"), f"{label}.commit")
        if sha in discovery_commits:
            fail(f"duplicate discovery {sha}")
        discovery_commits.add(sha)
        for field in ("subject", "creditEvidence", "source", "location"):
            require_string(item.get(field), f"{label}.{field}")
        require_date(item.get("date"), f"{label}.date", nullable=True)
        require_https(item.get("url"), f"{label}.url")
    require_string_list(output["discoveryErrors"], "discoveryErrors")

    summary = output["summary"]
    expected_keys = {
        "tracked",
        "active",
        "followUpDue",
        "creditConfirmed",
        "cves",
        "checkErrors",
        "newCreditDiscoveries",
    }
    if not isinstance(summary, dict) or set(summary) != expected_keys:
        fail("tracker summary has an invalid schema")
    expected = {
        "tracked": len(records),
        "active": sum(item["stage"] != "closed" for item in records),
        "followUpDue": sum(item["followUpState"] in {"overdue", "due"} for item in records),
        "creditConfirmed": sum(item["creditState"] == "confirmed" for item in records),
        "cves": len({cve for item in records for cve in item["cves"]}),
        "checkErrors": sum(item["checkState"] == "check-error" for item in records)
        + len(output["discoveryErrors"]),
        "newCreditDiscoveries": len(discoveries),
    }
    if summary != expected:
        fail(f"tracker summary {summary!r} differs from derived values {expected!r}")


def main() -> None:
    if FORBIDDEN_PRIVATE_OUTPUT.exists():
        fail("public/data/private-tracker.json must never enter the Pages tree")
    try:
        index = PUBLIC_INDEX.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {PUBLIC_INDEX}: {error}")
    if index.count('<body data-private-tracker="">') != 1:
        fail("the public page must keep the private-tracker body marker empty")
    findings = load(FINDINGS)
    entries = {entry["id"]: entry for entry in findings.get("publicEntries", [])}
    config = load(CONFIG)
    output = load(OUTPUT)
    validate_config(config, entries)
    validate_output(output, {record["id"] for record in config["records"]})
    print(
        "PASS: public tracker validated with "
        f"{len(output['records'])} records and {len(output['discoveries'])} new credit discoveries"
    )


if __name__ == "__main__":
    main()
