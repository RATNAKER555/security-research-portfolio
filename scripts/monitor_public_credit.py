#!/usr/bin/env python3
"""Build the public disclosure tracker from public upstream sources.

The monitor deliberately knows only about records that are already public.
Embargoed project names and correspondence belong in the ignored private
tracker and must never be added to tracker/public-monitor.json.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "tracker" / "public-monitor.json"
DEFAULT_OUTPUT = ROOT / "public" / "data" / "tracker.json"
USER_AGENT = "ratnaker-public-credit-monitor/1.0"
CREDIT_TRAILERS = {
    "reported-by",
    "signed-off-by",
    "co-developed-by",
    "tested-by",
    "reviewed-by",
}


class MonitorError(RuntimeError):
    """A source could not be checked or returned an invalid response."""


class HttpClient:
    def __init__(self, timeout: int = 25) -> None:
        self.timeout = timeout

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> Any:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        request_headers.update(headers or {})
        request = Request(url, headers=request_headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise MonitorError(f"GET {url}: {error}") from error
        if raw.startswith(")]}'"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise MonitorError(f"GET {url}: invalid JSON: {error}") from error

    def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        request_headers = {"User-Agent": USER_AGENT}
        request_headers.update(headers or {})
        request = Request(url, headers=request_headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError) as error:
            raise MonitorError(f"GET {url}: {error}") from error


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_source_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        pass
    match = re.search(r"\b\d{4}-\d{2}-\d{2}\b", value)
    if match:
        return match.group(0)
    # Gitiles uses strings such as "Sat Oct 17 22:01:51 2026 +0900".
    try:
        return datetime.strptime(value, "%a %b %d %H:%M:%S %Y %z").date().isoformat()
    except ValueError:
        return None


def exact_credit_line(message: str, patterns: list[str]) -> str | None:
    for line in message.splitlines():
        stripped = line.strip()
        if any(pattern.casefold() in stripped.casefold() for pattern in patterns):
            return stripped
    return None


def reporter_credit_line(message: str, reporter: dict[str, Any]) -> str | None:
    names = [reporter["name"].casefold()]
    names.extend(email.casefold() for email in reporter.get("emails", []))
    for line in message.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        trailer, _ = stripped.split(":", 1)
        if trailer.casefold() not in CREDIT_TRAILERS:
            continue
        folded = stripped.casefold()
        if any(identity in folded for identity in names):
            return stripped
    return None


def author_matches(author: dict[str, Any] | None, reporter: dict[str, Any]) -> bool:
    if not author:
        return False
    name = str(author.get("name", "")).casefold()
    email = str(author.get("email", "")).casefold()
    return name == reporter["name"].casefold() or email in {
        item.casefold() for item in reporter.get("emails", [])
    }


def evaluate_credit(
    message: str,
    expected: dict[str, Any],
    reporter: dict[str, Any],
    author: dict[str, Any] | None = None,
) -> tuple[str, str]:
    patterns = expected.get("patterns", [])
    line = exact_credit_line(message, patterns)
    kind = expected.get("kind")
    if kind == "authored-and-signed-off":
        if author_matches(author, reporter) and line:
            return "confirmed", f"Author: {reporter['name']}; {line}"
        return "missing", "Expected author identity and Signed-off-by trailer were not both present"
    if line:
        return "confirmed", line
    return "missing", "Expected public credit trailer was not present"


def baseline_result(record: dict[str, Any]) -> dict[str, Any]:
    baseline = record["baseline"]
    related_sources = []
    for source in record["monitor"].get("relatedCommits", []):
        source_baseline = source["baseline"]
        related_sources.append(
            {
                "commit": source["commit"],
                "url": source["url"],
                "creditState": source_baseline["creditState"],
                "creditEvidence": source_baseline["creditEvidence"],
                "checkedOn": source_baseline["checkedOn"],
            }
        )
    return {
        "id": record["id"],
        "findingId": record["findingId"],
        "project": record["project"],
        "title": record["title"],
        "reportedOn": record["reportedOn"],
        "lastPublicActivityOn": record["lastPublicActivityOn"],
        "followUpOn": record.get("followUpOn"),
        "nextAction": record["nextAction"],
        "sourceUrl": record["sourceUrl"],
        "stage": record["stage"],
        "commit": record["monitor"].get("commit"),
        "relatedSources": related_sources,
        "checkState": baseline["checkState"],
        "checkDetail": f"Last source verification: {baseline['checkedOn']}",
        "creditState": baseline["creditState"],
        "creditEvidence": baseline["creditEvidence"],
        "upstreamState": baseline["upstreamState"],
        "locations": baseline["locations"],
        "cves": baseline["cves"],
        "cveCheckState": "not-run",
    }


def gitiles_log(
    client: HttpClient,
    repository_url: str,
    branch: str,
    limit: int,
) -> list[dict[str, Any]]:
    commits: list[dict[str, Any]] = []
    cursor: str | None = None
    while len(commits) < limit:
        count = min(100, limit - len(commits))
        query: dict[str, Any] = {"format": "JSON", "n": count}
        if cursor:
            query["s"] = cursor
        url = (
            repository_url.rstrip("/")
            + "/+log/refs/heads/"
            + branch
            + "?"
            + urlencode(query)
        )
        payload = client.get_json(url)
        page = payload.get("log", [])
        if not isinstance(page, list):
            raise MonitorError(f"Gitiles log for {branch} has no log list")
        commits.extend(page)
        cursor = payload.get("next")
        if not cursor or not page:
            break
    return commits[:limit]


def check_github_commit(
    record: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> dict[str, Any]:
    monitor = record["monitor"]
    url = (
        "https://api.github.com/repos/"
        + monitor["repository"]
        + "/commits/"
        + monitor["commit"]
    )
    payload = client.get_json(url)
    commit = payload.get("commit", {})
    message = str(commit.get("message", ""))
    state, evidence = evaluate_credit(
        message,
        monitor["expectedCredit"],
        reporter,
        commit.get("author"),
    )
    related_sources = []
    for source in monitor.get("relatedCommits", []):
        related_url = (
            "https://api.github.com/repos/"
            + monitor["repository"]
            + "/commits/"
            + source["commit"]
        )
        related_payload = client.get_json(related_url)
        related_commit = related_payload.get("commit", {})
        related_state, related_evidence = evaluate_credit(
            str(related_commit.get("message", "")),
            source["expectedCredit"],
            reporter,
            related_commit.get("author"),
        )
        related_sources.append(
            {
                "commit": related_payload.get("sha", source["commit"]),
                "url": related_payload.get("html_url", source["url"]),
                "creditState": related_state,
                "creditEvidence": related_evidence,
                "checkedOn": parse_source_date(
                    related_commit.get("committer", {}).get("date")
                )
                or record["baseline"]["checkedOn"],
            }
        )
    result = baseline_result(record)
    result.update(
        {
            "checkState": "verified",
            "checkDetail": "Public commit metadata fetched from GitHub",
            "creditState": state,
            "creditEvidence": evidence,
            "upstreamState": "fixed-upstream",
            "stage": "fixed-upstream",
            "commit": payload.get("sha", monitor["commit"]),
            "sourceUrl": payload.get("html_url", record["sourceUrl"]),
            "relatedSources": related_sources,
        }
    )
    activity = parse_source_date(commit.get("committer", {}).get("date"))
    if activity:
        result["lastPublicActivityOn"] = activity
    return result


def check_forgejo_pull(
    record: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> dict[str, Any]:
    monitor = record["monitor"]
    base = monitor["apiBase"].rstrip("/")
    repo = monitor["repository"]
    pull = client.get_json(f"{base}/repos/{repo}/pulls/{monitor['pull']}")
    head_sha = pull.get("head", {}).get("sha") or monitor["commit"]
    commit_payload = client.get_json(f"{base}/repos/{repo}/git/commits/{head_sha}")
    commit = commit_payload.get("commit", {})
    message = str(commit.get("message", ""))
    state, evidence = evaluate_credit(
        message,
        monitor["expectedCredit"],
        reporter,
        commit.get("author"),
    )
    merged = bool(pull.get("merged"))
    pull_state = str(pull.get("state", "")).casefold()
    if merged:
        upstream = stage = "fixed-upstream"
        locations = ["master"]
    elif pull_state == "open":
        upstream = stage = "patch-review"
        locations = [f"pull request {monitor['pull']}"]
    else:
        upstream = stage = "closed"
        locations = [f"closed pull request {monitor['pull']}"]
    result = baseline_result(record)
    result.update(
        {
            "checkState": "verified",
            "checkDetail": "Pull request and head commit fetched from FFmpeg Forgejo",
            "creditState": state,
            "creditEvidence": evidence,
            "upstreamState": upstream,
            "stage": stage,
            "locations": locations,
            "commit": head_sha,
            "sourceUrl": pull.get("html_url", record["sourceUrl"]),
        }
    )
    activity = parse_source_date(pull.get("updated_at"))
    if activity:
        result["lastPublicActivityOn"] = activity
    return result


def check_gitiles_commit(
    record: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> dict[str, Any]:
    monitor = record["monitor"]
    repository = monitor["repositoryUrl"].rstrip("/")
    commit_url = f"{repository}/+/{monitor['commit']}?format=JSON"
    payload = client.get_json(commit_url)
    message = str(payload.get("message", ""))
    state, evidence = evaluate_credit(
        message,
        monitor["expectedCredit"],
        reporter,
        payload.get("author"),
    )
    locations: list[str] = []
    coverage: list[str] = []
    for branch in monitor["branches"]:
        commits = gitiles_log(client, repository, branch, monitor["scanLimit"])
        coverage.append(f"{branch}:{len(commits)}")
        exact_commit = any(item.get("commit") == monitor["commit"] for item in commits)
        content_match = False
        probe = monitor.get("branchProbe")
        if not exact_commit and probe:
            file_url = (
                repository
                + "/+/refs/heads/"
                + branch
                + "/"
                + probe["path"]
                + "?format=TEXT"
            )
            encoded = client.get_text(file_url)
            try:
                source = base64.b64decode("".join(encoded.split()), validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise MonitorError(f"Gitiles source probe for {branch} is invalid: {error}") from error
            content_match = all(pattern in source for pattern in probe["contains"])
        if exact_commit or content_match:
            locations.append(branch)

    if "master" in locations:
        upstream = stage = "fixed-upstream"
    elif "for-next" in locations:
        upstream = stage = "integration"
    elif locations:
        upstream = stage = "fix-queued"
    else:
        upstream = stage = "public-commit"

    result = baseline_result(record)
    result.update(
        {
            "checkState": "verified",
            "checkDetail": "Commit and recent branch history checked (" + ", ".join(coverage) + ")",
            "creditState": state,
            "creditEvidence": evidence,
            "upstreamState": upstream,
            "stage": stage,
            "locations": locations,
            "commit": payload.get("commit", monitor["commit"]),
        }
    )
    activity = parse_source_date(payload.get("committer", {}).get("time"))
    if activity:
        result["lastPublicActivityOn"] = activity
    return result


def check_record(
    record: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> dict[str, Any]:
    kind = record["monitor"]["kind"]
    checks = {
        "github-commit": check_github_commit,
        "forgejo-pull": check_forgejo_pull,
        "gitiles-commit": check_gitiles_commit,
    }
    try:
        return checks[kind](record, client, reporter)
    except (KeyError, TypeError, MonitorError) as error:
        result = baseline_result(record)
        result["checkState"] = "check-error"
        result["checkDetail"] = str(error)
        return result


def search_nvd(
    result: dict[str, Any],
    record: dict[str, Any],
    client: HttpClient,
    api_key: str | None,
) -> None:
    discovered = set(result.get("cves", []))
    headers = {"apiKey": api_key} if api_key else {}
    try:
        for index, keyword in enumerate(record["monitor"].get("cveKeywords", [])):
            if index and not api_key:
                time.sleep(6.1)
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(
                {"keywordSearch": keyword, "resultsPerPage": 20}
            )
            payload = client.get_json(url, headers=headers)
            for wrapper in payload.get("vulnerabilities", []):
                identifier = wrapper.get("cve", {}).get("id")
                if isinstance(identifier, str) and re.fullmatch(
                    r"CVE-\d{4}-\d{4,}", identifier
                ):
                    discovered.add(identifier)
        result["cves"] = sorted(discovered)
        result["cveCheckState"] = "verified"
    except (TypeError, MonitorError) as error:
        result["cveCheckState"] = "check-error"
        result["cveCheckDetail"] = str(error)


def discovery_line(message: str, reporter: dict[str, Any]) -> str | None:
    return reporter_credit_line(message, reporter)


def discover_gitiles(
    source: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    repository = source["repositoryUrl"].rstrip("/")
    for branch in source["branches"]:
        for commit in gitiles_log(client, repository, branch, source["scanLimit"]):
            message = str(commit.get("message", ""))
            line = discovery_line(message, reporter)
            if not line:
                continue
            sha = str(commit.get("commit", ""))
            found.append(
                {
                    "commit": sha,
                    "subject": message.splitlines()[0] if message else sha,
                    "creditEvidence": line,
                    "source": source["label"],
                    "location": branch,
                    "date": parse_source_date(commit.get("committer", {}).get("time")),
                    "url": f"{repository}/+/{sha}",
                }
            )
    return found


def discover_github(
    source: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> list[dict[str, Any]]:
    query = urlencode(
        {"sha": source["branch"], "per_page": min(source["scanLimit"], 100)}
    )
    url = f"https://api.github.com/repos/{source['repository']}/commits?{query}"
    found: list[dict[str, Any]] = []
    for item in client.get_json(url):
        commit = item.get("commit", {})
        message = str(commit.get("message", ""))
        line = discovery_line(message, reporter)
        if not line:
            continue
        found.append(
            {
                "commit": item.get("sha"),
                "subject": message.splitlines()[0],
                "creditEvidence": line,
                "source": source["label"],
                "location": source["branch"],
                "date": parse_source_date(commit.get("committer", {}).get("date")),
                "url": item.get("html_url"),
            }
        )
    return found


def discover_github_global(
    source: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> list[dict[str, Any]]:
    """Find public commit trailers without publishing embargoed target names."""
    query = source.get("query") or f'"{reporter["name"]}"'
    params = urlencode(
        {
            "q": query,
            "per_page": min(source["scanLimit"], 100),
        }
    )
    payload = client.get_json(
        f"https://api.github.com/search/commits?{params}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise MonitorError("GitHub commit search has no items list")

    found: list[dict[str, Any]] = []
    for item in items:
        commit = item.get("commit", {})
        message = str(commit.get("message", ""))
        line = discovery_line(message, reporter)
        if not line:
            continue
        repository = item.get("repository", {}).get("full_name", "public repository")
        found.append(
            {
                "commit": item.get("sha"),
                "subject": message.splitlines()[0],
                "creditEvidence": line,
                "source": source["label"],
                "location": repository,
                "date": parse_source_date(commit.get("committer", {}).get("date")),
                "url": item.get("html_url"),
            }
        )
    return found


def discover_forgejo(
    source: dict[str, Any], client: HttpClient, reporter: dict[str, Any]
) -> list[dict[str, Any]]:
    query = urlencode(
        {"sha": source["branch"], "limit": min(source["scanLimit"], 100)}
    )
    base = source["apiBase"].rstrip("/")
    url = f"{base}/repos/{source['repository']}/commits?{query}"
    found: list[dict[str, Any]] = []
    for item in client.get_json(url):
        commit = item.get("commit", {})
        message = str(commit.get("message", ""))
        line = discovery_line(message, reporter)
        if not line:
            continue
        found.append(
            {
                "commit": item.get("sha"),
                "subject": message.splitlines()[0],
                "creditEvidence": line,
                "source": source["label"],
                "location": source["branch"],
                "date": parse_source_date(commit.get("committer", {}).get("date")),
                "url": item.get("html_url"),
            }
        )
    return found


def run_discovery(
    sources: list[dict[str, Any]],
    client: HttpClient,
    reporter: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    adapters = {
        "gitiles-log": discover_gitiles,
        "github-log": discover_github,
        "github-global-search": discover_github_global,
        "forgejo-log": discover_forgejo,
    }
    found: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for source in sources:
        try:
            for item in adapters[source["kind"]](source, client, reporter):
                key = str(item.get("commit"))
                previous = found.get(key)
                if previous and item["location"] not in previous["location"].split(", "):
                    previous["location"] += ", " + item["location"]
                else:
                    found[key] = item
        except (KeyError, TypeError, MonitorError) as error:
            errors.append(f"{source.get('label', source.get('kind'))}: {error}")
    return sorted(found.values(), key=lambda item: (item.get("date") or "", item["commit"]), reverse=True), errors


def follow_up_state(value: str | None, today: date) -> str:
    if value is None:
        return "none"
    due = date.fromisoformat(value)
    distance = (due - today).days
    if distance < 0:
        return "overdue"
    if distance == 0:
        return "due"
    if distance <= 7:
        return "due-soon"
    return "scheduled"


def build_output(
    config: dict[str, Any],
    *,
    client: HttpClient | None,
    today: date,
    now: datetime,
    check_cves: bool,
) -> dict[str, Any]:
    reporter = config["reporter"]
    records: list[dict[str, Any]] = []
    for record in config["records"]:
        result = baseline_result(record) if client is None else check_record(record, client, reporter)
        if check_cves and client is not None:
            search_nvd(result, record, client, os.getenv("NVD_API_KEY"))
        result["followUpState"] = follow_up_state(result.get("followUpOn"), today)
        records.append(result)

    if client is None:
        discoveries: list[dict[str, Any]] = []
        discovery_errors: list[str] = []
        mode = "baseline"
    else:
        discoveries, discovery_errors = run_discovery(
            config.get("discoverySources", []), client, reporter
        )
        mode = "live"

    known_commits = {record.get("commit") for record in records}
    known_commits.update(
        source.get("commit")
        for record in records
        for source in record.get("relatedSources", [])
    )
    new_discoveries = [
        item for item in discoveries if item.get("commit") not in known_commits
    ]
    summary = {
        "tracked": len(records),
        "active": sum(record["stage"] not in {"closed"} for record in records),
        "followUpDue": sum(
            record["followUpState"] in {"overdue", "due"} for record in records
        ),
        "creditConfirmed": sum(
            record["creditState"] == "confirmed" for record in records
        )
        + sum(
            source["creditState"] == "confirmed"
            for record in records
            for source in record.get("relatedSources", [])
        ),
        "cves": len({cve for record in records for cve in record["cves"]}),
        "checkErrors": sum(
            record["checkState"] == "check-error" for record in records
        )
        + len(discovery_errors),
        "newCreditDiscoveries": len(new_discoveries),
    }
    return {
        "schemaVersion": 1,
        "generatedAt": iso_datetime(now),
        "dataDate": today.isoformat(),
        "mode": mode,
        "summary": summary,
        "records": records,
        "discoveries": new_discoveries,
        "discoveryErrors": discovery_errors,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="render the last verified baseline without network requests",
    )
    parser.add_argument(
        "--check-cves",
        action="store_true",
        help="query NVD by full fixing-commit hash",
    )
    parser.add_argument("--today", type=date.fromisoformat)
    args = parser.parse_args()

    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"MONITOR CONFIG ERROR: {error}") from error

    now = utc_now()
    payload = build_output(
        config,
        client=None if args.offline else HttpClient(),
        today=args.today or now.date(),
        now=now,
        check_cves=args.check_cves,
    )
    write_json(args.output, payload)
    print(
        "PASS: public tracker contains "
        f"{payload['summary']['tracked']} records, "
        f"{payload['summary']['creditConfirmed']} confirmed credits, and "
        f"{payload['summary']['checkErrors']} check errors"
    )


if __name__ == "__main__":
    main()
