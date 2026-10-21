from __future__ import annotations

import copy
import base64
import json
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from scripts import monitor_public_credit as monitor


ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __init__(self, responder):
        self.responder = responder
        self.urls: list[str] = []

    def get_json(self, url, *, headers=None):
        self.urls.append(url)
        return self.responder(url)

    def get_text(self, url, *, headers=None):
        self.urls.append(url)
        return self.responder(url)


class MonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(
            (ROOT / "tracker" / "public-monitor.json").read_text(encoding="utf-8")
        )

    def record(self, identifier: str):
        return copy.deepcopy(
            next(item for item in self.config["records"] if item["id"] == identifier)
        )

    def test_exact_credit_line_is_case_insensitive_but_returns_source_text(self):
        message = "subject\n\nReported-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>\n"
        self.assertEqual(
            monitor.exact_credit_line(message, ["reported-BY: ratnaker gautam"]),
            "Reported-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>",
        )

    def test_gitiles_check_confirms_credit_and_for_next_promotion(self):
        record = self.record("RG-2026-14")
        sha = record["monitor"]["commit"]
        record["monitor"]["scanLimit"] = 20

        def respond(url):
            if f"/+/{sha}?format=JSON" in url:
                return {
                    "commit": sha,
                    "message": (
                        "ksmbd: validate offsets\n\n"
                        "Reported-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>\n"
                    ),
                    "committer": {"time": "Sat Oct 17 22:01:51 2026 +0900"},
                }
            if "/+log/refs/heads/ksmbd-for-next?" in url:
                return {"log": [{"commit": sha}]}
            if "/+log/refs/heads/for-next?" in url:
                return {"log": [{"commit": "a" * 40}, {"commit": sha}]}
            if "/+log/refs/heads/master?" in url:
                return {"log": [{"commit": "b" * 40}]}
            if "/+/refs/heads/master/fs/smb/server/smbacl.c?format=TEXT" in url:
                return base64.b64encode(b"source without the fix").decode()
            self.fail(f"unexpected URL {url}")

        result = monitor.check_gitiles_commit(
            record, FakeClient(respond), self.config["reporter"]
        )
        self.assertEqual(result["creditState"], "confirmed")
        self.assertEqual(result["stage"], "integration")
        self.assertEqual(result["locations"], ["ksmbd-for-next", "for-next"])
        self.assertEqual(result["lastPublicActivityOn"], "2026-10-17")

    def test_forgejo_open_pull_confirms_author_and_signoff(self):
        record = self.record("RG-2026-09")
        sha = record["monitor"]["commit"]

        def respond(url):
            if url.endswith("/pulls/25160"):
                return {
                    "state": "open",
                    "merged": False,
                    "updated_at": "2026-10-18T09:30:00Z",
                    "html_url": record["sourceUrl"],
                    "head": {"sha": sha},
                }
            if url.endswith("/git/commits/" + sha):
                return {
                    "commit": {
                        "message": (
                            "avformat/rtsp: fix leak\n\n"
                            "Signed-off-by: Ratnaker Gautam "
                            "<ratnaker.gautam@kuleuven.be>\n"
                        ),
                        "author": {
                            "name": "Ratnaker Gautam",
                            "email": "ratnaker.gautam@kuleuven.be",
                        },
                    }
                }
            self.fail(f"unexpected URL {url}")

        result = monitor.check_forgejo_pull(
            record, FakeClient(respond), self.config["reporter"]
        )
        self.assertEqual(result["creditState"], "confirmed")
        self.assertEqual(result["stage"], "patch-review")
        self.assertEqual(result["lastPublicActivityOn"], "2026-10-18")

    def test_network_error_retains_last_verified_credit(self):
        config = copy.deepcopy(self.config)
        config["records"] = [self.record("RG-2026-12")]
        config["records"][0]["followUpOn"] = "2026-10-17"
        config["discoverySources"] = []

        def fail(_url):
            raise monitor.MonitorError("fixture network failure")

        payload = monitor.build_output(
            config,
            client=FakeClient(fail),
            today=date(2026, 10, 18),
            now=datetime(2026, 10, 18, 12, tzinfo=timezone.utc),
            check_cves=False,
        )
        result = payload["records"][0]
        self.assertEqual(result["checkState"], "check-error")
        self.assertEqual(result["creditState"], "confirmed")
        self.assertEqual(result["followUpState"], "overdue")
        self.assertEqual(payload["summary"]["creditConfirmed"], 2)
        self.assertEqual(payload["summary"]["checkErrors"], 1)
        self.assertEqual(payload["generatedAt"], "2026-10-18T12:00:00Z")

    def test_superseded_commit_is_not_a_new_discovery_or_extra_credit(self):
        record = self.record("RG-2026-14")
        superseded = record["monitor"]["supersededCommits"]
        self.assertTrue(superseded)
        self.assertNotIn(record["monitor"]["commit"], superseded)
        config = copy.deepcopy(self.config)
        config["records"] = [record]
        config["discoverySources"] = [
            {
                "kind": "github-global-search",
                "label": "GitHub public commit index",
                "query": '"Ratnaker Gautam"',
                "scanLimit": 100,
            }
        ]
        unrelated = "c" * 40

        def item(sha):
            return {
                "sha": sha,
                "html_url": "https://github.com/example/mirror/commit/" + sha,
                "repository": {"full_name": "example/mirror"},
                "commit": {
                    "message": (
                        "fix parser\n\n"
                        "Reported-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>"
                    ),
                    "committer": {"date": "2026-10-17T13:01:51Z"},
                },
            }

        def respond(url):
            if "api.github.com/search/commits" in url:
                return {"items": [item(superseded[0]), item(unrelated)]}
            raise monitor.MonitorError("fixture: record source unavailable")

        payload = monitor.build_output(
            config,
            client=FakeClient(respond),
            today=date(2026, 10, 21),
            now=datetime(2026, 10, 21, 12, tzinfo=timezone.utc),
            check_cves=False,
        )
        self.assertEqual([entry["commit"] for entry in payload["discoveries"]], [unrelated])
        self.assertEqual(payload["summary"]["newCreditDiscoveries"], 1)
        self.assertEqual(payload["summary"]["creditConfirmed"], 1)

    def test_discovery_requires_a_credit_trailer(self):
        reporter = self.config["reporter"]
        self.assertIsNone(
            monitor.reporter_credit_line(
                "Ratnaker Gautam described this behavior in a report", reporter
            )
        )
        self.assertEqual(
            monitor.reporter_credit_line(
                "fix parser\n\nTested-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>",
                reporter,
            ),
            "Tested-by: Ratnaker Gautam <ratnaker.gautam@kuleuven.be>",
        )

    def test_global_github_discovery_keeps_only_explicit_credit(self):
        source = {
            "kind": "github-global-search",
            "label": "GitHub public commit index",
            "query": '"Ratnaker Gautam"',
            "scanLimit": 100,
        }

        def respond(url):
            self.assertIn("api.github.com/search/commits", url)
            return {
                "items": [
                    {
                        "sha": "a" * 40,
                        "html_url": "https://github.com/example/project/commit/" + "a" * 40,
                        "repository": {"full_name": "example/project"},
                        "commit": {
                            "message": "fix parser\n\nReported-by: Ratnaker Gautam",
                            "committer": {"date": "2026-10-18T12:00:00Z"},
                        },
                    },
                    {
                        "sha": "b" * 40,
                        "html_url": "https://github.com/example/project/commit/" + "b" * 40,
                        "repository": {"full_name": "example/project"},
                        "commit": {
                            "message": "mention Ratnaker Gautam without a trailer",
                            "committer": {"date": "2026-10-18T12:00:00Z"},
                        },
                    },
                ]
            }

        found = monitor.discover_github_global(
            source, FakeClient(respond), self.config["reporter"]
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["commit"], "a" * 40)
        self.assertEqual(found[0]["location"], "example/project")


if __name__ == "__main__":
    unittest.main()
