# Disclosure tracker and public-credit monitor

The site has two related ledgers with a hard publication boundary.

## Public tracker

`tracker/public-monitor.json` contains only findings that already have a
reviewed public upstream source. Each record identifies its public finding,
current workflow stage, next review date, exact fixing commit or pull request,
and the credit text expected upstream.

`scripts/monitor_public_credit.py` checks:

- GitHub commit metadata;
- FFmpeg Forgejo pull-request and head-commit metadata;
- Gitiles commit messages and recent maintainer-branch history;
- explicit `Reported-by`, `Signed-off-by`, or other recognized credit trailers;
- configured public repositories for newly appearing credit; and
- on scheduled runs, NVD results keyed by the full fixing-commit hash.

The monitor writes `public/data/tracker.json`. A source outage does not erase
previously verified credit: the row is marked as a check error and retains the
last reviewed baseline. A newly discovered public credit appears in the
automated review queue until it is linked to the correct finding. One report
with two fixing commits remains one finding.

Run a current public check with:

~~~sh
python3 scripts/monitor_public_credit.py
python3 scripts/validate_public_tracker.py
~~~

Use `--offline` when preparing a deterministic build without network access.
Use `--check-cves` only for a periodic check; an optional masked
`NVD_API_KEY` CI variable raises the NVD rate limit.

## Private operations ledger

`private/report-tracker.json` tracks submitted reports, acknowledgements,
follow-up dates, public transitions, duplicates, held candidates, and reports
ready to send. The directory is ignored by Git. `scripts/validate_private_tracker.py`
also fails if Git begins tracking the file.

Build the local private view with:

~~~sh
python3 scripts/build_private_site.py
python3 -m http.server 8081 --directory dist-private
~~~

The build copies the private ledger only into ignored `dist-private/` and
marks that copy of the page as private mode. `public/`, `dist/`, GitLab Pages,
and GitHub Pages never receive the private JSON.

When a finding becomes public:

1. Verify its primary upstream source and attribution.
2. Add the reviewed finding to `public/data/findings.json`.
3. Add its public workflow record to `tracker/public-monitor.json`.
4. Change the local private record to `visibility: public` and the appropriate
   public state.
5. Reduce the anonymous under-coordination count if that report was previously
   included there.
6. Run all three validators and inspect both builds.

## GitLab schedule

The CI file contains a `credit-monitor` job. It runs on every default-branch
pipeline and passes its generated tracker to the Pages job. For an actual
recurring run, create one schedule in the KU Leuven GitLab project:

- target branch: `main`;
- cron: `23 5 * * *`;
- timezone: `Europe/Brussels`;
- status: active.

GitLab sets `CI_PIPELINE_SOURCE=schedule`, which enables the additional NVD
check. No repository or API credential is required for the configured public
sources. If an NVD key is added, store it as a masked CI/CD variable named
`NVD_API_KEY`.
