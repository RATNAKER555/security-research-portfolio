# Security research ledger

Ratnaker Gautam's research record in software, protocol, and connected-product
security. The site combines a public evidence ledger with a concise description
of the wider doctoral research programme, including stateful and over-the-air
testing of Thread and Matter systems.

The presentation follows an academic lab-record model. Every detailed finding
includes a public primary source, the observed behaviour, the validation
method, the tested scope, a reviewed CWE classification, and an attribution
statement. Programme descriptions identify research directions and remain
separate from evidence-backed results.

## Local validation

The site has no runtime dependencies. Validate the disclosure boundary and
build the deployment tree with:

~~~sh
python3 scripts/validate_public_data.py
python3 scripts/monitor_public_credit.py --offline
python3 scripts/validate_public_tracker.py
python3 scripts/build_site.py
python3 -m http.server 8080 --directory dist
~~~

Then open <http://localhost:8080>.

## Data model

The public dataset is public/data/findings.json.

`main` is the disclosure-safe public source. The KU Leuven deployment is built
from a separate `private-dashboard` branch whose exact private ledger is never
merged into `main` or pushed to a public remote.

- publicEntries contains only records supported by public upstream sources.
- privateEntries contains aggregate counts and generic workflow states. It
  never contains project names, triggers, versions, source locations, issue
  URLs, correspondence, or reproducer material.
- summary values are derived from the entries and checked by the validator;
  original findings and independent validations are counted separately.
- weakness mappings distinguish a primary root cause from any separately
  observed consequence CWE. IDs and official titles are checked against a
  pinned subset of MITRE CWE 4.20; the review method is documented in
  docs/CWE_CLASSIFICATION.md.
- assignedCves remains zero until a public CVE record exists.

The public disclosure tracker is generated from `tracker/public-monitor.json`.
It checks public upstream commits, pull requests, branch promotion, explicit
credit trailers, and full fixing-commit hashes in public CVE records. Its
published output is `public/data/tracker.json`. The monitor contains no
embargoed project names.

The complete report and follow-up ledger is
`private/report-tracker.json`. Git ignores that file, and the Pages pipeline
never copies it. To view the same dashboard with the private operations table:

~~~sh
python3 scripts/build_private_site.py
python3 -m http.server 8081 --directory dist-private
~~~

Read `docs/TRACKER.md` before adding a monitored source or changing a workflow
count.

The private evidence collection lives outside this repository. Client-side
redaction is not used: undisclosed data is absent from the build.

## Deployment

- The public KU Leuven GitLab Pages site is
  <https://u0190734.pages.gitlab.kuleuven.be/vulnerability-research/>.
- The authenticated research-operations dashboard is
  <https://u0190734.pages.gitlab.kuleuven.be/security-research-portfolio/>.
- GitHub Pages will mirror the public `main` branch after the GitHub repository
  is created and Pages is enabled.

Read docs/DISCLOSURE_RULES.md before adding a record and
docs/PUBLISHING.md before publishing. The GitLab schedule and tracker workflow
are documented in docs/TRACKER.md.
