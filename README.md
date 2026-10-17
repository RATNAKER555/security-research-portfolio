# Security research ledger

Ratnaker Gautam's disclosure-safe vulnerability research portfolio. The site
uses a compact, machine-readable ledger to distinguish original public work,
assigned CVEs, coordinated reports, queued research, and independent
validations of prior public findings.

The presentation is deliberately closer to an academic lab record than a
promotional portfolio. Every detailed finding includes a public primary
source, an observed primitive, the validation method, an explicit claim
boundary, and an attribution statement.

## Local validation

The site has no runtime dependencies. Validate the disclosure boundary and
build the deployment tree with:

~~~sh
python3 scripts/validate_public_data.py
python3 scripts/build_site.py
python3 -m http.server 8080 --directory dist
~~~

Then open <http://localhost:8080>.

## Data model

The public dataset is public/data/findings.json.

- publicEntries contains only records supported by public upstream sources.
- privateEntries contains aggregate counts and generic workflow states. It
  never contains project names, triggers, versions, source locations, issue
  URLs, correspondence, or reproducer material.
- summary values are derived from the entries and checked by the validator.
- assignedCves remains zero until a public CVE record exists.

The private evidence collection lives outside this repository. Client-side
redaction is not used: undisclosed data is absent from the build.

## Deployment

- GitHub Pages deploys public/ with .github/workflows/pages.yml.
- KU Leuven GitLab Pages deploys public/ with .gitlab-ci.yml.
- ChatGPT Sites builds dist/ from the same reviewed source.

Read docs/DISCLOSURE_RULES.md before adding a record and
docs/PUBLISHING.md before publishing.
