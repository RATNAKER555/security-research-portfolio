# Publishing the reviewed ledger

Every public deployment must originate from the same validated commit. Do not
copy private evidence into this repository while preparing a release.

## Pre-publication review

Run:

~~~sh
python3 scripts/build_site.py
python3 scripts/validate_public_tracker.py
git diff --check
git status --short
~~~

Then inspect public/data/findings.json and the generated dist/ tree. Confirm:

1. Every detailed record has a primary public HTTPS source.
2. Attribution matches that source.
3. CVE totals include only assigned, publicly verifiable identifiers.
4. CWE IDs and titles pass the pinned-catalog check, and mapping rationales do
   not exceed the public disclosure boundary.
5. Coordinated and queued work appears only as aggregate counts.
6. No private project name, issue URL, local path, trigger, version, hash,
   correspondence, or artifact entered the build.
7. Mobile and desktop layouts remain readable.
8. The public tracker references only already-public findings and contains no
   embargoed project, correspondence, or follow-up detail.
9. `private/report-tracker.json` and `dist-private/` remain ignored and absent
   from the commit.

## GitHub Pages

1. Create an empty public repository named security-research-portfolio under
   RATNAKER555.
2. Add its SSH URL as the github remote and push main.
3. In Settings, Pages, select GitHub Actions as the source.
4. The included workflow validates the ledger before it uploads public/.

Expected project URL after the first successful workflow:
<https://ratnaker555.github.io/security-research-portfolio/>

## KU Leuven GitLab Pages

1. Create an empty public project named vulnerability-research in the intended
   KU Leuven namespace.
2. Add its SSH URL as the kuleuven remote and push main.
3. The included pipeline validates the public findings and tracker before
   retaining public/ as the Pages artifact. The deployment rule is restricted
   to `u0190734/vulnerability-research`.
4. Read the exact Pages URL from Deploy, Pages after the pipeline succeeds.

## Authenticated KU Leuven research dashboard

The `private-dashboard` branch is the only branch allowed to deploy this
project's KU Leuven Pages site. It carries the private workflow ledger and
builds `dist-private/`; GitLab Pages access control must remain enabled. The
`main` branch remains disclosure-safe and is the source for the public GitHub
Pages portfolio.

Never push `private-dashboard` to a public remote. Merge reviewed public code
changes from `main` into `private-dashboard`, resolve the ledger separately,
and verify the Pages endpoint redirects anonymous visitors to KU Leuven OAuth.
