# Disclosure and attribution rules

The ledger is a research record. It separates evidence, disclosure state, and
credit so a reader can tell exactly what has been proved and who first
reported it.

## Public categories

**CVE assigned** means a public CVE record exists and supports the displayed
identifier. A request, maintainer acknowledgement, fix, or security impact
does not qualify by itself.

**Disclosed finding** means an original report has a public upstream fix or
advisory. It can be shown before a CVE exists.

**Public patch** covers an original correctness, availability, or resource
management contribution that is public but is not presented as a security
vulnerability.

**Independent validation** records a campaign result that was later matched
to a prior public report or fix. It identifies the prior source, stays outside
original-finder totals, and never implies CVE credit.

## Redacted categories

**Under coordination** is an aggregate count of reports already sent to
maintainers.

**Research queue** is an aggregate count of candidates still undergoing
impact, novelty, or report-worthiness review.

Neither category may expose:

- a project or component name;
- a source file, function, line, revision, affected version, or trigger;
- a private issue number, URL, email address, or maintainer message;
- a root-cause explanation, reproducer, attachment, hash, or patch;
- a CVE request or tentative identifier.

The public build must never receive those fields. CSS hiding, JavaScript
filtering, encrypted blobs, and unlinked routes are not disclosure controls.

## Evidence vocabulary

Each public record states three separate things:

1. **Observed primitive**: the memory or resource behavior actually measured.
2. **Validation**: the sanitizer, native replay, control, public API, or test
   evidence supporting the claim.
3. **Claim boundary**: the strongest implication that the evidence does not
   cross.

Memory corruption is not automatically code execution. A crash is not
automatically denial of service in a deployed application. Remote reachability
depends on the application's exposure and preconditions.

## Publication gate

Before a detailed entry becomes public:

1. Confirm the relevant upstream record is already public.
2. Recheck current source and public history.
3. Verify the stated credit against the upstream record.
4. Link a primary public source.
5. Remove local paths, private correspondence, reproducer material, and
   confidential identifiers.
6. Run scripts/validate_public_data.py.
7. Review the generated dist/ tree rather than relying on source intent.
