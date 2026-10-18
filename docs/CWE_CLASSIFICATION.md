# CWE classification protocol

The ledger maps demonstrated weaknesses, not severity labels or hypothetical
exploit outcomes. Mappings follow MITRE's root-cause mapping guidance and are
reviewed against CWE List 4.20, published 2026-04-30.

## Decision procedure

For each detailed public record:

1. Read the public upstream fix or report together with the retained
   experimental evidence.
2. State the concrete defect that produced the observation.
3. Select the most specific Base or Variant CWE whose definition matches that
   defect and whose vulnerability-mapping status is `Allowed`. A Class entry
   marked `Allowed-with-Review` is used only when it describes the demonstrated
   root cause more accurately than an available Base or Variant.
4. Record that entry as the primary CWE. Add a consequence CWE only when the
   downstream weakness was separately observed. Confidentiality, integrity,
   availability, severity, and exploit prerequisites remain prose impact
   statements rather than substitute CWE mappings.
5. Use `pending classification` when the evidence does not support a specific,
   mapping-eligible entry. Do not force a high-level or discouraged mapping.

Private workflow cards are aggregate counts, not detailed findings. They do
not receive public CWE mappings before coordinated disclosure permits the
underlying records to be published.

## Reproducibility

`vendor/cwe/cwe-4.20-subset.json` was extracted from MITRE's version-specific
official archive:

- Source: <https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip>
- Archive SHA-256:
  `3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50`

To reproduce the subset after downloading that archive:

~~~sh
python3 scripts/extract_cwe_catalog_subset.py /path/to/cwec_v4.20.xml.zip
~~~

The extractor derives the required IDs from the public records and copies the
official name, abstraction, entry status, and vulnerability-mapping status.
`scripts/validate_public_data.py` then fails the build if an ID or title does
not match the pinned catalog, a mapping is discouraged or prohibited, or a
record does not use the primary/consequence/pending schema.

The mapping rationale remains human-reviewed because taxonomy selection
depends on the demonstrated causal chain. The machine check establishes
catalog identity and schema consistency; it does not claim to infer root cause.
