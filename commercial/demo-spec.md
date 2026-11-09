# ∂ss — Reproducible Demonstration Specification

## Objective

Demonstrate the decision discipline of ∂ss without implying that a synthetic demonstration proves production accuracy.

The demo must make three outcomes visible:
- VERIFIED — the supplied record already satisfies the declared identity checks.
- CORRECTED — an authorised transformation was applied and the return check passed.
- UNRESOLVED — evidence is insufficient, conflicting or ambiguous; no automatic landing occurs.

## Demonstration boundary

Use synthetic addresses only. They must be clearly labelled fictional and must not be represented as valid delivery points. Do not query, scrape or redistribute PAF data without appropriate rights.

## Required scenarios

1. **Exact match:** candidate is identical under the declared comparison rules.
2. **Safe formatting normalisation:** casing and whitespace differ, while identity-bearing fields remain equal.
3. **Typographical candidate:** a candidate is textually close, but the return check must establish whether the permitted correction is safe.
4. **Conflicting postcode:** street/premise and postcode evidence disagree; return UNRESOLVED.
5. **Ambiguous premise:** two candidates remain plausible; return UNRESOLVED.
6. **No candidate:** no authoritative candidate supports the intended record; return UNRESOLVED.
7. **Return-check failure:** a candidate is selected but the post-operation comparison fails; refuse the landing.

## Interface

For each case, display:
- Input/intended record.
- Candidate(s) and provenance.
- Normalisation applied.
- Field-by-field comparison for every candidate, including its zero-based list position, raw and normalised values, normalised equality, retrieval eligibility, protected-field checks, disposition and candidate-level reason codes. Candidate position must disambiguate repeated source identifiers.
- Operation performed or refused.
- Return-check result.
- Terminal state and reason code.
- Deterministic trace ID bound to the case, candidate positions, ruleset version, trace-schema version, normalisation rule and decision outcome; separate ruleset/schema versions and declared normalisation rule. The demo trace ID is a convenience key, not a cryptographic integrity claim.

## Safety and truthfulness

- Similarity score is evidence, not proof of identity.
- A postcode match alone is not proof of a unique premise.
- Do not claim geographical precision from a postal address. Royal Mail notes that postcodes are routing instructions and are not intended to pinpoint exact satellite-navigation locations.
- Do not use "verified" to mean merely "a candidate was returned". Define the exact invariant that was checked.
- Keep synthetic data separate from any customer dataset.

## Definition of done

A reviewer unfamiliar with ∂ss can:
1. Run all scenarios from a documented command.
2. See why each case received its terminal state.
3. Reproduce the same output from the same code and configuration.
4. Confirm that conflicting or ambiguous cases are not silently auto-accepted.
5. Export a machine-readable trace and summary metrics.
6. Inspect every candidate's field evidence and understand why it was selected, refused or left ambiguous.
7. Run an independent trace audit that detects altered or missing candidate evidence, falsified candidate dispositions, invalid selection references, an incorrect aggregate outcome and an inconsistent deterministic trace ID.\n8. Export the audited trace array against the published Draft 2020-12 JSON Schema, with an explicit schema version separate from the decision-ruleset version.

The demo is not complete until the executable implementation, automated tests, and documented results are present. This specification alone is not evidence of working software.


## Export contract

The audited `--json-out` array is specified by [`../demo/schemas/candidate-trace-v1.schema.json`](../demo/schemas/candidate-trace-v1.schema.json). Consumers should validate against the pinned schema version and treat unknown properties as incompatible. A breaking export-shape change requires a new schema version; the decision ruleset version remains independently managed.
