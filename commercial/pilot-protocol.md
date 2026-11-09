# ∂ss — Pilot and Evaluation Protocol

## Purpose

Evaluate whether the ∂ss control loop reduces unsafe address acceptance while maintaining useful resolution coverage and an operationally acceptable review burden.

This protocol does not assume that ∂ss already achieves any performance target. Targets are agreed with the pilot customer before the test set is opened.

## 1. Dataset requirements

Use a customer-approved dataset with documented lawful basis, data minimisation, retention period, access controls and permitted processing. Do not upload personal address data to a public repository or public demo.

Each test case should contain:
- Stable, pseudonymous case ID.
- Original intended address record.
- Candidate set and source/provenance.
- Gold-standard intended delivery point or an explicit "no unique answer" label.
- Known corruption/ambiguity category.
- Dataset version and label provenance.

Suggested case strata:
- Exact record.
- Formatting-only variation.
- Typographical error.
- Missing premise identifier.
- Conflicting postcode and street.
- Multiple plausible premises.
- New/unknown address absent from reference data.
- Flat/sub-premise ambiguity.
- Stale or superseded address.
- Deliberately misleading near-match.

Split data into development and held-out evaluation sets. Keep all variants of the same underlying address in one split to prevent leakage. Record class balance and sampling method.

## 2. Baselines

Run the customer's existing process on the same held-out cases. Where relevant, include:
- Exact-match baseline.
- Existing address provider or candidate-generation service.
- ∂ss control workflow using the same candidates and reference data.

Do not compare systems using different reference datasets, licensing rights, candidate pools or label rules without disclosing the difference.

## 3. Required metrics

Report counts as well as rates, with confidence intervals where sample size permits.

- **False-accept rate:** incorrectly accepted records / all records automatically accepted.
- **False-accept prevalence:** incorrectly accepted records / all evaluation records.
- **Correct auto-resolution rate:** correctly resolved automatically / all evaluation records.
- **Coverage:** automatically resolved records / all evaluation records.
- **Unresolved rate:** unresolved records / all evaluation records.
- **Correction precision:** correct corrections / all corrections applied.
- **Review burden:** cases routed to human review and median review time.
- **Latency:** median and 95th percentile processing time.
- **Trace completeness:** decisions with all required evidence, rule/version and operation fields / all decisions.

Never report a zero false-accept rate without its numerator, denominator, sample composition and uncertainty. A small test set cannot establish a universal zero-error guarantee.

## 4. Acceptance criteria

Agree criteria with the customer before evaluation. A sample template:

- False-accept rate is below the customer's pre-agreed risk threshold.
- Correct auto-resolution coverage does not fall below the agreed minimum.
- Every automatic correction passes the return check.
- Every unresolved case is retained and routed according to the agreed workflow.
- Trace completeness meets the agreed audit requirement.
- Latency and operating cost remain within the customer's limits.

The customer owns risk thresholds. No universal threshold is asserted here.

## 5. Decision trace schema

For each case, preserve at minimum:
- case_id
- intended_record_hash or protected reference
- candidate IDs and evidence provenance
- normalisation and comparison rules with versions
- selected candidate, if any
- operation performed, if any
- return-check result and field-level differences
- terminal state
- reason code
- timestamp and software version

Avoid storing raw personal data in logs unless strictly necessary and explicitly approved. Prefer pseudonymous identifiers and protected references.

## 6. Reproducibility

- Freeze code commit, configuration, rules and reference-data version.
- Freeze the held-out dataset and label file before running.
- Record environment and dependency versions.
- Run each baseline and ∂ss on identical cases.
- Preserve machine-readable outputs and a human-readable report.
- Have an independent reviewer inspect all false accepts and a sample of each other outcome.
- Publish only synthetic or appropriately anonymised examples.

## 7. Pilot report

The final report must state:
1. Scope and exclusions.
2. Data provenance and permissions.
3. Dataset size and strata.
4. Baseline and ∂ss results with denominators.
5. False accepts and unresolved cases inspected individually.
6. Operational impact, latency and cost.
7. Limitations and unresolved risks.
8. Recommendation: stop, revise, extend or proceed to integration.
