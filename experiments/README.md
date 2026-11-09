# Synthetic Vehicle-Event Collision Benchmark

This experiment applies the ∂ss return-check discipline to fictional parcel journeys.
It is inspired by the *method* of controlled experiments (prepare known conditions,
introduce disturbances, observe detector outcomes), not by particle physics itself.
No LHC data, physical collision data, live telemetry, customer records or licensed
address data are used.

## Run

```bash
python experiments/vehicle_collision_bench.py
python experiments/vehicle_collision_bench.py --total 10000 --seed 88 --json-out vehicle-bench.json
python -c "from experiments.vehicle_collision_bench import benchmark, generate_compound_dataset; import json; print(json.dumps(benchmark(generate_compound_dataset(1200)), indent=2))"
python -m unittest discover -s tests -v
```

## Experimental design

The default dataset contains 10,000 deterministic journeys:

- 5,000 clean journeys
- 1,000 with GPS distance above the declared 100 m threshold
- 1,000 with a parcel identity mismatch
- 1,000 with a destination identity mismatch
- 1,000 with non-monotonic event timestamps
- 1,000 with missing delivery proof

The evaluator returns `VERIFIED` only when all six declared checks pass.
Otherwise it returns `UNRESOLVED` and names the failed checks. This benchmark
does not attempt fuzzy correction.

## Evidence classification

An unresolved journey now carries an `evidence_class` as well as reason codes:

- `INSUFFICIENT`: a required observation or reference is absent (for example, no delivery GPS or proof reference).
- `CONFLICTING`: observations contradict a declared invariant (for example, parcel identity changes or event timestamps run backwards).
- `MIXED`: at least one required item is missing and at least one observed item conflicts.
- `SUFFICIENT_AND_CONSISTENT`: all required evidence is present and all declared checks pass.

All unresolved classes remain `UNRESOLVED`; missing information is never promoted
to a successful verification. Malformed journey objects, malformed event records,
missing identity fields, duplicate/out-of-order event types, invalid timestamps and
negative or non-finite GPS distances are refused with reason codes rather than allowed
to crash the evaluator. Individually valid event records are still inspected when a
sibling record is malformed, so a schema defect does not erase independent observed
identity conflicts or other evidence. The GPS boundary is inclusive: exactly 100 m passes this
illustrative rule; any larger value fails. A proof reference is checked for presence
only, not cryptographic authenticity or independent authority. GPS is a supplied
distance value, not a raw-coordinate measurement. Timestamps are synthetic numeric
ticks used only for ordering; they do not represent wall-clock time or a timezone.

## Compound-disturbance experiment

The `generate_compound_dataset(1200)` experiment contains 400 clean journeys and
800 journeys carrying two or three simultaneous disturbances. It covers every
pair and every triple drawn from the five disturbance classes, with balanced
representation. This tests combinations rather than only isolated faults. Run it
from Python with:

```python
from experiments.vehicle_collision_bench import benchmark, generate_compound_dataset
report = benchmark(generate_compound_dataset(1200, seed=88))
print(report)
```

The generated compound cases are still rule-shaped synthetic tests; they are not
independent evidence of field performance.

A permutation test applies every pair and triple in every possible injection order.
For the current five anomaly classes, the resulting event evidence and evaluator
trace must be identical regardless of ordering. This checks that the compound
results are not an accidental consequence of which fixture mutation ran last.

The report's `pair_interaction_matrix` evaluates every unordered anomaly pair
co-occurring in a compound journey. Each pair records both-detected, first-only,
second-only and neither-detected outcomes, per-fault and joint detection rates,
and observed reason-code and terminal-state counts. Pairs are also counted inside three-anomaly journeys, so
these figures describe pair co-occurrence within the full compound dataset rather
than only isolated two-fault trials. The matrix is computed after evaluator output
is produced; synthetic labels remain benchmark-side oracle metadata.

## Reported measures

- **Anomaly detection rate:** injected anomalous journeys returned as `UNRESOLVED`
- **False accepts:** injected anomalous journeys incorrectly returned as `VERIFIED`
- **Clean acceptance rate:** clean journeys returned as `VERIFIED`
- **False rejects:** clean journeys incorrectly returned as `UNRESOLVED`
- **Reason-code frequency:** number of evaluated journeys carrying each reason code
- **Reason combinations:** frequency of each exact, sorted reason-code set (joined with ` + `)
- **Condition-level fingerprints:** reason-code and exact-combination counts grouped by the synthetic injected condition
- **Anomaly-to-invariant matrix:** each injected disturbance is mapped to its declared evaluator reason code; matrix rows show all reason codes observed in journeys carrying that disturbance
- **Per-anomaly detection:** injected, detected, missed and detection-rate counts for each disturbance
- **Clean reason-code counts:** any evaluator refusal reason appearing in journeys labelled clean
- **Interaction fingerprints:** exact reason-code combinations for controlled cases where one disturbance creates a secondary symptom or masks the primary diagnostic code
- **Interaction diagnostic summaries:** per-fixture counts of primary detections, missed primary diagnoses, diagnostic statuses and secondary symptoms
- **Pairwise interaction matrix:** for every anomaly pair appearing in compound journeys, counts cases where both expected reason codes, only the first, only the second, or neither were observed, alongside reason-code and terminal-state frequencies

Two interaction fixtures are available through `make_interaction_journey`:

- `reordered_events` + `sequence_echo`: the journey carries both a timestamp-order conflict and an event-sequence mismatch. The primary invariant remains detectable while the secondary symptom is exposed.
- `wrong_parcel` + `missing_parcel_masks_conflict`: the delivery parcel field is then made blank. The evaluator reports the missing field rather than the underlying identity conflict. The primary injected fault is therefore refused but not specifically diagnosed by its expected reason code.
- `wrong_parcel` + `missing_parcel_with_separate_conflict`: a different event's parcel field is made blank while the wrong delivery identity remains observable. The evaluator must report both the missing field and the separate identity conflict.
- `wrong_destination` + `missing_destination_with_separate_conflict`: the same independent-evidence check for destination identity.

These are deliberately constructed diagnostic stress cases, not statistical models of how often such interactions occur. A refusal can be correct while its diagnostic attribution is incomplete; the per-anomaly detection measure makes that distinction visible.

Identity diagnosis is field-aware rather than mutually exclusive: a missing value
must not suppress a contradictory non-empty value observed in another event. Parcel
and destination expectations are also validated independently: an absent expected
parcel ID must not suppress an independently testable destination conflict, and an
absent expected destination ID must not suppress a parcel conflict. The aggregate
`EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID` reason and
`expected_identity_fields_present` check remain for compatibility. The trace also
exposes `expected_parcel_id_present` and
`expected_destination_id_present` separately, with specific reason codes
`EXPECTED_PARCEL_ID_MISSING_OR_INVALID` and
`EXPECTED_DESTINATION_ID_MISSING_OR_INVALID` when either reference is absent.
When the only conflicting value itself is erased, the evaluator cannot infer it
and reports only what remains observable. This distinguishes evidence loss from
reason-code precedence.

Each evaluator trace now includes `evidence_provenance`, a deterministic list with
one entry per emitted reason code. Each entry identifies the evidence kind
(`missing`, `conflict` or `consistent`), source, field names, original zero-based
event indices and the declared comparison rule. Event indices refer to the input
list before malformed records are skipped, so an auditor can locate evidence in
the original journey. Provenance records deliberately omit raw observed and
expected values; they provide locations and rules without duplicating potentially
sensitive identity data. The success marker receives a `consistent` provenance
entry and remains distinct from failure findings. These are evaluator-produced
evidence pointers, not cryptographic attestations or proof that upstream source
data is authentic.

The report's `interaction_diagnostic_summary` keeps these fixture outcomes separate:
it counts primary detections and misses, diagnostic statuses and observed secondary
symptoms for each named interaction. This makes a masking failure visible without
relying on a reader to reconstruct it from individual traces.

The declared oracle mapping is explicit: `gps_drift` → `DELIVERY_GPS_OUTSIDE_LIMIT`,
`wrong_parcel` → `PARCEL_IDENTITY_CONFLICT`, `wrong_destination` →
`DESTINATION_IDENTITY_CONFLICT`, `reordered_events` → `TIMESTAMP_ORDER_CONFLICT`,
and `missing_proof` → `DELIVERY_PROOF_REFERENCE_MISSING`. For compound journeys,
each injected disturbance is counted as one occurrence. A disturbance is detected only
when its mapped reason code appears in the evaluator's reason list. Other reason codes
in that same row remain visible, exposing co-occurrence and unexpected classifications.
This is a test-oracle mapping for the synthetic generator, not a claim that every real
operational fault has one unique diagnostic signature.

`by_condition` is the oracle-condition × evaluator-terminal-state matrix: the left-hand labels
come from the generator's `injected_condition` metadata, while terminal states and reason
codes come from the evaluator. The evaluator does not read that metadata. This separation
keeps the expected synthetic condition from influencing the observed decision. The report
sorts keys for deterministic, JSON-friendly output. A clean journey's
`ALL_DECLARED_CHECKS_PASSED` marker is counted like any other reason code for frequency
accounting; it is a success marker, not a failure.

## Oracle-relative diagnostic traces

Each benchmark report now includes a deterministic `diagnostic_records` list and
`diagnostic_status_counts`. These records are created **after** the evaluator has
returned its evidence-derived trace. They compare the evaluator's observed reason
codes with the generator's synthetic oracle mapping; they are not evaluator inputs.

For a single injected disturbance, the record names the `primary_fault`, its
`expected_reason_code`, whether that code was detected, all observed reason codes,
and `secondary_symptoms` (observed codes other than the expected primary code).
Statuses are:

- `PRIMARY_IDENTIFIED`: the expected primary code appears without additional symptoms.
- `PRIMARY_IDENTIFIED_WITH_SYMPTOMS`: the expected primary code appears alongside other findings.
- `PRIMARY_MASKED`: the journey is refused, but the expected primary code is absent.
- `UNATTRIBUTED`: there is no single injected primary fault, or an anomalous case was not refused.
- `CLEAN`: no disturbance was injected.

Compound cases are deliberately marked `UNATTRIBUTED` at the single-primary level;
their injected faults and observed codes remain available in the record. No numeric
confidence score is reported: this experiment has no calibrated probability model.
The diagnostic trace is an oracle-relative benchmark assessment, not a claim that
the evaluator independently knows the injected cause. A correct refusal can still
have incomplete diagnostic attribution.

## Interpretation and limitations

A perfect score on this generated dataset demonstrates only that the implementation
enforces its own explicit rules against the disturbances deliberately injected.
It does **not** establish real-world GPS accuracy, proof-of-delivery reliability,
address resolution accuracy, fraud detection, operational performance or superiority
over a courier's existing systems.

The 100 m GPS threshold is an illustrative test parameter, not a recommended
universal delivery radius. Real deployment would require domain-specific tolerances,
clock and event semantics, trusted identity sources, data protection review,
representative labelled data and independent baseline comparison.

The benchmark is a deterministic test instrument, not a production tracking system.
