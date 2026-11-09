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
to crash the evaluator. The GPS boundary is inclusive: exactly 100 m passes this
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
