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
