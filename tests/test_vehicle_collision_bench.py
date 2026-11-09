import copy
import random
import sys
from itertools import combinations, permutations
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from vehicle_collision_bench import (  # noqa: E402
    ANOMALIES, audit_provenance, audit_provenance_trace, benchmark, evaluate_journey,
    generate_compound_dataset, generate_dataset, make_compound_journey,
    make_interaction_journey, make_journey,
)


class VehicleCollisionBenchTests(unittest.TestCase):
    def test_clean_journey_is_verified(self):
        result = evaluate_journey(make_journey(1))
        self.assertEqual(result["terminal_state"], "VERIFIED")
        self.assertEqual(result["reason_codes"], ["ALL_DECLARED_CHECKS_PASSED"])

    def test_full_compound_dataset_provenance_audit_is_consistent(self):
        journeys = generate_compound_dataset(1200, seed=88)
        audit = benchmark(journeys)["provenance_audit"]
        self.assertEqual(audit["journey_count"], 1200)
        self.assertEqual(audit["valid_journey_count"], 1200)
        self.assertEqual(audit["invalid_journey_count"], 0)
        self.assertEqual(audit["reason_count"], 2400)
        self.assertEqual(audit["provenance_entry_count"], 2400)
        self.assertEqual(audit["missing_reason_entry_count"], 0)
        self.assertEqual(audit["orphaned_entry_count"], 0)
        self.assertEqual(audit["duplicate_entry_count"], 0)
        self.assertEqual(audit["unsupported_finding_count"], 0)
        self.assertEqual(audit["invalid_pointer_count"], 0)
        self.assertEqual(audit["unreported_reason_count"], 0)
        self.assertEqual(audit["unexpected_reason_count"], 0)
        self.assertEqual(audit["decision_mismatch_count"], 0)
        self.assertEqual(audit["journeys_with_shared_event_findings"], 800)
        self.assertEqual(audit["shared_event_reference_count"], 800)
        self.assertTrue(audit["all_findings_distinct_by_reason_code"])

    def test_provenance_audit_rejects_missing_and_unreported_entries(self):
        journey = make_journey(901, "wrong_parcel")
        result = evaluate_journey(journey)
        result["evidence_provenance"] = []
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertEqual(audit["missing_reason_entries"], ["PARCEL_IDENTITY_CONFLICT"])
        self.assertEqual(audit["orphaned_provenance_entries"], [])

        result = evaluate_journey(journey)
        orphan = copy.deepcopy(result["evidence_provenance"][0])
        orphan["reason_code"] = "NOT_REPORTED_FINDING"
        result["evidence_provenance"].append(orphan)
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertEqual(audit["orphaned_provenance_entries"], ["NOT_REPORTED_FINDING"])

    def test_decision_audit_rejects_tampered_terminal_class_and_checks(self):
        journey = make_journey(916)
        mutations = {
            "terminal_state": lambda result: result.update(terminal_state="UNRESOLVED"),
            "evidence_class": lambda result: result.update(evidence_class="CONFLICTING"),
            "check_value": lambda result: result["checks"].update(delivery_within_gps_limit=False),
            "check_removed": lambda result: result["checks"].pop("timestamps_monotonic"),
            "check_fabricated": lambda result: result["checks"].update(unearned_check=True),
        }
        for name, mutate in mutations.items():
            result = evaluate_journey(journey)
            mutate(result)
            audit = audit_provenance_trace(journey, result)
            with self.subTest(mutation=name):
                self.assertFalse(audit["valid"], msg=audit)
                self.assertIn("checks" if name.startswith("check") else name, audit["decision_mismatches"])

        refused = make_journey(917, "wrong_parcel")
        result = evaluate_journey(refused)
        result["terminal_state"] = "VERIFIED"
        audit = audit_provenance_trace(refused, result)
        self.assertFalse(audit["valid"])
        self.assertIn("terminal_state", audit["decision_mismatches"])

    def test_provenance_audit_is_independent_for_clean_success_marker(self):
        journey = make_journey(907)
        result = evaluate_journey(journey)
        with patch(
            "vehicle_collision_bench.evaluate_journey",
            return_value={"terminal_state": "UNRESOLVED"},
        ):
            audit = audit_provenance_trace(journey, result)
        self.assertTrue(audit["valid"], msg=audit)

    def test_dataset_audit_aggregates_malformed_and_interaction_traces(self):
        journeys = [
            make_interaction_journey(909, "reordered_events", "sequence_echo"),
            make_interaction_journey(910, "wrong_parcel", "missing_parcel_masks_conflict"),
            make_interaction_journey(
                911, "wrong_parcel", "missing_parcel_with_separate_conflict"
            ),
            make_journey(912),
        ]
        journeys[3]["events"].insert(1, "malformed-event")
        audit = audit_provenance(journeys)
        self.assertEqual(audit["journey_count"], 4)
        details = [
            (journey["journey_id"], audit_provenance_trace(journey, evaluate_journey(journey)))
            for journey in journeys
        ]
        self.assertEqual(audit["valid_journey_count"], 4, msg=str(details))
        self.assertEqual(audit["invalid_journey_count"], 0)
        self.assertEqual(audit["missing_reason_entry_count"], 0)
        self.assertEqual(audit["orphaned_entry_count"], 0)
        self.assertEqual(audit["duplicate_entry_count"], 0)
        self.assertEqual(audit["unsupported_finding_count"], 0)
        self.assertEqual(audit["invalid_pointer_count"], 0)
        self.assertEqual(audit["unreported_reason_count"], 0)
        self.assertEqual(audit["unexpected_reason_count"], 0)

    def test_dataset_audit_rejects_malformed_outer_collections(self):
        for journeys in (None, "journey", {}, 4, (make_journey(1),)):
            with self.subTest(journeys=journeys):
                with self.assertRaisesRegex(TypeError, "journeys must be a list"):
                    audit_provenance(journeys)

        journey_list = [make_journey(2)]
        for results in ("result", {}, 4, (evaluate_journey(journey_list[0]),)):
            with self.subTest(results=results):
                with self.assertRaisesRegex(TypeError, "results must be a list or None"):
                    audit_provenance(journey_list, results=results)

    def test_dataset_audit_rejects_trace_count_mismatch(self):
        with self.assertRaisesRegex(ValueError, "exactly one trace per journey"):
            audit_provenance([make_journey(913)], results=[])

    def test_decision_audit_rejects_structurally_malformed_decision_fields(self):
        journey = make_journey(921)
        mutations = (
            ("checks", None),
            ("checks", []),
            ("checks", "not-a-map"),
            ("evidence_class", []),
            ("evidence_class", {"status": "forged"}),
            ("terminal_state", None),
            ("terminal_state", ["VERIFIED"]),
            ("reason_codes", None),
            ("reason_codes", "ALL_DECLARED_CHECKS_PASSED"),
            ("evidence_provenance", {}),
        )
        for field, value in mutations:
            result = evaluate_journey(journey)
            result[field] = value
            audit = audit_provenance_trace(journey, result)
            with self.subTest(field=field, value=value):
                self.assertFalse(audit["valid"], msg=audit)

    def test_provenance_audit_rejects_non_object_result_and_unhashable_codes(self):
        journey = make_journey(918)
        for malformed in (None, "not-a-result", 17, []):
            with self.subTest(result=malformed):
                audit = audit_provenance_trace(journey, malformed)
                self.assertFalse(audit["valid"], msg=audit)
                self.assertIn(
                    "<malformed-result-object>",
                    audit["unsupported_findings"],
                )
                self.assertIn("checks", audit["decision_mismatches"])

        result = evaluate_journey(journey)
        result["reason_codes"] = [{"forged": "code"}]
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertIn("<invalid-reason-code>", audit["unsupported_findings"])
        self.assertEqual(audit["distinct_finding_count"], 0)

    def test_provenance_audit_rejects_malformed_dataset_result_items(self):
        journeys = [make_journey(919), make_journey(920, "wrong_parcel")]
        for malformed in (None, "bad-result", 4, []):
            audit = audit_provenance(journeys, results=[evaluate_journey(journeys[0]), malformed])
            self.assertEqual(audit["journey_count"], 2)
            self.assertEqual(audit["valid_journey_count"], 1)
            self.assertEqual(audit["invalid_journey_count"], 1)
            self.assertEqual(audit["decision_mismatch_count"], 3)

    def test_provenance_audit_survives_deterministic_nested_mutation_matrix(self):
        """Exercise JSON-shaped corruption at every nested audit boundary."""
        journey = make_journey(917, "wrong_parcel")
        baseline = evaluate_journey(journey)
        mutations = (
            ("checks", None), ("checks", [True]), ("checks", {"forged": []}),
            ("evidence_class", {"nested": [None]}),
            ("terminal_state", {"state": "VERIFIED"}),
            ("reason_codes", [None]), ("reason_codes", [[]]),
            ("reason_codes", [{}]), ("reason_codes", [17]),
            ("reason_codes", {"not": "a-list"}),
            ("evidence_provenance", [None]),
            ("evidence_provenance", [{"reason_code": []}]),
            ("evidence_provenance", {"not": "a-list"}),
        )
        for field, value in mutations:
            result = copy.deepcopy(baseline)
            result[field] = value
            with self.subTest(field=field, value=value):
                audit = audit_provenance_trace(journey, result)
                self.assertFalse(audit["valid"], msg=audit)

        pointer_mutations = (
            [True], [1.5], [-1], ["0"], [{}], [[]], [None], [0, "1"],
        )
        for indices in pointer_mutations:
            result = copy.deepcopy(baseline)
            result["evidence_provenance"][0]["event_indices"] = indices
            with self.subTest(event_indices=indices):
                audit = audit_provenance_trace(journey, result)
                self.assertFalse(audit["valid"], msg=audit)

        entry_mutations = (
            {"evidence_kind": []}, {"source": {}}, {"fields": [None]},
            {"fields": {"parcel_id": True}}, {"rule": ["forged"]},
            {"reason_code": {"nested": []}},
        )
        for changes in entry_mutations:
            result = copy.deepcopy(baseline)
            result["evidence_provenance"][0].update(changes)
            with self.subTest(provenance_changes=changes):
                audit = audit_provenance_trace(journey, result)
                self.assertFalse(audit["valid"], msg=audit)

    def test_provenance_audit_rejects_pairwise_compound_tampering(self):
        """Pair individually plausible corruptions to exercise failure interactions."""
        journey = make_journey(916, "wrong_destination")
        baseline = evaluate_journey(journey)
        mutations = (
            ("checks", lambda result: result.update(checks={})),
            ("class", lambda result: result.update(evidence_class="SUFFICIENT_AND_CONSISTENT")),
            ("terminal", lambda result: result.update(terminal_state="VERIFIED")),
            ("reasons", lambda result: result["reason_codes"].clear()),
            ("provenance", lambda result: result["evidence_provenance"].append(copy.deepcopy(result["evidence_provenance"][0]))),
            ("pointer", lambda result: result["evidence_provenance"][0].update(event_indices=[True])),
            ("rule", lambda result: result["evidence_provenance"][0].update(rule="")),
        )
        for left, right in combinations(mutations, 2):
            result = copy.deepcopy(baseline)
            left[1](result)
            right[1](result)
            audit = audit_provenance_trace(journey, result)
            with self.subTest(pair=(left[0], right[0])):
                self.assertFalse(audit["valid"], msg=audit)

    def test_evaluator_and_audit_agree_under_pairwise_evidence_mutations(self):
        """Exercise deterministic two-field corruption of the source journey."""
        mutations = (
            ("journey_id", lambda j: j.update(journey_id=None)),
            ("expected_parcel", lambda j: j.update(expected_parcel_id=[])),
            ("expected_destination", lambda j: j.update(expected_destination_id=0)),
            ("event_type", lambda j: j["events"][0].update(type="delivered")),
            ("parcel", lambda j: j["events"][1].update(parcel_id={"bad": True})),
            ("destination", lambda j: j["events"][2].update(destination_id="OTHER")),
            ("timestamp", lambda j: j["events"][0].update(timestamp=float("nan"))),
            ("gps", lambda j: j["events"][2].update(gps_distance_m=float("inf"))),
            ("proof", lambda j: j["events"][2].update(proof_id=[])),
        )
        bases = (
            make_journey(930),
            make_compound_journey(931, ("gps_drift", "wrong_parcel")),
        )
        checked = 0
        for base in bases:
            for left, right in combinations(mutations, 2):
                journey = copy.deepcopy(base)
                left[1](journey)
                right[1](journey)
                result = evaluate_journey(journey)
                audit = audit_provenance_trace(journey, result)
                with self.subTest(base=base["journey_id"], pair=(left[0], right[0])):
                    self.assertEqual(result["terminal_state"], "UNRESOLVED")
                    self.assertTrue(audit["valid"], msg=audit)
                    self.assertEqual(
                        [entry["reason_code"] for entry in result["evidence_provenance"]],
                        sorted(result["reason_codes"]),
                    )
                checked += 1
        self.assertEqual(checked, 72)

    def test_evaluator_and_audit_agree_on_malformed_event_containers(self):
        malformed_containers = (None, "events", {}, 7, (make_journey(932)["events"]))
        for index, events in enumerate(malformed_containers):
            journey = make_journey(932 + index)
            journey["events"] = copy.deepcopy(events)
            result = evaluate_journey(journey)
            audit = audit_provenance_trace(journey, result)
            with self.subTest(events=events):
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertTrue(audit["valid"], msg=audit)
    def test_seeded_mutation_walk_preserves_evaluator_audit_agreement(self):
        """Run reproducible multi-field evidence mutations across varied baselines."""
        rng = random.Random(20261109)
        mutations = (
            lambda j: j.update(journey_id=None),
            lambda j: j.update(expected_parcel_id=[]),
            lambda j: j.update(expected_destination_id=0),
            lambda j: j["events"][0].update(type="unknown"),
            lambda j: j["events"][1].update(parcel_id={"bad": True}),
            lambda j: j["events"][2].update(destination_id="OTHER"),
            lambda j: j["events"][0].update(timestamp=float("nan")),
            lambda j: j["events"][2].update(gps_distance_m=float("inf")),
            lambda j: j["events"][2].update(proof_id=[]),
            lambda j: j["events"][1].update(timestamp=-1),
        )
        for index in range(256):
            base = (
                make_journey(940 + index)
                if index % 2 == 0
                else make_compound_journey(940 + index, ("gps_drift", "wrong_parcel"))
            )
            journey = copy.deepcopy(base)
            for mutation_index in rng.sample(range(len(mutations)), rng.randint(1, 4)):
                mutations[mutation_index](journey)
            result = evaluate_journey(journey)
            audit = audit_provenance_trace(journey, result)
            with self.subTest(case=index, seed=20261109):
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertTrue(audit["valid"], msg=audit)
                self.assertEqual(
                    [item["reason_code"] for item in result["evidence_provenance"]],
                    sorted(result["reason_codes"]),
                )
    def test_dataset_audit_aggregates_seeded_evidence_and_decision_mutations(self):
        rng = random.Random(20261110)
        mutations = (
            lambda j: j.update(journey_id=None),
            lambda j: j.update(expected_parcel_id=[]),
            lambda j: j["events"][0].update(type="unknown"),
            lambda j: j["events"][1].update(parcel_id="OTHER"),
            lambda j: j["events"][2].update(destination_id=None),
            lambda j: j["events"][0].update(timestamp=float("nan")),
            lambda j: j["events"][2].update(gps_distance_m=-1),
            lambda j: j["events"][2].update(proof_id={}),
        )
        journeys, results = [], []
        for index in range(96):
            journey = make_journey(1200 + index)
            for mutation_index in rng.sample(range(len(mutations)), rng.randint(1, 3)):
                mutations[mutation_index](journey)
            result = evaluate_journey(journey)
            if index % 12 == 0:
                result["terminal_state"] = "VERIFIED"
            journeys.append(journey)
            results.append(result)
        individual = [
            audit_provenance_trace(journey, result)
            for journey, result in zip(journeys, results)
        ]
        aggregate = audit_provenance(journeys, results=results)
        self.assertEqual(aggregate["journey_count"], 96)
        self.assertEqual(aggregate["valid_journey_count"], 88)
        self.assertEqual(aggregate["invalid_journey_count"], 8)
        self.assertEqual(
            aggregate["decision_mismatch_count"],
            sum(len(trace["decision_mismatches"]) for trace in individual),
        )
        self.assertEqual(
            aggregate["invalid_pointer_count"],
            sum(len(trace["invalid_evidence_pointers"]) for trace in individual),
        )
        counter_pairs = (
            ("reason_count", lambda trace: trace["reason_count"]),
            ("provenance_entry_count", lambda trace: trace["provenance_entry_count"]),
            ("missing_reason_entry_count", lambda trace: len(trace["missing_reason_entries"])),
            ("orphaned_entry_count", lambda trace: len(trace["orphaned_provenance_entries"])),
            ("duplicate_entry_count", lambda trace: len(trace["duplicate_reason_entries"])),
            ("unsupported_finding_count", lambda trace: len(trace["unsupported_findings"])),
            ("unreported_reason_count", lambda trace: len(trace["unreported_reason_codes"])),
            ("unexpected_reason_count", lambda trace: len(trace["unexpected_reason_codes"])),
            ("decision_mismatch_count", lambda trace: len(trace["decision_mismatches"])),
            ("shared_event_reference_count", lambda trace: len(trace["shared_event_indices"])),
        )
        for aggregate_key, measure in counter_pairs:
            self.assertEqual(
                aggregate[aggregate_key],
                sum(measure(trace) for trace in individual),
                msg=aggregate_key,
            )
        self.assertEqual(
            aggregate["journeys_with_shared_event_findings"],
            sum(bool(trace["shared_event_indices"]) for trace in individual),
        )
        self.assertEqual(
            aggregate["all_findings_distinct_by_reason_code"],
            all(not trace["duplicate_reason_entries"] for trace in individual),
        )
    def test_provenance_audit_handles_non_object_journeys(self):
        for malformed in (None, "not-a-journey", 17, []):
            with self.subTest(malformed=malformed):
                result = evaluate_journey(malformed)
                audit = audit_provenance_trace(malformed, result)
                self.assertTrue(audit["valid"], msg=audit)
                self.assertEqual(audit["missing_reason_entries"], [])
                self.assertEqual(audit["orphaned_provenance_entries"], [])

    def test_provenance_audit_rejects_malformed_trace_collections_and_indices(self):
        journey = make_journey(908)
        result = evaluate_journey(journey)
        result["evidence_provenance"][0]["event_indices"] = None
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertIn("ALL_DECLARED_CHECKS_PASSED", audit["invalid_evidence_pointers"])

        result = evaluate_journey(journey)
        result["evidence_provenance"] = None
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertIn("<malformed-trace-collections>", audit["unsupported_findings"])

    def test_provenance_audit_covers_interaction_and_malformed_refusal_fixtures(self):
        journeys = [
            make_interaction_journey(903, "reordered_events", "sequence_echo"),
            make_interaction_journey(904, "wrong_parcel", "missing_parcel_masks_conflict"),
            make_interaction_journey(
                905, "wrong_parcel", "missing_parcel_with_separate_conflict"
            ),
        ]
        malformed = make_journey(906)
        malformed["events"].insert(1, "malformed-event")
        malformed["events"][-1]["destination_id"] = "OTHER-DESTINATION"
        journeys.append(malformed)

        for journey in journeys:
            with self.subTest(journey_id=journey["journey_id"]):
                result = evaluate_journey(journey)
                audit = audit_provenance_trace(journey, result)
                self.assertTrue(audit["valid"], msg=audit)
                self.assertEqual(audit["missing_reason_entries"], [])
                self.assertEqual(audit["orphaned_provenance_entries"], [])
                self.assertEqual(audit["invalid_evidence_pointers"], [])

    def test_provenance_audit_rejects_wrong_event_and_field_pointers(self):
        journey = make_compound_journey(902, ("wrong_parcel", "wrong_destination"))
        result = evaluate_journey(journey)
        valid_audit = audit_provenance_trace(journey, result)
        self.assertTrue(valid_audit["valid"])
        self.assertEqual(valid_audit["shared_event_indices"], [2])
        parcel = next(
            item for item in result["evidence_provenance"]
            if item["reason_code"] == "PARCEL_IDENTITY_CONFLICT"
        )
        parcel["event_indices"] = [0]
        parcel["fields"] = ["destination_id"]
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", audit["invalid_evidence_pointers"])
        self.assertEqual(audit["shared_event_indices"], [])

    def test_provenance_audit_rejects_tampered_metadata_and_fabricated_findings(self):
        journey = make_journey(914, "wrong_parcel")
        mutations = {
            "evidence_kind": lambda entry: entry.update(evidence_kind="missing"),
            "source": lambda entry: entry.update(source="journey"),
            "fields": lambda entry: entry.update(fields=["destination_id"]),
            "event_indices": lambda entry: entry.update(event_indices=[0]),
            "rule": lambda entry: entry.update(rule="A plausible but false explanation."),
        }
        for field, mutate in mutations.items():
            result = evaluate_journey(journey)
            target = next(
                item for item in result["evidence_provenance"]
                if item["reason_code"] == "PARCEL_IDENTITY_CONFLICT"
            )
            mutate(target)
            audit = audit_provenance_trace(journey, result)
            with self.subTest(field=field):
                self.assertFalse(audit["valid"], msg=audit)
                self.assertIn(
                    "PARCEL_IDENTITY_CONFLICT",
                    audit["invalid_evidence_pointers"],
                )

        result = evaluate_journey(journey)
        result["evidence_provenance"].append(
            copy.deepcopy(result["evidence_provenance"][0])
        )
        duplicate_audit = audit_provenance_trace(journey, result)
        self.assertFalse(duplicate_audit["valid"])
        self.assertTrue(duplicate_audit["duplicate_reason_entries"])

        result = evaluate_journey(journey)
        fabricated = copy.deepcopy(result["evidence_provenance"][0])
        fabricated["reason_code"] = "FABRICATED_FINDING"
        result["evidence_provenance"].append(fabricated)
        fabricated_audit = audit_provenance_trace(journey, result)
        self.assertFalse(fabricated_audit["valid"])
        self.assertIn("FABRICATED_FINDING", fabricated_audit["unsupported_findings"])
        self.assertIn("FABRICATED_FINDING", fabricated_audit["orphaned_provenance_entries"])

    def test_provenance_audit_detects_silently_removed_reason_and_malformed_code(self):
        journey = make_journey(915, "wrong_parcel")
        result = evaluate_journey(journey)
        result["reason_codes"].remove("PARCEL_IDENTITY_CONFLICT")
        result["evidence_provenance"] = [
            item for item in result["evidence_provenance"]
            if item["reason_code"] != "PARCEL_IDENTITY_CONFLICT"
        ]
        audit = audit_provenance_trace(journey, result)
        self.assertFalse(audit["valid"])
        self.assertEqual(
            audit["unreported_reason_codes"], ["PARCEL_IDENTITY_CONFLICT"]
        )

        result = evaluate_journey(journey)
        result["evidence_provenance"][0]["reason_code"] = {"forged": "code"}
        malformed_audit = audit_provenance_trace(journey, result)
        self.assertFalse(malformed_audit["valid"])
        self.assertIn("<invalid-reason-code>", malformed_audit["unsupported_findings"])

    def test_evidence_provenance_covers_every_reason_without_copying_values(self):
        journeys = [make_journey(61)] + [
            make_journey(62 + index, anomaly)
            for index, anomaly in enumerate(ANOMALIES)
        ]
        for journey in journeys:
            with self.subTest(condition=journey["injected_condition"]):
                result = evaluate_journey(journey)
                provenance = result["evidence_provenance"]
                self.assertEqual(
                    [item["reason_code"] for item in provenance],
                    sorted(result["reason_codes"]),
                )
                for item in provenance:
                    self.assertIn(item["evidence_kind"], {"missing", "conflict", "consistent"})
                    self.assertIn("fields", item)
                    self.assertIn("event_indices", item)
                    self.assertIn("rule", item)
                    self.assertNotIn("observed_value", item)
                    self.assertNotIn("expected_value", item)
        clean = evaluate_journey(journeys[0])
        self.assertEqual(clean["evidence_provenance"][0]["evidence_kind"], "consistent")

    def test_each_single_fault_points_to_its_exact_evidence_field_and_event(self):
        expected = {
            "gps_drift": ("DELIVERY_GPS_OUTSIDE_LIMIT", "gps_distance_m", [2]),
            "wrong_parcel": ("PARCEL_IDENTITY_CONFLICT", "parcel_id", [2]),
            "wrong_destination": ("DESTINATION_IDENTITY_CONFLICT", "destination_id", [2]),
            "reordered_events": ("TIMESTAMP_ORDER_CONFLICT", "timestamp", [1, 2]),
            "missing_proof": ("DELIVERY_PROOF_REFERENCE_MISSING", "proof_id", [2]),
        }
        for anomaly, (reason, field, indices) in expected.items():
            with self.subTest(anomaly=anomaly):
                result = evaluate_journey(make_journey(78, anomaly))
                record = next(
                    item for item in result["evidence_provenance"]
                    if item["reason_code"] == reason
                )
                self.assertEqual(record["fields"], [field])
                self.assertEqual(record["event_indices"], indices)
                self.assertEqual(record["evidence_kind"], "conflict" if anomaly != "missing_proof" else "missing")

    def test_evidence_provenance_uses_original_indices_after_malformed_event(self):
        journey = make_journey(68)
        journey["events"].insert(1, "malformed-event")
        journey["events"][-1]["destination_id"] = "OTHER-DESTINATION"
        result = evaluate_journey(journey)
        provenance = {
            item["reason_code"]: item
            for item in result["evidence_provenance"]
        }
        self.assertEqual(
            provenance["DESTINATION_IDENTITY_CONFLICT"]["event_indices"],
            [3],
        )
        self.assertEqual(
            provenance["EVENT_RECORDS_MISSING_OR_INVALID"]["event_indices"],
            [1],
        )
        self.assertEqual(result["terminal_state"], "UNRESOLVED")

    def test_every_emitted_reason_has_provenance_under_malformed_inputs(self):
        invalid_values = (None, "", "   ", 0, False, [], {})
        cases = []
        for field in ("journey_id", "expected_parcel_id", "expected_destination_id", "events"):
            for invalid in invalid_values:
                journey = make_journey(69)
                journey[field] = copy.deepcopy(invalid)
                cases.append(journey)
        event_fields = ("type", "parcel_id", "destination_id", "timestamp",
                        "gps_distance_m", "proof_id")
        for event_index in range(3):
            for field in event_fields:
                for invalid in invalid_values:
                    journey = make_journey(70 + event_index)
                    journey["events"][event_index][field] = copy.deepcopy(invalid)
                    cases.append(journey)
        malformed_lists = (
            ["bad-record"],
            [None, *make_journey(74)["events"]],
            make_journey(75)["events"][:2],
            make_journey(76)["events"] + [{"type": "unexpected"}],
        )
        for events in malformed_lists:
            journey = make_journey(77)
            journey["events"] = copy.deepcopy(events)
            cases.append(journey)

        for index, journey in enumerate(cases):
            with self.subTest(case=index):
                result = evaluate_journey(journey)
                self.assertTrue(
                    audit_provenance_trace(journey, result)["valid"],
                    msg=audit_provenance_trace(journey, result),
                )
                provenance_codes = [
                    item["reason_code"] for item in result["evidence_provenance"]
                ]
                self.assertEqual(provenance_codes, sorted(result["reason_codes"]))
                original_events = journey.get("events")
                if isinstance(original_events, list):
                    for item in result["evidence_provenance"]:
                        for event_index in item["event_indices"]:
                            self.assertGreaterEqual(event_index, 0)
                            self.assertLess(event_index, len(original_events))

    def test_each_declared_disturbance_is_unresolved(self):
        for anomaly in ANOMALIES:
            with self.subTest(anomaly=anomaly):
                result = evaluate_journey(make_journey(2, anomaly))
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertNotEqual(result["reason_codes"], ["ALL_DECLARED_CHECKS_PASSED"])

    def test_benchmark_is_deterministic_and_balanced(self):
        first = generate_dataset(1000, seed=88)
        second = generate_dataset(1000, seed=88)
        self.assertEqual(first, second)
        report = benchmark(first)
        self.assertEqual(report["journey_count"], 1000)
        self.assertEqual(report["injected_anomaly_count"], 500)
        self.assertEqual(report["detected_anomaly_count"], 500)
        self.assertEqual(report["false_accept_count"], 0)
        self.assertEqual(report["false_reject_count"], 0)


    def test_missing_proof_is_classified_as_insufficient_evidence(self):
        result = evaluate_journey(make_journey(10, "missing_proof"))
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["evidence_class"], "INSUFFICIENT")
        self.assertIn("DELIVERY_PROOF_REFERENCE_MISSING", result["reason_codes"])

    def test_identity_mismatch_is_classified_as_conflicting_evidence(self):
        result = evaluate_journey(make_journey(11, "wrong_parcel"))
        self.assertEqual(result["evidence_class"], "CONFLICTING")
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

    def test_missing_gps_and_wrong_identity_are_mixed_evidence(self):
        journey = make_journey(12)
        journey["events"][-1]["gps_distance_m"] = None
        journey["events"][-1]["parcel_id"] = "OTHER-PARCEL"
        result = evaluate_journey(journey)
        self.assertEqual(result["evidence_class"], "MIXED")
        self.assertIn("DELIVERY_GPS_MISSING", result["reason_codes"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

    def test_boolean_is_not_accepted_as_timestamp_or_distance(self):
        journey = make_journey(13)
        journey["events"][-1]["timestamp"] = True
        journey["events"][-1]["gps_distance_m"] = True
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("TIMESTAMP_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("DELIVERY_GPS_INVALID", result["reason_codes"])

    def test_malformed_event_record_does_not_erase_other_observed_conflicts(self):
        journey = make_journey(46)
        journey["events"][1] = None
        journey["events"][-1]["parcel_id"] = "OTHER-000046"
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["evidence_class"], "MIXED")
        self.assertIn("EVENT_RECORDS_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertIn("TIMESTAMP_MISSING_OR_INVALID", result["reason_codes"])

    def test_malformed_journey_and_event_records_return_refusal_traces(self):
        for malformed in (None, [], {"journey_id": "J-x", "events": [None]}):
            with self.subTest(malformed=malformed):
                result = evaluate_journey(malformed)
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertTrue(result["reason_codes"])

    def test_missing_or_blank_journey_and_expected_ids_are_refused(self):
        journey = make_journey(20)
        journey["journey_id"] = "  "
        journey["expected_parcel_id"] = ""
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("JOURNEY_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID", result["reason_codes"])

    def test_duplicate_event_type_is_not_silently_reordered(self):
        journey = make_journey(21)
        journey["events"][1]["type"] = "pickup"
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("EVENT_SEQUENCE_MISMATCH", result["reason_codes"])

    def test_non_finite_and_negative_gps_distances_are_rejected(self):
        for distance in (-0.1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(distance=distance):
                journey = make_journey(22)
                journey["events"][-1]["gps_distance_m"] = distance
                result = evaluate_journey(journey)
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertIn("DELIVERY_GPS_INVALID", result["reason_codes"])

    def test_gps_limit_is_inclusive_but_values_above_it_fail(self):
        journey = make_journey(23)
        journey["events"][-1]["gps_distance_m"] = 100.0
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "VERIFIED")
        journey["events"][-1]["gps_distance_m"] = 100.0001
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "UNRESOLVED")

    def test_compound_disturbances_are_unresolved(self):
        compound = make_compound_journey(3, ("gps_drift", "wrong_parcel", "missing_proof"))
        result = evaluate_journey(compound)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["checks"]["parcel_identity_preserved"])
        self.assertFalse(result["checks"]["delivery_within_gps_limit"])
        self.assertFalse(result["checks"]["delivery_proof_present"])

    def test_compound_benchmark_reports_pair_and_triple_failures(self):
        dataset = generate_compound_dataset(1200, seed=88)
        report = benchmark(dataset)
        self.assertEqual(report["journey_count"], 1200)
        self.assertEqual(report["injected_anomaly_count"], 800)
        self.assertEqual(report["detected_anomaly_count"], 800)
        self.assertEqual(report["false_accept_count"], 0)
        self.assertEqual(report["false_reject_count"], 0)
        self.assertTrue(any(k.startswith("compound:") for k in report["by_condition"]))
        self.assertEqual(report["diagnostic_status_counts"], {
            "CLEAN": 400,
            "UNATTRIBUTED": 800,
        })
        self.assertEqual(len(report["diagnostic_records"]), 1200)
        self.assertEqual(
            len({record["journey_id"] for record in report["diagnostic_records"]}),
            1200,
        )

    def test_single_anomaly_report_has_exact_reason_frequencies(self):
        report = benchmark(generate_dataset(1000, seed=88))
        self.assertEqual(report["reason_code_counts"], {
            "ALL_DECLARED_CHECKS_PASSED": 500,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 100,
            "DELIVERY_PROOF_REFERENCE_MISSING": 100,
            "DESTINATION_IDENTITY_CONFLICT": 100,
            "PARCEL_IDENTITY_CONFLICT": 100,
            "TIMESTAMP_ORDER_CONFLICT": 100,
        })
        self.assertEqual(report["reason_combinations"], {
            "ALL_DECLARED_CHECKS_PASSED": 500,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 100,
            "DELIVERY_PROOF_REFERENCE_MISSING": 100,
            "DESTINATION_IDENTITY_CONFLICT": 100,
            "PARCEL_IDENTITY_CONFLICT": 100,
            "TIMESTAMP_ORDER_CONFLICT": 100,
        })
        self.assertEqual(
            report["condition_reason_code_counts"]["gps_drift"],
            {"DELIVERY_GPS_OUTSIDE_LIMIT": 100},
        )

    def test_compound_report_fingerprints_every_pair_and_triple(self):
        report = benchmark(generate_compound_dataset(1200, seed=88))
        self.assertEqual(report["reason_code_counts"], {
            "ALL_DECLARED_CHECKS_PASSED": 400,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 400,
            "DELIVERY_PROOF_REFERENCE_MISSING": 400,
            "DESTINATION_IDENTITY_CONFLICT": 400,
            "PARCEL_IDENTITY_CONFLICT": 400,
            "TIMESTAMP_ORDER_CONFLICT": 400,
        })
        self.assertEqual(report["reason_combinations"]["ALL_DECLARED_CHECKS_PASSED"], 400)
        self.assertEqual(len(report["reason_combinations"]), 21)
        self.assertEqual(
            sum(count for key, count in report["reason_combinations"].items()
                if key != "ALL_DECLARED_CHECKS_PASSED"),
            800,
        )
        for condition, counts in report["condition_reason_combinations"].items():
            if condition.startswith("compound:"):
                self.assertEqual(sum(counts.values()), 40)
                self.assertEqual(len(counts), 1)

    def test_single_anomaly_detection_matrix_maps_each_fault_to_its_invariant(self):
        report = benchmark(generate_dataset(1000, seed=88))
        expected = {
            "gps_drift": "DELIVERY_GPS_OUTSIDE_LIMIT",
            "wrong_parcel": "PARCEL_IDENTITY_CONFLICT",
            "wrong_destination": "DESTINATION_IDENTITY_CONFLICT",
            "reordered_events": "TIMESTAMP_ORDER_CONFLICT",
            "missing_proof": "DELIVERY_PROOF_REFERENCE_MISSING",
        }
        for anomaly, reason_code in expected.items():
            with self.subTest(anomaly=anomaly):
                detection = report["anomaly_detection"][anomaly]
                self.assertEqual(detection["expected_reason_code"], reason_code)
                self.assertEqual(detection["injected_occurrences"], 100)
                self.assertEqual(detection["detected_occurrences"], 100)
                self.assertEqual(detection["missed_occurrences"], 0)
                self.assertEqual(detection["detection_rate"], 1.0)
                self.assertEqual(
                    report["anomaly_reason_matrix"][anomaly],
                    {reason_code: 100},
                )
        self.assertEqual(report["clean_reason_code_counts"], {})

    def test_compound_anomaly_application_is_order_independent(self):
        index = 43
        for size in (2, 3):
            for anomaly_set in combinations(ANOMALIES, size):
                baseline = make_compound_journey(index, anomaly_set)
                baseline_result = evaluate_journey(baseline)
                for ordering in permutations(anomaly_set):
                    with self.subTest(anomalies=anomaly_set, ordering=ordering):
                        candidate = make_compound_journey(index, ordering)
                        self.assertEqual(candidate["events"], baseline["events"])
                        self.assertEqual(evaluate_journey(candidate), baseline_result)

    def test_pair_interaction_matrix_covers_all_pairs_and_counts_detection_outcomes(self):
        report = benchmark(generate_compound_dataset(1200, seed=88))
        matrix = report["pair_interaction_matrix"]
        self.assertEqual(len(matrix), 10)
        for pair, stats in matrix.items():
            with self.subTest(pair=pair):
                self.assertEqual(stats["journey_count"], 160)
                self.assertEqual(stats["both_detected"], 160)
                self.assertEqual(stats["first_only"], 0)
                self.assertEqual(stats["second_only"], 0)
                self.assertEqual(stats["neither_detected"], 0)
                self.assertEqual(stats["first_detection_rate"], 1.0)
                self.assertEqual(stats["second_detection_rate"], 1.0)
                self.assertEqual(stats["joint_detection_rate"], 1.0)
                self.assertEqual(stats["terminal_state_counts"], {"UNRESOLVED": 160})
                self.assertEqual(
                    set(stats["expected_reason_codes"]),
                    set(stats["anomalies"]),
                )

    def test_compound_detection_matrix_counts_each_injected_invariant(self):
        report = benchmark(generate_compound_dataset(1200, seed=88))
        for anomaly, detection in report["anomaly_detection"].items():
            with self.subTest(anomaly=anomaly):
                self.assertEqual(detection["injected_occurrences"], 400)
                self.assertEqual(detection["detected_occurrences"], 400)
                self.assertEqual(detection["missed_occurrences"], 0)
                self.assertEqual(detection["detection_rate"], 1.0)
                row = report["anomaly_reason_matrix"][anomaly]
                self.assertEqual(row[detection["expected_reason_code"]], 400)
                self.assertEqual(sum(row.values()), 400 + 4 * 160)
        self.assertEqual(report["clean_reason_code_counts"], {})

    def test_oracle_label_mismatch_is_visible_as_a_missed_invariant(self):
        journey = make_journey(31, "wrong_parcel")
        journey["injected_condition"] = "gps_drift"
        report = benchmark([journey])
        detection = report["anomaly_detection"]["gps_drift"]
        self.assertEqual(detection["injected_occurrences"], 1)
        self.assertEqual(detection["detected_occurrences"], 0)
        self.assertEqual(detection["missed_occurrences"], 1)
        self.assertEqual(
            report["anomaly_reason_matrix"]["gps_drift"],
            {"PARCEL_IDENTITY_CONFLICT": 1},
        )

    def test_sequence_echo_preserves_primary_detection_and_exposes_secondary_symptom(self):
        journey = make_interaction_journey(32, "reordered_events", "sequence_echo")
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("TIMESTAMP_ORDER_CONFLICT", result["reason_codes"])
        self.assertIn("EVENT_SEQUENCE_MISMATCH", result["reason_codes"])

        report = benchmark([journey])
        detection = report["anomaly_detection"]["reordered_events"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)
        self.assertEqual(
            report["interaction_reason_combinations"]["sequence_echo"],
            {"EVENT_SEQUENCE_MISMATCH + TIMESTAMP_ORDER_CONFLICT": 1},
        )

    def test_missing_identity_field_does_not_mask_separate_observed_conflict(self):
        journey = make_interaction_journey(
            44, "wrong_parcel", "missing_parcel_with_separate_conflict"
        )
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("PARCEL_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertEqual(result["evidence_class"], "MIXED")

        report = benchmark([journey])
        detection = report["anomaly_detection"]["wrong_parcel"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)
        summary = report["interaction_diagnostic_summary"][
            "missing_parcel_with_separate_conflict"
        ]
        self.assertEqual(summary["primary_fault_detected_count"], 1)
        self.assertEqual(summary["primary_fault_missed_count"], 0)
        self.assertEqual(
            summary["secondary_symptom_counts"],
            {"PARCEL_ID_MISSING_OR_INVALID": 1},
        )

    def test_missing_destination_does_not_mask_separate_destination_conflict(self):
        journey = make_interaction_journey(
            45, "wrong_destination", "missing_destination_with_separate_conflict"
        )
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("DESTINATION_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("DESTINATION_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertEqual(result["evidence_class"], "MIXED")

        report = benchmark([journey])
        detection = report["anomaly_detection"]["wrong_destination"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)
        summary = report["interaction_diagnostic_summary"][
            "missing_destination_with_separate_conflict"
        ]
        self.assertEqual(summary["primary_fault_detected_count"], 1)
        self.assertEqual(summary["primary_fault_missed_count"], 0)

    def test_missing_expected_parcel_does_not_mask_destination_conflict(self):
        journey = make_journey(47)
        journey["expected_parcel_id"] = ""
        journey["events"][-1]["destination_id"] = "OTHER-DESTINATION"
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["checks"]["expected_parcel_id_present"])
        self.assertTrue(result["checks"]["expected_destination_id_present"])
        self.assertIn("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("EXPECTED_PARCEL_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("DESTINATION_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertNotIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertEqual(result["evidence_class"], "MIXED")
        journey["injected_condition"] = "wrong_destination"
        detection = benchmark([journey])["anomaly_detection"]["wrong_destination"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)

    def test_missing_expected_destination_does_not_mask_parcel_conflict(self):
        journey = make_journey(48)
        journey["expected_destination_id"] = ""
        journey["events"][-1]["parcel_id"] = "OTHER-PARCEL"
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertTrue(result["checks"]["expected_parcel_id_present"])
        self.assertFalse(result["checks"]["expected_destination_id_present"])
        self.assertIn("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("EXPECTED_DESTINATION_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertNotIn("DESTINATION_IDENTITY_CONFLICT", result["reason_codes"])
        self.assertEqual(result["evidence_class"], "MIXED")
        journey["injected_condition"] = "wrong_parcel"
        detection = benchmark([journey])["anomaly_detection"]["wrong_parcel"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)

    def test_malformed_expected_identity_values_do_not_mask_other_conflicts(self):
        invalid_values = (None, "   ", 17, True)
        for invalid in invalid_values:
            with self.subTest(missing_parcel_reference=invalid):
                journey = make_journey(49)
                journey["expected_parcel_id"] = invalid
                journey["events"][-1]["destination_id"] = "OTHER-DESTINATION"
                result = evaluate_journey(journey)
                self.assertIn("EXPECTED_PARCEL_ID_MISSING_OR_INVALID", result["reason_codes"])
                self.assertIn("DESTINATION_IDENTITY_CONFLICT", result["reason_codes"])
                self.assertNotIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
                self.assertEqual(result["terminal_state"], "UNRESOLVED")

            with self.subTest(missing_destination_reference=invalid):
                journey = make_journey(50)
                journey["expected_destination_id"] = invalid
                journey["events"][-1]["parcel_id"] = "OTHER-PARCEL"
                result = evaluate_journey(journey)
                self.assertIn("EXPECTED_DESTINATION_ID_MISSING_OR_INVALID", result["reason_codes"])
                self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])
                self.assertNotIn("DESTINATION_IDENTITY_CONFLICT", result["reason_codes"])
                self.assertEqual(result["terminal_state"], "UNRESOLVED")

    def test_missing_secondary_symptom_can_mask_primary_fault(self):
        journey = make_interaction_journey(
            33, "wrong_parcel", "missing_parcel_masks_conflict"
        )
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("PARCEL_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertNotIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

        report = benchmark([journey])
        detection = report["anomaly_detection"]["wrong_parcel"]
        self.assertEqual(detection["injected_occurrences"], 1)
        self.assertEqual(detection["detected_occurrences"], 0)
        self.assertEqual(detection["missed_occurrences"], 1)
        self.assertEqual(
            report["interaction_reason_combinations"]["missing_parcel_masks_conflict"],
            {"PARCEL_ID_MISSING_OR_INVALID": 1},
        )

    def test_interaction_summary_separates_echo_and_masking_outcomes(self):
        echo = make_interaction_journey(41, "reordered_events", "sequence_echo")
        masked = make_interaction_journey(
            42, "wrong_parcel", "missing_parcel_masks_conflict"
        )
        summary = benchmark([echo, masked])["interaction_diagnostic_summary"]
        self.assertEqual(summary["sequence_echo"], {
            "case_count": 1,
            "diagnostic_status_counts": {"PRIMARY_IDENTIFIED_WITH_SYMPTOMS": 1},
            "primary_fault_detected_count": 1,
            "primary_fault_missed_count": 0,
            "secondary_symptom_counts": {"EVENT_SEQUENCE_MISMATCH": 1},
        })
        self.assertEqual(summary["missing_parcel_masks_conflict"], {
            "case_count": 1,
            "diagnostic_status_counts": {"PRIMARY_MASKED": 1},
            "primary_fault_detected_count": 0,
            "primary_fault_missed_count": 1,
            "secondary_symptom_counts": {"PARCEL_ID_MISSING_OR_INVALID": 1},
        })

    def test_diagnostic_trace_identifies_primary_and_secondary_symptoms(self):
        journey = make_interaction_journey(34, "reordered_events", "sequence_echo")
        report = benchmark([journey])
        trace = report["diagnostic_records"][0]
        self.assertEqual(trace["primary_fault"], "reordered_events")
        self.assertEqual(trace["expected_reason_code"], "TIMESTAMP_ORDER_CONFLICT")
        self.assertTrue(trace["primary_fault_detected"])
        self.assertEqual(trace["secondary_symptoms"], ["EVENT_SEQUENCE_MISMATCH"])
        self.assertEqual(trace["diagnostic_status"], "PRIMARY_IDENTIFIED_WITH_SYMPTOMS")

    def test_diagnostic_trace_marks_refusal_with_masked_primary(self):
        journey = make_interaction_journey(
            35, "wrong_parcel", "missing_parcel_masks_conflict"
        )
        report = benchmark([journey])
        trace = report["diagnostic_records"][0]
        self.assertEqual(trace["primary_fault"], "wrong_parcel")
        self.assertFalse(trace["primary_fault_detected"])
        self.assertEqual(trace["observed_reason_codes"], ["PARCEL_ID_MISSING_OR_INVALID"])
        self.assertEqual(trace["secondary_symptoms"], ["PARCEL_ID_MISSING_OR_INVALID"])
        self.assertEqual(trace["diagnostic_status"], "PRIMARY_MASKED")
        self.assertEqual(report["diagnostic_status_counts"], {"PRIMARY_MASKED": 1})

    def test_clean_and_compound_diagnostic_attribution_is_not_overstated(self):
        clean = make_journey(36)
        compound = make_compound_journey(37, ("gps_drift", "wrong_parcel"))
        report = benchmark([clean, compound])
        by_id = {record["journey_id"]: record for record in report["diagnostic_records"]}
        self.assertEqual(by_id["J-000036"]["diagnostic_status"], "CLEAN")
        self.assertIsNone(by_id["J-000036"]["primary_fault_detected"])
        self.assertEqual(by_id["J-000037"]["diagnostic_status"], "UNATTRIBUTED")
        self.assertIsNone(by_id["J-000037"]["primary_fault"])
        self.assertIsNone(by_id["J-000037"]["expected_reason_code"])

    def test_evaluator_output_is_invariant_to_oracle_metadata_changes(self):
        journeys = [
            make_journey(38, anomaly) for anomaly in ANOMALIES
        ]
        journeys.extend([
            make_compound_journey(39, ("gps_drift", "wrong_parcel")),
            make_interaction_journey(40, "wrong_parcel", "missing_parcel_masks_conflict"),
        ])
        for journey in journeys:
            with self.subTest(journey_id=journey["journey_id"]):
                relabelled = copy.deepcopy(journey)
                relabelled["injected_condition"] = "clean"
                relabelled["injected_interaction"] = "not-an-evaluator-input"
                self.assertEqual(
                    evaluate_journey(journey), evaluate_journey(relabelled)
                )

    def test_evaluator_does_not_consume_injected_oracle_label(self):
        journey = make_journey(30)
        journey["injected_condition"] = "compound:wrong_parcel+gps_drift"
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "VERIFIED")

    def test_compound_generator_rejects_duplicate_anomalies(self):
        with self.assertRaises(ValueError):
            make_compound_journey(4, ("gps_drift", "gps_drift"))

    def test_invalid_dataset_size_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_dataset(999)


if __name__ == "__main__":
    unittest.main()
