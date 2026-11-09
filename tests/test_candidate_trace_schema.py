"""Dependency-free conformance checks for the published candidate-trace JSON Schema."""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
from dss_demo import main  # noqa: E402


SCHEMA_PATH = ROOT / "demo" / "schemas" / "candidate-trace-v1.schema.json"


def schema_errors(value, schema, path="$"):
    """Validate the JSON Schema keywords used by this contract (no external package)."""
    errors = []
    expected_type = schema.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        checks = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
            "null": lambda v: v is None,
        }
        if not any(checks[t](value) for t in types):
            return [f"{path}: expected {types}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value outside enum")
    if isinstance(value, str):
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: pattern mismatch")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: string too short")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, schema["items"], f"{path}[{index}]"))
    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            errors.append(f"{path}: too few properties")
        missing = set(schema.get("required", ())) - set(value)
        if missing:
            errors.append(f"{path}: missing {sorted(missing)}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key}")
        if "anyOf" in schema and not any(
            not schema_errors(value, option, path) for option in schema["anyOf"]
        ):
            errors.append(f"{path}: no anyOf branch matched")
    return errors


class CandidateTraceSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trace.json"
            old_argv = sys.argv
            try:
                sys.argv = ["dss_demo.py", "--json-out", str(output)]
                main()
            finally:
                sys.argv = old_argv
            return json.loads(output.read_text(encoding="utf-8"))

    def test_schema_declares_draft_2020_12_and_current_trace_version(self):
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["items"]["properties"]["trace_schema_version"]["const"],
                         "candidate-trace/1.0")

    def test_complete_cli_export_conforms_to_schema(self):
        exported = self.export()
        self.assertEqual(len(exported), 7)
        self.assertEqual(schema_errors(exported, self.schema), [])

    def test_schema_rejects_missing_required_fields(self):
        exported = self.export()
        del exported[0]["candidate_trace_audit"]
        errors = schema_errors(exported, self.schema)
        self.assertTrue(any("candidate_trace_audit" in error for error in errors))

    def test_schema_rejects_invalid_terminal_state_and_candidate_disposition(self):
        exported = self.export()
        exported[0]["terminal_state"] = "PROBABLY"
        self.assertTrue(schema_errors(exported, self.schema))
        exported = self.export()
        exported[0]["candidate_trace"][0]["disposition"] = "ACCEPTED_BY_SIMILARITY"
        self.assertTrue(schema_errors(exported, self.schema))

    def test_schema_rejects_wrong_version_and_trace_id_shape(self):
        exported = self.export()
        exported[0]["trace_schema_version"] = "candidate-trace/9.9"
        self.assertTrue(schema_errors(exported, self.schema))
        exported = self.export()
        exported[0]["trace_id"] = "addr-not-a-digest"
        self.assertTrue(schema_errors(exported, self.schema))

    def test_schema_rejects_unexpected_top_level_and_candidate_properties(self):
        exported = self.export()
        exported[0]["unreviewed_field"] = True
        self.assertTrue(schema_errors(exported, self.schema))
        exported = self.export()
        exported[0]["candidate_trace"][0]["unreviewed_field"] = True
        self.assertTrue(schema_errors(exported, self.schema))


if __name__ == "__main__":
    unittest.main()
