"""Boundary tests for the fixture JSON preflight scanner.

These tests exercise only resource-budget scanning; json.loads remains
responsible for full JSON grammar and schema validation.
"""
import json
import unittest
from unittest.mock import patch

from tools.protocol_fixture_audit import (
    MAX_JSON_NESTING,
    MAX_JSON_TOKENS,
    FixtureAuditError,
    _validate_json_nesting,
)


class FixtureJsonGuardBoundaryTests(unittest.TestCase):
    def test_accepts_exact_nesting_limit(self):
        document = "[" * MAX_JSON_NESTING + "0" + "]" * MAX_JSON_NESTING
        _validate_json_nesting(document)

    def test_rejects_one_level_over_nesting_limit(self):
        document = "[" * (MAX_JSON_NESTING + 1) + "0" + "]" * (
            MAX_JSON_NESTING + 1
        )
        with self.assertRaisesRegex(FixtureAuditError, "nesting"):
            _validate_json_nesting(document)

    def test_accepts_exact_token_budget(self):
        # The opening array is one token; each primitive value is one more.
        values = ",".join("0" for _ in range(MAX_JSON_TOKENS - 1))
        _validate_json_nesting("[" + values + "]")

    def test_rejects_one_token_over_budget(self):
        values = ",".join("0" for _ in range(MAX_JSON_TOKENS))
        with self.assertRaisesRegex(FixtureAuditError, "token count"):
            _validate_json_nesting("[" + values + "]")

    def test_escaped_quotes_and_structural_text_inside_strings_are_ignored(self):
        value = 'quote: " ; braces: {}[] ; primitives: true,false,null,-123'
        document = json.dumps({"value": value})
        _validate_json_nesting(document)

    def test_boolean_null_and_negative_number_are_counted_as_values(self):
        # Array + four primitive values = five JSON tokens.
        _validate_json_nesting("[-1,true,false,null]")
        with self.assertRaisesRegex(FixtureAuditError, "token count"):
            with patch("tools.protocol_fixture_audit.MAX_JSON_TOKENS", 4):
                _validate_json_nesting("[-1,true,false,null]")


if __name__ == "__main__":
    unittest.main()
