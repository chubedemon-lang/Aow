"""Regression coverage for encoded network locators in public evidence metadata."""
import unittest
from urllib.parse import quote

from server.offline_evidence_validation import EvidenceError, validate_record


class EncodedLocatorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.base = {
            "kind": "local_capture",
            "sha256": "b" * 64,
            "source": "authorized local artifact",
            "observation": "redacted offline inspection",
            "verified": False,
        }

    def test_rejects_percent_encoded_bare_network_locators(self):
        values = (
            "192.0.2.44",
            "capture.example.invalid",
            "2001:db8::44",
        )
        for raw in values:
            encoded = quote(raw, safe="")
            # Mix escape casing to ensure matching is case-insensitive.
            encoded = encoded.replace("%2e", "%2E").replace("%3a", "%3A")
            for field in ("source", "observation"):
                with self.subTest(raw=raw, field=field):
                    with self.assertRaises(EvidenceError):
                        validate_record({**self.base, field: encoded})

    def test_rejects_three_round_encoded_network_locator(self):
        raw = "capture.example.invalid"
        encoded = raw
        for _ in range(3):
            encoded = quote(encoded, safe="")
        for field in ("source", "observation"):
            with self.subTest(field=field):
                with self.assertRaises(EvidenceError):
                    validate_record({**self.base, field: encoded})


if __name__ == "__main__":
    unittest.main()
