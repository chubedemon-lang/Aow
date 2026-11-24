"""Additional metadata-only evidence validation regressions.

No APK, capture, private endpoint or AOW packet data is used.
"""
import unittest

from server.offline_protocol_evidence import EvidenceError, validate_manifest, validate_record


def record(**changes):
    data = {
        "id": "offline-fixture-1",
        "kind": "framing",
        "status": "unverified",
        "artifact_sha256": "a" * 64,
        "method": "Authorized local offline analysis",
        "reproduction": "Run a local fixture test",
        "test_reference": "tests/local_fixture.py",
        "notes": "Synthetic fixture; not evidence of AOW compatibility",
    }
    data.update(changes)
    return data


class EvidenceBoundaryTests(unittest.TestCase):
    def test_all_protocol_stages_are_metadata_only(self):
        for kind in ("transport", "framing", "handshake", "login", "session",
                     "player", "map", "movement", "inventory", "shop", "combat", "quest"):
            with self.subTest(kind=kind):
                self.assertEqual(validate_record(record(kind=kind))["kind"], kind)

    def test_rejects_unexpected_binary_or_endpoint_field(self):
        for key in ("raw_packet", "endpoint", "credentials", "apk_bytes"):
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                validate_record(record(**{key: "not allowed"}))

    def test_rejects_bad_hash_forms(self):
        for value in ("A" * 64, "a" * 63, "z" * 64, 42, None):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                validate_record(record(artifact_sha256=value))

    def test_verified_requires_real_test_reference(self):
        for placeholder in ("pending", "none", "unknown", "n/a"):
            with self.subTest(placeholder=placeholder), self.assertRaises(EvidenceError):
                validate_record(record(status="verified", test_reference=placeholder))

    def test_duplicate_ids_rejected_even_with_different_kinds(self):
        with self.assertRaises(EvidenceError):
            validate_manifest([record(), record(kind="login")])

    def test_metadata_cannot_contain_control_characters(self):
        for value in ("bad\nline", "bad\rline", "bad\x00value"):
            with self.subTest(value=repr(value)), self.assertRaises(EvidenceError):
                validate_record(record(notes=value))


if __name__ == "__main__":
    unittest.main()
