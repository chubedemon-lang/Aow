import unittest

from server.protocol_evidence_registry import Evidence, EvidenceError, EvidenceRegistry


class EvidenceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.sha = EvidenceRegistry.digest(b"offline fixture")

    def test_digest(self):
        self.assertEqual(len(self.sha), 64)
        with self.assertRaises(EvidenceError):
            EvidenceRegistry.digest("not bytes")

    def test_unverified_does_not_claim_compatibility(self):
        registry = EvidenceRegistry()
        registry.add(Evidence("framing", self.sha, "synthetic fixture", "synthetic_test"))
        self.assertEqual(registry.summary()["framing"], {"observations": 1, "verified": 0})

    def test_verified_explicit_only_with_reproducible_local_test(self):
        registry = EvidenceRegistry()
        registry.add(Evidence(
            "login", self.sha, "offline observation", "il2cpp_offline", True,
            "tests/test_protocol_evidence_registry.py",
            "python -m unittest discover -s tests -p test_protocol_evidence_registry.py -v",
        ))
        self.assertEqual(registry.summary()["login"], {"observations": 1, "verified": 1})

    def test_verified_requires_test_reference_and_reproduction(self):
        with self.assertRaisesRegex(EvidenceError, "local test reference"):
            Evidence("login", self.sha, "offline observation", "il2cpp_offline", True)
        with self.assertRaisesRegex(EvidenceError, "provided together"):
            Evidence(
                "login", self.sha, "offline observation", "il2cpp_offline", True,
                "tests/test_protocol_evidence_registry.py", None,
            )

    def test_synthetic_only_method_cannot_mark_protocol_evidence_verified(self):
        with self.assertRaisesRegex(EvidenceError, "offline or authorized method"):
            Evidence(
                "framing", self.sha, "synthetic fixture observation", "synthetic_test", True,
                "tests/test_protocol_evidence_registry.py",
                "python -m unittest discover -s tests -p test_protocol_evidence_registry.py -v",
            )

    def test_rejects_sensitive_observation_and_method_text(self):
        for field in ("observation", "method"):
            values = {
                "observation": "offline observation",
                "method": "il2cpp_offline",
            }
            values[field] = "captured endpoint game.example.invalid"
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                Evidence("transport", self.sha, values["observation"], values["method"])

    def test_rejects_non_local_test_references(self):
        invalid = (
            "https://example.invalid/capture",
            "game.example.invalid",
            "/tmp/capture.pcap",
            "tests/../private.py",
            "private/capture.pcap",
            "issue:0",
        )
        for reference in invalid:
            with self.subTest(reference=reference), self.assertRaises(EvidenceError):
                Evidence(
                    "transport", self.sha, "offline observation", "il2cpp_offline",
                    False, reference,
                    "python -m unittest discover -s tests -p test_protocol_evidence_registry.py -v",
                )

    def test_rejects_sensitive_reproduction_commands(self):
        for reproduction in (
            "python -m unittest https://example.invalid",
            "python -m unittest token=secret",
            "/tmp/private/capture.pcap",
            "python ../outside.py",
        ):
            with self.subTest(reproduction=reproduction), self.assertRaises(EvidenceError):
                Evidence(
                    "transport", self.sha, "offline observation", "il2cpp_offline",
                    False, "tests/test_protocol_evidence_registry.py", reproduction,
                )

    def test_duplicate_rejected(self):
        registry = EvidenceRegistry()
        entry = Evidence("transport", self.sha, "note", "offline")
        registry.add(entry)
        with self.assertRaises(EvidenceError):
            registry.add(entry)

    def test_invalid_fields(self):
        bad = [
            ("unknown", self.sha, "a", "b", False),
            ("login", "abc", "a", "b", False),
            ("login", self.sha, "", "b", False),
            ("login", self.sha, "a", "", False),
            ("login", self.sha, "a", "b", 1),
        ]
        for fields in bad:
            with self.assertRaises(EvidenceError):
                Evidence(*fields)

    def test_player_and_map_topics_are_registered(self):
        registry = EvidenceRegistry()
        registry.add(Evidence("player", self.sha, "player init evidence", "offline test"))
        registry.add(Evidence("map", self.sha, "map join evidence", "offline test"))
        summary = registry.summary()
        self.assertEqual(summary["player"]["observations"], 1)
        self.assertEqual(summary["map"]["observations"], 1)

    def test_primitive_serialization_is_a_distinct_topic(self):
        registry = EvidenceRegistry()
        registry.add(Evidence(
            "serialization", self.sha,
            "primitive helper method-body observation",
            "authorized offline native inspection",
        ))
        self.assertEqual(
            registry.summary()["serialization"],
            {"observations": 1, "verified": 0},
        )

    def test_summary_empty(self):
        self.assertEqual(EvidenceRegistry().summary()["handshake"]["verified"], 0)


    def test_summary_rejects_mixed_artifacts_without_explicit_selector(self):
        other_sha = EvidenceRegistry.digest(b"another APK build")
        registry = EvidenceRegistry()
        registry.add(Evidence(
            "transport", self.sha, "offline observation", "il2cpp_offline", True,
            "tests/test_protocol_evidence_registry.py",
            "python -m unittest discover -s tests -p test_protocol_evidence_registry.py -v",
        ))
        registry.add(Evidence(
            "framing", other_sha, "offline observation", "il2cpp_offline", True,
            "tests/test_protocol_evidence_registry.py",
            "python -m unittest discover -s tests -p test_protocol_evidence_registry.py -v",
        ))

        with self.assertRaisesRegex(EvidenceError, "multiple artifacts"):
            registry.summary()

        first = registry.summary(artifact_sha256=self.sha)
        second = registry.summary(artifact_sha256=other_sha)
        self.assertEqual(first["transport"], {"observations": 1, "verified": 1})
        self.assertEqual(first["framing"], {"observations": 0, "verified": 0})
        self.assertEqual(second["transport"], {"observations": 0, "verified": 0})
        self.assertEqual(second["framing"], {"observations": 1, "verified": 1})

    def test_summary_validates_explicit_artifact_selector(self):
        registry = EvidenceRegistry()
        registry.add(Evidence("transport", self.sha, "offline observation", "il2cpp_offline"))

        for digest in ("BAD", "A" * 64, "b" * 64):
            with self.subTest(digest=digest), self.assertRaises(EvidenceError):
                registry.summary(artifact_sha256=digest)



if __name__ == "__main__":
    unittest.main()
