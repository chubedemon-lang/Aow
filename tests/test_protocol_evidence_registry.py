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
        registry.add(Evidence("framing", self.sha, "synthetic fixture", "unit test"))
        self.assertEqual(registry.summary()["framing"], {"observations": 1, "verified": 0})

    def test_verified_explicit_only(self):
        registry = EvidenceRegistry()
        registry.add(Evidence("login", self.sha, "offline observation", "manual review", True))
        self.assertEqual(registry.summary()["login"]["verified"], 1)

    def test_duplicate_rejected(self):
        registry = EvidenceRegistry()
        entry = Evidence("transport", self.sha, "note", "offline")
        registry.add(entry)
        with self.assertRaises(EvidenceError):
            registry.add(entry)

    def test_invalid_fields(self):
        bad = [("unknown", self.sha, "a", "b", False),
               ("login", "abc", "a", "b", False),
               ("login", self.sha, "", "b", False),
               ("login", self.sha, "a", "", False),
               ("login", self.sha, "a", "b", 1)]
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

    def test_summary_empty(self):
        self.assertEqual(EvidenceRegistry().summary()["handshake"]["verified"], 0)


if __name__ == "__main__":
    unittest.main()
