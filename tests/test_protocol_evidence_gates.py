"""Readiness gates only describe evidence coverage, not APK compatibility."""
import unittest

from server.protocol_evidence_registry import Evidence, EvidenceError
from server.protocol_evidence_gates import STAGES, evaluate_evidence


def evidence(topic, verified=True):
    return Evidence(topic, "a" * 64, "offline fixture observation",
                    "authorized local inspection", verified)


class EvidenceGateTests(unittest.TestCase):
    def test_empty_registry_blocks_all_stages(self):
        result = evaluate_evidence([])
        self.assertEqual(len(result), len(STAGES))
        self.assertTrue(all(not item.ready for item in result))
        self.assertEqual(result[0].missing, ("transport",))

    def test_unverified_records_do_not_unlock(self):
        result = evaluate_evidence([evidence("transport", False)])
        self.assertFalse(result[0].ready)

    def test_prerequisites_required(self):
        result = evaluate_evidence([evidence("login"), evidence("framing")])
        self.assertFalse(result[3].ready)
        self.assertEqual(result[3].missing, ("transport", "handshake"))

    def test_verified_prefix_only(self):
        result = evaluate_evidence([evidence("transport"), evidence("framing")])
        self.assertTrue(result[0].ready)
        self.assertTrue(result[1].ready)
        self.assertFalse(result[2].ready)

    def test_all_stages_need_individual_evidence(self):
        result = evaluate_evidence([evidence(topic) for topic in STAGES])
        self.assertTrue(all(item.ready for item in result))

    def test_player_and_map_are_required_before_movement(self):
        prefix = ("transport", "framing", "handshake", "login", "session", "movement")
        result = {item.stage: item for item in evaluate_evidence([evidence(x) for x in prefix])}
        self.assertFalse(result["player"].ready)
        self.assertFalse(result["map"].ready)
        self.assertFalse(result["movement"].ready)
        self.assertEqual(result["movement"].missing, ("player", "map"))

    def test_invalid_collection_fails_closed(self):
        for invalid in (None, {}, [object()], [evidence("transport"), None]):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(EvidenceError):
                    evaluate_evidence(invalid)

    def test_input_order_does_not_change_results(self):
        items = [evidence("handshake"), evidence("transport"), evidence("framing")]
        self.assertEqual(evaluate_evidence(items), evaluate_evidence(list(reversed(items))))


if __name__ == "__main__":
    unittest.main()
