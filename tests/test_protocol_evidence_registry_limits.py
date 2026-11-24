"""Bounded evidence-registry capacity regressions."""
import threading
import unittest
from unittest.mock import patch

from server.protocol_evidence_registry import (
    Evidence,
    EvidenceError,
    EvidenceRegistry,
    MAX_EVIDENCE_RECORDS,
)


class EvidenceRegistryLimitTests(unittest.TestCase):
    def setUp(self):
        self.sha = EvidenceRegistry.digest(b"bounded evidence registry")

    def record(self, index):
        return Evidence(
            "transport",
            self.sha,
            f"synthetic observation {index}",
            "synthetic_test",
        )

    def test_registry_and_readiness_gates_share_the_same_limit(self):
        from server.protocol_evidence_gates import MAX_EVIDENCE_RECORDS as gate_limit

        self.assertEqual(MAX_EVIDENCE_RECORDS, 4096)
        self.assertEqual(gate_limit, MAX_EVIDENCE_RECORDS)

    def test_add_rejects_entries_beyond_limit_without_mutating_summary(self):
        registry = EvidenceRegistry()
        with patch("server.protocol_evidence_registry.MAX_EVIDENCE_RECORDS", 2):
            registry.add(self.record(1))
            registry.add(self.record(2))
            with self.assertRaisesRegex(EvidenceError, "at most 2 records"):
                registry.add(self.record(3))

            self.assertEqual(
                registry.summary()["transport"],
                {"observations": 2, "verified": 0},
            )

    def test_duplicate_is_reported_before_capacity_error(self):
        registry = EvidenceRegistry()
        record = self.record(1)
        with patch("server.protocol_evidence_registry.MAX_EVIDENCE_RECORDS", 1):
            registry.add(record)
            with self.assertRaisesRegex(EvidenceError, "duplicate evidence"):
                registry.add(record)

    def test_concurrent_additions_cannot_exceed_registry_limit(self):
        registry = EvidenceRegistry()
        limit = 5
        worker_count = 12
        barrier = threading.Barrier(worker_count)
        successes = []
        errors = []

        def add(index):
            try:
                barrier.wait(timeout=2)
                registry.add(self.record(index))
                successes.append(index)
            except BaseException as exc:
                errors.append(exc)

        with patch("server.protocol_evidence_registry.MAX_EVIDENCE_RECORDS", limit):
            workers = [
                threading.Thread(target=add, args=(index,))
                for index in range(worker_count)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=3)

            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(len(successes), limit)
            self.assertEqual(len(errors), worker_count - limit)
            self.assertTrue(all(isinstance(error, EvidenceError) for error in errors))
            self.assertEqual(
                registry.summary()["transport"],
                {"observations": limit, "verified": 0},
            )

    def test_summary_rejects_over_limit_internal_state_before_snapshot(self):
        registry = EvidenceRegistry()
        with patch("server.protocol_evidence_registry.MAX_EVIDENCE_RECORDS", 1):
            registry.add(self.record(1))
            # Simulate corrupted private state; summary must fail closed.
            registry._records.append(self.record(2))
            with self.assertRaisesRegex(EvidenceError, "more than 1 records"):
                registry.summary()


if __name__ == "__main__":
    unittest.main()
