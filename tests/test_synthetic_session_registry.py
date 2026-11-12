"""Synthetic registry regression tests; no APK claims."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

from server.synthetic_session_registry import RegistryError, SessionRegistry
from server.synthetic_session_state import Phase, SessionError, Snapshot


class RegistryTests(unittest.TestCase):
    def test_capacity_and_release(self):
        registry = SessionRegistry(1)
        first = registry.open("a")
        self.assertEqual(first.phase, Phase.NEW)
        with self.assertRaises(RegistryError):
            registry.open("b")
        self.assertTrue(registry.close("a"))
        self.assertEqual(registry.active_count, 0)
        registry.open("b")
        self.assertEqual(registry.active_count, 1)

    def test_duplicate_connection_is_atomic(self):
        registry = SessionRegistry()
        opened = registry.open("a")
        with self.assertRaises(RegistryError):
            registry.open("a")
        self.assertIsInstance(opened, Snapshot)
        self.assertEqual(registry.get("a"), opened)

    def test_account_uniqueness_and_release(self):
        registry = SessionRegistry()
        registry.open("a")
        registry.open("b")
        registry.authenticate("a", "account")
        with self.assertRaises(RegistryError):
            registry.authenticate("b", "account")
        self.assertEqual(registry.get("b").phase, Phase.NEW)
        registry.close("a")
        registry.authenticate("b", "account")
        self.assertEqual(registry.get("b").phase, Phase.AUTHENTICATED)

    def test_character_uniqueness(self):
        registry = SessionRegistry()
        for key in ("a", "b"):
            registry.open(key)
            registry.authenticate(key, key)
        registry.select_character("a", "hero")
        with self.assertRaises(RegistryError):
            registry.select_character("b", "hero")
        self.assertEqual(registry.get("b").phase, Phase.AUTHENTICATED)
        registry.select_character("b", "other")

    def test_invalid_identifiers_and_capacity(self):
        for capacity in (True, 0, -1, 100001, "2"):
            with self.assertRaises(RegistryError):
                SessionRegistry(capacity)
        registry = SessionRegistry()
        for key in ("", " ", None, 5, "x" * 129):
            with self.assertRaises(RegistryError):
                registry.open(key)
        self.assertEqual(registry.active_count, 0)

    def test_failed_auth_does_not_reserve_account(self):
        registry = SessionRegistry()
        registry.open("a")
        registry.open("b")
        with self.assertRaises(SessionError):
            registry.authenticate("a", "")
        registry.authenticate("b", "account")
        self.assertEqual(registry.get("a").phase, Phase.NEW)

    def test_close_all_removes_sessions(self):
        registry = SessionRegistry()
        registry.open("a")
        registry.authenticate("a", "secret")
        registry.open("b")
        registry.close_all()
        self.assertEqual(registry.active_count, 0)
        self.assertFalse(registry.close("a"))
        with self.assertRaises(RegistryError):
            registry.get("b")

    def test_no_cross_session_state_mutation(self):
        registry = SessionRegistry()
        a_initial = registry.open("a")
        b_initial = registry.open("b")
        registry.authenticate("a", "user")
        self.assertEqual(a_initial.phase, Phase.NEW)
        self.assertEqual(b_initial.phase, Phase.NEW)
        self.assertEqual(registry.get("a").phase, Phase.AUTHENTICATED)
        self.assertEqual(registry.get("b").phase, Phase.NEW)
        registry.close("a")
        with self.assertRaises(RegistryError):
            registry.get("a")
        self.assertEqual(registry.get("b").phase, Phase.NEW)

    def test_only_immutable_snapshots_leave_registry(self):
        registry = SessionRegistry()
        opened = registry.open("old")
        self.assertIsInstance(opened, Snapshot)
        with self.assertRaises(FrozenInstanceError):
            opened.phase = Phase.CLOSED
        with self.assertRaises(AttributeError):
            opened.authenticate("account")

        registry.authenticate("old", "account")
        current = registry.get("old")
        self.assertIsInstance(current, Snapshot)
        self.assertEqual(current.phase, Phase.AUTHENTICATED)
        with self.assertRaises(FrozenInstanceError):
            current.account_id = "other"

        transferred = registry.transfer_connection("old", "new", verified=True)
        self.assertIsInstance(transferred, Snapshot)
        self.assertEqual(transferred, current)
        with self.assertRaises(RegistryError):
            registry.get("old")
        self.assertEqual(registry.get("new"), current)

    def test_concurrent_opens_respect_capacity(self):
        workers = 16
        registry = SessionRegistry(capacity=1)
        barrier = threading.Barrier(workers)

        def open_one(index):
            barrier.wait(timeout=5)
            try:
                registry.open("connection-" + str(index))
                return True
            except RegistryError:
                return False

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(open_one, range(workers)))

        self.assertEqual(sum(results), 1)
        self.assertEqual(registry.active_count, 1)

    def test_concurrent_authentication_reserves_account_once(self):
        workers = 16
        registry = SessionRegistry()
        for index in range(workers):
            registry.open("connection-" + str(index))
        barrier = threading.Barrier(workers)

        def authenticate_one(index):
            barrier.wait(timeout=5)
            try:
                registry.authenticate("connection-" + str(index), "same-account")
                return True
            except RegistryError:
                return False

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(authenticate_one, range(workers)))

        self.assertEqual(sum(results), 1)
        phases = [
            registry.get("connection-" + str(index)).phase
            for index in range(workers)
        ]
        self.assertEqual(phases.count(Phase.AUTHENTICATED), 1)
        self.assertEqual(phases.count(Phase.NEW), workers - 1)

    def test_concurrent_character_selection_reserves_character_once(self):
        workers = 16
        registry = SessionRegistry()
        for index in range(workers):
            key = "connection-" + str(index)
            registry.open(key)
            registry.authenticate(key, "account-" + str(index))
        barrier = threading.Barrier(workers)

        def select_one(index):
            barrier.wait(timeout=5)
            try:
                registry.select_character("connection-" + str(index), "same-character")
                return True
            except RegistryError:
                return False

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(select_one, range(workers)))

        self.assertEqual(sum(results), 1)
        phases = [
            registry.get("connection-" + str(index)).phase
            for index in range(workers)
        ]
        self.assertEqual(phases.count(Phase.CHARACTER_SELECTED), 1)
        self.assertEqual(phases.count(Phase.AUTHENTICATED), workers - 1)


if __name__ == "__main__":
    unittest.main()
