"""Concurrency regressions for the synthetic player presence registry."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from server.player_presence import PresenceError, PresenceRegistry
from server.session_state import Session


class PresenceConcurrencyTests(unittest.TestCase):
    def authenticated(self, session_id, player_id):
        session = Session(session_id)
        session.authenticate(player_id)
        return session

    def test_concurrent_bind_of_same_player_has_one_owner(self):
        registry = PresenceRegistry()
        sessions = (
            self.authenticated("session-a", "shared-player"),
            self.authenticated("session-b", "shared-player"),
        )
        barrier = Barrier(2)

        def bind(session):
            barrier.wait(timeout=5)
            try:
                registry.bind(session)
                return session.session_id
            except PresenceError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(bind, sessions))

        winner = next(value for value in outcomes if value is not None)
        self.assertEqual(sum(value is not None for value in outcomes), 1)
        self.assertEqual(registry.get("shared-player").session_id, winner)

    def test_concurrent_map_entry_has_one_winner(self):
        registry = PresenceRegistry()
        session = self.authenticated("session-a", "player-a")
        registry.bind(session)
        session.enter_world()
        barrier = Barrier(2)

        def enter(map_id):
            barrier.wait(timeout=5)
            try:
                registry.enter_map(session, map_id)
                return map_id
            except PresenceError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(enter, ("map-a", "map-b")))

        winner = next(value for value in outcomes if value is not None)
        self.assertEqual(sum(value is not None for value in outcomes), 1)
        self.assertEqual(registry.get("player-a").map_id, winner)

    def test_concurrent_release_removes_presence_once(self):
        registry = PresenceRegistry()
        session = self.authenticated("session-a", "player-a")
        registry.bind(session)
        barrier = Barrier(2)

        def release():
            barrier.wait(timeout=5)
            try:
                registry.release(session)
                return True
            except PresenceError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: release(), range(2)))

        self.assertCountEqual(outcomes, [True, False])
        self.assertIsNone(registry.get("player-a"))


if __name__ == "__main__":
    unittest.main()
