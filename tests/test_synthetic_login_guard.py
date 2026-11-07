"""Tests for transport-independent synthetic login throttling."""
import unittest

from server.synthetic_login_guard import LoginGuardError, SyntheticLoginGuard


class LoginGuardTests(unittest.TestCase):
    def test_limit_and_retry(self):
        guard = SyntheticLoginGuard(limit=2, window=10)
        self.assertTrue(guard.attempt("alice", 0).allowed)
        self.assertTrue(guard.attempt("alice", 1).allowed)
        denied = guard.attempt("alice", 2)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.retry_after, 8)
        self.assertTrue(guard.attempt("alice", 10).allowed)

    def test_independent_keys(self):
        guard = SyntheticLoginGuard(limit=1)
        guard.attempt("a", 0)
        self.assertFalse(guard.attempt("a", 0).allowed)
        self.assertTrue(guard.attempt("b", 0).allowed)

    def test_capacity_and_expiry(self):
        guard = SyntheticLoginGuard(limit=1, window=2, max_keys=1)
        guard.attempt("a", 0)
        with self.assertRaises(LoginGuardError):
            guard.attempt("b", 1)
        self.assertTrue(guard.attempt("b", 2).allowed)

    def test_invalid_input_does_not_mutate(self):
        guard = SyntheticLoginGuard(limit=1)
        guard.attempt("a", 5)
        for key, now in [("", 6), ("a", float("nan")), ("a", 4), ("a!", 6), ("a", True)]:
            with self.subTest(key=key, now=now):
                with self.assertRaises(LoginGuardError):
                    guard.attempt(key, now)
        self.assertFalse(guard.attempt("a", 6).allowed)

    def test_clear_after_trusted_success(self):
        guard = SyntheticLoginGuard(limit=1)
        guard.attempt("a", 0)
        guard.clear("a")
        self.assertTrue(guard.attempt("a", 1).allowed)

    def test_invalid_config(self):
        for kwargs in ({"limit": True}, {"window": 0}, {"window": float("inf")}, {"max_keys": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(LoginGuardError):
                    SyntheticLoginGuard(**kwargs)


if __name__ == "__main__":
    unittest.main()
