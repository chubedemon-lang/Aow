"""Regression tests for the synthetic API's loopback bind input boundary."""
import unittest

from server.runtime_safety import RuntimeSafetyError, validate_loopback_bind


class HostileHost(str):
    """A string subclass that must be rejected before its hooks are invoked."""

    def __bool__(self):
        raise AssertionError("custom truthiness hook must not run")

    def __len__(self):
        raise AssertionError("custom length hook must not run")

    def strip(self, *args, **kwargs):
        raise AssertionError("custom strip hook must not run")


class LoopbackHostBoundaryTests(unittest.TestCase):
    def test_rejects_string_subclass_before_custom_hooks(self):
        host = HostileHost("127.0.0.1")
        with self.assertRaisesRegex(RuntimeSafetyError, "literal IPv4 loopback"):
            validate_loopback_bind(host, 8765)

    def test_accepts_exact_builtin_loopback_string(self):
        self.assertEqual(
            validate_loopback_bind("127.0.0.1", 8765),
            ("127.0.0.1", 8765),
        )


if __name__ == "__main__":
    unittest.main()
