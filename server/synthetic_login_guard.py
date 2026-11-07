"""Transport-independent, synthetic login attempt guard.

No real AOW authentication protocol or credential handling is implemented.
The caller supplies monotonic timestamps; no wall-clock or network dependency.
"""
from dataclasses import dataclass
import math


class LoginGuardError(ValueError):
    pass


@dataclass(frozen=True)
class LoginDecision:
    allowed: bool
    retry_after: float
    remaining: int


class SyntheticLoginGuard:
    """Per-key sliding window with bounded keys and fail-closed input validation."""

    def __init__(self, *, limit=5, window=60.0, max_keys=1024):
        if type(limit) is not int or limit < 1:
            raise LoginGuardError("invalid limit")
        if type(max_keys) is not int or max_keys < 1:
            raise LoginGuardError("invalid max_keys")
        if isinstance(window, bool) or not isinstance(window, (int, float)) or not math.isfinite(window) or window <= 0:
            raise LoginGuardError("invalid window")
        self.limit = limit
        self.window = float(window)
        self.max_keys = max_keys
        self._events = {}
        self._last_time = None

    def _validate(self, key, now):
        if not isinstance(key, str) or not 1 <= len(key) <= 128 or not all(
            c.isascii() and (c.isalnum() or c in "_-") for c in key
        ):
            raise LoginGuardError("invalid key")
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
            raise LoginGuardError("invalid timestamp")
        if self._last_time is not None and now < self._last_time:
            raise LoginGuardError("clock moved backwards")

    def attempt(self, key, now):
        self._validate(key, now)
        now = float(now)
        # Expire old keys before enforcing memory cap.
        for old_key, events in list(self._events.items()):
            fresh = [t for t in events if now - t < self.window]
            if fresh:
                self._events[old_key] = fresh
            else:
                del self._events[old_key]
        if key not in self._events and len(self._events) >= self.max_keys:
            raise LoginGuardError("key capacity exceeded")
        events = self._events.setdefault(key, [])
        self._last_time = now
        if len(events) >= self.limit:
            return LoginDecision(False, max(0.0, self.window - (now - events[0])), 0)
        events.append(now)
        return LoginDecision(True, 0.0, self.limit - len(events))

    def clear(self, key):
        """Clear after a trusted successful authentication, never on failed login."""
        if not isinstance(key, str):
            raise LoginGuardError("invalid key")
        self._events.pop(key, None)
