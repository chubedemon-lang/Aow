"""Bounded, deterministic replay for the *synthetic* combat domain.

This is an internal server test utility, not a decoder or protocol for AOW.
"""
from dataclasses import dataclass

from server.combat import Battle, MAX_STAT


MAX_REPLAY_ACTIONS = 10_000


@dataclass(frozen=True)
class ReplayResult:
    battle: Battle
    events: tuple


def replay_battle(initial: Battle, actor_ids, *, expected_events=None):
    """Replay actions without mutating the initial snapshot.

    Reject oversized, malformed or divergent traces. No network or APK data is
    accepted or interpreted here.
    """
    if not isinstance(initial, Battle):
        raise TypeError("initial must be a Battle")
    if not isinstance(actor_ids, (tuple, list)):
        raise TypeError("actor_ids must be a list or tuple")
    if len(actor_ids) > MAX_REPLAY_ACTIONS:
        raise ValueError("replay action limit exceeded")
    if expected_events is not None:
        if not isinstance(expected_events, (tuple, list)):
            raise TypeError("expected_events must be a list or tuple")
        if len(expected_events) != len(actor_ids):
            raise ValueError("event count mismatch")
    battle = initial
    events = []
    for index, actor_id in enumerate(actor_ids):
        if type(actor_id) is not int or not 1 <= actor_id <= MAX_STAT:
            raise ValueError(f"invalid actor at action {index}")
        battle, event = battle.attack(actor_id)
        if expected_events is not None and event != expected_events[index]:
            raise ValueError(f"event mismatch at action {index}")
        events.append(event)
    return ReplayResult(battle=battle, events=tuple(events))
