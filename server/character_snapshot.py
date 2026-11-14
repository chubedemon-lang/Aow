"""Strict decoding of persisted synthetic character rows.

SQLite tables are dynamically typed unless every table is STRICT. These
readers therefore validate the storage classes and domain bounds instead of
coercing REAL/BLOB values into apparently valid character snapshots.
This is synthetic server-domain validation, not an AOW field contract.
"""
from dataclasses import dataclass


_MAX_CHARACTER_ID = 2**63 - 1
_MIN_COORDINATE = -(2**31)
_MAX_COORDINATE = 2**31 - 1


class CharacterSnapshotError(ValueError):
    """Persisted character data is malformed or outside synthetic bounds."""


@dataclass(frozen=True)
class CharacterSnapshot:
    character_id: int
    name: str
    map_id: str
    x: int
    y: int


def _valid_name(value) -> bool:
    if (type(value) is not str or not value or value != value.strip()
            or "\x00" in value or len(value) > 64):
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= 256
    except UnicodeEncodeError:
        return False


def _valid_map_id(value) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and all(
            ch.isascii() and (ch.isalnum() or ch in "._-")
            for ch in value
        )
    )


def character_snapshot_from_row(row) -> CharacterSnapshot:
    """Decode one SQLite row without lossy int()/str() coercion."""
    try:
        character_id, name, map_id, x, y = row
    except (TypeError, ValueError) as exc:
        raise CharacterSnapshotError("invalid stored character row") from exc

    if (type(character_id) is not int
            or not 1 <= character_id <= _MAX_CHARACTER_ID):
        raise CharacterSnapshotError("invalid stored character row")
    if not _valid_name(name) or not _valid_map_id(map_id):
        raise CharacterSnapshotError("invalid stored character row")
    if any(
        type(value) is not int
        or not _MIN_COORDINATE <= value <= _MAX_COORDINATE
        for value in (x, y)
    ):
        raise CharacterSnapshotError("invalid stored character row")

    return CharacterSnapshot(character_id, name, map_id, x, y)
