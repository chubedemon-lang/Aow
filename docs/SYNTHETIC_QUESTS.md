# Synthetic quest progression

`server/synthetic_quests.py` provides immutable, bounded quest progress for offline server domain tests. It does not encode, decode, or assert any AOW APK packet, objective identifier, quest table, reward, or game rule.

A quest has a positive ID, objective label and bounded target count. A player-specific `QuestBook` holds up to 256 unique quests. Progress is capped; claiming requires completion and can occur only once. Invalid types, duplicate IDs and wrong objectives are rejected.

Run `python -m unittest discover -s tests`. Production integration requires verified client protocol, authoritative quest definitions, authenticated player ownership, durable storage and atomic reward granting. Do not grant inventory/currency rewards based on an untrusted client completion claim.
