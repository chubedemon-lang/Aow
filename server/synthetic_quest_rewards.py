"""In-memory synthetic quest reward adapter; NOT an AOW wire contract.

Caller must persist both resulting quest state and inventory transaction atomically
before using this pattern in a real server. No concurrent writer guarantees.
"""
from dataclasses import dataclass

from server.inventory_ledger import InventoryLedger, InventoryError
from server.synthetic_quests import QuestBook


@dataclass(frozen=True)
class ItemReward:
    item_id: str
    quantity: int

    def __post_init__(self):
        if not isinstance(self.item_id, str) or not self.item_id.strip():
            raise ValueError("invalid reward item")
        if type(self.quantity) is not int or self.quantity < 1:
            raise ValueError("invalid reward quantity")


def claim_item_reward(book: QuestBook, quest_id: int, reward: ItemReward,
                      inventory: InventoryLedger) -> QuestBook:
    """Return claimed book only after inventory accepts the reward.

    This is a synchronous single-process helper. The caller must replace its
    old book with the returned book; otherwise retries can duplicate rewards.
    """
    if type(book) is not QuestBook or type(reward) is not ItemReward:
        raise ValueError("invalid claim inputs")
    if not isinstance(inventory, InventoryLedger):
        raise ValueError("invalid inventory")
    # Preflight quest completion and single-claim status before mutating items.
    claimed = book.claim(quest_id)
    try:
        inventory.grant(str(book.player_id), reward.item_id, reward.quantity)
    except InventoryError as exc:
        raise ValueError("reward inventory rejected") from exc
    return claimed
