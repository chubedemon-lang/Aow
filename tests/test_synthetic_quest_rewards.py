"""Tests for synthetic in-memory quest reward behavior only."""
import unittest

from server.inventory_ledger import InventoryLedger, ItemDefinition
from server.synthetic_quests import Quest, QuestBook
from server.synthetic_quest_rewards import ItemReward, claim_item_reward


class QuestRewardTests(unittest.TestCase):
    def setUp(self):
        self.inventory = InventoryLedger({"gem": ItemDefinition("gem", 5)}, 1)
        self.book = QuestBook(17).add(Quest(3, "walk", 2))
        self.reward = ItemReward("gem", 2)

    def test_claim_grants_item_and_returns_new_book(self):
        done = self.book.advance(3, "walk", 2)
        claimed = claim_item_reward(done, 3, self.reward, self.inventory)
        self.assertTrue(claimed.entries[0].claimed)
        self.assertFalse(done.entries[0].claimed)
        self.assertEqual(self.inventory.snapshot("17"), {"gem": 2})

    def test_incomplete_quest_does_not_grant(self):
        with self.assertRaises(ValueError):
            claim_item_reward(self.book, 3, self.reward, self.inventory)
        self.assertEqual(self.inventory.snapshot("17"), {})

    def test_reclaim_rejected_without_second_grant(self):
        done = self.book.advance(3, "walk", 2)
        claimed = claim_item_reward(done, 3, self.reward, self.inventory)
        with self.assertRaises(ValueError):
            claim_item_reward(claimed, 3, self.reward, self.inventory)
        self.assertEqual(self.inventory.snapshot("17"), {"gem": 2})

    def test_inventory_failure_keeps_quest_unclaimed(self):
        done = self.book.advance(3, "walk", 2)
        self.inventory.grant("17", "gem", 5)
        with self.assertRaises(ValueError):
            claim_item_reward(done, 3, self.reward, self.inventory)
        self.assertFalse(done.entries[0].claimed)
        self.assertEqual(self.inventory.snapshot("17"), {"gem": 5})

    def test_invalid_reward_values(self):
        for quantity in (0, -1, True, 1.2):
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                ItemReward("gem", quantity)

    def test_player_isolation(self):
        done = self.book.advance(3, "walk", 2)
        claim_item_reward(done, 3, self.reward, self.inventory)
        self.assertEqual(self.inventory.snapshot("18"), {})

    def test_unknown_item_does_not_claim(self):
        done = self.book.advance(3, "walk", 2)
        with self.assertRaises(ValueError):
            claim_item_reward(done, 3, ItemReward("missing", 1), self.inventory)
        self.assertEqual(self.inventory.snapshot("17"), {})


if __name__ == "__main__":
    unittest.main()
