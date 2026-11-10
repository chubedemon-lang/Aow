"""Tests for synthetic server domain only; no APK protocol assertions."""
import http.client
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from server.mock import Domain, make_handler


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.domain = Domain(Path(self.temp.name) / "test.sqlite3")

    def test_create_read_move_and_persistence(self):
        created = self.domain.create_character("alice", "hero")
        self.assertEqual(created["x"], 0)
        moved = self.domain.move(created["id"], 25, -10)
        self.assertEqual((moved["x"], moved["y"]), (25, -10))
        reopened = Domain(self.domain.database)
        self.assertEqual(reopened.get_character(created["id"]), moved)

    def test_unique_character_per_account(self):
        self.domain.create_character("alice", "hero")
        with self.assertRaises(sqlite3.IntegrityError):
            self.domain.create_character("alice", "second")

    def test_missing_character(self):
        with self.assertRaises(KeyError):
            self.domain.get_character(999)

    def test_reject_invalid_input(self):
        with self.assertRaises(ValueError):
            self.domain.create_character("", "hero")
        created = self.domain.create_character("alice", "hero")
        for invalid_id in (True, 1.0, "1", 0, -1):
            with self.assertRaises(ValueError):
                self.domain.get_character(invalid_id)
            with self.assertRaises(ValueError):
                self.domain.move(invalid_id, 1, 1)
        for x, y in [(True, 1), (1.5, 2), (10001, 0)]:
            with self.assertRaises(ValueError):
                self.domain.move(created["id"], x, y)


    def test_inventory_grant_consume_and_persist(self):
        character = self.domain.create_character("alice", "hero")
        cid = character["id"]
        self.assertEqual(self.domain.list_inventory(cid), [])
        self.assertEqual(self.domain.change_inventory(cid, "test_item", 5), {"item_id": "test_item", "quantity": 5})
        reopened = Domain(self.domain.database)
        self.assertEqual(reopened.list_inventory(cid), [{"item_id": "test_item", "quantity": 5}])
        self.assertEqual(reopened.change_inventory(cid, "test_item", -3)["quantity"], 2)
        self.assertEqual(reopened.change_inventory(cid, "test_item", -2)["quantity"], 0)
        self.assertEqual(reopened.list_inventory(cid), [])

    def test_inventory_rejects_bad_inputs_without_mutating(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        for bad_delta in (0, True, 1.5, 1_000_001):
            with self.assertRaises(ValueError):
                self.domain.change_inventory(cid, "test_item", bad_delta)
        for bad_item in ("", "spaces are invalid", "a" * 65, "id/other"):
            with self.assertRaises(ValueError):
                self.domain.change_inventory(cid, bad_item, 1)
        with self.assertRaises(ValueError):
            self.domain.change_inventory(cid, "test_item", -1)
        with self.assertRaises(KeyError):
            self.domain.change_inventory(9999, "test_item", 1)
        with self.assertRaises(KeyError):
            self.domain.list_inventory(9999)
        self.assertEqual(self.domain.list_inventory(cid), [])

    def test_inventory_atomic_concurrent_updates(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.domain.change_inventory(cid, "test_item", 1), range(40)))
        self.assertEqual(self.domain.list_inventory(cid), [{"item_id": "test_item", "quantity": 40}])


    def test_shop_purchase_debits_wallet_and_grants_item(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 30)
        self.assertEqual(self.domain.credit_wallet(cid, 100), 100)
        receipt = self.domain.buy_item(cid, "potion", 2)
        self.assertEqual(receipt, {"item_id": "potion", "quantity_purchased": 2, "total": 60, "balance": 40})
        self.assertEqual(Domain(self.domain.database).list_inventory(cid), [{"item_id": "potion", "quantity": 2}])

    def test_shop_insufficient_funds_rolls_back(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 50)
        self.domain.credit_wallet(cid, 10)
        with self.assertRaises(ValueError):
            self.domain.buy_item(cid, "potion")
        self.assertEqual(self.domain.list_inventory(cid), [])
        self.assertEqual(self.domain.credit_wallet(cid, 1), 11)

    def test_shop_disabled_and_invalid_requests(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 1, False)
        self.domain.credit_wallet(cid, 10)
        with self.assertRaises(KeyError):
            self.domain.buy_item(cid, "potion")
        for invalid in (True, 0, 101, 1.5):
            with self.assertRaises(ValueError):
                self.domain.buy_item(cid, "potion", invalid)
        with self.assertRaises(KeyError):
            self.domain.buy_item(999, "potion")
        with self.assertRaises(ValueError):
            self.domain.credit_wallet(cid, True)

    def test_shop_concurrent_purchase_cannot_overspend(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 10)
        self.domain.credit_wallet(cid, 100)
        def purchase(_):
            try:
                self.domain.buy_item(cid, "potion")
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(purchase, range(20)))
        self.assertEqual(sum(results), 10)
        self.assertEqual(self.domain.list_inventory(cid), [{"item_id": "potion", "quantity": 10}])
        self.assertEqual(self.domain.credit_wallet(cid, 1), 1)


class HandlerRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.domain = Domain(Path(self.temp.name) / "routes.sqlite3")
        self.character_id = self.domain.create_character("alice", "hero")["id"]
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.domain))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        body = json.dumps(payload) if payload is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = (response.status, json.loads(response.read().decode("utf-8")))
        connection.close()
        return result

    def test_get_rejects_extra_path_segments(self):
        status, _ = self.request("GET", f"/characters/ignored/{self.character_id}")
        self.assertEqual(status, 404)
        self.assertEqual(self.domain.get_character(self.character_id)["x"], 0)

    def test_move_rejects_extra_path_segments_without_mutation(self):
        status, _ = self.request(
            "POST",
            f"/characters/{self.character_id}/ignored/move",
            {"x": 7, "y": 8},
        )
        self.assertEqual(status, 404)
        self.assertEqual(
            (self.domain.get_character(self.character_id)["x"],
             self.domain.get_character(self.character_id)["y"]),
            (0, 0),
        )

    def test_move_accepts_exact_route(self):
        status, payload = self.request(
            "POST", f"/characters/{self.character_id}/move", {"x": 7, "y": -8}
        )
        self.assertEqual(status, 200)
        self.assertEqual((payload["x"], payload["y"]), (7, -8))
    
    def test_post_rejects_duplicate_json_keys_without_creating_character(self):
        body = b'{"username":"alice","username":"mallory","name":"hero"}'
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST", "/characters", body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()

        with self.assertRaises(KeyError):
            self.domain.get_character(2)

    def test_post_rejects_non_json_content_type(self):
        body = b'{"username":"alice","name":"hero"}'
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST", "/characters", body=body,
            headers={"Content-Type": "text/plain", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()
        with self.assertRaises(KeyError):
            self.domain.get_character(2)


if __name__ == "__main__":
    unittest.main()
