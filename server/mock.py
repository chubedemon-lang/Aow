"""Local-only, deliberately synthetic API to exercise server domain behavior.

This is NOT the original AOW protocol. Do not expose it on a public interface.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
from pathlib import Path


def initialize(conn):
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS characters (
            id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL, map_id TEXT NOT NULL DEFAULT 'test_map',
            x INTEGER NOT NULL DEFAULT 0, y INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        );
        CREATE TABLE IF NOT EXISTS wallets (
            character_id INTEGER PRIMARY KEY,
            balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
            FOREIGN KEY(character_id) REFERENCES characters(id)
        );
        CREATE TABLE IF NOT EXISTS shop_catalog (
            item_id TEXT PRIMARY KEY,
            price INTEGER NOT NULL CHECK(price > 0),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
        );
        CREATE TABLE IF NOT EXISTS inventory (
            character_id INTEGER NOT NULL, item_id TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity >= 0),
            PRIMARY KEY(character_id, item_id),
            FOREIGN KEY(character_id) REFERENCES characters(id)
        );
    """)
    conn.commit()


class Domain:
    def __init__(self, database):
        self.database = str(database)
        with self.connect() as db:
            initialize(db)

    def connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def create_character(self, username, name):
        if not isinstance(username, str) or not 1 <= len(username) <= 64:
            raise ValueError("invalid username")
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            raise ValueError("invalid character name")
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO accounts(username) VALUES (?)", (username,))
            account = db.execute("SELECT id FROM accounts WHERE username=?", (username,)).fetchone()
            db.execute("INSERT INTO characters(account_id, name) VALUES (?,?)", (account["id"], name))
            char_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            return {"id": char_id, "name": name, "map_id": "test_map", "x": 0, "y": 0}

    def get_character(self, character_id):
        with self.connect() as db:
            row = db.execute("SELECT id,name,map_id,x,y FROM characters WHERE id=?", (character_id,)).fetchone()
            if row is None:
                raise KeyError("character not found")
            return dict(row)

    def move(self, character_id, x, y):
        if type(x) is not int or type(y) is not int or abs(x) > 10000 or abs(y) > 10000:
            raise ValueError("invalid coordinates")
        with self.connect() as db:
            result = db.execute("UPDATE characters SET x=?, y=? WHERE id=?", (x, y, character_id))
            if result.rowcount == 0:
                raise KeyError("character not found")
        return self.get_character(character_id)


    def list_inventory(self, character_id):
        """List a character's synthetic items; does not represent APK item IDs."""
        if type(character_id) is not int or character_id < 1:
            raise ValueError("invalid character id")
        with self.connect() as db:
            if db.execute("SELECT 1 FROM characters WHERE id=?", (character_id,)).fetchone() is None:
                raise KeyError("character not found")
            rows = db.execute(
                "SELECT item_id, quantity FROM inventory WHERE character_id=? ORDER BY item_id",
                (character_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def change_inventory(self, character_id, item_id, delta):
        """Atomically grant or consume an item in the local synthetic domain."""
        if type(character_id) is not int or character_id < 1:
            raise ValueError("invalid character id")
        if not isinstance(item_id, str) or not (1 <= len(item_id) <= 64) or not all(
            c.isascii() and (c.isalnum() or c in "._-") for c in item_id
        ):
            raise ValueError("invalid item id")
        if type(delta) is not int or delta == 0 or abs(delta) > 1_000_000:
            raise ValueError("invalid quantity change")
        with self.connect() as db:
            # Lock before reading to prevent lost updates between concurrent requests.
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM characters WHERE id=?", (character_id,)).fetchone() is None:
                raise KeyError("character not found")
            row = db.execute(
                "SELECT quantity FROM inventory WHERE character_id=? AND item_id=?",
                (character_id, item_id),
            ).fetchone()
            quantity = (row["quantity"] if row is not None else 0) + delta
            if not 0 <= quantity <= 2_147_483_647:
                raise ValueError("insufficient quantity or overflow")
            if quantity == 0:
                db.execute(
                    "DELETE FROM inventory WHERE character_id=? AND item_id=?",
                    (character_id, item_id),
                )
            else:
                db.execute(
                    """INSERT INTO inventory(character_id, item_id, quantity) VALUES (?, ?, ?)
                       ON CONFLICT(character_id, item_id)
                       DO UPDATE SET quantity=excluded.quantity""",
                    (character_id, item_id, quantity),
                )
            return {"item_id": item_id, "quantity": quantity}


    def credit_wallet(self, character_id, amount):
        """Test fixture funding only; never expose as a client-controlled endpoint."""
        if type(character_id) is not int or character_id < 1:
            raise ValueError("invalid character id")
        if type(amount) is not int or not 1 <= amount <= 1_000_000:
            raise ValueError("invalid credit amount")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM characters WHERE id=?", (character_id,)).fetchone() is None:
                raise KeyError("character not found")
            db.execute("INSERT OR IGNORE INTO wallets(character_id, balance) VALUES (?,0)", (character_id,))
            result = db.execute(
                "UPDATE wallets SET balance=balance+? WHERE character_id=? AND balance<=?",
                (amount, character_id, 2_147_483_647 - amount),
            )
            if result.rowcount != 1:
                raise ValueError("wallet overflow")
            return db.execute("SELECT balance FROM wallets WHERE character_id=?", (character_id,)).fetchone()[0]

    def set_shop_item(self, item_id, price, enabled=True):
        """Local operator configuration; no client API is provided."""
        if not isinstance(item_id, str) or not 1 <= len(item_id) <= 64 or not all(
            ch.isascii() and (ch.isalnum() or ch in "._-") for ch in item_id
        ):
            raise ValueError("invalid item id")
        if type(price) is not int or not 1 <= price <= 1_000_000:
            raise ValueError("invalid price")
        if type(enabled) is not bool:
            raise ValueError("invalid enabled flag")
        with self.connect() as db:
            db.execute(
                """INSERT INTO shop_catalog(item_id, price, enabled) VALUES (?,?,?)
                   ON CONFLICT(item_id) DO UPDATE SET price=excluded.price, enabled=excluded.enabled""",
                (item_id, price, int(enabled)),
            )

    def buy_item(self, character_id, item_id, count=1):
        """Synthetic shop purchase: atomically debit wallet and grant inventory."""
        if type(character_id) is not int or character_id < 1:
            raise ValueError("invalid character id")
        if not isinstance(item_id, str) or not 1 <= len(item_id) <= 64 or not all(
            ch.isascii() and (ch.isalnum() or ch in "._-") for ch in item_id
        ):
            raise ValueError("invalid item id")
        if type(count) is not int or not 1 <= count <= 100:
            raise ValueError("invalid count")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM characters WHERE id=?", (character_id,)).fetchone() is None:
                raise KeyError("character not found")
            catalog = db.execute(
                "SELECT price FROM shop_catalog WHERE item_id=? AND enabled=1", (item_id,)
            ).fetchone()
            if catalog is None:
                raise KeyError("item unavailable")
            total = catalog["price"] * count
            result = db.execute(
                "UPDATE wallets SET balance=balance-? WHERE character_id=? AND balance>=?",
                (total, character_id, total),
            )
            if result.rowcount != 1:
                raise ValueError("insufficient funds")
            existing = db.execute(
                "SELECT quantity FROM inventory WHERE character_id=? AND item_id=?",
                (character_id, item_id),
            ).fetchone()
            if existing is not None and existing["quantity"] > 2_147_483_647 - count:
                raise ValueError("inventory overflow")
            db.execute(
                """INSERT INTO inventory(character_id,item_id,quantity) VALUES (?,?,?)
                   ON CONFLICT(character_id,item_id)
                   DO UPDATE SET quantity=quantity+excluded.quantity""",
                (character_id, item_id, count),
            )
            balance = db.execute(
                "SELECT balance FROM wallets WHERE character_id=?", (character_id,)
            ).fetchone()["balance"]
            return {"item_id": item_id, "quantity_purchased": count, "total": total, "balance": balance}


def make_handler(domain):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, payload):
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                return self.respond(200, {"status": "ok", "protocol": "synthetic-test-only"})
            if self.path.startswith("/characters/"):
                try:
                    character_id = int(self.path.split("/")[-1])
                    return self.respond(200, domain.get_character(character_id))
                except (ValueError, KeyError):
                    return self.respond(404, {"error": "not found"})
            return self.respond(404, {"error": "not found"})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    return self.respond(400, {"error": "invalid body size"})
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("expected object")
                if self.path == "/characters":
                    return self.respond(201, domain.create_character(payload.get("username"), payload.get("name")))
                if self.path.startswith("/characters/") and self.path.endswith("/move"):
                    character_id = int(self.path.split("/")[2])
                    return self.respond(200, domain.move(character_id, payload.get("x"), payload.get("y")))
                return self.respond(404, {"error": "not found"})
            except (ValueError, TypeError, json.JSONDecodeError):
                return self.respond(400, {"error": "invalid request"})
            except (KeyError, sqlite3.IntegrityError):
                return self.respond(409, {"error": "conflict or missing character"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="aow_mock.sqlite3")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    domain = Domain(Path(args.db))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(domain))
    print(f"Synthetic AOW domain API on http://127.0.0.1:{args.port} (NOT APK compatible)")
    server.serve_forever()


if __name__ == "__main__":
    main()
