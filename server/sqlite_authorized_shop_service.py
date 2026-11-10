"""Session-authorized facade for synthetic durable SQLite shop purchases.

This is a local server-domain integration only. It does not implement AOW
login, shop packets, item catalogs, or original-game economy rules. Offer IDs,
prices and item IDs remain caller-supplied synthetic data.

Every purchase holds one BEGIN IMMEDIATE transaction across session
resolution, character ownership, debit, item grant and receipt replay. Session
revocation therefore serializes before or after the complete purchase.

Session tokens must only be issued after trusted account authentication.
No HTTP route is registered here. Character ownership transfer is not supported.
"""
import sqlite3

from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_session_store import SqliteSessionStore
from server.sqlite_shop_store import (
    ShopOffer,
    ShopPurchase,
    SqliteShopStore,
)


_MAX_TTL_SECONDS = 31_536_000
_MAX_PURCHASE_QUANTITY = 999


class SqliteAuthorizedShopService:
    """Require an active session and character ownership before every purchase."""

    def __init__(self, connection: sqlite3.Connection,
                 offers: dict[str, ShopOffer], *,
                 max_purchase_quantity: int = 99,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")

        # Validate all caller configuration and ownership schema before any
        # constructor creates tables or commits schema changes.
        require_character_schema(connection)
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise ValueError("invalid session ttl")
        if (type(max_purchase_quantity) is not int
                or not 1 <= max_purchase_quantity <= _MAX_PURCHASE_QUANTITY):
            raise ValueError("invalid maximum purchase quantity")
        if not isinstance(offers, dict) or any(
            not isinstance(offer, ShopOffer) or key != offer.offer_id
            for key, offer in offers.items()
        ):
            raise ValueError("offer keys must match valid shop offers")

        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self._shop = SqliteShopStore(
            connection, offers,
            max_purchase_quantity=max_purchase_quantity,
        )

    def purchase(self, token: str, character_id: int, request_id: str,
                 expected_player_revision: int,
                 expected_inventory_revision: int,
                 offer_id: str, quantity: int = 1) -> ShopPurchase:
        """Purchase atomically with authorization and idempotent receipt replay."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._shop.purchase(
                owned_id,
                request_id,
                expected_player_revision,
                expected_inventory_revision,
                offer_id,
                quantity,
            )
