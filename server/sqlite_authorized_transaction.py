"""Atomic durable-session and character authorization boundary.

Use this helper around protected SQLite domain operations. BEGIN IMMEDIATE
serializes session revocation with the authorization check and the state
operation that follows it. The authorizer and its session store must both use
the exact supplied connection. This is a synthetic server-domain primitive,
not an AOW login or wire protocol.
"""
from contextlib import contextmanager
import sqlite3


@contextmanager
def authorized_character_transaction(connection, authorizer, token,
                                      character_id):
    """Yield the owned character ID while holding one caller-managed transaction.

    The helper owns the transaction for its entire context. Nested store methods
    may participate in it but must not commit or roll it back. The authorizer
    must use this exact SQLite connection so revocation and state mutation are
    serialized by the same database write lock.
    """
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("sqlite connection required")
    if getattr(authorizer, "db", None) is not connection:
        raise ValueError("authorizer must use the same SQLite connection")
    session_store = getattr(authorizer, "sessions", None)
    if getattr(session_store, "db", None) is not connection:
        raise ValueError("session store must use the same SQLite connection")
    if not callable(getattr(authorizer, "require_in_transaction", None)):
        raise TypeError("authorizer must support transactional authorization")
    if connection.in_transaction:
        raise ValueError("connection must not have an active transaction")

    connection.execute("BEGIN IMMEDIATE")
    try:
        owned_id = authorizer.require_in_transaction(token, character_id)
        yield owned_id
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
