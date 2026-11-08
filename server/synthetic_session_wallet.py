"""Bounded synthetic session wallet; no AOW currency or wire assumptions."""
from server.synthetic_session_lifecycle import SessionState


class WalletError(ValueError):
    """Invalid wallet operation; rejected transactions do not change balance."""


class SessionWallet:
    def __init__(self, maximum=2_000_000_000):
        if type(maximum) is not int or not 1 <= maximum <= 2_000_000_000:
            raise WalletError("invalid maximum")
        self.maximum = maximum
        self._session = None
        self._epoch = None
        self._balance = None

    @property
    def balance(self):
        return self._balance

    def sync(self, session):
        snapshot = session.snapshot
        if (session is not self._session or snapshot is not self._epoch
                or snapshot.state not in (SessionState.CHARACTER_READY, SessionState.IN_MAP)):
            self._session = None
            self._epoch = None
            self._balance = None
        return self._balance

    def initialize(self, session, initial=0):
        self.sync(session)
        if session.snapshot.state is not SessionState.CHARACTER_READY:
            raise WalletError("character not ready")
        if self._balance is not None:
            raise WalletError("already initialized")
        if type(initial) is not int or not 0 <= initial <= self.maximum:
            raise WalletError("invalid initial balance")
        self._session, self._epoch, self._balance = session, session.snapshot, initial
        return self._balance

    def _check(self, session, amount):
        self.sync(session)
        if self._balance is None:
            raise WalletError("wallet not initialized")
        if type(amount) is not int or not 1 <= amount <= self.maximum:
            raise WalletError("invalid amount")

    def credit(self, session, amount):
        self._check(session, amount)
        if self._balance > self.maximum - amount:
            raise WalletError("balance overflow")
        self._balance += amount
        return self._balance

    def debit(self, session, amount):
        self._check(session, amount)
        if amount > self._balance:
            raise WalletError("insufficient funds")
        self._balance -= amount
        return self._balance
