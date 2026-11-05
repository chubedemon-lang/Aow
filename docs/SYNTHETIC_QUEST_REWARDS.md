# Synthetic quest item rewards

This adapter joins the immutable synthetic quest book to the in-memory inventory ledger. It is **not** a verified AOW APK packet or a production transaction boundary.

Call `claim_item_reward` only with a completed, unclaimed quest. The function validates claim eligibility first, then grants the item and returns the updated book. Inventory rejection leaves the caller's original book unchanged.

**Critical limitation:** the ledger mutates before the caller persists the new book. A crash, retry using an old book, or concurrent writers can duplicate grants. Production implementation requires one durable transaction containing inventory changes, quest claim status and an idempotency key. Never expose this helper directly to untrusted network traffic.

Run `python -m unittest discover -s tests`. No APK/client compatibility is asserted.
