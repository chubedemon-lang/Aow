"""Atomic local inventory transfer; synthetic server mechanics, not AOW wire data."""
from server.synthetic_inventory import Inventory, InventoryError


def transfer(source: Inventory, destination: Inventory, item_id: int, quantity: int):
    """Move a stack quantity between independent inventories without partial writes.

    This in-memory operation assumes a single-threaded caller. Synchronize externally
    if concurrent session workers can mutate either inventory.
    """
    if not isinstance(source, Inventory) or not isinstance(destination, Inventory):
        raise InventoryError("invalid inventory")
    if source is destination:
        raise InventoryError("source and destination must differ")
    source._validate(item_id, quantity)
    before_source = source.snapshot()
    before_destination = destination.snapshot()
    # Validate both proposed states on private copies before either commit.
    trial_source = Inventory(source.capacity, source.max_stack)
    trial_source._items = before_source
    trial_destination = Inventory(destination.capacity, destination.max_stack)
    trial_destination._items = before_destination
    trial_source.remove(item_id, quantity)
    trial_destination.add(item_id, quantity)
    source._items = trial_source.snapshot()
    destination._items = trial_destination.snapshot()
    return source.snapshot(), destination.snapshot()
