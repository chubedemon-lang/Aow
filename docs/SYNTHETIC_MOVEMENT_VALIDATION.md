# Synthetic movement validation boundary

`server/movement_validation.py` is a transport-independent domain helper used by local tests. It does not define AOW coordinate units, map bounds, movement speed, tick timing, packet fields, or anti-cheat behavior.

## Accepted runtime values

- Coordinates, maximum speed, epsilon, and elapsed time must be exact built-in `int` or `float` values. Booleans and numeric subclasses are rejected before conversion, so caller-defined `__float__` methods are never invoked.
- Movement endpoints must be exact `Position` instances. Subclasses are rejected before coordinate attributes are read, avoiding overridden attribute-access hooks in the authoritative comparison.
- Values must remain representable as finite floats. Overflowed deltas, distances, or allowed-distance calculations fail closed.

Persisted or external request data must be decoded and validated at its boundary before constructing a `Position`. These restrictions are synthetic input-safety rules only; they are not evidence of the original AOW movement contract.

Run the focused suite:

```sh
python -m unittest discover -s tests -p 'test_movement_validation.py' -v
```
