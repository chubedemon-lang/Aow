# Protocol evidence object boundaries

The protocol evidence registry and readiness gates are bookkeeping controls for
authorized offline analysis. They are not packet decoders and do not establish
APK compatibility.

## Accepted object shapes

- Registry records must be exact instances of `Evidence`; subclasses are
  rejected before any record fields are read.
- Gate input must be an exact built-in `list` or `tuple`, containing only
  exact `Evidence` instances.
- Artifact fingerprints must be exact built-in lowercase SHA-256 strings.
- Evidence digest input must be exact immutable `bytes`.

These constraints prevent caller-defined subclasses from running custom
attribute, iteration, conversion, or equality hooks while evidence is being
accepted or evaluated. They also keep the registry and ordered gates on the
same narrow input contract.

## Validation

```sh
python -m unittest discover -s tests -p 'test_protocol_evidence_registry.py' -v
python -m unittest discover -s tests -p 'test_protocol_evidence_gates.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

Synthetic hostile-subclass tests validate only the Python input boundary.
They do not add native APK observations, packet fixtures, wire semantics,
handshake/login evidence, or an interoperability claim. Keep the original APK,
native assets, packet bytes, captures, endpoint values, and credentials out of
the public repository.


## Public metadata manifest input boundary

The metadata-only manifest path is equally strict: JSON ingestion accepts only
exact built-in `bytes`; decoded manifests must be exact built-in `list`
objects; records must be exact built-in `dict` objects; dictionary keys and
free-text values must be exact built-in `str` objects. These checks happen
before length, decoding, iteration, indexing, hashing, or string methods can
dispatch to caller-defined subclass hooks.

This is input-boundary hardening for the evidence bookkeeping tools only. It
does not add APK observations, packet fixtures, protocol semantics, or an
interoperability claim.
