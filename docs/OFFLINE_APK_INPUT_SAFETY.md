# Offline APK analyzer input safety

The redacted native callsite analyzer reads an authorized APK only from a private local workspace. Its digest and ZIP member extraction must refer to the same opened file object.

`_read_apk_members()` in `tools/il2cpp_network_callsite_evidence.py` enforces this boundary:

- `lstat` rejects symlinks and non-regular paths before opening.
- `O_NOFOLLOW` is used when available; `fstat` identity checks provide a second check.
- The APK size is bounded before hashing or ZIP parsing.
- SHA-256 hashing and ZIP extraction use one descriptor, avoiding a second path open between those operations.
- Truncation, growth, in-place metadata changes, and path replacement are rejected.
- The two required IL2CPP members must each occur exactly once and remain within their independent size limits.
- Only the digest and bounded member bytes are passed to the existing in-memory analyzer. The report remains aggregate/redacted.

The tests use small synthetic ZIP fixtures only. They do not contain the user's APK, native binaries, packet bytes, endpoints, credentials, or proprietary assets.

This input hardening improves reproducibility and prevents the analyzer from mixing a digest from one file with metadata/native members from another. It does not add protocol findings or establish packet framing, handshake, login, or APK/server compatibility.
