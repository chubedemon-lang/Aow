# AOW server-only scope

The user explicitly requires **source server only**. Do not create a Unity project or rebuild an APK. The existing Android client must remain unchanged.

## First technical gate
Before implementing a compatible gateway, identify and verify:
- Actual transport and endpoint discovery
- Authentication/session handshake
- Serialization/framing and any version negotiation
- Initial character/world packets

Use only offline static analysis of the user's APK and authorized local testing. The `tools/protocol_candidates.py` scanner extracts **unverified** URL/host string candidates; results can contain third-party SDK URLs, false positives or sensitive information. Do not commit its output.

## Development order
Protocol evidence → transport adapter → session/login → player persistence → map sync → inventory → combat → shop/quests → end-to-end test with unchanged APK.

## Tooling
```sh
python -m unittest discover -s tests -p 'test_protocol_candidates.py'
python tools/protocol_candidates.py /secure/path/aow.apk --output /secure/path/candidates.json
```

The scanner makes no network requests. A candidate string is not proof of a production endpoint. Do not probe official servers without authorization.
