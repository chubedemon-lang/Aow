#!/usr/bin/env python3
"""Read-only IL2CPP metadata identifier inventory for an authorized local APK.

This tool reads one bounded global-metadata.dat member from the APK ZIP. It does
not extract assets, decompile code, make network requests, or emit endpoint data.
The result is a static identifier inventory, not a packet decoder.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

METADATA_MEMBER = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
METADATA_MAGIC = 0xFAB11BAF
SUPPORTED_METADATA_VERSION = 31
HEADER_MIN_BYTES = 32
STRING_HEAP_PAIR_OFFSET = 24
MAX_APK_BYTES = 4 * 1024**3
MAX_METADATA_BYTES = 256 * 1024**2
MAX_STRING_HEAP_BYTES = 64 * 1024**2

NAMESPACE_TOKENS = (
    "com.geargames.aow.messages",
    "com.geargames.common.network",
    "com.geargames.unity.network",
    "com.geargames.aow.config",
)
NETWORK_IDENTIFIER_TOKENS = (
    "NetworkSocket",
    "NetworkSocketStream",
    "NetworkSettings",
    "MessageDispatcher",
    "MessageHelper",
    "MessageMeta",
    "MessageTypes",
    "IClientMessageSerializer",
    "IClientMessageDeserializer",
    "SerializeMessage",
    "DeserializeMessage",
    "RemoteServerAddresses",
    "ServerAddressHelper",
    "ClientServerAddressConfiguration",
    "ClientServerPreset",
    "TransportType",
    "CSEstablishConnection",
    "CSHttpSendRequestAndReceiveResponse",
)
MESSAGE_IDENTIFIER_TOKENS = (
    "LoginRequest",
    "LoginAnswer",
    "SessionRestoreRequest",
    "SessionRestoreAnswer",
    "LoginToBattleRequest",
    "LoginToBattleAnswer",
    "RegistrationRequest",
    "RegistrationAnswer",
    "CheckSocket",
    "Ping",
)


class MetadataInventoryError(ValueError):
    """The local APK or metadata header is missing, malformed, or unsupported."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_metadata(path: Path) -> tuple[bytes, int, str]:
    if path.is_symlink() or not path.is_file():
        raise MetadataInventoryError("expected a regular local APK file")
    apk_size = path.stat().st_size
    if not 0 < apk_size <= MAX_APK_BYTES:
        raise MetadataInventoryError("APK size outside safety bounds")

    try:
        with zipfile.ZipFile(path) as archive:
            matches = [item for item in archive.infolist()
                       if item.filename == METADATA_MEMBER]
            if len(matches) != 1:
                raise MetadataInventoryError(
                    "expected exactly one IL2CPP global metadata member"
                )
            info = matches[0]
            if info.flag_bits & 0x1:
                raise MetadataInventoryError("encrypted metadata member")
            if not HEADER_MIN_BYTES <= info.file_size <= MAX_METADATA_BYTES:
                raise MetadataInventoryError("metadata size outside safety bounds")
            with archive.open(info) as source:
                metadata = source.read(MAX_METADATA_BYTES + 1)
            if len(metadata) != info.file_size:
                raise MetadataInventoryError("metadata member size mismatch")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise MetadataInventoryError("not a readable APK ZIP") from exc

    return metadata, apk_size, _sha256_file(path)


def inspect_apk(path: str | Path) -> dict:
    """Return only allowlisted metadata identifiers and aggregate counts."""
    source = Path(path)
    metadata, apk_size, apk_sha256 = _read_metadata(source)
    if len(metadata) < HEADER_MIN_BYTES:
        raise MetadataInventoryError("metadata header is truncated")

    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != METADATA_MAGIC:
        raise MetadataInventoryError("invalid IL2CPP metadata magic")
    if version != SUPPORTED_METADATA_VERSION:
        raise MetadataInventoryError("unsupported IL2CPP metadata version")

    string_offset, string_size = struct.unpack_from(
        "<II", metadata, STRING_HEAP_PAIR_OFFSET
    )
    string_end = string_offset + string_size
    if (
        string_offset < HEADER_MIN_BYTES
        or string_size <= 0
        or string_size > MAX_STRING_HEAP_BYTES
        or string_end < string_offset
        or string_end > len(metadata)
    ):
        raise MetadataInventoryError("invalid metadata string-heap bounds")

    heap = metadata[string_offset:string_end]
    # Metadata identifiers are inventoried only when they are bounded,
    # printable ASCII NUL-terminated strings. No arbitrary bytes are emitted.
    strings = {
        token.decode("ascii")
        for token in heap.split(b"\x00")
        if 0 < len(token) <= 256 and all(0x20 <= byte <= 0x7E for byte in token)
    }

    serializer_names = {
        token for token in strings if token.endswith("STSerializer")
        and len(token) > len("STSerializer")
    }
    deserializer_names = {
        token for token in strings if token.endswith("STDeserializer")
        and len(token) > len("STDeserializer")
    }
    serializer_bases = {name[:-len("STSerializer")] for name in serializer_names}
    deserializer_bases = {name[:-len("STDeserializer")] for name in deserializer_names}
    paired_bases = serializer_bases & deserializer_bases

    observed_messages = [
        name for name in MESSAGE_IDENTIFIER_TOKENS if name in strings
    ]
    paired_messages = [name for name in observed_messages if name in paired_bases]

    return {
        "apk_size_bytes": apk_size,
        "apk_sha256": apk_sha256,
        "metadata_member": METADATA_MEMBER,
        "metadata_size_bytes": len(metadata),
        "metadata_magic": f"0x{magic:08x}",
        "metadata_version": version,
        "string_heap_bytes": string_size,
        "unique_printable_string_count": len(strings),
        "serializer_identifier_count": len(serializer_names),
        "deserializer_identifier_count": len(deserializer_names),
        "paired_serializer_identifier_count": len(paired_bases),
        "observed_namespace_tokens": [
            token for token in NAMESPACE_TOKENS if token in strings
        ],
        "observed_network_identifier_tokens": [
            token for token in NETWORK_IDENTIFIER_TOKENS if token in strings
        ],
        "observed_message_identifier_tokens": observed_messages,
        "message_identifiers_with_serializer_and_deserializer_tokens": paired_messages,
        "interpretation": (
            "Static IL2CPP metadata string identifiers only. They do not establish "
            "wire framing, packet IDs, field schemas, endpoint selection, transport, "
            "authentication semantics, or APK-to-server compatibility."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only, offline IL2CPP metadata identifier inventory."
    )
    parser.add_argument("apk", help="Path to an authorized local APK")
    parser.add_argument(
        "--output",
        help="Optional local JSON report path; review before sharing",
    )
    args = parser.parse_args()
    report = json.dumps(inspect_apk(args.apk), indent=2, ensure_ascii=True)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
