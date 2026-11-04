#!/usr/bin/env python3
"""Offline, metadata-only APK inventory. Never uploads or extracts APK content."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

MAX_ENTRIES = 100_000

def inventory(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("APK file not found")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    counts = {"dex": 0, "native_libraries": 0, "assets": 0, "other": 0}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError("APK ZIP has too many entries")
        for entry in entries:
            if entry.is_dir():
                continue
            name = entry.filename
            if name.startswith("classes") and name.endswith(".dex") and "/" not in name:
                counts["dex"] += 1
            elif name.startswith("lib/") and name.endswith(".so"):
                counts["native_libraries"] += 1
            elif name.startswith("assets/"):
                counts["assets"] += 1
            else:
                counts["other"] += 1
    return {"schema_version": 1, "sha256": digest.hexdigest(), "size_bytes": path.stat().st_size,
            "zip_entry_counts": counts, "network_access": False,
            "protocol_verified": False}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="Authorized local APK file")
    args = parser.parse_args()
    print(json.dumps(inventory(args.apk), indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
