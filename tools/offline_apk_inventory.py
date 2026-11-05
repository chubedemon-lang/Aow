"""Offline, metadata-only APK inventory. Never extracts or uploads APK contents."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

MAX_ENTRIES = 100_000
MAX_METADATA_BYTES = 64 * 1024 * 1024


def inspect_apk(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError("too many ZIP entries")
        if any(item.flag_bits & 0x1 for item in entries):
            raise ValueError("encrypted ZIP entries are not supported")
        names = {item.filename for item in entries}
        dex = sorted(name for name in names if name == "classes.dex" or (name.startswith("classes") and name.endswith(".dex") and name[7:-4].isdigit() and int(name[7:-4]) >= 2))
        abi = sorted({name.split("/")[1] for name in names
                      if name.startswith("lib/") and name.endswith(".so") and len(name.split("/")) == 3})
        metadata_name = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
        metadata = {"present": metadata_name in names, "version": None, "valid_magic": False}
        if metadata_name in names:
            info = archive.getinfo(metadata_name)
            if info.file_size > MAX_METADATA_BYTES:
                raise ValueError("metadata size exceeds safety limit")
            with archive.open(info) as stream:
                header = stream.read(8)
            if len(header) == 8:
                magic, version = struct.unpack("<II", header)
                metadata["valid_magic"] = magic == 0xFAB11BAF
                if metadata["valid_magic"]:
                    metadata["version"] = version
        return {
            "sha256": digest.hexdigest(),
            "size_bytes": path.stat().st_size,
            "entry_count": len(entries),
            "dex_count": len(dex),
            "native_abis": abi,
            "unity_library_present": any(name.endswith("/libunity.so") for name in names),
            "il2cpp_library_present": any(name.endswith("/libil2cpp.so") for name in names),
            "il2cpp_metadata": metadata,
        }


def main():
    parser = argparse.ArgumentParser(description="Safe offline APK inventory; no network or extraction")
    parser.add_argument("apk", help="Path to authorized local APK")
    args = parser.parse_args()
    print(json.dumps(inspect_apk(args.apk), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
