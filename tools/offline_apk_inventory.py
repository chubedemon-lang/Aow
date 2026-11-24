"""Offline, metadata-only APK inventory. Never extracts or uploads APK contents."""
import argparse
import hashlib
import json
import os
import stat
import struct
import zipfile
from pathlib import Path

MAX_APK_BYTES = 4 * 1024**3
MAX_ENTRIES = 100_000
MAX_UNCOMPRESSED_BYTES = 16 * 1024**3
MAX_METADATA_BYTES = 64 * 1024 * 1024


def _stat_identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
    )


def _open_regular_file(path):
    """Open one regular file without following a symlink where supported."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("expected a regular local file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    return stream, before


def inspect_apk(path):
    """Return bounded APK metadata without extracting archive members.

    The file is opened once and the same descriptor is used for hashing and
    ZIP inspection, avoiding a path replacement between those operations.
    ZIP member CRCs are not fully checked: only the bounded metadata header is
    read. This function makes no protocol or APK-compatibility claims.
    """
    source = Path(path)
    stream, before = _open_regular_file(source)
    with stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (
            before.st_dev, before.st_ino
        ) != (opened.st_dev, opened.st_ino):
            raise ValueError("APK file changed while opening")
        size = opened.st_size
        if not 0 < size <= MAX_APK_BYTES:
            raise ValueError("APK size outside safety bounds")

        digest = hashlib.sha256()
        bytes_read = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            bytes_read += len(chunk)
            if bytes_read > MAX_APK_BYTES:
                raise ValueError("APK size outside safety bounds")
            digest.update(chunk)
        after_hash = os.fstat(stream.fileno())
        if bytes_read != size or _stat_identity(opened) != _stat_identity(after_hash):
            raise ValueError("APK changed while hashing")

        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ValueError("too many ZIP entries")

            names = set()
            total_uncompressed = 0
            for item in entries:
                if item.filename in names:
                    raise ValueError("duplicate ZIP member name")
                names.add(item.filename)
                if item.flag_bits & 0x1:
                    raise ValueError("encrypted ZIP entries are not supported")
                mode = item.external_attr >> 16
                if item.create_system == 3 and stat.S_ISLNK(mode):
                    raise ValueError("symlink ZIP member")
                if item.file_size < 0:
                    raise ValueError("invalid ZIP member size")
                if item.is_dir():
                    continue
                total_uncompressed += item.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("uncompressed size limit exceeded")

            dex = sorted(
                name for name in names
                if name == "classes.dex"
                or (
                    name.startswith("classes") and name.endswith(".dex")
                    and name[7:-4].isdigit() and int(name[7:-4]) >= 2
                )
            )
            abi = sorted({
                name.split("/")[1] for name in names
                if name.startswith("lib/") and name.endswith(".so")
                and len(name.split("/")) == 3
            })
            metadata_name = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
            metadata = {
                "present": metadata_name in names,
                "version": None,
                "valid_magic": False,
            }
            if metadata_name in names:
                info = archive.getinfo(metadata_name)
                if info.file_size > MAX_METADATA_BYTES:
                    raise ValueError("metadata size exceeds safety limit")
                with archive.open(info) as member_stream:
                    header = member_stream.read(8)
                if len(header) == 8:
                    magic, version = struct.unpack("<II", header)
                    metadata["valid_magic"] = magic == 0xFAB11BAF
                    if metadata["valid_magic"]:
                        metadata["version"] = version

            result = {
                "sha256": digest.hexdigest(),
                "size_bytes": size,
                "entry_count": len(entries),
                "dex_count": len(dex),
                "native_abis": abi,
                "unity_library_present": any(
                    name.endswith("/libunity.so") for name in names
                ),
                "il2cpp_library_present": any(
                    name.endswith("/libil2cpp.so") for name in names
                ),
                "il2cpp_metadata": metadata,
            }

        final = os.fstat(stream.fileno())
        if _stat_identity(opened) != _stat_identity(final):
            raise ValueError("APK changed during ZIP inspection")
        return result


def main():
    parser = argparse.ArgumentParser(
        description="Safe offline APK inventory; no network or extraction"
    )
    parser.add_argument("apk", help="Path to authorized local APK")
    args = parser.parse_args()
    print(json.dumps(inspect_apk(args.apk), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
