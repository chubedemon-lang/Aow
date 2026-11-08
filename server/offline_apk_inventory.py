"""Offline APK ZIP inventory with no extraction, network access, or asset disclosure.

Only aggregate extension counts and bounded size totals are returned. No file names,
contents, URLs, credentials or packet formats are emitted.
"""
from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import zipfile

MAX_APK_BYTES = 4 * 1024**3
MAX_MEMBERS = 100_000
MAX_UNCOMPRESSED_BYTES = 16 * 1024**3


class ApkInventoryError(ValueError):
    """Invalid or unsafe local APK inventory input."""


@dataclass(frozen=True)
class ApkInventory:
    sha256: str
    apk_bytes: int
    member_count: int
    uncompressed_bytes: int
    extension_counts: tuple


def inventory_apk(path):
    """Inventory an authorized local APK without extracting or listing members."""
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ApkInventoryError("expected a regular local file")
    size = source.stat().st_size
    if not 0 < size <= MAX_APK_BYTES:
        raise ApkInventoryError("APK size outside safety bounds")
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    try:
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            if len(members) > MAX_MEMBERS:
                raise ApkInventoryError("too many archive members")
            total = 0
            counts = Counter()
            for member in members:
                if member.is_dir():
                    continue
                if member.flag_bits & 0x1:
                    raise ApkInventoryError("encrypted member")
                if member.file_size < 0:
                    raise ApkInventoryError("invalid member size")
                total += member.file_size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ApkInventoryError("uncompressed size limit exceeded")
                suffix = Path(member.filename).suffix.lower()
                # Avoid disclosing arbitrary filenames masquerading as extensions.
                extension = suffix if 1 < len(suffix) <= 12 and suffix[1:].isalnum() else "<other>"
                counts[extension] += 1
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ApkInventoryError("not a readable APK ZIP") from exc
    return ApkInventory(digest.hexdigest(), size, sum(counts.values()), total,
                        tuple(sorted(counts.items())))
