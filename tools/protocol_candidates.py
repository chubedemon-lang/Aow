#!/usr/bin/env python3
"""Offline, read-only APK network string candidate inventory. No network requests."""
import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter

URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,240}", re.I)
HOST = re.compile(rb"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|gg|game|games|dev|app|cn|ru|vn)(?::[0-9]{2,5})?(?![A-Za-z0-9_.-])", re.I)
SENSITIVE = re.compile(r"(?:token|key|secret|auth|session|password|signature|credential)", re.I)
MAX_ENTRY = 32 * 1024 * 1024
MAX_RESULTS = 100

def scan_bytes(data):
    candidates = []
    for pattern, kind in ((URL, "url"), (HOST, "host")):
        for match in pattern.finditer(data):
            raw = match.group().decode("ascii", "ignore").rstrip(".,;)")
            if SENSITIVE.search(raw):
                continue
            candidates.append((kind, raw))
    return candidates

def inspect(apk):
    sha = hashlib.sha256()
    with open(apk, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
    counts = Counter()
    skipped = 0
    with zipfile.ZipFile(apk) as z:
        for item in z.infolist():
            if item.is_dir() or item.file_size > MAX_ENTRY:
                skipped += 1
                continue
            # Candidate strings are hints, NOT verified endpoints.
            data = z.read(item)
            for kind, value in scan_bytes(data):
                counts[(kind, value)] += 1
    return {"sha256": sha.hexdigest(), "scanned_entry_limit_bytes": MAX_ENTRY,
            "skipped_entries": skipped,
            "candidates": [{"kind": k, "value": v, "occurrences": n}
                           for ((k, v), n) in counts.most_common(MAX_RESULTS)],
            "warning": "Unverified strings; may be third-party SDK URLs or false positives. Review locally before publishing."}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("--output", required=True, help="Local report path; never commit raw output")
    args = p.parse_args()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(inspect(args.apk), f, indent=2)

if __name__ == "__main__":
    main()
