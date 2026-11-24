#!/usr/bin/env python3
"""Offline, read-only APK network string candidate inventory. No network requests."""
import argparse
import hashlib
import json
import re
from urllib.parse import urlsplit
import zipfile
from collections import Counter

URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,240}", re.I)
HOST = re.compile(rb"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|gg|game|games|dev|app|cn|ru|vn)(?::[0-9]{2,5})?(?![A-Za-z0-9_.-])", re.I)
SENSITIVE = re.compile(r"(?:token|key|secret|auth|session|password|signature|credential)", re.I)
MAX_ENTRY = 32 * 1024 * 1024
MAX_RESULTS = 100

def scan_bytes(data):
    """Collect origin-only hints, never URLs with paths, queries or fragments."""
    candidates = []
    url_spans = []
    for match in URL.finditer(data):
        raw = match.group().decode("ascii", "ignore").rstrip(".,;)")
        url_spans.append(match.span())
        try:
            parsed = urlsplit(raw)
            # Never emit URL userinfo, query strings or fragments.
            if parsed.username or parsed.password or SENSITIVE.search(raw):
                continue
            host = parsed.hostname or ""
            if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                continue
            if parsed.scheme.lower() not in ("http", "https"):
                continue
            netloc = host.lower() + ((":" + str(parsed.port)) if parsed.port else "")
            candidates.append(("origin", parsed.scheme.lower() + "://" + netloc))
        except ValueError:
            continue
    for match in HOST.finditer(data):
        if any(start <= match.start() < end for start, end in url_spans):
            continue
        raw = match.group().decode("ascii", "ignore")
        if not SENSITIVE.search(raw):
            candidates.append(("host", raw.lower()))
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
            # Refuse entries whose advertised size is misleading or CRC is invalid.
            with z.open(item) as source:
                data = source.read(MAX_ENTRY + 1)
            if len(data) > MAX_ENTRY:
                skipped += 1
                continue
            for kind, value in scan_bytes(data):
                counts[(kind, value)] += 1
    return {"sha256": sha.hexdigest(), "scanned_entry_limit_bytes": MAX_ENTRY,
            "skipped_entries": skipped,
            "candidates": [{"kind": k, "value": v, "occurrences": n}
                           for ((k, v), n) in counts.most_common(MAX_RESULTS)],
            "warning": "Unverified origin/host hints; may be third-party SDK hosts or false positives. Review locally before publishing; do not probe hosts."}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("--output", required=True, help="Local report path; never commit raw output")
    args = p.parse_args()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(inspect(args.apk), f, indent=2)

if __name__ == "__main__":
    main()
