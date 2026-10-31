"""Optional local threat-intelligence lookup (exact hostname / exact URL match).

The blocklist file is produced by `python -m ml.prepare_dataset` from the public
Phishing.Database feed, or can be any text file with one hostname or URL per line.
If the file is missing, this check is reported as unavailable (not as 'clean')."""
from __future__ import annotations

import os
from urllib.parse import urlsplit

_cache: dict = {}


def _load(path: str):
    if not path or not os.path.exists(path):
        return None
    mtime = os.path.getmtime(path)
    cached = _cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    hosts, urls = set(), set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            (urls if "://" in line else hosts).add(line.rstrip("/") if "://" in line else line)
    _cache[path] = (mtime, (hosts, urls))
    return hosts, urls


def check(parsed, path: str) -> dict:
    data = _load(path)
    if data is None:
        return {"status": "unavailable", "match": False, "note": "No local threat-intelligence list is loaded."}
    hosts, urls = data
    host = parsed.hostname.lower()
    if host in hosts or parsed.normalized.lower().rstrip("/") in urls:
        return {"status": "match", "match": True, "note": "The host or URL appears in the local phishing feed."}
    return {"status": "no_match", "match": False,
            "note": "Not found in the local feed. This is NOT evidence that the URL is safe."}
