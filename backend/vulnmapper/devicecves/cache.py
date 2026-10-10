"""nvd-cache.json: NVD answers kept between scans.

The plugin can start a scan every 120 seconds; NVD allows 5 requests per 30
seconds without a key. So every answer is cached, keyed by the query (the CPE
string, the dictionary check of a CPE, or the keyword query), and two devices
on the same software share one entry. With a warm cache a scan makes no NVD
request at all.

  * A successful answer with CVEs (or a CPE the dictionary lists) is fresh
    for 7 days; an empty or inconclusive one for 1 day.
  * When NVD cannot be reached, an expired entry is used anyway and the
    result is marked stale: a device never loses its CVEs because NVD had a
    bad day.
  * A corrupt or unreadable file is ignored and rebuilt; it never stops a scan.

The file is written atomically (temp file and rename, as vulnerabilities.json
is). Each CVE is stored trimmed to what the stage reads. The trim keeps every
CVSS metric whole, vector included, so entries written before the vector
fields were parsed (vulnmapper.devicecves.vectors) serve them as they are.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger("vulnmapper.devicecves")

FILENAME = "nvd-cache.json"
FORMAT = 1
FRESH_FOUND = timedelta(days=7)
FRESH_EMPTY = timedelta(days=1)


def default_path(beside: str) -> str:
    """nvd-cache.json in the same folder as ``beside`` (a graph or vulnerabilities file)."""
    return os.path.join(os.path.dirname(os.path.abspath(beside)), FILENAME)


def trim_cve(cve: dict, keep_configurations: bool = False) -> dict:
    """The parts of an NVD CVE record the stage reads."""
    out = {k: cve[k] for k in ("id", "vulnStatus", "published") if k in cve}
    out["descriptions"] = [d for d in cve.get("descriptions") or [] if d.get("lang") == "en"]
    out["metrics"] = {k: v for k, v in (cve.get("metrics") or {}).items()
                      if k.startswith("cvssMetric")}
    out["references"] = (cve.get("references") or [])[:1]
    if keep_configurations:
        out["configurations"] = cve.get("configurations") or []
    return out


def _parse_time(text) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


class Cache:
    """The cache file in memory; :meth:`save` writes it back if anything changed."""

    def __init__(self, path: Optional[str], clock) -> None:
        self.path = path
        self._clock = clock
        self.entries: dict = {}
        self.corrupt = False
        self.dirty = False
        self.hits = 0
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
                if not isinstance(doc, dict) or not isinstance(doc.get("entries"), dict):
                    raise ValueError("not a cache document")
                self.entries = {k: v for k, v in doc["entries"].items()
                                if isinstance(v, dict) and _parse_time(v.get("fetched_at"))}
            except (OSError, ValueError) as e:
                log.warning("NVD cache %s is unreadable (%s); starting a new one", path, e)
                self.corrupt = True
                self.entries = {}

    def get(self, key: str) -> Optional[dict]:
        """The entry with ``fresh`` and ``fetched_at`` filled in, or None."""
        entry = self.entries.get(key)
        if entry is None:
            return None
        fetched = _parse_time(entry["fetched_at"])
        found = bool(entry.get("found"))
        age = self._clock.now() - fetched
        return {**entry, "fresh": age < (FRESH_FOUND if found else FRESH_EMPTY)}

    def put(self, key: str, *, found: bool, data) -> dict:
        entry = {"fetched_at": self._clock.now().isoformat(), "found": found, "data": data}
        self.entries[key] = entry
        self.dirty = True
        return {**entry, "fresh": True}

    def save(self) -> None:
        if not self.path or not self.dirty:
            return
        folder = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(prefix=".nvd-cache.", suffix=".tmp", dir=folder)
        try:
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"format": FORMAT, "entries": self.entries}, f, separators=(",", ":"))
                f.write("\n")
            os.replace(tmp, self.path)
            self.dirty = False
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
