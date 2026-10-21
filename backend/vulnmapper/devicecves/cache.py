"""nvd-cache.json: NVD answers kept between scans, shared by every NVD lookup
of a scan (device CVEs, the service scan and the CVE vectors).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..common import write_json_atomic

log = logging.getLogger("vulnmapper.devicecves")

# The plugin can start a scan every 120 seconds; NVD allows 5 requests per 30
# seconds without a key. So every answer is cached, keyed by the query (the CPE
# string, the dictionary check of a CPE, or the keyword query), and two devices
# on the same software share one entry. With a warm cache a scan makes no NVD
# request at all.
#
#   * A CVE query NVD answered is fresh for 7 days, with CVEs or without (an
#     empty answer is cached like a hit, so it is not asked again every scan);
#     so is a CPE the dictionary lists. One it does not list is fresh for 1 day.
#   * A query NVD failed to answer (no answer, a timeout, 5xx, 403/429) is not
#     asked again for :data:`RETRY_FAILED`, so the scan right after does not
#     wait on it again; an expired entry, if any, serves meanwhile.
#   * When NVD cannot be reached, an expired entry is used anyway and the
#     result is marked stale: a device never loses its CVEs because NVD had a
#     bad day.
#   * A corrupt or unreadable file is ignored and rebuilt; it never stops a scan.
#   * A query NVD calls malformed is cached like an empty answer, with the data
#     :data:`INVALID_QUERY`, so it is not asked again every scan.
#
# The file is written atomically (temp file and rename, as vulnerabilities.json
# is). Each CVE is stored trimmed to what the stage reads. The trim keeps every
# CVSS metric whole, vector included, so entries written before the vector
# fields were parsed (vulnmapper.devicecves.vectors) serve them as they are.

FILENAME = "nvd-cache.json"
FORMAT = 1
FRESH_FOUND = timedelta(days=7)
FRESH_EMPTY = timedelta(days=1)
RETRY_FAILED = timedelta(hours=1)
INVALID_QUERY = {"invalid_query": True}    # the cached answer to a malformed query


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

    def __init__(self, path: Optional[str], clock, *, fresh_found: timedelta = FRESH_FOUND,
                 fresh_empty: timedelta = FRESH_EMPTY, label: str = "NVD cache") -> None:
        self.path = path
        self._clock = clock
        self._fresh = {True: fresh_found, False: fresh_empty}
        self.label = label
        self.entries: dict = {}
        self.failures: dict = {}           # key -> when NVD last failed on it
        self.corrupt = False
        self.dirty = False
        # lookups served fresh (of them, empty answers) / not cached at all /
        # cached but expired / failed, now or within RETRY_FAILED
        self.hits = self.empty = self.misses = self.expired = self.failed = 0
        self.retry_after: Optional[datetime] = None    # the latest failure's retry time
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
                if not isinstance(doc, dict) or not isinstance(doc.get("entries"), dict):
                    raise ValueError("not a cache document")
                self.entries = {k: v for k, v in doc["entries"].items()
                                if isinstance(v, dict) and _parse_time(v.get("fetched_at"))}
                failures = doc.get("failures")
                self.failures = {k: v for k, v in failures.items() if self._failed_until(v)} \
                    if isinstance(failures, dict) else {}
            except (OSError, ValueError) as e:
                log.warning("%s %s is unreadable (%s); starting a new one", label, path, e)
                self.corrupt = True
                self.entries, self.failures = {}, {}
        log.info("%s %s: %d entries", label, path or "(in memory)", len(self.entries))

    def tally(self) -> tuple:
        """``(hits, misses, expired, empty, failed)`` so far, for a stage's before/after note."""
        return self.hits, self.misses, self.expired, self.empty, self.failed

    def _failed_until(self, text) -> Optional[datetime]:
        t = _parse_time(text) if isinstance(text, str) else None
        return t + RETRY_FAILED if t and self._clock.now() < t + RETRY_FAILED else None

    def failed_recently(self, key: str) -> bool:
        """Whether NVD failed on ``key`` within RETRY_FAILED (counted as failed if so)."""
        until = self._failed_until(self.failures.get(key))
        if until is not None:
            self._count_failure(until)
        return until is not None

    def put_failure(self, key: str) -> None:
        now = self._clock.now()
        self.failures[key] = now.isoformat()
        self.dirty = True
        self._count_failure(now + RETRY_FAILED)

    def _count_failure(self, until: datetime) -> None:
        self.failed += 1
        self.retry_after = max(self.retry_after or until, until)

    def get(self, key: str) -> Optional[dict]:
        """The entry with ``fresh`` and ``fetched_at`` filled in, or None."""
        entry = self.entries.get(key)
        if entry is None:
            return None
        fetched = _parse_time(entry["fetched_at"])
        age = self._clock.now() - fetched
        return {**entry, "fresh": age < self._fresh[bool(entry.get("found"))]}

    def put(self, key: str, *, found: bool, data) -> dict:
        entry = {"fetched_at": self._clock.now().isoformat(), "found": found, "data": data}
        self.entries[key] = entry
        self.failures.pop(key, None)
        self.dirty = True
        return {**entry, "fresh": True}

    def save(self) -> None:
        if not self.path or not self.dirty:
            return
        doc = {"format": FORMAT, "entries": self.entries}
        if self.failures:
            doc["failures"] = self.failures
        write_json_atomic(self.path, doc)
        self.dirty = False
