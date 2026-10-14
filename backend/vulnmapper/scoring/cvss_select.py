"""The CVSS base score each finding is scored from (CVSS_B), and the CVE
records it is read from.

Preference: the CNA's own score (the organisation that published the CVE),
else an ADP's (an authorised data publisher such as CISA's Vulnrichment), else
the score the tool reported (the Wazuh indexer, or NVD for devices). Within
the CNA, and within the ADPs together, the block with the highest CVSS version
that has a baseScore wins; equal versions go to the first block in the record.
No score anywhere: the finding is Unrated.

CNA and ADP scores come from CVE JSON 5 records, one per CVE, from the CVE
Services API. Records are cached in ``cve-records.json`` beside
nvd-cache.json, trimmed to their scored blocks: a record for 30 days, a CVE
the API does not know for 1 day. Each scan fetches the CVEs it has no fresh
entry for, worst tool score first, a few at a time and within a time budget.
A request that gets no answer (timeout, connection error) or a rate limit
stops all fetching for the scan, with no retry; whatever was not fetched uses
its expired entry if there is one, else the tool score. Other CVEs fill in on
later scans. cve.org being slow or down never fails a scan.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Callable, Optional

from ..devicecves.cache import Cache
from . import feeds
from .feeds import FeedUnavailable

log = logging.getLogger("vulnmapper.scoring")

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"
FILENAME = "cve-records.json"
FRESH_FOUND = timedelta(days=30)
FRESH_MISSING = timedelta(days=1)
BUDGET_S = 60.0
CONCURRENCY = 4
REQUEST_TIMEOUT_S = 10.0

SRC_CNA, SRC_ADP, SRC_TOOL = "CNA", "ADP", "tool"


def version_key(version) -> tuple:
    """"3.1" -> (3, 1); unparseable -> ()."""
    return tuple(int(x) for x in re.findall(r"\d+", str(version or "")))


def scored_blocks(metrics) -> list:
    """``[{"version", "score"}]`` for every ``cvssV*`` block with a baseScore,
    in record order. The version is the block's own, else read from the key
    (``cvssV3_1`` -> "3.1")."""
    out = []
    for m in metrics if isinstance(metrics, list) else []:
        if not isinstance(m, dict):
            continue
        for key, block in m.items():
            if not key.startswith("cvssV") or not isinstance(block, dict):
                continue
            if isinstance(block.get("baseScore"), (int, float)):
                version = str(block.get("version") or key[len("cvssV"):].replace("_", "."))
                out.append({"version": version, "score": float(block["baseScore"])})
    return out


def trim_record(record: dict) -> dict:
    """A CVE JSON 5 record -> ``{"cna": [blocks], "adp": [blocks]}`` (what the cache keeps)."""
    containers = (record or {}).get("containers") or {}
    adp = containers.get("adp") if isinstance(containers.get("adp"), list) else []
    return {"cna": scored_blocks((containers.get("cna") or {}).get("metrics")),
            "adp": [b for c in adp if isinstance(c, dict) for b in scored_blocks(c.get("metrics"))]}


def _best(blocks: list) -> Optional[dict]:
    return max(blocks, key=lambda b: version_key(b["version"]), default=None)


def select(record: Optional[dict], tool_score, tool_version) -> tuple:
    """``(cvss_used, cvss_src, cvss_ver)`` from a trimmed record (or None) and the
    tool's score; ``(None, None, None)`` when nothing has a score (Unrated)."""
    for src, key in ((SRC_CNA, "cna"), (SRC_ADP, "adp")):
        block = _best((record or {}).get(key) or [])
        if block:
            return block["score"], src, block["version"]
    if tool_score is not None:
        return float(tool_score), SRC_TOOL, (str(tool_version) if tool_version else None)
    return None, None, None


def conflict(cvss_src, cvss_used, cvss_ver, tool_score, tool_version) -> int:
    """1 when a CNA/ADP score and the tool's are of the same CVSS version and
    differ by 1.0 or more (informational only); else 0."""
    if cvss_src == SRC_TOOL or cvss_used is None or tool_score is None:
        return 0
    if version_key(cvss_ver) != version_key(tool_version):
        return 0
    return int(abs(cvss_used - float(tool_score)) >= 1.0)


class CveRecords:
    """The trimmed CVE records of one scan, from the cache and cve.org."""

    def __init__(self, cache: Cache, clock, transport: Optional[Callable] = None,
                 budget_s: float = BUDGET_S, concurrency: int = CONCURRENCY) -> None:
        self.cache = cache
        self._clock = clock
        self._transport = transport or feeds.http_get
        self.budget_s = budget_s
        self.concurrency = concurrency
        self._started = clock.monotonic()
        self._stop = threading.Event()        # no answer or rate limited: ask no more
        self._lock = threading.Lock()
        self.stats = {"hits": 0, "fetched": 0, "not_found": 0, "expired_used": 0,
                      "unanswered": 0, "requests": 0}

    def _remaining(self) -> float:
        return self.budget_s - (self._clock.monotonic() - self._started)

    def _fetch(self, cve_id: str):
        """``("found", trimmed)``, ``("missing", None)`` or ``("unanswered", None)``."""
        if self._stop.is_set() or self._remaining() <= 0:
            return "unanswered", None
        with self._lock:
            self.stats["requests"] += 1
        try:
            status, body = self._transport(CVE_API_URL.format(cve_id),
                                           min(REQUEST_TIMEOUT_S, max(1.0, self._remaining())))
        except Exception as e:          # any transport failure stops the fetching, never the scan
            if not self._stop.is_set():
                log.warning("cve.org did not answer (%s); no more CVE record requests "
                            "this scan", e if isinstance(e, FeedUnavailable) else type(e).__name__)
            self._stop.set()
            return "unanswered", None
        if status == 404:
            return "missing", None
        if status == 429:
            log.warning("cve.org rate limit; no more CVE record requests this scan")
            self._stop.set()
            return "unanswered", None
        if status != 200:
            return "unanswered", None
        try:
            return "found", trim_record(json.loads(body))
        except (ValueError, AttributeError, TypeError):
            return "unanswered", None

    def load(self, cve_ids: list) -> dict:
        """``{CVE id: trimmed record or None}``. ``cve_ids`` in the order to fetch
        (most important first); a CVE with no record is left out."""
        out, todo, expired = {}, [], {}
        for cve_id in dict.fromkeys(cve_ids):
            entry = self.cache.get(cve_id)
            if entry and entry["fresh"]:
                self.stats["hits"] += 1
                if entry["found"]:
                    out[cve_id] = entry["data"]
                continue
            if entry:
                expired[cve_id] = entry
            todo.append(cve_id)
        if todo:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                answers = list(pool.map(self._fetch, todo))
            for cve_id, (state, record) in zip(todo, answers):
                if state == "found":
                    self.stats["fetched"] += 1
                    self.cache.put(cve_id, found=True, data=record)
                    out[cve_id] = record
                elif state == "missing":
                    self.stats["not_found"] += 1
                    self.cache.put(cve_id, found=False, data=None)
                elif cve_id in expired:
                    self.stats["expired_used"] += 1
                    if expired[cve_id]["found"]:
                        out[cve_id] = expired[cve_id]["data"]
                else:
                    self.stats["unanswered"] += 1
        self.cache.save()
        s = self.stats
        log.info("CVE records: %d cache hit(s), %d fetched, %d not found, %d expired entr%s "
                 "used, %d left to the tool score (%d request(s))", s["hits"], s["fetched"],
                 s["not_found"], s["expired_used"], "y" if s["expired_used"] == 1 else "ies",
                 s["unanswered"], s["requests"])
        return out


def records_cache(path: Optional[str], clock) -> Cache:
    return Cache(path, clock, fresh_found=FRESH_FOUND, fresh_empty=FRESH_MISSING,
                 label="CVE record cache")
