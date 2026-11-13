"""Juniper's own CVE records (Juniper is the CNA, ``sirt@juniper.net``), the
source the device CVE stage decides Junos devices from.

NVD's applicability statements for Junos lag behind and often enumerate a few
releases, so a cpeName query for most Junos releases misses CVEs Juniper lists
as affecting them. Juniper's CVE JSON 5 records state the affected releases in
Juniper's own notation, which :mod:`vulnmapper.devicecves.junos` compares.

Two parts, both cached in ``juniper-cna.json`` beside nvd-cache.json:

  * The index: the ids of every CVE Juniper assigned, from NVD
    (``sourceIdentifier=sirt@juniper.net``, about 1200 ids, one page). A full
    pull when there is no index or the last sync is older than
    :data:`INDEX_FULL_AFTER` (NVD accepts a modification window of at most 120
    days); otherwise, every :data:`INDEX_EVERY`, only the CVEs NVD modified
    since the last sync, with :data:`INDEX_OVERLAP` of overlap. An id seen in
    that window is fetched again even if its record is fresh. The index uses
    its own NVD client (same transport and clock, its own time budget and
    unreachable flag), so a slow index pull never spends the device lookups'
    budget or marks NVD unreachable for them.
  * The records: one per id, from the CVE Services API
    (https://cveawg.mitre.org/api/cve/{id}), trimmed to the NVD record shape
    (id, published, English description, first reference, the CNA's CVSS
    metrics mapped onto NVD's metric names) plus the record's state and its
    Junos OS ``affected`` blocks. Fresh for 30 days (an id the API does not
    know: 1 day). Fetched :data:`CONCURRENCY` at a time within
    :data:`RECORD_BUDGET_S`; no answer or a rate limit stops the fetching for
    the scan, as cve-records.json's fetches do (vulnmapper.scoring.cvss_select).

The stage asks :meth:`JuniperRecords.prepare` once, at the first Junos device.
Junos devices are decided only from a complete set: an index and an entry for
every id in it. Anything less leaves :attr:`JuniperRecords.complete` false and
the devices ``unavailable`` (never a partial ``ok`` that would hide CVEs);
later scans fill the gaps. An expired entry, or an index not synced for more
than :data:`INDEX_STALE_AFTER`, still serves, with ``stale`` set.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait as wait_futures
from datetime import datetime, timedelta
from typing import Callable, Optional

from ..scoring import feeds
from ..scoring.feeds import FeedUnavailable
from . import junos
from .cache import Cache, _parse_time
from .nvd import NvdBudgetExceeded, NvdClient, NvdInvalidQuery, NvdUnavailable

log = logging.getLogger("vulnmapper.devicecves")

FILENAME = "juniper-cna.json"
SOURCE_ID = "sirt@juniper.net"
INDEX_KEY = "index:" + SOURCE_ID       # never a CVE id, so it cannot clash with a record
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"

FRESH_RECORD = timedelta(days=30)
FRESH_MISSING = timedelta(days=1)
INDEX_FULL_AFTER = timedelta(days=119)
INDEX_EVERY = timedelta(hours=6)
INDEX_OVERLAP = timedelta(hours=1)
INDEX_STALE_AFTER = timedelta(days=1)
INDEX_BUDGET_S = 60.0
RECORD_BUDGET_S = 120.0
CONCURRENCY = 8
REQUEST_TIMEOUT_S = 10.0

# CVE JSON 5 metric block -> NVD metric list and CVSS version
_METRICS = (("cvssV3_1", "cvssMetricV31"), ("cvssV3_0", "cvssMetricV30"),
            ("cvssV4_0", "cvssMetricV40"), ("cvssV2_0", "cvssMetricV2"))


def default_path(nvd_cache_path: str) -> str:
    """juniper-cna.json in the folder of nvd-cache.json."""
    return os.path.join(os.path.dirname(os.path.abspath(nvd_cache_path)), FILENAME)


def records_cache(path: Optional[str], clock) -> Cache:
    return Cache(path, clock, fresh_found=FRESH_RECORD, fresh_empty=FRESH_MISSING,
                 label="Juniper CNA cache")


def trim_record(doc: dict) -> dict:
    """A CVE JSON 5 record -> the NVD record shape ``parse_cve`` reads, plus
    ``state``, ``blocks`` (the Junos OS affected blocks) and ``evo_blocks``
    (the Junos OS Evolved affected blocks)."""
    meta = doc.get("cveMetadata") or {}
    cna = (doc.get("containers") or {}).get("cna") or {}
    if not isinstance(meta, dict) or not isinstance(cna, dict):
        raise ValueError("not a CVE record")
    cve_id = meta.get("cveId")
    if not isinstance(cve_id, str):
        raise ValueError("no cveId")
    desc = next((d.get("value") for d in cna.get("descriptions") or []
                 if isinstance(d, dict) and str(d.get("lang", "")).lower().startswith("en")), None)
    refs = [r.get("url") for r in cna.get("references") or [] if isinstance(r, dict) and r.get("url")]
    metrics: dict = {}
    for m in cna.get("metrics") or []:
        if not isinstance(m, dict):
            continue
        for block_key, nvd_key in _METRICS:
            block = m.get(block_key)
            if isinstance(block, dict) and block.get("baseScore") is not None:
                metrics.setdefault(nvd_key, []).append(
                    {"source": SOURCE_ID, "type": "Secondary", "cvssData": block})
    return {
        "id": cve_id,
        "state": meta.get("state"),
        "published": meta.get("datePublished"),
        "descriptions": [{"lang": "en", "value": desc}] if desc else [],
        "references": [{"url": refs[0]}] if refs else [],
        "metrics": metrics,
        "blocks": junos.junos_blocks(cna.get("affected")),
        "evo_blocks": junos.evo_blocks(cna.get("affected")),
    }


class JuniperRecords:
    """Juniper's CVE records for one scan: the index and the records, cached,
    brought up to date once by :meth:`prepare`."""

    def __init__(self, cache: Cache, clock, index_client: Callable[[], NvdClient],
                 transport: Optional[Callable] = None, record_budget_s: float = RECORD_BUDGET_S,
                 concurrency: int = CONCURRENCY) -> None:
        self.cache = cache
        self._clock = clock
        self._index_client = index_client
        self._transport = transport or feeds.http_get
        self.record_budget_s = record_budget_s
        self.concurrency = concurrency
        self._lock = threading.Lock()          # the cache and the stats, shared with the fetches
        self._stop = threading.Event()         # no answer or rate limited: ask no more
        self._closed = False                   # prepare() returned: late answers are dropped
        self._started = 0.0
        self.prepared = False
        self.complete = False
        self.evo_complete = False              # every found record carries its Evolved blocks
        self.stale = False
        self.reason: Optional[str] = None      # why not complete
        self.ids: list = []
        self.records: dict = {}                # CVE id -> trimmed record (found entries only)
        self._assessed: dict = {}              # (release, model, evolved) -> (affected, undecided)
        self.fetched_at: dict = {}             # CVE id -> when its entry was fetched
        self.stats = {"index": None, "index_requests": 0, "ids": 0, "fetched": 0,
                      "not_found": 0, "unanswered": 0, "requests": 0, "pending": 0}

    # -- the index ---------------------------------------------------------

    def _sync_index(self) -> Optional[dict]:
        """The index entry's data after a sync attempt (None when there is none)."""
        entry = self.cache.get(INDEX_KEY)
        data = entry["data"] if entry and isinstance(entry.get("data"), dict) else None
        now = self._clock.now()
        synced = _parse_time(data.get("synced_at")) if data else None
        if data is not None and not isinstance(data.get("ids"), list):
            data, synced = None, None
        if synced is not None and now - synced < INDEX_EVERY:
            self.stats["index"] = "fresh"
            return data
        full = synced is None or now - synced >= INDEX_FULL_AFTER
        client = self._index_client()
        try:
            if full:
                ids = client.cve_ids_for_source(SOURCE_ID)
            else:
                ids = client.cve_ids_for_source(SOURCE_ID, synced - INDEX_OVERLAP, now)
        except (NvdUnavailable, NvdBudgetExceeded, NvdInvalidQuery) as e:
            self.stats["index"] = "unanswered"
            log.warning("Juniper CVE index: NVD did not answer (%s); using the cached index",
                        type(e).__name__)
            return data
        finally:
            self.stats["index_requests"] = client.requests
        if full and not ids:
            # a full pull with nothing in it is no index: keep what there was
            self.stats["index"] = "empty"
            return data
        changed = dict(data.get("changed") or {}) if data else {}
        stamp = now.isoformat()
        if full:
            # which records changed is unknown here; the 30-day freshness covers it
            all_ids = list(ids)
        else:
            all_ids = list(data["ids"])
            seen = set(all_ids)
            all_ids.extend(i for i in ids if i not in seen)
            changed.update({i: stamp for i in ids})
        data = {"ids": all_ids, "synced_at": stamp, "changed": changed,
                "full_at": stamp if full else data.get("full_at")}
        with self._lock:
            self.cache.put(INDEX_KEY, found=True, data=data)
        self.stats["index"] = "full" if full else "incremental"
        log.info("Juniper CVE index: %s sync, %d id(s), %d in the answer", self.stats["index"],
                 len(all_ids), len(ids))
        return data

    # -- the records -------------------------------------------------------

    def _remaining(self) -> float:
        # real time, not the clock's, as CveRecords does
        return self.record_budget_s - (time.monotonic() - self._started)

    def _fetch(self, cve_id: str):
        """``("found", trimmed)``, ``("missing", None)``, ``("unanswered", None)``
        (asked, no usable answer) or ``("skipped", None)`` (not asked)."""
        if self._stop.is_set() or self._remaining() <= 0:
            return "skipped", None
        with self._lock:
            self.stats["requests"] += 1
        try:
            status, body = self._transport(CVE_API_URL.format(cve_id),
                                           min(REQUEST_TIMEOUT_S, max(1.0, self._remaining())))
        except Exception as e:          # any transport failure stops the fetching, never the scan
            if not self._stop.is_set():
                log.warning("cve.org did not answer (%s); no more Juniper record requests "
                            "this scan", e if isinstance(e, FeedUnavailable) else type(e).__name__)
            self._stop.set()
            return "unanswered", None
        if status == 404:
            return "missing", None
        if status == 429:
            if not self._stop.is_set():
                log.warning("cve.org rate limit; no more Juniper record requests this scan")
            self._stop.set()
            return "unanswered", None
        if status != 200:
            return "unanswered", None
        try:
            record = trim_record(json.loads(body))
        except (ValueError, AttributeError, TypeError):
            return "unanswered", None
        if record["id"] != cve_id:
            return "unanswered", None
        return "found", record

    def _fetch_and_keep(self, cve_id: str) -> str:
        state, record = self._fetch(cve_id)
        with self._lock:
            if self._closed or state == "skipped":
                return "skipped"
            if state == "unanswered":
                # not asked again for an hour (Cache.RETRY_FAILED); an expired entry serves
                self.cache.put_failure(cve_id)
                self.stats["unanswered"] += 1
            else:
                self.cache.put(cve_id, found=state == "found", data=record)
                self.stats["fetched" if state == "found" else "not_found"] += 1
        return state

    def _due(self, cve_id: str, changed: dict) -> tuple:
        """``(entry, due)``: the cached entry and whether it should be fetched."""
        entry = self.cache.get(cve_id)
        if entry is None:
            return None, True
        if entry["found"] and isinstance(entry.get("data"), dict) and "evo_blocks" not in entry["data"]:
            return entry, True          # kept before Evolved blocks were stored
        since = _parse_time(changed.get(cve_id)) if cve_id in changed else None
        if since is not None and _parse_time(entry["fetched_at"]) < since:
            return entry, True
        return entry, not entry["fresh"]

    def prepare(self) -> bool:
        """Bring the index and the records up to date (once per scan); whether
        the set is complete."""
        if self.prepared:
            return self.complete
        self.prepared = True
        data = self._sync_index()
        if data is None:
            self.reason = "juniper_index_unavailable"
            log.warning("Juniper CVE index unavailable; Junos devices left unavailable")
            return False
        self.ids = list(data["ids"])
        changed = dict(data.get("changed") or {})
        due = []
        for cve_id in self.ids:
            entry, needed = self._due(cve_id, changed)
            if needed and not self.cache.failed_recently(cve_id):
                due.append((entry is not None, cve_id))
        due.sort()                                  # never fetched first, then expired
        if due:
            self._started = time.monotonic()
            pool = ThreadPoolExecutor(max_workers=self.concurrency,
                                      thread_name_prefix="juniper-records")
            futures = [pool.submit(self._fetch_and_keep, cve_id) for _, cve_id in due]
            wait_futures(futures, timeout=self.record_budget_s + REQUEST_TIMEOUT_S)
            self._stop.set()
            pool.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            self._closed = True
            # ids whose change was seen and whose record has been fetched since
            for cve_id in list(changed):
                entry = self.cache.get(cve_id)
                since = _parse_time(changed[cve_id])
                if cve_id not in self.ids or (entry and since
                                              and _parse_time(entry["fetched_at"]) >= since):
                    changed.pop(cve_id)
            if changed != (data.get("changed") or {}):
                index = self.cache.entries[INDEX_KEY]
                index["data"] = {**index["data"], "changed": changed}
                self.cache.dirty = True
            self.cache.save()
            missing, expired, no_evo = [], 0, 0
            for cve_id in self.ids:
                entry = self.cache.get(cve_id)
                if entry is None:
                    missing.append(cve_id)
                    continue
                if not entry["fresh"] or cve_id in changed:
                    expired += 1
                self.fetched_at[cve_id] = entry["fetched_at"]
                if entry["found"] and isinstance(entry.get("data"), dict):
                    self.records[cve_id] = entry["data"]
                    no_evo += "evo_blocks" not in entry["data"]
        synced = _parse_time(data.get("synced_at"))
        self.stats.update(ids=len(self.ids), pending=len(missing) + expired, evo_pending=no_evo)
        self.stale = expired > 0 or synced is None \
            or self._clock.now() - synced >= INDEX_STALE_AFTER
        if missing:
            self.reason = "juniper_records_incomplete"
            log.warning("Juniper CVE records: %d of %d not fetched yet; Junos devices left "
                        "unavailable until a later scan", len(missing), len(self.ids))
            return False
        self.complete = True
        self.evo_complete = no_evo == 0
        if not self.evo_complete:
            log.warning("Juniper CVE records: %d of %d kept without their Junos OS Evolved "
                        "blocks; Evolved devices left unavailable until a later scan",
                        no_evo, len(self.records))
        return True

    # -- one device --------------------------------------------------------

    def assess(self, v: "junos.Release", model: Optional[str], evolved: bool = False) -> tuple:
        """``(affected, undecided)`` for a device running ``v``: the published
        records whose Junos OS blocks (Junos OS Evolved blocks with
        ``evolved``) give AFFECTED, and the ids they leave UNDECIDED, both
        sorted by id. Devices on the same release and model share one
        assessment: the records do not change after :meth:`prepare`."""
        key = (v, model or "", evolved)
        if key not in self._assessed:
            self._assessed[key] = self._assess(v, model or "", evolved)
        affected, undecided = self._assessed[key]
        return list(affected), list(undecided)

    def _assess(self, v: "junos.Release", model: str, evolved: bool = False) -> tuple:
        field = "evo_blocks" if evolved else "blocks"
        affected, undecided = [], []
        for cve_id in sorted(self.records):
            record = self.records[cve_id]
            if record.get("state") != "PUBLISHED":
                continue
            try:
                status, _ = junos.decide(record.get(field) or [], v, model or "", evolved)
            except (ValueError, TypeError, AttributeError, KeyError, IndexError):
                status = junos.UNDECIDED       # a block this module cannot read: no claim
            if status == junos.AFFECTED:
                affected.append(record)
            elif status == junos.UNDECIDED:
                undecided.append(cve_id)
        return affected, undecided

    def block(self) -> dict:
        """The stage's ``juniper`` stats object."""
        return {"complete": self.complete, "evo_complete": self.evo_complete,
                "stale": self.stale, "reason": self.reason,
                **self.stats}
