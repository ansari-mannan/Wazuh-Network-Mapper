"""The two threat feeds OVSS reads: CISA's Known Exploited Vulnerabilities
catalogue (KEV) and FIRST's Exploit Prediction Scoring System (EPSS).

Each feed is downloaded at most once a day and kept as downloaded beside
nvd-cache.json (``kev.json``, ``epss_scores-current.csv.gz``); the file's
modification time is when it was fetched. When a download fails the copy on
disk is used however old it is (``stale``). With no copy at all the feed is
``unavailable``: every CVE then scores as not in KEV with EPSS 0, and the
graph's ``metadata.threat_feeds`` says so, so the dashboard can warn that
scores may be understated. A feed never fails a scan.

The HTTP layer is a parameter (``transport(url, timeout) -> (status, bytes)``),
so tests serve saved bodies.
"""

from __future__ import annotations

import csv
import gzip
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from ..common import VulnmapperError

log = logging.getLogger("vulnmapper.scoring")

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_FILENAME = "kev.json"
EPSS_FILENAME = "epss_scores-current.csv.gz"
REFRESH = timedelta(days=1)
DOWNLOAD_TIMEOUT_S = 30.0

FRESH, STALE, UNAVAILABLE = "fresh", "stale", "unavailable"


class FeedUnavailable(VulnmapperError):
    """A feed or CVE record could not be fetched (no answer, or not HTTP 200)."""


def http_get(url: str, timeout: float) -> tuple:
    """GET ``url`` -> ``(status, body bytes)``; raises FeedUnavailable on no answer."""
    import requests
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        raise FeedUnavailable(type(e).__name__) from None
    return r.status_code, r.content


def parse_kev(raw: bytes) -> tuple:
    """``({CVE id}, catalogue date)`` from the KEV JSON feed."""
    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("not a KEV catalogue")
    ids = {v["cveID"] for v in doc["vulnerabilities"] if isinstance(v, dict) and v.get("cveID")}
    return ids, doc.get("dateReleased")


def parse_epss(raw: bytes) -> tuple:
    """``({CVE id: epss}, score date)`` from the EPSS daily CSV (gzipped or not).
    Its first line is a comment such as ``#model_version:v2025.03.14,score_date:...``."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    lines = raw.decode("utf-8").splitlines()
    date = None
    if lines and lines[0].startswith("#"):
        for part in lines[0][1:].split(","):
            key, _, value = part.partition(":")
            if key.strip() == "score_date":
                date = value.strip()
    reader = csv.DictReader(line for line in lines if not line.startswith("#"))
    if not reader.fieldnames or not {"cve", "epss"} <= set(reader.fieldnames):
        raise ValueError("not an EPSS score file")
    return {row["cve"]: float(row["epss"]) for row in reader if row.get("cve")}, date


def _write_bytes_atomic(path: str, data: bytes, fetched: datetime) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".feed.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    # the modification time is the fetch time, on the scan's clock
    ts = fetched.timestamp()
    os.utime(path, (ts, ts))


def load_feed(name: str, url: str, path: Optional[str], parse: Callable, clock,
              transport: Callable) -> tuple:
    """``(parsed data or None, status, feed date)`` for one feed; see the module doc."""
    fetched = None
    if path and os.path.exists(path):
        fetched = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    if fetched and clock.now() - fetched < REFRESH:
        try:
            with open(path, "rb") as f:
                data, date = parse(f.read())
            return data, FRESH, date
        except (OSError, ValueError, KeyError) as e:
            log.warning("%s copy %s is unreadable (%s); downloading again", name, path, e)
    try:
        status, raw = transport(url, DOWNLOAD_TIMEOUT_S)
        if status != 200:
            raise FeedUnavailable(f"HTTP {status}")
        data, date = parse(raw)
        if path:
            _write_bytes_atomic(path, raw, clock.now())
        log.info("%s downloaded (%s)", name, date)
        return data, FRESH, date
    except (FeedUnavailable, OSError, ValueError, KeyError) as e:
        log.warning("%s could not be downloaded (%s)", name, e)
    if fetched:
        try:
            with open(path, "rb") as f:
                data, date = parse(f.read())
            log.warning("%s: using the copy fetched %s", name, fetched.isoformat())
            return data, STALE, date
        except (OSError, ValueError, KeyError):
            pass
    log.warning("%s unavailable: scoring as if no CVE had threat data", name)
    return None, UNAVAILABLE, None


@dataclass
class Threat:
    """What OVSS reads from the feeds, and the ``metadata.threat_feeds`` block."""

    kev: set = field(default_factory=set)
    epss: dict = field(default_factory=dict)
    block: dict = field(default_factory=dict)


def load_threat(folder: Optional[str], clock, transport: Optional[Callable] = None) -> Threat:
    """Both feeds, cached in ``folder`` (None: no cache, download every time)."""
    transport = transport or http_get
    paths = {n: os.path.join(folder, n) if folder else None for n in (KEV_FILENAME, EPSS_FILENAME)}
    kev, kev_status, kev_date = load_feed("CISA KEV", KEV_URL, paths[KEV_FILENAME],
                                          parse_kev, clock, transport)
    epss, epss_status, epss_date = load_feed("FIRST EPSS", EPSS_URL, paths[EPSS_FILENAME],
                                             parse_epss, clock, transport)
    return Threat(kev=kev or set(), epss=epss or {},
                  block={"kev": kev_status, "epss": epss_status,
                         "kev_date": kev_date, "epss_date": epss_date})
