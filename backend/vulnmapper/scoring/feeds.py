"""The two threat feeds OVSS reads: CISA's Known Exploited Vulnerabilities
catalogue (KEV) and FIRST's Exploit Prediction Scoring System (EPSS).

Each feed is downloaded at most once a day, in one attempt with its own time
budget (FEED_BUDGET_S), and kept as downloaded beside
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

import argparse
import csv
import gzip
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from ..common import VulnmapperError, setup_logging, write_bytes_atomic

log = logging.getLogger("vulnmapper.scoring")

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_FILENAME = "kev.json"
EPSS_FILENAME = "epss_scores-current.csv.gz"
REFRESH = timedelta(days=1)
FEED_BUDGET_S = 20.0       # the whole of one feed's download, then it is abandoned
REFRESH_BUDGET_S = 600.0   # the refresh command, outside a scan
READ_TIMEOUT_S = 10.0      # connect, and each read of the body

FRESH, STALE, UNAVAILABLE = "fresh", "stale", "unavailable"


class FeedUnavailable(VulnmapperError):
    """A feed or CVE record could not be fetched (no answer, or not HTTP 200)."""


def http_get(url: str, timeout: float, progress: Optional[Callable] = None) -> tuple:
    """GET ``url`` -> ``(status, body bytes)``. ``timeout`` is the whole
    download's budget: connecting and each read wait at most READ_TIMEOUT_S, and
    a body still arriving when the budget is spent is abandoned, so a trickling
    link cannot hold a scan. ``progress(bytes so far)`` is called after each
    read. Raises FeedUnavailable on no answer or over budget."""
    import requests
    start = time.monotonic()
    wait = min(timeout, READ_TIMEOUT_S)
    try:
        with requests.get(url, timeout=(wait, wait), stream=True) as r:
            chunks = []
            for chunk in r.iter_content(64 * 1024):
                chunks.append(chunk)
                if progress:
                    progress(sum(map(len, chunks)))
                if time.monotonic() - start > timeout:
                    raise FeedUnavailable(f"still downloading after {timeout:.0f} s")
            return r.status_code, b"".join(chunks)
    except FeedUnavailable:
        raise
    except Exception as e:              # any failure, never a scan's: the type only, no detail
        raise FeedUnavailable(type(e).__name__) from None


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


def _write_feed(path: str, data: bytes, fetched: datetime) -> None:
    write_bytes_atomic(path, data)
    # the modification time is the fetch time, on the scan's clock
    ts = fetched.timestamp()
    os.utime(path, (ts, ts))


def store(raw: bytes, path: str, parse: Callable, clock) -> tuple:
    """Validate a feed body (``parse`` raises ValueError/KeyError on a bad one)
    and keep it at ``path`` as fetched now; returns ``(data, feed date)``."""
    data, date = parse(raw)
    _write_feed(path, raw, clock.now())
    return data, date


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
    # one attempt, never retried: a dead or slow link falls back to the copy on disk
    started = clock.monotonic()
    try:
        status, raw = transport(url, FEED_BUDGET_S)
        if status != 200:
            raise FeedUnavailable(f"HTTP {status}")
        data, date = store(raw, path, parse, clock) if path else parse(raw)
        log.info("%s downloaded in %.1f s, %d bytes (%s)", name, clock.monotonic() - started,
                 len(raw), date)
        return data, FRESH, date
    except Exception as e:              # an injected transport may fail any way; never the scan
        log.warning("%s could not be downloaded after %.1f s (%s)", name,
                    clock.monotonic() - started,
                    e if isinstance(e, (FeedUnavailable, ValueError, KeyError)) else type(e).__name__)
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


# --- filling the cache outside a scan ------------------------------------------

FEEDS = {"kev": ("CISA KEV", KEV_URL, KEV_FILENAME, parse_kev),
         "epss": ("FIRST EPSS", EPSS_URL, EPSS_FILENAME, parse_epss)}
# shortcut: the dashboard's graphPath is not known here, so the default is the
# repository's data/ (where the README puts graph.json); pass --cache-dir otherwise
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))), "data")


def _mib(n: int) -> str:
    return f"{n / 1048576:.1f} MB"


def main(argv: Optional[list] = None, transport: Optional[Callable] = None, clock=None) -> int:
    """``python -m vulnmapper.scoring.feeds --refresh | --from-kev PATH | --from-epss PATH``:
    fill the scan's KEV and EPSS cache outside a scan. ``--refresh`` downloads
    whichever feed is not given as a file, with no scan budget (10 minutes
    each) and progress on stderr; ``--from-*`` validates a file downloaded
    elsewhere and imports it. Both write the same files, in the same form, the
    scan reads, as fetched now. Exit 1 if any feed failed."""
    setup_logging()
    parser = argparse.ArgumentParser(
        prog="vulnmapper.scoring.feeds",
        description="Fill the KEV/EPSS cache the scan reads, outside a scan.")
    parser.add_argument("--refresh", action="store_true",
                        help="download KEV and EPSS (those not given with --from-*)")
    parser.add_argument("--from-kev", metavar="PATH", help="import a KEV JSON file")
    parser.add_argument("--from-epss", metavar="PATH", help="import an EPSS CSV (.csv or .csv.gz)")
    parser.add_argument("--cache-dir", metavar="DIR", default=DEFAULT_CACHE_DIR,
                        help="the folder of the graph.json the dashboard reads (vulnmapper."
                             "graphPath), where nvd-cache.json lives (default: %(default)s)")
    args = parser.parse_args(argv)
    sources = {"kev": args.from_kev, "epss": args.from_epss}
    if not args.refresh and not any(sources.values()):
        parser.error("give --refresh, --from-kev or --from-epss")
    from ..devicecves.nvd import SystemClock
    clock = clock or SystemClock()
    transport = transport or http_get
    os.makedirs(args.cache_dir, exist_ok=True)

    failed = False
    for key, (name, url, filename, parse) in FEEDS.items():
        if not sources[key] and not args.refresh:
            continue
        path = os.path.join(args.cache_dir, filename)
        try:
            if sources[key]:
                with open(sources[key], "rb") as f:
                    raw = f.read()
            else:
                print(f"{name}: downloading {url}", file=sys.stderr)
                reported = [0]

                def progress(n, reported=reported, name=name):
                    if n >= reported[0] + 1048576:          # a line per MB
                        reported[0] = n
                        print(f"  {name}: {_mib(n)}", file=sys.stderr)
                status, raw = transport(url, REFRESH_BUDGET_S, progress=progress)
                if status != 200:
                    raise FeedUnavailable(f"HTTP {status}")
            _, date = store(raw, path, parse, clock)
        except (FeedUnavailable, OSError, ValueError, KeyError) as e:
            print(f"{name}: failed ({e}); the cache is unchanged", file=sys.stderr)
            failed = True
            continue
        print(f"{name}: {date or 'undated'}, {_mib(len(raw))} -> {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
