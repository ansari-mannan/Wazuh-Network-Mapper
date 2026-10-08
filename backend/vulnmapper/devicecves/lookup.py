"""One device's lookup: identity -> NVD (through the cache) -> CVE rows.

The result's ``status``:

  * ``ok``           NVD answered (CVEs found or not)
  * ``unverified``   NVD could not confirm the query: the CPE is not in its
                     dictionary, or NVD called the query malformed
  * ``unavailable``  NVD could not be reached (or the stage's time budget ran
                     out) and nothing was cached
  * ``unidentified`` vendor, family or version missing, or never polled

An expired cache entry is used when NVD cannot be reached; ``stale`` says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .cache import Cache, trim_cve
from .families import keyword_accepts
from .nvd import (NvdBudgetExceeded, NvdClient, NvdInvalidQuery, NvdUnavailable,
                  is_rejected, parse_cve)

STATUS_OK = "ok"
STATUS_UNVERIFIED = "unverified"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNIDENTIFIED = "unidentified"

# Sent with every CPE query: only CVEs where the device's software is the
# vulnerable component, not merely the platform it runs on.
IS_VULNERABLE = True


@dataclass
class Lookup:
    status: str
    match: Optional[str] = None
    product: Optional[str] = None
    cpe: Optional[str] = None
    rows: Optional[list] = None          # CVE rows (parse_cve shape), None unless ok
    fetched_at: Optional[str] = None
    stale: bool = False
    from_cache: bool = False             # every answer came from the cache
    reason: Optional[str] = None         # unreachable | budget | not_in_dictionary | invalid_query
    queries: list = field(default_factory=list)


class _Unanswered(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _answer(cache: Cache, key: str, fetch, found_of, result: Lookup) -> dict:
    """A fresh cache entry, else NVD's answer (cached), else an expired entry."""
    result.queries.append(key)
    entry = cache.get(key)
    if entry is not None and entry["fresh"]:
        cache.hits += 1
        return entry
    result.from_cache = False
    try:
        data = fetch()
    except (NvdUnavailable, NvdBudgetExceeded) as e:
        if entry is not None:            # an old answer beats no answer
            result.stale = True
            return entry
        raise _Unanswered("budget" if isinstance(e, NvdBudgetExceeded) else "unreachable")
    return cache.put(key, found=found_of(data), data=data)


def lookup(ident: dict, client: NvdClient, cache: Cache) -> Lookup:
    """Look one identified device up. ``ident`` is :func:`families.identify`'s result."""
    result = Lookup(status=STATUS_UNIDENTIFIED, match=None, product=ident.get("product"),
                    cpe=ident.get("cpe"), from_cache=True)
    if ident.get("match") not in ("cpe", "keyword"):
        return result
    result.match = ident["match"]
    package, version = ident.get("product"), ident.get("version")
    try:
        if ident["match"] == "cpe":
            cpe = ident["cpe"]
            try:
                listed = _answer(cache, f"cpe-dictionary:{cpe}",
                                 lambda: client.cpe_listed(cpe), bool, result)
            except NvdInvalidQuery:
                cache.put(f"cpe-dictionary:{cpe}", found=False, data=False)
                result.status, result.reason = STATUS_UNVERIFIED, "invalid_query"
                return result
            if not listed["data"]:
                result.status, result.reason = STATUS_UNVERIFIED, "not_in_dictionary"
                result.fetched_at = listed["fetched_at"]
                return result
            answer = _answer(cache, f"cves:{cpe}",
                             lambda: [trim_cve(c) for c in client.cves_for_cpe(cpe, IS_VULNERABLE)],
                             bool, result)
            cves = answer["data"]
        else:
            kw = ident["keyword"]
            answer = _answer(cache, f"keyword:{kw['query']}",
                             lambda: [trim_cve(c, keep_configurations=True)
                                      for c in client.cves_for_keyword(kw["query"])],
                             bool, result)
            cves = [c for c in answer["data"] if keyword_accepts(
                c, vendors=kw["vendors"], line=kw["line"], version=kw["version"])]
    except _Unanswered as e:
        result.status, result.reason = STATUS_UNAVAILABLE, e.reason
        return result
    except NvdInvalidQuery:
        result.status, result.reason = STATUS_UNVERIFIED, "invalid_query"
        return result

    result.status = STATUS_OK
    result.fetched_at = answer["fetched_at"]
    result.rows = [parse_cve(c, package=package, version=version, detected_at=answer["fetched_at"])
                   for c in cves if not is_rejected(c)]
    return result
