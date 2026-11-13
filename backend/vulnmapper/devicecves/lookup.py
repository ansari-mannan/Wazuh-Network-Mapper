"""One lookup: a device's identity, or one CVE id, to NVD through the cache, and
back as CVE rows with a status. Used by the device CVE, service-scan and vector
stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..common import VulnmapperError
from .cache import INVALID_QUERY, Cache, trim_cve
from .families import FAMILIES, keyword_accepts
from . import junos
from .nvd import (NvdBudgetExceeded, NvdClient, NvdInvalidQuery, NvdUnavailable,
                  is_rejected, parse_cve)

# The result's status:
#
# The result's ``status``:
#
#   * ``ok``           NVD answered (CVEs found or not)
#   * ``unverified``   NVD could not confirm the query: the CPE is not in its
#                      dictionary, or NVD called the query malformed
#   * ``unavailable``  NVD could not be reached (or the stage's time budget ran
#                      out) and nothing was cached
#   * ``unidentified`` vendor, family or version missing, or never polled
#
# A device whose family is known but has no NVD product name that can be
# trusted (families.identify's match ``none``) is ``unverified`` with reason
# ``no_cpe_rule``: identified, its CVEs not looked up. An ArubaOS-Switch
# device whose model line is not known is ``unverified`` (``model_not_mapped``):
# NVD files part of its CVEs under a per-model name only.
#
# An expired cache entry is used when NVD cannot be reached; ``stale`` says so.
#
# Junos (with a JuniperRecords source passed in) is decided from Juniper's own
# CVE records (vulnmapper.devicecves.juniper), compared release by release
# (vulnmapper.devicecves.junos), plus the NVD cpeName hits for CVEs Juniper did
# not assign (most from before Juniper became a CNA) whose Junos criterion is
# bounded: a bare ``junos:*`` with no version range claims every release ever
# and is not counted. ``source`` is then "juniper-cna+nvd" and ``undecided``
# lists the CVEs whose records make no claim for the device's release. A
# firmware string that is not a regular release (``<major>.<minor>R<n>[-S<n>][.<build>]``) is
# ``unverified`` (``version_not_comparable``); an incomplete set of Juniper
# records makes the device ``unavailable``, never a partial ``ok``.

STATUS_OK = "ok"
STATUS_UNVERIFIED = "unverified"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNIDENTIFIED = "unidentified"

SOURCE_NVD = "nvd"
SOURCE_JUNIPER = "juniper-cna+nvd"
JUNOS_FAMILY = "juniper_junos"
JUNOS_EVO_FAMILY = "juniper_junos_evolved"

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
    source: str = SOURCE_NVD
    undecided: Optional[list] = None     # Junos: CVE ids the records make no claim on


class Unanswered(VulnmapperError):
    def __init__(self, reason: str):
        self.reason = reason


def _answer(cache: Cache, key: str, fetch, found_of, result: Lookup) -> dict:
    """A fresh cache entry, else NVD's answer (cached), else an expired entry.
    Raises :class:`NvdInvalidQuery` for a query NVD called malformed, now or
    when it was cached. A query NVD failed on within the hour is not asked."""
    result.queries.append(key)
    entry = cache.get(key)
    if entry is not None and entry["fresh"]:
        cache.hits += 1
        cache.empty += entry["data"] in ([], None)
        return _valid(entry)
    if cache.failed_recently(key):
        return _stale_or_unanswered(entry, result, "unreachable")
    if entry is None:
        cache.misses += 1
    else:
        cache.expired += 1
    result.from_cache = False
    try:
        data = fetch()
    except NvdUnavailable:
        cache.put_failure(key)
        return _stale_or_unanswered(entry, result, "unreachable")
    except NvdBudgetExceeded:
        return _stale_or_unanswered(entry, result, "budget")
    except NvdInvalidQuery:
        cache.put(key, found=False, data=INVALID_QUERY)
        raise
    return cache.put(key, found=found_of(data), data=data)


def _stale_or_unanswered(entry: Optional[dict], result: Lookup, reason: str) -> dict:
    if entry is None:
        raise Unanswered(reason)
    result.stale = True                  # an old answer beats no answer
    return _valid(entry)


def _answered(data) -> bool:
    """A CVE query's answer, empty or not, is kept as long as one with CVEs."""
    return True


def _valid(entry: dict) -> dict:
    if entry["data"] == INVALID_QUERY:
        raise NvdInvalidQuery("cached")
    return entry


def _junos_bounded(cve: dict, product: str = "junos") -> bool:
    """Whether a vulnerable criterion for ``juniper:<product>`` of an NVD record
    names a version or a version range (a bare ``cpe:2.3:o:juniper:junos:*``
    does neither)."""
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for m in (node or {}).get("cpeMatch") or []:
                parts = str((m or {}).get("criteria") or "").split(":")
                if len(parts) < 6 or parts[3:5] != ["juniper", product] or not m.get("vulnerable"):
                    continue
                if parts[5] not in ("*", "-") or any(m.get(k) for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding")):
                    return True
    return False


def _junos_trim(cve: dict, product: str = "junos") -> dict:
    """An NVD hit for a Junos CPE, trimmed, with the bounded-criterion flag."""
    return {**trim_cve(cve), "junos_bounded": _junos_bounded(cve, product)}


def _lookup_junos(ident: dict, client: NvdClient, cache: Cache, juniper, model: Optional[str],
                  result: Lookup) -> Lookup:
    result.source = SOURCE_JUNIPER
    evolved = ident.get("family") == JUNOS_EVO_FAMILY
    product = "junos_os_evolved" if evolved else "junos"
    package, version = ident.get("product"), ident.get("version")
    v = junos.parse_device(version or "", evolved)
    if v is None:
        result.status, result.reason = STATUS_UNVERIFIED, "version_not_comparable"
        return result
    complete = juniper.prepare()
    if juniper.stats.get("requests") or juniper.stats.get("index_requests"):
        result.from_cache = False
    if not complete:
        result.status, result.reason = STATUS_UNAVAILABLE, juniper.reason
        return result
    if evolved and not juniper.evo_complete:
        result.status, result.reason = STATUS_UNAVAILABLE, "juniper_records_incomplete"
        return result
    cpe = ident["cpe"]
    try:
        answer = _answer(cache, f"junos-cves:{cpe}",
                         lambda: [_junos_trim(c, product)
                                  for c in client.cves_for_cpe(cpe, IS_VULNERABLE)],
                         _answered, result)
    except Unanswered as e:
        result.status, result.reason = STATUS_UNAVAILABLE, e.reason
        return result
    except NvdInvalidQuery:
        result.status, result.reason = STATUS_UNVERIFIED, "invalid_query"
        return result
    nvd_by_id = {c.get("id"): c for c in answer["data"] if isinstance(c, dict)}
    affected, undecided = juniper.assess(v, model, evolved)
    rows = []
    for record in affected:
        cve = record
        if not record.get("metrics") and (nvd_by_id.get(record["id"]) or {}).get("metrics"):
            # no CNA score in the record: NVD's own, from the same answer
            cve = {**record, "metrics": nvd_by_id[record["id"]]["metrics"]}
        rows.append(parse_cve(cve, package=package, version=version,
                              detected_at=juniper.fetched_at.get(record["id"])))
    known = set(juniper.ids)
    for cve in answer["data"]:
        if cve.get("id") in known or not cve.get("junos_bounded") or is_rejected(cve):
            continue
        rows.append(parse_cve(cve, package=package, version=version,
                              detected_at=answer["fetched_at"]))
    result.status = STATUS_OK
    result.fetched_at = answer["fetched_at"]
    result.stale = result.stale or juniper.stale
    result.rows = rows
    result.undecided = undecided
    return result


def lookup(ident: dict, client: NvdClient, cache: Cache, juniper=None,
           model: Optional[str] = None) -> Lookup:
    """Look one identified device up. ``ident`` is :func:`families.identify`'s result;
    ``juniper`` (a :class:`~vulnmapper.devicecves.juniper.JuniperRecords`) decides Junos
    devices, whose ``model`` places them among a record's platforms."""
    result = Lookup(status=STATUS_UNIDENTIFIED, match=None, product=ident.get("product"),
                    cpe=ident.get("cpe"), from_cache=True)
    if ident.get("match") == "none":
        result.match = "none"
        result.status, result.reason = STATUS_UNVERIFIED, "no_cpe_rule"
        return result
    if ident.get("match") not in ("cpe", "keyword"):
        return result
    result.match = ident["match"]
    if juniper is not None and ident.get("family") in (JUNOS_FAMILY, JUNOS_EVO_FAMILY) \
            and ident["match"] == "cpe":
        return _lookup_junos(ident, client, cache, juniper, model, result)
    package, version = ident.get("product"), ident.get("version")
    try:
        if ident["match"] == "cpe":
            if "extra_cpes" in ident and not ident["extra_cpes"]:
                result.status, result.reason = STATUS_UNVERIFIED, "model_not_mapped"
                return result
            listed_rule = (FAMILIES.get(ident.get("family")) or {}).get("listed", "release")
            cves, seen, fetched = [], set(), []
            for cpe in [ident["cpe"]] + list(ident.get("extra_cpes") or []):
                if listed_rule != "skip":
                    probe = cpe if listed_rule == "release" else \
                        ":".join(cpe.split(":")[:5] + ["*"] * 8)
                    listed = _answer(cache, f"cpe-dictionary:{probe}",
                                     lambda probe=probe: client.cpe_listed(probe), bool, result)
                    if not listed["data"]:
                        result.status, result.reason = STATUS_UNVERIFIED, "not_in_dictionary"
                        result.fetched_at = listed["fetched_at"]
                        return result
                answer = _answer(cache, f"cves:{cpe}",
                                 lambda cpe=cpe: [trim_cve(c)
                                                  for c in client.cves_for_cpe(cpe, IS_VULNERABLE)],
                                 _answered, result)
                fetched.append(answer["fetched_at"])
                for c in answer["data"]:
                    if c.get("id") not in seen:
                        seen.add(c.get("id"))
                        cves.append(c)
            # the oldest answer dates the set
            answer = {"fetched_at": min((f for f in fetched if f), default=None)}
        else:
            kw = ident["keyword"]
            answer = _answer(cache, f"keyword:{kw['query']}",
                             lambda: [trim_cve(c, keep_configurations=True)
                                      for c in client.cves_for_keyword(kw["query"])],
                             _answered, result)
            cves = [c for c in answer["data"] if keyword_accepts(
                c, vendors=kw["vendors"], line=kw["line"], version=kw["version"])]
    except Unanswered as e:
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


def lookup_cve(cve_id: str, client: NvdClient, cache: Cache) -> Optional[dict]:
    """One CVE's trimmed NVD record by id, through the cache; None when NVD has
    no such CVE. Raises :class:`Unanswered` when NVD cannot be asked (or the
    budget is spent) and nothing is cached."""
    def fetch():
        cve = client.cve_by_id(cve_id)
        return trim_cve(cve) if cve else None

    try:
        return _answer(cache, f"cve:{cve_id}", fetch, _answered, Lookup(status=STATUS_OK))["data"]
    except NvdInvalidQuery:              # an id NVD calls malformed is no CVE it knows
        return None
