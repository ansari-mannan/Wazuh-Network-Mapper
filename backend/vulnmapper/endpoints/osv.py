"""The Wazuh server's own CVEs, from its syscollector package list matched
with OSV.dev. Wazuh never indexes agent 000 into the package and
vulnerability states, so without this the server is always unscored.
"""

from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Callable, Optional
from urllib.parse import quote

import requests

from ..common import StageResult, VulnmapperError, plural
from ..devicecves.cache import Cache
from ..schema import endpoint_node_id
from .findings import enrich_agent, slim_findings

log = logging.getLogger("vulnmapper.endpoints")

# How it works:
#   * Only agent 000, and only when the indexer has no packages for it (the
#     score step left it unscored with unscored_reason "no_inventory").
#   * Its deb packages go to OSV's querybatch, BATCH at a time. A vuln id that
#     names its CVE (UBUNTU-CVE-2024-1234, DEBIAN-CVE-…, CVE-…) is taken
#     directly; any other (USN-…, DSA-…) is fetched for its CVE aliases,
#     CONCURRENCY at a time. An id with no CVE is dropped.
#   * One BUDGET_S for every request, each read at most READ_TIMEOUT_S.
#     Running out, or OSV not answering, leaves the server unscored with the
#     reason "OSV unavailable"; it never fails the scan.
#   * Each package's CVEs are cached in osv-cache.json for FRESH (keyed by
#     ecosystem, name and version), including those finished before a failure.
#   * The rows have no CVSS: the OVSS stage scores them from the CVE records
#     like any other row. They are potential (the package is installed, the
#     match is OSV's, not Wazuh's).

OSV_URL = "https://api.osv.dev/v1"
FILENAME = "osv-cache.json"
FRESH = timedelta(days=1)
BATCH = 1000
BUDGET_S = 30.0
READ_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 5.0
CONCURRENCY = 4
SOURCE = "osv"
POTENTIAL = "potential"
SERVER_AGENT_ID = "000"
UNAVAILABLE = "OSV unavailable"
STAGE = "Wazuh server via OSV"

_CVE_ID = re.compile(r"^(?:UBUNTU-|DEBIAN-)?(CVE-\d{4}-\d+)$")


class OsvUnavailable(VulnmapperError):
    """OSV did not answer, answered with something unexpected, or the time
    budget ran out."""


def http_json(url: str, body: Optional[dict], timeout: float):
    """POST ``body`` (GET without one) and return the parsed JSON reply."""
    try:
        r = (requests.post(url, json=body, timeout=(CONNECT_TIMEOUT_S, timeout)) if body is not None
             else requests.get(url, timeout=(CONNECT_TIMEOUT_S, timeout)))
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        raise OsvUnavailable(type(e).__name__) from None


def cache(folder: Optional[str], clock) -> Cache:
    """osv-cache.json in ``folder`` (beside nvd-cache.json; none: in memory only)."""
    return Cache(os.path.join(folder, FILENAME) if folder else None, clock,
                 fresh_found=FRESH, fresh_empty=FRESH, label="OSV cache")


class OsvClient:
    """The OSV.dev calls of one scan, within one time budget."""

    def __init__(self, clock, transport: Optional[Callable] = None,
                 budget_s: float = BUDGET_S) -> None:
        self._clock = clock
        self._transport = transport or http_json
        self._deadline = clock.monotonic() + budget_s
        self.budget_s = budget_s

    def _call(self, path: str, body: Optional[dict] = None):
        left = self._deadline - self._clock.monotonic()
        if left <= 0:
            raise OsvUnavailable(f"the {self.budget_s:.0f} s time budget ran out")
        return self._transport(f"{OSV_URL}{path}", body, min(READ_TIMEOUT_S, left))

    def query(self, eco: str, packages: list, out: dict) -> None:
        """``out[(name, version)]`` = its vuln ids, batch by batch."""
        # shortcut: a query's next_page_token (over a page of vulns for one
        # package) is not followed; follow it if a package ever has that many
        for i in range(0, len(packages), BATCH):
            chunk = packages[i:i + BATCH]
            doc = self._call("/querybatch", {"queries": [
                {"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in chunk]})
            results = doc.get("results") if isinstance(doc, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                log.warning("OSV querybatch: unexpected reply (%s)", _shape(doc))
                raise OsvUnavailable("unexpected querybatch reply")
            for pkg, res in zip(chunk, results):
                vulns = res.get("vulns") if isinstance(res, dict) else None
                out[pkg] = [v["id"] for v in vulns or [] if isinstance(v, dict) and v.get("id")]

    def aliases(self, ids: list, out: dict) -> None:
        """``out[id]`` = the CVEs a vuln record names (aliases and upstream)."""
        def fetch(vid):
            doc = self._call(f"/vulns/{quote(vid, safe='')}")
            names = (doc.get("aliases") or []) + (doc.get("upstream") or []) \
                if isinstance(doc, dict) else []
            out[vid] = sorted({m.group(1) for a in names if (m := _CVE_ID.match(str(a)))})

        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            for _ in pool.map(fetch, ids):
                pass


def _key(eco: str, name: str, version: str) -> str:
    return f"{eco}|{name}|{version}"


def match(packages: list, eco: str, client: OsvClient, store: Cache) -> tuple:
    """``(rows, n_packages, cache_hits)`` for the deb packages of ``packages``:
    one CVE row per CVE and package. Raises OsvUnavailable; what finished
    before is cached all the same."""
    pkgs = sorted({(p["name"], p["version"]) for p in packages
                   if isinstance(p, dict) and p.get("format") == "deb"
                   and p.get("name") and p.get("version")})
    found: dict = {}
    for pkg in pkgs:
        entry = store.get(_key(eco, *pkg))
        if entry and entry["fresh"]:
            found[pkg] = entry["data"]
    hits = len(found)
    ids: dict = {}
    resolved: dict = {}
    try:
        client.query(eco, [p for p in pkgs if p not in found], ids)
        every = {v for vs in ids.values() for v in vs}
        for vid in every:
            m = _CVE_ID.match(vid)
            if m:
                resolved[vid] = [m.group(1)]
        client.aliases(sorted(every - set(resolved)), resolved)
    finally:
        for pkg, vids in ids.items():
            if all(v in resolved for v in vids):
                found[pkg] = sorted({c for v in vids for c in resolved[v]})
                store.put(_key(eco, *pkg), found=bool(found[pkg]), data=found[pkg])
        store.save()
    rows = [{"cve": cve, "cvss": None, "cvss_version": None, "severity": None,
             "package": name, "version": version, "description": None, "reference": None,
             "published_at": None, "detected_at": None, "source": SOURCE,
             "confidence": POTENTIAL}
            for (name, version), cves in sorted(found.items()) for cve in cves]
    return rows, len(pkgs), hits


def unscored_server(endpoints: list) -> Optional[dict]:
    """Agent 000 when the score step found no package inventory for it."""
    return next((e for e in endpoints if e.get("agent_id") == SERVER_AGENT_ID
                 and e.get("unscored_reason") == "no_inventory"), None)


def score_server(endpoints: list, warnings: list, inventory: Callable, store: Cache,
                 client: OsvClient, clock, catalogue: Optional[dict] = None) -> StageResult:
    """Score the server endpoint (:func:`unscored_server`) in place from its
    own package list; ``inventory()`` gives ``(os items, packages)``. A CVE
    the scan's ``catalogue`` already has takes its score and text from there.
    On success it leaves the ``not_yet_inventoried`` warning. The result's
    rows join the CVE catalogue; its note is the stage line."""
    i = endpoints.index(unscored_server(endpoints))
    server = endpoints[i]
    t0 = clock.monotonic()
    try:
        os_items, packages = inventory()
    except requests.RequestException as e:
        log.warning("Wazuh server package list not read (%s)", type(e).__name__)
        server["osv"] = {"status": "unavailable", "reason": "its package list could not be read"}
        return StageResult(note="package list could not be read")
    eco, reason = ecosystem(os_items)
    if eco is None:
        server["osv"] = {"status": "skipped", "reason": reason}
        return StageResult(note=f"skipped: {reason}", ran=False)
    try:
        rows, n_pkgs, hits = match(packages if isinstance(packages, list) else [],
                                   eco, client, store)
    except OsvUnavailable as e:
        log.warning("Wazuh server left unscored: %s (%s)", UNAVAILABLE, e)
        server["osv"] = {"status": "unavailable", "reason": UNAVAILABLE, "ecosystem": eco}
        return StageResult(note=f"{UNAVAILABLE} ({e})")
    rows = [{**r, **{k: v for k, v in ((catalogue or {}).get(r["cve"]) or {}).items()
                     if v is not None}} for r in rows]
    scored = enrich_agent({k: v for k, v in server.items() if k != "unscored_reason"}, rows)
    scored["findings"] = slim_findings(rows)
    scored["osv"] = {"status": "ok", "reason": None, "ecosystem": eco, "packages": n_pkgs}
    endpoints[i] = scored
    for w in warnings:
        if w.get("type") == "not_yet_inventoried" and SERVER_AGENT_ID in w.get("agents", []):
            w["agents"] = [a for a in w["agents"] if a != SERVER_AGENT_ID]
            w["node_ids"] = [endpoint_node_id(a) for a in w["agents"]]
    warnings[:] = [w for w in warnings
                   if not (w.get("type") == "not_yet_inventoried" and not w.get("agents"))]
    n_cves = scored["cve_summary"]["total"]
    note = (f"{plural(n_pkgs, 'package')}, {plural(n_cves, 'CVE')}, "
            f"{clock.monotonic() - t0:.1f} s (cache hits {hits})")
    log.info("%s: %s", STAGE, note)
    return StageResult(rows={endpoint_node_id(SERVER_AGENT_ID): rows}, note=note)


def _shape(value) -> str:
    """What a reply looks like (types and keys, never values), for a log line."""
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {type(v).__name__}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return f"list of {len(value)}" + (f", first {_shape(value[0])}" if value else "")
    return type(value).__name__


def ecosystem(os_items) -> tuple:
    """``(OSV ecosystem, None)`` from the server's /syscollector/000/os items,
    or ``(None, reason)``. Ubuntu LTS releases are named with ":LTS"
    ("Ubuntu:22.04:LTS"), as OSV lists them; interim ones without it."""
    item = os_items[0] if isinstance(os_items, list) and os_items else None
    os_info = item.get("os") if isinstance(item, dict) else None
    if not isinstance(os_info, dict):
        log.warning("Wazuh server OS: unexpected syscollector reply (%s)", _shape(os_items))
        return None, "its OS is not in the syscollector inventory"
    name = str(os_info.get("platform") or os_info.get("name") or "").lower()
    major, minor = str(os_info.get("major") or ""), str(os_info.get("minor") or "")
    if not major:
        m = re.match(r"(\d+)(?:\.(\d+))?", str(os_info.get("version") or ""))
        major, minor = (m.group(1), m.group(2) or "") if m else ("", "")
    if "ubuntu" in name and major.isdigit() and minor.isdigit():
        release = f"{major}.{int(minor):02d}"
        lts = int(major) % 2 == 0 and int(minor) == 4
        return f"Ubuntu:{release}" + (":LTS" if lts else ""), None
    if "debian" in name and major.isdigit():
        return f"Debian:{major}", None
    shown = " ".join(str(os_info.get(k) or "") for k in ("name", "version")).strip()
    return None, f"OSV matching is not set up for its OS ({shown or 'unknown'})"
