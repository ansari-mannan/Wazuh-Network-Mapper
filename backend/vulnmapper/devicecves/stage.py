"""The device vulnerability stage: CVEs and a base score for every network device.

A host without an agent that answered the optional SNMP question with a
software family the lookup knows (vulnmapper.hosts) is looked up the same way.

Works on an assembled graph's device nodes, so it runs the same after a live
crawl, after ``--network PATH`` and in the refresh command
(``python -m vulnmapper.devicecves``). Each device gets the fields hosts
already have, built with the same helpers (``endpoints.enrich_agent``:
distinct_cves, summarize_cves, TOP_CVES, scoring.base_score):

  ``cve_summary``, ``top_cves``, ``max_cvss``, ``risk_score``, and
  ``cve_lookup``: {status, match, product, cpe, source, fetched_at, stale, total}

How the lookup's status maps to the score:

  CPE query answered, CVEs found        ok                    base_score(rows)
  CPE query answered, nothing found     ok                    0.0
  keyword fallback, CVEs found          ok, match keyword     base_score(rows)
  keyword fallback, nothing found       ok, match keyword     null (Unscored)
  vendor, family or version missing     unidentified          null
  NVD unreachable and nothing cached    unavailable           null
  NVD could not confirm the query       unverified            null
  device not polled                     unidentified          null

A 0.0 means "asked precisely, and NVD has nothing"; a failed, guessed or
skipped lookup never produces it. Every device finding is potential: the
software version matches, which does not prove the affected feature is in use.
``cve_lookup`` marks that; the rows carry no flag of their own.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Optional

from ..endpoints import catalogue_entry, distinct_cves, enrich_agent, slim_findings
from . import families
from .cache import Cache
from .lookup import STATUS_OK, STATUS_UNAVAILABLE, STATUS_UNIDENTIFIED, Lookup, lookup
from .nvd import VECTOR_KEYS, NvdClient

log = logging.getLogger("vulnmapper.devicecves")

DEFAULT_BUDGET_S = 180.0
SOURCE = "nvd"
KIND_DEVICE = "device"


def _lookup_object(result: Lookup, rows: Optional[list]) -> dict:
    return {
        "status": result.status,
        "match": result.match,
        "product": result.product,
        "cpe": result.cpe,
        "source": SOURCE,
        "fetched_at": result.fetched_at,
        "stale": result.stale,
        "total": len(distinct_cves(rows)) if rows is not None else None,
    }


def apply_result(node: dict, result: Lookup) -> Optional[list]:
    """Set a device node's CVE fields from its lookup; returns the scored rows."""
    rows = result.rows if result.status == STATUS_OK else None
    # keyword fallback with nothing accepted: no claim either way (Unscored)
    scored = None if rows is None or (result.match == "keyword" and not rows) else rows
    enriched = enrich_agent({}, scored)
    node["risk_score"] = enriched["risk_score"]
    node["max_cvss"] = enriched["max_cvss"]
    # the vector fields go on only through the vectors stage (vectors.py)
    node["top_cves"] = [{k: v for k, v in r.items() if k not in VECTOR_KEYS}
                        for r in enriched["top_cves"]]
    node["cve_summary"] = enriched["cve_summary"]
    node["cve_lookup"] = _lookup_object(result, rows)
    return rows


def merge_catalogue(catalogue: dict, rows: list) -> None:
    """Add NVD's text for CVEs the catalogue lacks; when both Wazuh and NVD know
    a CVE, keep the existing rule (the higher-scored entry wins)."""
    for row in rows:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        known = catalogue.get(cve_id)
        if known is None or (row.get("cvss") is not None and (
                known.get("cvss") is None or row["cvss"] > known["cvss"])):
            catalogue[cve_id] = catalogue_entry(row)


class StageResult:
    def __init__(self) -> None:
        self.entries: dict = {}           # node_id -> vulnerabilities.json device entry
        self.rows: dict = {}              # node_id -> CVE rows (status ok)
        self.warnings: list = []
        self.block: dict = {}


def run_stage(graph: dict, client: NvdClient, cache: Cache) -> StageResult:
    """Look up every device node of ``graph`` and update it in place."""
    out = StageResult()
    by_status: Counter = Counter()
    unreachable, stale, budget, unidentified = [], [], [], []
    from_cache = 0
    # A host that answered SNMP with a software family is looked up the same way.
    devices = [n for n in graph.get("nodes") or [] if n.get("kind") == KIND_DEVICE
               or (n.get("snmp") and n.get("software_family"))]
    for node in devices:
        result = lookup(families.identify(node), client, cache)
        rows = apply_result(node, result)
        nid = node["node_id"]
        by_status[result.status] += 1
        if result.status == STATUS_UNAVAILABLE:
            (budget if result.reason == "budget" else unreachable).append(nid)
        if result.stale:
            stale.append(nid)
        if result.status == STATUS_UNIDENTIFIED and node.get("pollable"):
            unidentified.append(nid)
        if result.queries and result.from_cache:
            from_cache += 1
        if rows is not None:
            out.rows[nid] = rows
        out.entries[nid] = {
            "kind": node["kind"],
            "hostname": node.get("hostname"),
            "agent_id": None,
            "cve_lookup": node["cve_lookup"],
            "findings": slim_findings(rows) if rows is not None else None,
        }
    cache.save()

    for kind, ids in (("nvd_unreachable", unreachable), ("nvd_stale_cache", stale),
                      ("nvd_budget_exceeded", budget), ("device_unidentified", unidentified)):
        if ids:
            out.warnings.append({"type": kind, "node_ids": ids})
    if budget:
        log.warning("NVD time budget (%.0f s) ran out; %d device(s) left for the next scan",
                    client.budget_s, len(budget))
    out.block = {
        "looked_up": len(devices),
        "by_status": dict(sorted(by_status.items())),
        "from_cache": from_cache,
        "nvd_requests": client.requests,
        "stale": len(stale),
        "api_key": client.has_key,
        "budget_s": client.budget_s,
    }
    log.info("device CVEs: %d device(s) %s, %d NVD request(s)", len(devices),
             dict(by_status), client.requests)
    return out
