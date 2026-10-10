"""The CVE vector stage: how each asset's most easily reached CVE can be reached.

Each CVE has four exploitability fields in its CVSS vector (nvd.vector_fields):
attack_vector, attack_complexity, privileges_required, user_interaction. Device
CVEs come from NVD with them; host CVEs come from the Wazuh indexer with only a
score, so this stage asks NVD for them by id (lookup.lookup_cve), through the
NVD cache and within the client's time budget.

An asset's most easily reached CVE is, among its CVEs with attack vector
NETWORK or ADJACENT, no privileges required and no user interaction, the one
with the lowest attack complexity (LOW, then MEDIUM (v2 only), then HIGH),
ties going to the higher score. To keep requests few, an asset's CVEs are
looked at highest score first, and the asset is done as soon as one is
NETWORK, LOW, no privileges and no interaction: nothing can rank above it. A
CVE is looked up once for every asset that has it, and CVE records the device
stage already cached are read from the cache, so a warm cache makes no request.

Each asset (endpoint or device node) gets ``reachable_cve``:

  {status: "found", source, cve, attack_vector, attack_complexity,
   privileges_required, user_interaction, cvss}
  {status: "none_found", source}   every candidate looked at, none qualifies
  {status: "unverified", source}   a lookup did not finish inside the budget
                                   (or NVD could not be reached): no claim
  null                             the asset has no CVE data (unscored)

``source`` says where the candidates came from: ``findings`` (every CVE of the
asset, from vulnerabilities.json) or ``top_cves`` (only the worst few, when the
full list is not available). The four fields are also written, when known, on
the graph's top_cves rows and on the CVE catalogue of vulnerabilities.json.

Refresh an existing graph without a rescan::

    python -m vulnmapper.devicecves.vectors --graph data/graph.json [--vulns PATH]
                                            [--nvd-cache PATH] [--budget SECONDS]

Only the fields above, metadata.cve_vectors and this stage's warning change; the
catalogue of an existing vulnerabilities.json beside the graph (or --vulns) is
updated, and none is created.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from typing import Optional

from .. import vulnfile
from ..endpoints import distinct_cves
from .__main__ import _load, _write_json_atomic
from .cache import Cache, default_path
from .lookup import Unanswered, lookup_cve
from .nvd import VECTOR_FIELDS, NvdClient, SystemClock, vector_fields
from .stage import DEFAULT_BUDGET_S

log = logging.getLogger("vulnmapper.devicecves")

FIELD = "reachable_cve"
FOUND, NONE_FOUND, UNVERIFIED = "found", "none_found", "unverified"
ASSET_KINDS = ("endpoint", "device")
WARNING = "cve_vectors_unverified"
_COMPLEXITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _reachable(f: dict) -> bool:
    return (f["attack_vector"] in ("NETWORK", "ADJACENT") and f["privileges_required"] == "NONE"
            and f["user_interaction"] == "NONE")


def _cached_records(cache: Cache) -> dict:
    """Vector fields of every CVE record the device stage's answers hold."""
    known: dict = {}
    for key, entry in cache.entries.items():
        if key.startswith(("cves:", "keyword:")):
            for rec in entry.get("data") or []:
                if isinstance(rec, dict) and rec.get("id"):
                    known[rec["id"]] = vector_fields(rec.get("metrics") or {})
    return known


def candidates(node: dict, entry: Optional[dict], catalogue: dict) -> tuple:
    """``(rows, source)``: the asset's distinct CVEs as {cve, cvss}, highest score first."""
    findings = (entry or {}).get("findings")
    if findings is not None:
        rows = [{"cve": f["cve"], "cvss": (catalogue.get(f["cve"]) or {}).get("cvss")}
                for f in findings if f.get("cve")]
        return distinct_cves(rows), "findings"
    rows = [{"cve": r["cve"], "cvss": r.get("cvss")} for r in node.get("top_cves") or []
            if r.get("cve")]
    return distinct_cves(rows), "top_cves"


def assess(rows: list, fields_of) -> dict:
    """The summary for one asset; ``fields_of(cve)`` may raise :class:`Unanswered`."""
    best = None
    for row in rows:
        try:
            f = fields_of(row["cve"])
        except Unanswered:
            return {"status": UNVERIFIED}
        if not f or not _reachable(f):
            continue
        # rows come highest score first, so the first at a complexity wins its ties
        if best is None or _COMPLEXITY.get(f["attack_complexity"], 3) < \
                _COMPLEXITY.get(best[1]["attack_complexity"], 3):
            best = (row, f)
        if f["attack_vector"] == "NETWORK" and f["attack_complexity"] == "LOW":
            break
    if best is None:
        return {"status": NONE_FOUND}
    row, f = best
    return {"status": FOUND, "cve": row["cve"], **{k: f[k] for k in VECTOR_FIELDS},
            "cvss": row["cvss"]}


class StageResult:
    def __init__(self) -> None:
        self.warnings: list = []
        self.block: dict = {}


def run_stage(graph: dict, hosts: dict, catalogue: dict, client: NvdClient,
              cache: Cache) -> StageResult:
    """Summarise every asset of ``graph`` in place and add the four fields, where
    known, to its top_cves rows and to ``catalogue`` (vulnerabilities.json's
    ``cves``). ``hosts`` is vulnerabilities.json's ``hosts`` (full findings)."""
    out = StageResult()
    requests_before = client.requests
    known = _cached_records(cache)       # cve id -> vector fields, or None if NVD has no record
    asked: set = set()

    def fields_of(cve_id: str) -> Optional[dict]:
        if cve_id not in known:
            asked.add(cve_id)
            rec = lookup_cve(cve_id, client, cache)
            known[cve_id] = vector_fields(rec.get("metrics") or {}) if rec else None
        return known[cve_id]

    by_status: Counter = Counter()
    unverified = []
    nodes = [n for n in graph.get("nodes") or [] if n.get("kind") in ASSET_KINDS]
    for node in nodes:
        if node.get("cve_summary") is None:
            node[FIELD] = None
            continue
        rows, source = candidates(node, hosts.get(node["node_id"]), catalogue)
        summary = assess(rows, fields_of)
        node[FIELD] = {"status": summary["status"], "source": source,
                       **{k: v for k, v in summary.items() if k != "status"}}
        by_status[summary["status"]] += 1
        if summary["status"] == UNVERIFIED:
            unverified.append(node["node_id"])
    cache.save()

    def four(cve_id) -> Optional[dict]:
        f = known.get(cve_id)
        return {k: f[k] for k in VECTOR_FIELDS} if f and f["attack_vector"] else None

    for node in nodes:
        for row in node.get("top_cves") or []:
            row.update(four(row.get("cve")) or {})
    for cve_id, entry in catalogue.items():
        entry.update(four(cve_id) or {})

    if unverified:
        out.warnings.append({"type": WARNING, "node_ids": unverified})
        log.warning("NVD time budget (%.0f s) ran out or NVD was unreachable; %d asset(s) "
                    "unverified", client.budget_s, len(unverified))
    out.block = {
        "assets": len(nodes),
        "by_status": dict(sorted(by_status.items())),
        "looked_up": len(asked),
        "nvd_requests": client.requests - requests_before,
        "api_key": client.has_key,
        "budget_s": client.budget_s,
    }
    log.info("CVE vectors: %d asset(s) %s, %d CVE(s) looked up, %d NVD request(s)",
             len(nodes), dict(by_status), len(asked), out.block["nvd_requests"])
    return out


def main(argv: Optional[list] = None, transport=None, clock=None) -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(
        prog="vulnmapper.devicecves.vectors",
        description="Refresh the CVSS vector fields of a graph's CVEs from NVD, without a rescan.")
    parser.add_argument("--graph", required=True, metavar="PATH", help="graph.json to refresh")
    parser.add_argument("--vulns", metavar="PATH",
                        help="vulnerabilities.json to read findings from and update "
                             "(default: beside the graph; skipped if there is none)")
    parser.add_argument("--nvd-cache", metavar="PATH",
                        help="NVD answer cache (default: nvd-cache.json beside the graph)")
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET_S, metavar="SECONDS",
                        help="time budget for the NVD lookups (default 180)")
    args = parser.parse_args(argv)

    graph = _load(args.graph)
    if graph is None or not isinstance(graph.get("nodes"), list):
        print(f"vulnmapper.devicecves.vectors: cannot read graph {args.graph}", file=sys.stderr)
        return 1
    vulns_path = args.vulns or vulnfile.default_path(args.graph)
    vulns = _load(vulns_path) if os.path.exists(vulns_path) else None

    clock = clock or SystemClock()
    client = NvdClient(transport=transport, clock=clock, budget_s=args.budget)
    cache = Cache(args.nvd_cache or default_path(args.graph), clock)
    result = run_stage(graph, (vulns or {}).get("hosts") or {}, (vulns or {}).get("cves") or {},
                       client, cache)

    meta = graph.setdefault("metadata", {})
    meta["warnings"] = [w for w in meta.get("warnings") or []
                        if not (isinstance(w, dict) and w.get("type") == WARNING)]
    meta["warnings"].extend(result.warnings)
    meta["cve_vectors"] = {**result.block, "refreshed_at": clock.now().isoformat()}
    _write_json_atomic(args.graph, graph, indent=2)
    log.info("refreshed CVE vectors in %s", args.graph)
    if vulns is not None:
        vulnfile.write_atomic(vulns_path, vulns)
        log.info("updated the CVE catalogue in %s", vulns_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
