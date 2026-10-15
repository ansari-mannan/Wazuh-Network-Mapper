"""The OVSS stage: every finding in vulnerabilities.json gets its OVSS fields
(ovss.finding_record) and every graph node its roll-up (ovss.node_record).

Runs after every CVE stage and before the attack paths: it needs the attack
path engine's placement (which VLANs each node is in, which are routed) and
its per-asset dependants, and the engine then ranks routes by the node scores
it writes. Reads the threat feeds and CVE records (cached); writes
``metadata.threat_feeds`` on the graph.
"""

from __future__ import annotations

import os
import time
from collections import Counter
from typing import TYPE_CHECKING, Optional

from ..common import StageResult, plural
from ..devicecves.nvd import VECTOR_FIELDS
from ..endpoints.findings import TOP_CVES
from .cvss_select import FILENAME as RECORDS_FILENAME, CveRecords, records_cache
from .feeds import UNAVAILABLE, Threat, load_threat
from .ovss import (CONFIRMED, POTENTIAL, TIERS, UNRATED, dependency_of, exposure_of,
                   finding_record, node_record)

if TYPE_CHECKING:
    from ..attackpaths import AttackPathEngine
    from ..pipeline import ScanContext

WARNING = "threat_feeds_unavailable"
# --records-in-background: the longest the stage waits for cve.org
RECORDS_WAIT_S = 5.0


def ovss_order(row: dict) -> tuple:
    """Highest OVSS first (Unrated last), then highest CVSS, then CVE id."""
    score, cvss = row.get("score"), row.get("cvss")
    return (score is None, -(score or 0), cvss is None, -(cvss or 0), row.get("cve") or "")


# A top_cves row as the CVE stages write it (endpoints.parse_hit), in key order.
_CATALOGUE_KEYS = ("cvss", "cvss_version", "severity")
_TEXT_KEYS = ("description", "reference", "published_at")


def top_cves(current: list, findings: Optional[list], per_cve: dict, catalogue: dict) -> list:
    """The node's TOP_CVES rows by OVSS, then CVSS, so the CVE that sets the
    node's score is always listed. With the full findings, a CVE not yet among
    the rows is built from its first finding and the catalogue, in the row
    shape the CVE stages use; without them, the rows are only reordered."""
    if findings is None:
        return sorted(current, key=ovss_order)[:TOP_CVES]
    have = {r.get("cve"): r for r in current}
    first: dict = {}
    for f in findings:
        first.setdefault(f.get("cve"), f)
    rows = []
    for cve, record in per_cve.items():
        row = have.get(cve)
        if row is None:
            f, c = first[cve], catalogue.get(cve) or {}
            row = {"cve": cve, **{k: c.get(k) for k in _CATALOGUE_KEYS},
                   "package": f.get("package"), "version": f.get("version"),
                   **{k: c.get(k) for k in _TEXT_KEYS}, "detected_at": f.get("detected_at"),
                   **{k: c[k] for k in VECTOR_FIELDS if k in c}, **record}
        rows.append(row)
    return sorted(rows, key=ovss_order)[:TOP_CVES]


def fetch_order(ids, catalogue: dict) -> list:
    """CVE ids worst tool score first: the order their records are fetched in."""
    return sorted(set(ids), key=lambda c: (-((catalogue.get(c) or {}).get("cvss") or 0), c))


def score_graph(graph: dict, vulns: dict, targets: Optional[dict], engine: "AttackPathEngine",
                threat: Threat, records: CveRecords, wait_s: Optional[float] = None) -> dict:
    """Score ``vulns``' findings and ``graph``'s nodes in place; returns the
    ``metadata.ovss`` block. ``wait_s``: see :meth:`CveRecords.load`."""
    hosts, catalogue = vulns.get("hosts") or {}, vulns.get("cves") or {}
    targets = targets or {}
    ids = fetch_order({f["cve"] for h in hosts.values() for f in h.get("findings") or []
                       if f.get("cve")} | {r["cve"] for n in graph["nodes"]
                                           for r in n.get("top_cves") or [] if r.get("cve")},
                      catalogue)
    recs = records.load(ids, wait_s)
    # a VLAN is routed when some router has an up layer-3 interface in it and another
    routed = set().union(*(v for v in engine.routers.values() if len(v) >= 2))
    dependants = engine.dependants()
    n_nodes = len(graph["nodes"])
    tiers, statuses = Counter(), Counter()
    for node in graph["nodes"]:
        nid = node["node_id"]
        exposure, flag = exposure_of(node, engine.placed.get(nid), routed)
        dependency, weight = dependency_of(dependants.get(nid, 0), n_nodes,
                                           (targets.get(nid) or {}).get("importance"))
        host = hosts.get(nid) or {}
        confidence = CONFIRMED if host.get("agent_id") else POTENTIAL
        # the full findings (one row per CVE and package); when they are not
        # known (an old-shape --scored file), the worst few the node carries
        findings = host.get("findings")
        rows = findings if findings is not None else node.get("top_cves") or []
        per_cve: dict = {}
        for f in rows:
            cve = f.get("cve")
            if cve not in per_cve:
                c = catalogue.get(cve) or f          # top_cves rows carry their own score
                per_cve[cve] = finding_record(
                    cve, c.get("cvss"), c.get("cvss_version"), recs.get(cve),
                    kev_ids=threat.kev, epss_scores=threat.epss, exposure=exposure,
                    dependency=dependency, confidence=confidence)
            f.update(per_cve[cve])
        for r in node.get("top_cves") or []:      # the rows the dashboard lists
            r.update(per_cve.get(r.get("cve")) or {})
        if "top_cves" in node:
            node["top_cves"] = top_cves(node["top_cves"], findings, per_cve, catalogue)
        rollup = node_record(list(per_cve.values()), cve_lookup=node.get("cve_lookup"),
                             exposure=exposure, exposure_flag=flag, dependency=dependency,
                             importance=weight)
        node.update(rollup)
        tiers.update(r["tier"] for r in per_cve.values())
        statuses[rollup["ovss_status"]] += 1
    return {"findings_by_tier": {t: tiers[t] for t in TIERS + (UNRATED,)},
            "nodes_by_status": dict(sorted(statuses.items())),
            # requests in flight when a link dies vary, so that count is only logged
            "cve_records": {k: v for k, v in records.stats.items() if k != "requests"}}


def cve_records(folder: Optional[str], clock, transport=None) -> CveRecords:
    """The CVE records cached in ``folder`` (none: in memory only)."""
    return CveRecords(records_cache(os.path.join(folder, RECORDS_FILENAME) if folder else None,
                                    clock), clock, transport)


def score(graph: dict, vulns: dict, targets: Optional[dict], folder: Optional[str], clock,
          transport=None, records: Optional[CveRecords] = None,
          wait_s: Optional[float] = None) -> tuple:
    """Load the feeds and records (cached in ``folder``; ``records`` when the
    scan already started fetching them), build the attack path engine and
    score ``graph`` and ``vulns`` in place. Returns ``(engine, result)``; the
    result's block is ``metadata.ovss``, and the graph gains
    ``metadata.threat_feeds``."""
    from ..attackpaths import AttackPathEngine

    threat = load_threat(folder, clock, transport)
    records = records or cve_records(folder, clock, transport)
    engine = AttackPathEngine(graph, targets, vulns)
    t0 = time.monotonic()
    block = score_graph(graph, vulns, targets, engine, threat, records, wait_s)
    scoring_s = time.monotonic() - t0 - records.load_s
    graph.setdefault("metadata", {})["threat_feeds"] = threat.block

    out = StageResult(block=block)
    missing = [name for name in ("kev", "epss") if threat.block[name] == UNAVAILABLE]
    if missing:
        out.warnings.append({"type": WARNING, "feeds": missing})
    scored = sum(v for k, v in block["findings_by_tier"].items() if k != UNRATED)
    out.note = (f"{plural(scored, 'finding')} scored on "
                f"{plural(block['nodes_by_status'].get('assessed', 0), 'asset')}; "
                f"KEV {threat.block['kev']}, EPSS {threat.block['epss']}; "
                f"records fetch {records.load_s:.1f} s, {records.stats['fetched']} fetched, "
                f"{records.stats['hits']} cached; scoring {scoring_s:.1f} s")
    return engine, out


def run_ovss(scan: "ScanContext") -> StageResult:
    """The pipeline's OVSS stage. Builds the scan's attack path engine
    (``scan.engine``), which the attack path stage then uses."""
    from ..attackpaths import load_targets

    # The findings here are the very dicts vulnerabilities.json is later built
    # from, so the fields this stage adds to them are written with it.
    vulns = scan.vulnerabilities(None)
    warnings: list = []
    targets = load_targets(scan.targets_path, warnings)
    scan.engine, result = score(scan.document, vulns, targets, scan.cache_folder(), scan.clock,
                                scan.threat_transport, records=scan.records(),
                                wait_s=RECORDS_WAIT_S if scan.args.records_in_background else None)
    result.warnings.extend(warnings)
    return result
