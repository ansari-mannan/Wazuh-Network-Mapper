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
from collections import Counter
from typing import TYPE_CHECKING, Optional

from ..common import StageResult, plural
from .cvss_select import FILENAME as RECORDS_FILENAME, CveRecords, records_cache
from .feeds import UNAVAILABLE, Threat, load_threat
from .ovss import (CONFIRMED, POTENTIAL, TIERS, UNRATED, dependency_of, exposure_of,
                   finding_record, node_record)

if TYPE_CHECKING:
    from ..attackpaths import AttackPathEngine
    from ..pipeline import ScanContext

WARNING = "threat_feeds_unavailable"


def score_graph(graph: dict, vulns: dict, targets: Optional[dict], engine: "AttackPathEngine",
                threat: Threat, records: CveRecords) -> dict:
    """Score ``vulns``' findings and ``graph``'s nodes in place; returns the
    ``metadata.ovss`` block."""
    hosts, catalogue = vulns.get("hosts") or {}, vulns.get("cves") or {}
    targets = targets or {}
    ids = sorted({f["cve"] for h in hosts.values() for f in h.get("findings") or []
                  if f.get("cve")} | {r["cve"] for n in graph["nodes"]
                                      for r in n.get("top_cves") or [] if r.get("cve")},
                 key=lambda c: (-((catalogue.get(c) or {}).get("cvss") or 0), c))  # worst first
    recs = records.load(ids)
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


def score(graph: dict, vulns: dict, targets: Optional[dict], folder: Optional[str], clock,
          transport=None) -> tuple:
    """Load the feeds and records (cached in ``folder``), build the attack path
    engine and score ``graph`` and ``vulns`` in place. Returns ``(engine, result)``;
    the result's block is ``metadata.ovss``, and the graph gains
    ``metadata.threat_feeds``."""
    from ..attackpaths import AttackPathEngine

    threat = load_threat(folder, clock, transport)
    records = CveRecords(records_cache(os.path.join(folder, RECORDS_FILENAME) if folder else None,
                                       clock), clock, transport)
    engine = AttackPathEngine(graph, targets, vulns)
    block = score_graph(graph, vulns, targets, engine, threat, records)
    graph.setdefault("metadata", {})["threat_feeds"] = threat.block

    out = StageResult(block=block)
    missing = [name for name in ("kev", "epss") if threat.block[name] == UNAVAILABLE]
    if missing:
        out.warnings.append({"type": WARNING, "feeds": missing})
    scored = sum(v for k, v in block["findings_by_tier"].items() if k != UNRATED)
    out.note = (f"{plural(scored, 'finding')} scored on "
                f"{plural(block['nodes_by_status'].get('assessed', 0), 'asset')}; "
                f"KEV {threat.block['kev']}, EPSS {threat.block['epss']}")
    return engine, out


def run_ovss(scan: "ScanContext") -> StageResult:
    """The pipeline's OVSS stage. Builds the scan's attack path engine
    (``scan.engine``), which the attack path stage then uses."""
    from ..attackpaths import load_targets

    # The findings here are the very dicts vulnerabilities.json is later built
    # from, so the fields this stage adds to them are written with it.
    vulns = scan.vulnerabilities(None)
    scan.engine, result = score(scan.document, vulns, load_targets(scan.targets_path),
                                scan.cache_folder(), scan.clock, scan.threat_transport)
    return result
