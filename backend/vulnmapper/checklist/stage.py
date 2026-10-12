"""The configuration checklist stage: evaluate every polled device of a graph.

Runs after assembly, beside the device CVE stage. The data comes from the
crawl's network document (``config_data`` on each crawled node, keyed by
chassis id); the graph's device nodes get only the results:

  config_checks    [{id, title, result, reason?}] one per check
  config_findings  [{id, title, severity, why, remediation, references, cwe,
                     evidence}] one per failed check
  config_summary   {checks, results: {pass, fail, ...}, findings: {high,
                    medium, low, advisory}}

A device that was not polled gets no checklist at all. risk_score is not
touched: how findings and CVEs combine is for a later stage.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING, Optional

from ..common import StageResult, plural
from ..devicecves.families import family_of
from ..schema import KIND_DEVICE
from .evaluate import RESULTS, evaluate_device, l3_vlans, normalise

if TYPE_CHECKING:
    from ..pipeline import ScanContext

log = logging.getLogger("vulnmapper.checklist")


def run_stage(graph: dict, network_doc: dict, probe_enabled: bool,
              source: str = "scan", port_test: bool = False) -> StageResult:
    """Evaluate the checks for every polled device node of ``graph`` in place."""
    out = StageResult()
    config_by_chassis = {n.get("chassis_id"): n.get("config_data")
                         for n in network_doc.get("nodes") or [] if n.get("chassis_id")}
    results: Counter = Counter()
    findings: Counter = Counter()
    not_collected, failed = [], []
    checked = 0
    # VLANs in use network-wide: hosts were learned on them, or a polled device
    # has an up layer-3 interface for them.
    vlans_in_use = {n["vlan"] for n in graph.get("nodes") or []
                    if n.get("kind") != KIND_DEVICE and n.get("vlan") is not None}
    for config in config_by_chassis.values():
        if config and not config.get("failed"):
            vlans_in_use |= l3_vlans(normalise(config))
    for node in graph.get("nodes") or []:
        if node.get("kind") != KIND_DEVICE or not node.get("pollable"):
            continue
        config = config_by_chassis.get(node.get("chassis_id"))
        if config is None:
            not_collected.append(node["node_id"])
        elif config.get("failed"):
            failed.append(node["node_id"])
        node.update(evaluate_device(node, config, probe_enabled, family_of(node),
                                    port_test, vlans_in_use))
        checked += 1
        results.update(node["config_summary"]["results"])
        findings.update(node["config_summary"]["findings"])

    for kind, ids in (("checklist_data_missing", not_collected),
                      ("checklist_unreadable", failed)):
        if ids:
            out.warnings.append({"type": kind, "node_ids": ids})
    out.block = {
        "devices_checked": checked,
        "results": {r: results.get(r, 0) for r in RESULTS},
        "findings": {s: findings.get(s, 0) for s in ("high", "medium", "low", "advisory")},
        "probe_enabled": probe_enabled,
        "port_test_enabled": port_test,
        "source": source,
    }
    log.info("configuration checks: %d device(s), findings %s", checked, out.block["findings"])
    return out


def run_checklist(scan: "ScanContext") -> StageResult:
    """The pipeline's checklist stage, on the configuration data the crawl read."""
    args = scan.args
    result = run_stage(scan.document, scan.network_doc, args.check_default_communities,
                       port_test=args.check_management_ports)
    note = f"{plural(result.block['devices_checked'], 'device')} checked"
    if args.check_default_communities:
        note += "; " + (_default_community_note(scan.document)
                        or "no device tested for the default community")
    result.note = note
    return result


def _default_community_note(graph: dict) -> Optional[str]:
    """e.g. "5 devices tested, 0 answered the default community"; None if none was."""
    results = [c["result"] for n in graph["nodes"] if n.get("kind") == KIND_DEVICE
               for c in n.get("config_checks") or [] if c.get("id") == "snmp-default-community"]
    tested = [r for r in results if r in ("pass", "fail")]
    if not tested:
        return None
    return (f"{plural(len(tested), 'device')} tested, {tested.count('fail')} answered "
            "the default community")
