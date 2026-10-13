"""``python -m vulnmapper.devicecves``: re-runs only the device CVE stage on an
existing graph, without a rescan (NVD publishes new CVEs every day; a full
scan needs the network).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from typing import Optional

from ..common import setup_logging
from .. import vulnfile
from .cache import Cache, default_path
from .nvd import NvdClient, SystemClock
from ..endpoints import merge_catalogue
from .stage import DEFAULT_BUDGET_S, run_stage
from ..attackpaths import load_targets, targets_path
from ..scoring.stage import WARNING, score

log = logging.getLogger("vulnmapper.devicecves")

# Warnings this stage writes; a refresh replaces the previous ones.
STAGE_WARNINGS = {"nvd_unreachable", "nvd_stale_cache", "nvd_budget_exceeded",
                  "device_unidentified"}


def _write_json_atomic(path: str, doc: dict, indent: Optional[int]) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".graph.", suffix=".tmp", dir=folder)
    try:
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=indent)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _load(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def update_vulns(path: str, entries: dict, rows: dict, scan_time: Optional[str]) -> dict:
    """vulnerabilities.json with its device entries replaced, host entries kept
    (not written)."""
    doc = _load(path) or {}
    hosts = {k: v for k, v in (doc.get("hosts") or {}).items()
             if isinstance(v, dict) and v.get("kind") != "device"}
    catalogue = dict(doc.get("cves") or {})
    for device_rows in rows.values():
        merge_catalogue(catalogue, device_rows)
    hosts.update(entries)
    used = set()
    findings = 0
    for entry in hosts.values():
        for f in entry.get("findings") or []:
            findings += 1
            if f.get("cve"):
                used.add(f["cve"])
    meta = dict(doc.get("metadata") or {"scan_time": scan_time})
    n_devices = sum(1 for v in hosts.values() if v.get("kind") == "device")
    meta["counts"] = {"hosts": len(hosts) - n_devices, "devices": n_devices,
                      "cves": len(used & set(catalogue)), "findings": findings}
    return {
        "metadata": meta,
        "cves": {c: catalogue[c] for c in sorted(used) if c in catalogue},
        "hosts": hosts,
    }


def main(argv: Optional[list] = None, transport=None, clock=None) -> int:
    """Refresh the device CVEs of an existing graph::

        python -m vulnmapper.devicecves --graph data/graph.json [--nvd-cache PATH]
                                        [--vulns PATH] [--budget SECONDS]

    Refreshes the device nodes' CVE fields (and the stage's metadata block and
    warnings), updates the device entries of vulnerabilities.json beside it
    (creating a devices-only file if there is none, leaving host entries as
    they were), then scores every finding and node again with OVSS
    (vulnmapper.scoring) and rewrites both files atomically. Nothing else in
    the graph changes. No SNMP, no Wazuh; only NVD (``NVD_API_KEY`` optional,
    from the environment) and the OVSS threat feeds and CVE records, cached.
    """
    setup_logging()
    parser = argparse.ArgumentParser(
        prog="vulnmapper.devicecves",
        description="Refresh the CVEs of a graph's network devices from NVD, without a rescan.")
    parser.add_argument("--graph", required=True, metavar="PATH", help="graph.json to refresh")
    parser.add_argument("--vulns", metavar="PATH",
                        help="vulnerabilities.json to update (default: beside the graph)")
    parser.add_argument("--nvd-cache", metavar="PATH",
                        help="NVD answer cache (default: nvd-cache.json beside the graph)")
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET_S, metavar="SECONDS",
                        help="time budget for the NVD lookups (default 180)")
    args = parser.parse_args(argv)

    graph = _load(args.graph)
    if graph is None or not isinstance(graph.get("nodes"), list):
        print(f"vulnmapper.devicecves: cannot read graph {args.graph}", file=sys.stderr)
        return 1

    clock = clock or SystemClock()
    client = NvdClient(transport=transport, clock=clock, budget_s=args.budget)
    cache = Cache(args.nvd_cache or default_path(args.graph), clock)
    result = run_stage(graph, client, cache)

    meta = graph.setdefault("metadata", {})
    meta["warnings"] = [w for w in meta.get("warnings") or []
                        if not (isinstance(w, dict) and w.get("type") in STAGE_WARNINGS)]
    meta["warnings"].extend(result.warnings)
    meta["device_cves"] = {**result.block, "refreshed_at": clock.now().isoformat()}
    vulns_path = args.vulns or vulnfile.default_path(args.graph)
    vulns = update_vulns(vulns_path, result.entries, result.rows, meta.get("scan_time"))

    _, scored = score(graph, vulns, load_targets(targets_path(args.graph)),
                      os.path.dirname(os.path.abspath(cache.path)), clock)
    meta["ovss"] = scored.block
    meta["warnings"] = [w for w in meta["warnings"]
                        if not (isinstance(w, dict) and w.get("type") == WARNING)]
    meta["warnings"].extend(scored.warnings)

    _write_json_atomic(args.graph, graph, indent=2)
    log.info("refreshed device CVEs and OVSS in %s", args.graph)
    vulnfile.write_atomic(vulns_path, vulns)
    log.info("updated device entries in %s", vulns_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
