#!/usr/bin/env python3
"""Developer helper: put configuration-check results from captures into a graph.

The sample graph (data/graph.json) was written before the checklist existed
and the lab cannot be rescanned from here. This reads the raw SNMP captures
of the lab devices (``scripts/captures.py``), runs them through the same
collection and evaluation code the pipeline uses, and writes the results onto
the matching device nodes. It is not a scan: nothing touches the network, and
``metadata.checklist.source`` says where the data came from.

A device is matched by its sysName in the capture against the node's
hostname. Device nodes without a capture get no checklist; nothing else in
the graph changes.

The captures do not say which credential the scan used, so its SNMP version
is given on the command line; whether that credential is a factory name is
not known, so the default-community check stays "not checked".

    python3 scripts/checklist_sample_graph.py ~/dev/captures ../data/graph.json \\
        --snmp-version v2c --source "captures 2026-10-08"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from captures import DEVICES, read_device  # noqa: E402
from vulnmapper.checklist import tables as t  # noqa: E402
from vulnmapper.checklist.collect import collect_config  # noqa: E402
from vulnmapper.checklist.stage import run_stage  # noqa: E402


class CaptureClient:
    """Answers the collector's reads from captured rows, as SnmpClient would."""

    def __init__(self, rows: list, version: str) -> None:
        self.rows = rows
        self.version = version

    def credential_summary(self, ip):
        return {"version": self.version, "default_name": None}

    def is_v2c(self, ip):
        return self.version == "v2c"

    async def get_many(self, ip, oids):
        values = dict(self.rows)
        return {o: values[o] for o in oids if o in values}

    async def walk(self, ip, base):
        return [(o, v) for o, v in self.rows if o.startswith(base + ".")]

    async def walk_vlan_context(self, ip, base, vlan):
        return []      # per-VLAN contexts were not captured

    async def answers_to_community(self, ip, community, oid, timeout):
        raise RuntimeError("the sample is built from captures; there is no probe")


def _short(name) -> str:
    return str(name or "").split(".")[0].lower()


def apply(graph: dict, captures: str, version: str, source: str) -> dict:
    """Evaluate every captured device found in ``graph``; ``{hostname: device}``."""
    by_host = {_short(n.get("hostname")): n for n in graph["nodes"] if n.get("kind") == "device"}
    network_nodes, matched = [], {}
    for device in DEVICES:
        rows = read_device(captures, device)
        sys_name = dict(rows).get(t.SYS_NAME)
        node = by_host.get(_short(sys_name))
        if node is None:
            print(f"{device}: sysName {sys_name!r} is not in the graph; skipped")
            continue
        config = asyncio.run(collect_config(CaptureClient(rows, version), node.get("ip"),
                                            node.get("vendor")))
        network_nodes.append({"chassis_id": node["chassis_id"], "config_data": config})
        matched[node["hostname"]] = device

    # Only the matched devices are evaluated: the others keep no checklist. The
    # hosts stay in, since the VLANs they were learned on are VLANs in use.
    keep = {n["chassis_id"] for n in network_nodes}
    subset = {"nodes": [n for n in graph["nodes"]
                        if n.get("chassis_id") in keep or n.get("kind") != "device"]}
    stage = run_stage(subset, {"nodes": network_nodes}, False, source=source)
    graph["metadata"]["checklist"] = stage.block
    graph["metadata"].setdefault("warnings", []).extend(stage.warnings)
    return matched


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("captures", help="folder with <device>-<table>.txt captures")
    parser.add_argument("graph", help="graph.json to update in place")
    parser.add_argument("--snmp-version", required=True, choices=("v2c", "v3"),
                        help="the SNMP version of the credential the scan used")
    parser.add_argument("--source", required=True,
                        help='recorded as metadata.checklist.source, e.g. "captures 2026-10-08"')
    args = parser.parse_args(argv)

    with open(args.graph, encoding="utf-8") as fh:
        graph = json.load(fh)
    matched = apply(graph, os.path.expanduser(args.captures), args.snmp_version, args.source)
    with open(args.graph, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2)
        fh.write("\n")
    for node in graph["nodes"]:
        if node.get("kind") == "device":
            summary = node.get("config_summary")
            print(f"  {node['hostname']:<26} "
                  + (f"{matched[node['hostname']]:<3} {summary['results']} {summary['findings']}"
                     if summary else "no checklist"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
