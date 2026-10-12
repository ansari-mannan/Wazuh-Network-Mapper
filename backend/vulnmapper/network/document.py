"""The network document a crawl produces: ``{scan_time, discovery_method,
nodes, edges}``, read by the assembler or written out by the network CLI.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from .model import Device, Link


def _dedupe_edges(links: list[Link]) -> list[dict]:
    """One edge per cable: A lists B and B lists A, so links are keyed on the
    unordered chassis-id pair, keeping any port name either end reported."""
    merged: dict[tuple[str, str], dict] = {}
    protocols: dict[tuple[str, str], set] = {}
    for link in links:
        a, b = link.source_chassis_id, link.target_chassis_id
        # the smaller chassis id is always the source
        if a <= b:
            key, local, remote = (a, b), link.local_port, link.remote_port
        else:
            key, local, remote = (b, a), link.remote_port, link.local_port

        protocols.setdefault(key, set()).add(link.protocol)
        edge = merged.get(key)
        if edge is None:
            merged[key] = {"source_chassis_id": key[0], "target_chassis_id": key[1],
                           "local_port": local, "remote_port": remote}
        else:
            edge["local_port"] = edge["local_port"] or local
            edge["remote_port"] = edge["remote_port"] or remote

    # Only a link no LLDP table reported says which protocol found it.
    for key, edge in merged.items():
        if "lldp" not in protocols[key]:
            edge["protocol"] = sorted(protocols[key])[0]
    return list(merged.values())


def build_document(devices: list[Device], links: list[Link], *,
                   pollable_only: bool = False) -> dict:
    """``pollable_only`` keeps just the polled backbone: every device that was
    not polled is dropped, with any edge touching it."""
    if pollable_only:
        devices = [d for d in devices if d.pollable]
        keep = {d.chassis_id for d in devices}
        links = [link for link in links
                 if link.source_chassis_id in keep and link.target_chassis_id in keep]

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "discovery_method": "snmp_lldp",
        "nodes": [d.to_node() for d in devices],
        "edges": _dedupe_edges(links),
    }


def merge_documents(base: dict, extra: dict) -> dict:
    """``base`` plus what ``extra`` adds.

    A device in both keeps its ``base`` node unless only ``extra`` polled it
    (``base`` knew it from a neighbour's table). A link already in ``base``
    keeps its ``base`` edge.
    """
    nodes = {n["chassis_id"]: n for n in base.get("nodes") or []}
    for node in extra.get("nodes") or []:
        old = nodes.get(node["chassis_id"])
        if old is None or (node.get("pollable") and not old.get("pollable")):
            nodes[node["chassis_id"]] = node

    def pair(edge):
        return frozenset((edge["source_chassis_id"], edge["target_chassis_id"]))

    linked = {pair(e) for e in base.get("edges") or []}
    edges = list(base.get("edges") or []) + [e for e in extra.get("edges") or []
                                             if pair(e) not in linked]
    return dict(base, nodes=list(nodes.values()), edges=edges)


def emit(document: dict) -> None:
    """The document on stdout, and nothing else ever goes there."""
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.stdout.flush()


def write(document: dict, path: str) -> None:
    """The document as UTF-8 with LF endings. Writing the file ourselves avoids
    the UTF-16 with a BOM that a PowerShell ``>`` redirect would produce."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, indent=2)
        fh.write("\n")
