"""Assemble the final node/edge document and write it to stdout (only).

The Node.js plugin layer reads this process's stdout to get the result, so a
single valid JSON document is the entire stdout output — every diagnostic goes
to stderr. Even an empty crawl emits a well-formed document so the downstream
graph builder always receives parseable JSON.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Optional

from .models import Device, Link


def _dedupe_edges(links: list[Link]) -> list[dict]:
    """Collapse the two directions of each physical link into one edge.

    The same cable is reported from both ends (A lists B as a neighbor and B
    lists A). Keying on the *unordered* chassis-id pair merges them; we keep the
    best port label seen for each endpoint from either direction.
    """
    merged: dict[tuple[str, str], dict] = {}
    for link in links:
        a, b = link.source_chassis_id, link.target_chassis_id
        # Canonical orientation: source = the smaller chassis id.
        if a <= b:
            key = (a, b)
            local, remote = link.local_port, link.remote_port
        else:
            key = (b, a)
            local, remote = link.remote_port, link.local_port

        edge = merged.get(key)
        if edge is None:
            merged[key] = {
                "source_chassis_id": key[0],
                "target_chassis_id": key[1],
                "local_port": local,
                "remote_port": remote,
            }
        else:
            # Fill any port label still missing from the reverse direction.
            edge["local_port"] = edge["local_port"] or local
            edge["remote_port"] = edge["remote_port"] or remote

    return list(merged.values())


def build_document(
    devices: list[Device], links: list[Link], *, pollable_only: bool = False
) -> dict:
    """Build the output document (nodes + deduplicated edges).

    When ``pollable_only`` is set, every node that could not be polled
    (no working credential or no usable management address) is dropped, along
    with any edge that touches one — leaving only the actual SNMP-polled
    infrastructure backbone.
    """
    if pollable_only:
        devices = [d for d in devices if d.pollable]
        keep = {d.chassis_id for d in devices}
        links = [
            link
            for link in links
            if link.source_chassis_id in keep and link.target_chassis_id in keep
        ]

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "discovery_method": "snmp_lldp",
        "nodes": [d.to_node() for d in devices],
        "edges": _dedupe_edges(links),
    }


def emit(document: dict) -> None:
    """Write the document as JSON to stdout — and nothing else goes there."""
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.stdout.flush()


def write(document: dict, path: str) -> None:
    """Write the document as UTF-8 JSON to ``path`` (no BOM, LF-terminated).

    Used when the tool writes the result file itself instead of relying on a
    shell redirect — which on PowerShell would otherwise produce UTF-16+BOM that
    a downstream JSON parser can choke on.
    """
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, indent=2)
        fh.write("\n")
