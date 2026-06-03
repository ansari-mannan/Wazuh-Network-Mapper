"""LLDP topology: walk neighbor tables, correlate to nodes, build edges.

Phase 2 walks each device's LLDP remote table and parses neighbor rows.
Phase 3 correlates each neighbor to a discovered node (by hostname, then MAC)
to form directed edges. Phase 4 collapses the two directions of each physical
link into a single deduplicated edge.
"""

from __future__ import annotations

from typing import Optional

from utils import collapse_whitespace, normalize_mac

# lldpRemTable entry. Rows are indexed by (timeMark, localPortNum, remIndex);
# that index also tells us which LOCAL interface the neighbor was seen on.
LLDP_REM_BASE = "1.0.8802.1.1.2.1.4.1.1"

# Column number (first arc after the table base) -> field name. Confirmed
# against the real lab in new_task.txt.
_COLUMNS = {
    "5": "chassis_id",
    "7": "port_id",
    "8": "port_descr",
    "9": "sys_name",
    "10": "sys_descr",
}


def parse_lldp_rows(rows: list[tuple[str, Optional[str]]]) -> list[dict]:
    """Turn raw ``(oid, value)`` walk output into neighbor records.

    Each OID looks like ``<base>.<column>.<index>`` where ``<index>`` (e.g.
    ``0.3.1``) is the local-port row key. We group cells sharing an index into
    one neighbor.
    """
    prefix = LLDP_REM_BASE.rstrip(".") + "."
    groups: dict[str, dict[str, Optional[str]]] = {}

    for oid, value in rows:
        if not oid.startswith(prefix):
            continue
        remainder = oid[len(prefix):]
        parts = remainder.split(".")
        column = parts[0]
        index = ".".join(parts[1:])
        field = _COLUMNS.get(column)
        if field is None:
            continue  # a column we don't care about
        groups.setdefault(index, {})[field] = value

    neighbors = []
    for index, cells in groups.items():
        neighbors.append(
            {
                "local_port_index": index,
                "chassis_mac": normalize_mac(cells.get("chassis_id")),
                "port_id": cells.get("port_id"),
                "port_descr": cells.get("port_descr"),
                "sys_name": cells.get("sys_name"),
                "sys_descr": collapse_whitespace(cells.get("sys_descr")),
            }
        )
    return neighbors


async def walk_lldp_neighbors(snmp_client, ip: str) -> list[dict]:
    """Walk one device's LLDP remote table and return parsed neighbors.

    A device without LLDP yields an empty list (the walk returns no rows); it
    still exists as a node, it just contributes no edges.
    """
    rows = await snmp_client.walk(ip, LLDP_REM_BASE)
    return parse_lldp_rows(rows)


def _node_id(node: dict) -> str:
    """Stable identifier for a node: hostname if present, else IP."""
    return node.get("hostname") or node["ip"]


def build_edges(nodes: list[dict], neighbors_by_ip: dict[str, list[dict]]) -> list[dict]:
    """Phase 3 — correlate neighbor rows to nodes into directed edges.

    Match priority: neighbor sysName == a node hostname (primary), then
    neighbor chassis MAC == a node MAC (fallback). Unmatched neighbors are kept
    as external endpoints with ``resolved: False`` so no link is lost.
    """
    by_hostname = {n["hostname"]: n for n in nodes if n.get("hostname")}
    by_mac = {n["mac"]: n for n in nodes if n.get("mac")}

    edges = []
    for node in nodes:
        source_id = _node_id(node)
        for nb in neighbors_by_ip.get(node["ip"], []):
            target_node = None
            if nb["sys_name"] and nb["sys_name"] in by_hostname:
                target_node = by_hostname[nb["sys_name"]]
            elif nb["chassis_mac"] and nb["chassis_mac"] in by_mac:
                target_node = by_mac[nb["chassis_mac"]]

            if target_node is not None:
                target_id = _node_id(target_node)
                resolved = True
            else:
                # External neighbor: identify by sysName, then MAC.
                target_id = nb["sys_name"] or nb["chassis_mac"] or "unknown"
                resolved = False

            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "source_port": nb["local_port_index"],
                    "target_port": nb["port_id"] or nb["port_descr"],
                    "resolved": resolved,
                }
            )
    return edges


def _pick_port(candidates: list[Optional[str]]) -> Optional[str]:
    """Choose the most informative port label for an endpoint.

    Prefer a named interface (e.g. "Gi2/0/1", reported by the far end) over a
    bare numeric local index.
    """
    values = [c for c in candidates if c]
    if not values:
        return None
    named = [v for v in values if any(ch.isalpha() for ch in v)]
    return named[0] if named else values[0]


def dedupe_edges(edges: list[dict]) -> list[dict]:
    """Phase 4 — collapse both-direction reports of one link into one edge.

    Key each edge by its sorted endpoint pair so A->B and B->A merge. Keep the
    best port label seen for each endpoint from either direction; the link is
    resolved if either direction resolved it.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for edge in edges:
        key = tuple(sorted((edge["source"], edge["target"])))
        groups.setdefault(key, []).append(edge)

    merged = []
    for (a, b), group in groups.items():
        ports: dict[str, list[Optional[str]]] = {a: [], b: []}
        resolved = False
        for edge in group:
            ports.setdefault(edge["source"], []).append(edge["source_port"])
            ports.setdefault(edge["target"], []).append(edge["target_port"])
            resolved = resolved or edge["resolved"]

        merged.append(
            {
                "source": a,
                "target": b,
                "source_port": _pick_port(ports[a]),
                "target_port": _pick_port(ports[b]),
                "resolved": resolved,
            }
        )
    return merged
