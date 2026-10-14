"""Each device port's ``state`` for the dashboard's front-panel view:

- ``shutdown``: administratively down;
- ``up``: link up;
- ``link_lost``: no link, but something was plugged in (an LLDP or CDP
  neighbour on it, or link up in the previous scan's graph), kept until the
  port comes back (link_lost in the previous graph and still down);
- ``unused``: anything else.
"""

from __future__ import annotations

from typing import Optional

from ..checklist.evaluate import port_key


def set_port_states(graph: dict, previous: Optional[dict] = None) -> None:
    """Stamp ``state`` on every entry of every node's ``ports``, in place.

    ``previous`` is the graph this scan replaces: a port up there, or already
    link_lost there, is link_lost while it stays down. Without one, a port
    only counts as having lost its link when a neighbour is still listed on it.
    Port names compare in any form ("Fa1/0/1" = "FastEthernet1/0/1"), and a
    neighbour may name the port by its alias.
    """
    was_plugged = {node.get("node_id"): _plugged_before(node)
                   for node in (previous or {}).get("nodes") or []}
    for node in graph.get("nodes") or []:
        if not node.get("ports"):
            continue
        plugged = {port_key(p) for p in node.get("neighbor_ports") or []}
        plugged |= was_plugged.get(node.get("node_id"), set())
        for port in node["ports"]:
            names = {port_key(port["name"])}
            if port.get("alias"):
                names.add(port_key(port["alias"]))
            port["state"] = ("shutdown" if port.get("admin") == "down"
                             else "up" if port.get("oper") == "up"
                             else "link_lost" if names & plugged
                             else "unused")


def _plugged_before(node: dict) -> set:
    """Port keys of a previous-graph node that were up, or already link_lost."""
    keys = {port_key(name) for name, state in (node.get("port_status") or {}).items()
            if state == "up"}
    for port in node.get("ports") or []:
        if port.get("state") == "link_lost":
            keys.add(port_key(port["name"]))
            if port.get("alias"):
                keys.add(port_key(port["alias"]))
    return keys
