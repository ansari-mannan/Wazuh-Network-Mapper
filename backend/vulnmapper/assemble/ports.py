"""Each device port's ``state`` for the dashboard's front-panel view:

- ``shutdown``: administratively down;
- ``up``: link up;
- ``link_lost``: no link, but something was plugged in (an LLDP or CDP
  neighbour on it, or link up in the previous scan's graph);
- ``unused``: anything else.
"""

from __future__ import annotations

from typing import Optional

from ..checklist.evaluate import port_key


def set_port_states(graph: dict, previous: Optional[dict] = None) -> None:
    """Stamp ``state`` on every entry of every node's ``ports``, in place.

    ``previous`` is the graph this scan replaces; without one, a port only
    counts as having lost its link when a neighbour is still listed on it.
    Port names compare in any form ("Fa1/0/1" = "FastEthernet1/0/1"), and a
    neighbour may name the port by its alias.
    """
    was_up = {node.get("node_id"): {port_key(name) for name, state
                                    in (node.get("port_status") or {}).items() if state == "up"}
              for node in (previous or {}).get("nodes") or []}
    for node in graph.get("nodes") or []:
        if not node.get("ports"):
            continue
        plugged = {port_key(p) for p in node.get("neighbor_ports") or []}
        plugged |= was_up.get(node.get("node_id"), set())
        for port in node["ports"]:
            names = {port_key(port["name"])}
            if port.get("alias"):
                names.add(port_key(port["alias"]))
            port["state"] = ("shutdown" if port.get("admin") == "down"
                             else "up" if port.get("oper") == "up"
                             else "link_lost" if names & plugged
                             else "unused")
