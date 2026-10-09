"""Hosts without a Wazuh agent: label them, and learn what they probably are.

A host is an endpoint-kind node. One with an ``agent_id`` is managed (active
or disconnected alike; the Wazuh server is agent 000); one without came from
a switch's forwarding table, an LLDP or CDP announcement, or an access
point's client list, and is unmanaged: nothing reports its software, so its
vulnerabilities are not known. Network devices are not hosts.

risk_score is not touched.
"""

from __future__ import annotations

from .schema import KIND_ENDPOINT


def label(graph: dict) -> dict:
    """Mark every host managed or unmanaged and add ``metadata.coverage``.
    In place; returns ``graph``."""
    hosts = [n for n in graph.get("nodes") or [] if n.get("kind") == KIND_ENDPOINT]
    for node in hosts:
        node["unmanaged"] = node.get("agent_id") is None
    managed = sum(not n["unmanaged"] for n in hosts)
    graph.setdefault("metadata", {})["coverage"] = {
        "hosts": len(hosts),
        "managed": managed,
        "unmanaged": len(hosts) - managed,
        "managed_share": round(managed / len(hosts), 3) if hosts else None,
    }
    return graph
