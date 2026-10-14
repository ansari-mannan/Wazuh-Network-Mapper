"""Turning the two inputs into graph nodes: a crawled device, a scored Wazuh
endpoint, and a host no agent reports (found in a switch table, an access
point's client list or a neighbour announcement).
"""

from __future__ import annotations

from typing import Optional

from ..network.roles import decode_capabilities, derive_role
from ..schema import (
    DISCOVERY_SNMP_LLDP,
    DISCOVERY_WAZUH,
    KIND_DEVICE,
    KIND_ENDPOINT,
    ROLE_ACCESS_POINT,
    Node,
    device_node_id,
    endpoint_node_id,
    host_node_id,
)


def is_network_equipment(capabilities) -> bool:
    """Whether an LLDP capability bitmap advertises bridge or router."""
    return bool(decode_capabilities(capabilities) & {"bridge", "router"})


def is_end_host(raw: dict) -> bool:
    """A neighbour nobody polled that advertises no bridge or router role.

    That is a host announcing itself (a PC whose chassis id is its hostname,
    say), not network equipment. A device we tried and failed to poll
    ("unreachable") is left alone: it may be a switch we lack credentials for.
    """
    if raw.get("pollable") or raw.get("status") == "unreachable" or raw.get("access_point"):
        return False
    return not is_network_equipment(raw.get("lldp_cap_enabled"))


def device_node(raw: dict) -> Node:
    """A node of the crawl's network document as a device node."""
    chassis_id = raw.get("chassis_id")
    return Node(
        node_id=device_node_id(chassis_id),
        kind=KIND_DEVICE,
        discovery_method=raw.get("discovery_method") or DISCOVERY_SNMP_LLDP,
        ip=raw.get("ip"),
        hostname=raw.get("hostname"),
        vendor=raw.get("vendor"),
        model=raw.get("model"),
        firmware=raw.get("firmware"),
        serial=raw.get("serial"),
        mac=raw.get("mac"),
        status=raw.get("status"),
        role=ROLE_ACCESS_POINT if raw.get("access_point") else derive_role(
            capabilities=raw.get("lldp_cap_enabled"),
            vendor=raw.get("vendor"),
            model=raw.get("model"),
            mac=raw.get("mac") or chassis_id,
            # an end host's fallback role is "host", not "Unknown Network Device"
            kind=KIND_ENDPOINT if is_end_host(raw) else KIND_DEVICE,
        ),
        chassis_id=chassis_id,
        pollable=raw.get("pollable"),
        neighbor_ports=raw.get("neighbor_ports") or [],
        uplink_ports=raw.get("uplink_ports") or [],
        inferred_ports=raw.get("inferred_ports") or None,
        port_status=raw.get("port_status") or {},
        risk_score=raw.get("risk_score"),
        software_family=raw.get("software_family"),
    )


def _max_cvss(top_cves: list) -> Optional[float]:
    return max((c.get("cvss") for c in top_cves if c.get("cvss") is not None), default=None)


def endpoint_node(raw: dict) -> Node:
    """A scored Wazuh endpoint as an endpoint node."""
    top_cves = raw.get("top_cves") or []
    return Node(
        node_id=endpoint_node_id(raw.get("agent_id")),
        kind=KIND_ENDPOINT,
        discovery_method=raw.get("discovery_method") or DISCOVERY_WAZUH,
        ip=raw.get("ip"),
        hostname=raw.get("hostname"),
        vendor=raw.get("vendor"),
        model=raw.get("model"),
        firmware=raw.get("firmware"),
        serial=raw.get("serial"),
        mac=raw.get("mac"),
        status=raw.get("status"),
        agent_id=raw.get("agent_id"),
        risk_score=raw.get("risk_score"),  # the OVSS stage sets it
        max_cvss=_max_cvss(top_cves),
        top_cves=top_cves,
        cve_summary=raw.get("cve_summary"),
        is_wazuh_server=bool(raw.get("is_wazuh_server")),
        unscored_reason=raw.get("unscored_reason"),
    )


_ROLE_FROM_MAC = object()


def discovered_host(key: str, discovery_method: str, *, ip: Optional[str], mac: Optional[str],
                    role=_ROLE_FROM_MAC, **identity) -> Node:
    """A host no agent reports, named ``host:<key>``. Unscored: nothing tells
    us its software. Without a role from LLDP it is a plain "host"."""
    if role is _ROLE_FROM_MAC:
        role = derive_role(mac=mac, kind=KIND_ENDPOINT)
    return Node(
        node_id=host_node_id(key),
        kind=KIND_ENDPOINT,
        discovery_method=discovery_method,
        ip=ip,
        mac=mac,
        status="discovered",
        role=role,
        risk_score=None,
        **identity,
    )
