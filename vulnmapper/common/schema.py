"""The one shared graph schema: Node, Edge, CVE — and the ``node_id`` helpers.

Every node carries exactly one stable, unique ``node_id`` that edges reference.
We never key on hostname or IP (both are soft and collide). Instead:

  * endpoints  -> ``endpoint:<agent_id>``   (the Wazuh agent id; hard + unique)
  * devices    -> ``device:<chassis_id>``   (the LLDP/SNMP chassis id)

The ``endpoint:`` / ``device:`` prefixes guarantee the two id spaces never
collide and make a node's kind obvious at a glance.

The base node schema shared by both worlds is::

    {ip, hostname, vendor, model, firmware, serial, mac, discovery_method, status}

Endpoints add ``agent_id``, ``risk_score`` and ``top_cves``; devices add
``chassis_id``, ``pollable``, ``uplink_ports`` and (optionally) ``fdb``. The
assembler additionally stamps ``node_id``, ``kind``, ``discovery_order`` and
``parent_id`` so the frontend can replay discovery as a growing graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# ---- node kinds + id namespaces -------------------------------------------

KIND_ENDPOINT = "endpoint"
KIND_DEVICE = "device"

# discovery_method values stamped by each source.
DISCOVERY_WAZUH = "wazuh"
DISCOVERY_SNMP_LLDP = "snmp_lldp"

# edge relationship types.
EDGE_LLDP = "lldp"                 # device <-> device adjacency (LLDP)
EDGE_ENDPOINT_LINK = "endpoint_link"  # endpoint -> switch access port


def endpoint_node_id(agent_id: Any) -> str:
    """Stable node id for an endpoint, from its Wazuh agent id."""
    return f"endpoint:{agent_id}"


def device_node_id(chassis_id: Any) -> str:
    """Stable node id for a network device, from its LLDP/SNMP chassis id."""
    return f"device:{chassis_id}"


def host_node_id(mac: Any) -> str:
    """Stable node id for a host discovered only from FDB/ARP (no agent, no LLDP)."""
    return f"host:{mac}"


# discovery_method for a host reconstructed purely from switch/router tables.
DISCOVERY_SNMP_FDB = "snmp_fdb"


@dataclass
class CVE:
    """One vulnerability finding attached to an endpoint node."""

    cve: Optional[str] = None
    cvss: Optional[float] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "cvss": self.cvss,
            "cvss_version": self.cvss_version,
            "severity": self.severity,
            "package": self.package,
            "version": self.version,
            "description": self.description,
        }


@dataclass
class Edge:
    """A graph edge referencing nodes by ``node_id`` (never hostname/IP).

    ``type`` is :data:`EDGE_LLDP` for an inter-device adjacency or
    :data:`EDGE_ENDPOINT_LINK` for an endpoint hanging off a switch access port.
    For an endpoint link, ``local_port`` is the switch access port and
    ``confidence`` records how certain the placement is
    (``resolved`` / ``tiebreak`` / ``fallback``).
    """

    source: str            # node_id
    target: str            # node_id
    type: str
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    confidence: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "source": self.source,
            "target": self.target,
            "type": self.type,
        }
        if self.local_port is not None:
            out["local_port"] = self.local_port
        if self.remote_port is not None:
            out["remote_port"] = self.remote_port
        if self.confidence is not None:
            out["confidence"] = self.confidence
        return out


@dataclass
class Node:
    """A unified graph node — an endpoint or a network device.

    The dataclass is the superset of both worlds' fields; a field that does not
    apply to a given kind stays ``None`` / its default. ``to_dict`` emits a
    stable shape with ``node_id`` first.
    """

    node_id: str
    kind: str
    discovery_method: str
    # ---- shared base schema ----
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    serial: Optional[str] = None
    mac: Optional[str] = None
    status: Optional[str] = None
    # ``role`` is what the node IS (l3-switch / l2-switch / router / access-point
    # / phone / station / host / "Unknown Network Device"), derived purely from
    # the LLDP capability bitmap — no vendor/model guessing. Distinct from
    # ``kind`` (which records which discovery track found it).
    role: Optional[str] = None
    # ---- endpoint extras ----
    agent_id: Optional[str] = None
    risk_score: float = 0
    # Highest CVSS across ``top_cves`` (null when unscored / no CVEs). Distinct
    # from ``risk_score``, which remains the field of record for ranking and edge
    # weights; ``max_cvss`` is exposed for consumers that key on raw CVSS.
    max_cvss: Optional[float] = None
    top_cves: list = field(default_factory=list)
    # True when this endpoint's IP collides with a currently-active endpoint and
    # its own status is disconnected (a stale Wazuh agent — IP reassigned).
    stale: bool = False
    # ---- device extras ----
    chassis_id: Optional[str] = None
    pollable: Optional[bool] = None
    neighbor_ports: Optional[list] = None
    uplink_ports: Optional[list] = None
    port_status: Optional[dict] = None
    fdb: Optional[list] = None
    # ---- discovery stamping (set by the assembler) ----
    discovery_order: Optional[int] = None
    parent_id: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "node_id": self.node_id,
            "kind": self.kind,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "mac": self.mac,
            "discovery_method": self.discovery_method,
            "status": self.status,
            "role": self.role,
            "risk_score": self.risk_score,
            "max_cvss": self.max_cvss,
            "discovery_order": self.discovery_order,
            "parent_id": self.parent_id,
        }
        if self.kind == KIND_ENDPOINT:
            out["agent_id"] = self.agent_id
            out["stale"] = self.stale
            out["top_cves"] = self.top_cves
        else:
            out["chassis_id"] = self.chassis_id
            out["pollable"] = self.pollable
            if self.neighbor_ports is not None:
                out["neighbor_ports"] = self.neighbor_ports
            if self.uplink_ports is not None:
                out["uplink_ports"] = self.uplink_ports
            if self.port_status is not None:
                out["port_status"] = self.port_status
        return out
