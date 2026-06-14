"""Assemble the single unified ``{nodes, edges, metadata}`` graph document.

Inputs:
  * ``endpoints`` — the scored endpoint list (``scored_agents.json``).
  * ``network_doc`` — the crawler's output document (nodes + LLDP edges + FDB).

Parenting ladder (per endpoint, stop at the first tier that succeeds; the tier
becomes the edge's ``confidence``):

  Tier 1 — LLDP match. An LLDP-discovered device node whose ``chassis_id`` equals
    an endpoint's MAC *is that endpoint* (it runs an LLDP agent). Merge them: keep
    the endpoint node, delete the phantom device node, and parent the endpoint to
    the switch that reported it, using the switch's local port from that LLDP
    adjacency. Confidence ``lldp``.
  Tier 2 — per-VLAN FDB match (online, non-LLDP hosts). See
    :func:`vulnmapper.linking.fdb_link.resolve_access`. Confidence
    ``resolved`` / ``tiebreak``.
  Tier 3 — IP/subnet fallback (offline hosts / no MAC). Parent by subnet
    ownership; confidence ``subnet_fallback``. If even that fails, the endpoint
    stays unparented with an honest reason.

Every edge also carries ``source_name`` / ``target_name`` (hostname, else IP,
else node_id) for readability, alongside the machine-readable node_ids.

Network nodes may not be CVE-scored yet (a separate NVD stage); their
``risk_score`` defaults to 0 and they merge anyway.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

from ..common.mac import canonical_mac, format_mac
from ..common.schema import (
    DISCOVERY_SNMP_FDB,
    DISCOVERY_SNMP_LLDP,
    DISCOVERY_WAZUH,
    EDGE_ENDPOINT_LINK,
    EDGE_LLDP,
    KIND_DEVICE,
    KIND_ENDPOINT,
    Edge,
    Node,
    device_node_id,
    endpoint_node_id,
    host_node_id,
)
from ..linking.fdb_link import (
    CONF_FDB,
    CONF_LLDP,
    CONF_SUBNET_FALLBACK,
    REASON_ABSENT,
    REASON_NO_MAC,
    REASON_OFFLINE,
    build_mac_table,
    same_subnet,
)
from ..network.roles import derive_role


def _device_node(raw: dict) -> Node:
    """Map a crawler network node into a unified device :class:`Node`."""
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
        role=derive_role(
            capabilities=raw.get("lldp_cap_enabled"),
            vendor=raw.get("vendor"),
            model=raw.get("model"),
            mac=raw.get("mac") or chassis_id,
            kind=KIND_DEVICE,
        ),
        chassis_id=chassis_id,
        pollable=raw.get("pollable"),
        neighbor_ports=raw.get("neighbor_ports") or [],
        uplink_ports=raw.get("uplink_ports") or [],
        port_status=raw.get("port_status") or {},
        risk_score=raw.get("risk_score", 0) or 0,
    )


def _endpoint_node(raw: dict) -> Node:
    """Map a scored endpoint dict into a unified endpoint :class:`Node`."""
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
        risk_score=raw.get("risk_score", 0) or 0,
        top_cves=raw.get("top_cves") or [],
    )


def _lldp_switch_and_port(phantom_chassis: str, raw_edges: list[dict]):
    """Find the switch + its local port that reported ``phantom_chassis``.

    Returns ``(switch_chassis, switch_port)`` or ``(None, None)``. The switch is
    whichever end of the LLDP adjacency *isn't* the phantom, and the switch's
    local port is the ``local_port`` when the phantom is the target, or the
    ``remote_port`` when the phantom is the source.
    """
    for raw in raw_edges:
        src = raw.get("source_chassis_id")
        tgt = raw.get("target_chassis_id")
        if tgt == phantom_chassis:
            return src, raw.get("local_port")
        if src == phantom_chassis:
            return tgt, raw.get("remote_port")
    return None, None


def _subnet_parent(ip: Optional[str], device_nodes: list[Node]) -> Optional[str]:
    """Best-effort subnet parent: a device sharing the endpoint's /24.

    Prefers a pollable device (a real switch/router that owns the segment) over a
    bare discovered node. Returns its node_id, or None.
    """
    match = None
    for dev in device_nodes:
        if same_subnet(dev.ip, ip):
            if dev.pollable:
                return dev.node_id
            match = match or dev.node_id
    return match


def _bfs_device_order(device_ids: list[str], lldp_edges: list[Edge]):
    """Order devices BFS from the seed; return (order, parent_id map)."""
    known = set(device_ids)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in lldp_edges:
        adjacency[edge.source].append(edge.target)
        adjacency[edge.target].append(edge.source)

    order: list[str] = []
    parent: dict[str, Optional[str]] = {}
    visited: set[str] = set()

    for seed in device_ids:  # document order -> seed first, then component roots
        if seed in visited:
            continue
        visited.add(seed)
        parent[seed] = None
        queue = deque([seed])
        while queue:
            current = queue.popleft()
            order.append(current)
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited and neighbor in known:
                    visited.add(neighbor)
                    parent[neighbor] = current
                    queue.append(neighbor)
    return order, parent


def assemble(endpoints: list[dict], network_doc: dict) -> dict:
    """Build the unified graph document from endpoints + the network document."""
    raw_nodes = [n for n in (network_doc.get("nodes") or []) if n.get("chassis_id")]
    raw_edges = network_doc.get("edges") or []

    device_by_chassis = {n["chassis_id"]: _device_node(n) for n in raw_nodes}

    # Capabilities a switch reported for an LLDP-speaking neighbor are keyed by the
    # neighbor's chassis id (== its MAC). An endpoint that speaks LLDP is merged
    # from such a phantom device node (Tier 1), so this lets it inherit a real role
    # (e.g. "station") instead of the generic "host" fallback.
    caps_by_mac: dict[str, str] = {}
    for n in raw_nodes:
        cmac = canonical_mac(n.get("chassis_id"))
        caps = n.get("lldp_cap_enabled")
        if cmac and caps:
            caps_by_mac[cmac] = caps

    endpoint_nodes = [_endpoint_node(e) for e in endpoints]
    endpoints_by_mac = {}
    for ep in endpoint_nodes:
        mac = canonical_mac(ep.mac)
        if mac:
            endpoints_by_mac[mac] = ep
        ep.role = derive_role(
            capabilities=caps_by_mac.get(mac),
            vendor=ep.vendor, model=ep.model, mac=ep.mac, kind=KIND_ENDPOINT,
        )

    # One MAC lookup table built from every device's FDB + ARP, read both for
    # parenting (below) and host discovery (further down) — never walked twice.
    mac_table = build_mac_table(raw_nodes)

    # parent_of: node_id -> (parent_node_id | None, port | None, confidence | None)
    parent_of: dict[str, tuple] = {}
    unparented_reason: dict[str, str] = {}
    enriched_ids: list[str] = []   # endpoints whose mac/port we filled from the table

    # --- TIER 1: merge LLDP phantom device nodes into their endpoints ---
    phantom_chassis: set[str] = set()
    for chassis in list(device_by_chassis):
        cmac = canonical_mac(chassis)
        ep = endpoints_by_mac.get(cmac) if cmac else None
        if ep is None:
            continue
        switch_chassis, switch_port = _lldp_switch_and_port(chassis, raw_edges)
        if switch_chassis is None or switch_chassis not in device_by_chassis:
            continue  # can't identify the reporting switch; leave both nodes
        phantom_chassis.add(chassis)
        parent_of[ep.node_id] = (device_node_id(switch_chassis), switch_port, CONF_LLDP)

    for chassis in phantom_chassis:
        device_by_chassis.pop(chassis, None)

    device_nodes = list(device_by_chassis.values())
    device_node_ids = {n.node_id for n in device_nodes}

    # --- LLDP edges between surviving devices (phantom edges drop out naturally) ---
    lldp_edges: list[Edge] = []
    for raw in raw_edges:
        src = device_node_id(raw.get("source_chassis_id"))
        tgt = device_node_id(raw.get("target_chassis_id"))
        if src in device_node_ids and tgt in device_node_ids:
            lldp_edges.append(Edge(
                source=src, target=tgt, type=EDGE_LLDP,
                local_port=raw.get("local_port"), remote_port=raw.get("remote_port"),
            ))

    # --- TIER 2 (FDB table) + TIER 3 (subnet fallback) for the rest ---
    for ep in endpoint_nodes:
        if ep.node_id in parent_of:
            continue
        mac = canonical_mac(ep.mac)
        online = (ep.status or "").lower() == "active"

        # Tier 2a: known MAC found in the forwarding table.
        fact = mac_table.by_mac.get(mac) if mac else None
        # Tier 2b: Wazuh gave no MAC, but the ARP/FDB table knows this IP — enrich
        # the endpoint's MAC from the table (e.g. an offline host still in the FDB).
        if fact is None and not mac and ep.ip and ep.ip in mac_table.by_ip:
            mac = mac_table.by_ip[ep.ip]
            fact = mac_table.by_mac[mac]
            ep.mac = format_mac(mac)
            enriched_ids.append(ep.node_id)

        if fact is not None:
            parent_of[ep.node_id] = (fact.switch_node_id, fact.port, fact.confidence)
            continue

        gateway = _subnet_parent(ep.ip, device_nodes)
        if gateway:
            parent_of[ep.node_id] = (gateway, None, CONF_SUBNET_FALLBACK)
            continue

        parent_of[ep.node_id] = (None, None, None)
        if not ep.mac:
            unparented_reason[ep.node_id] = REASON_NO_MAC if online else REASON_OFFLINE
        elif not online:
            unparented_reason[ep.node_id] = REASON_OFFLINE
        else:
            unparented_reason[ep.node_id] = REASON_ABSENT

    # --- FDB/ARP HOST DISCOVERY: a table MAC matching no node is a new host ---
    known_macs = {canonical_mac(n.chassis_id) for n in device_nodes}
    known_macs |= {canonical_mac(ep.mac) for ep in endpoint_nodes if ep.mac}
    known_macs |= mac_table.infra_macs
    known_macs.discard(None)

    discovered_nodes: list[Node] = []
    for mac, fact in mac_table.by_mac.items():
        if mac in known_macs:
            continue
        node = Node(
            node_id=host_node_id(format_mac(mac)),
            kind=KIND_ENDPOINT,
            discovery_method=DISCOVERY_SNMP_FDB,
            ip=fact.ip,
            mac=format_mac(mac),
            status="discovered",
            role=derive_role(mac=format_mac(mac), kind=KIND_ENDPOINT),  # -> "host"
            risk_score=None,          # unscored — no Wazuh agent
        )
        discovered_nodes.append(node)
        parent_of[node.node_id] = (fact.switch_node_id, fact.port, CONF_FDB)

    # --- endpoint edges (no remote_port: the host's MAC is not a switch port) ---
    endpoint_edges = [
        Edge(source=ep_id, target=parent, type=EDGE_ENDPOINT_LINK,
             local_port=port, confidence=conf)
        for ep_id, (parent, port, conf) in parent_of.items()
        if parent is not None
    ]
    all_edges = lldp_edges + endpoint_edges

    # --- discovery stamping: devices BFS-first, endpoints after their switch ---
    nodes_by_id = {n.node_id: n for n in device_nodes + endpoint_nodes + discovered_nodes}
    device_order, device_parent = _bfs_device_order(
        [n.node_id for n in device_nodes], lldp_edges
    )

    endpoints_by_parent: dict[Optional[str], list[str]] = defaultdict(list)
    unparented: list[str] = []
    for ep_id, (parent, _port, _conf) in parent_of.items():
        (unparented if parent is None else endpoints_by_parent[parent]).append(ep_id)

    reveal: list[str] = []
    for device_id in device_order:
        reveal.append(device_id)
        reveal.extend(endpoints_by_parent.get(device_id, []))
    reveal.extend(unparented)
    for node_id in nodes_by_id:  # defensive: anything not yet placed
        if node_id not in reveal:
            reveal.append(node_id)

    for order, node_id in enumerate(reveal):
        node = nodes_by_id[node_id]
        node.discovery_order = order
        if node.kind == KIND_DEVICE:
            node.parent_id = device_parent.get(node_id)
        else:
            node.parent_id = parent_of[node_id][0]

    # --- readable edge name lookup ---
    def name_of(node_id: str) -> str:
        node = nodes_by_id.get(node_id)
        if node is None:
            return node_id
        return node.hostname or node.ip or node_id

    def edge_dict(edge: Edge) -> dict:
        out = {
            "source": edge.source,
            "source_name": name_of(edge.source),
            "target": edge.target,
            "target_name": name_of(edge.target),
            "type": edge.type,
        }
        if edge.local_port is not None:
            out["local_port"] = edge.local_port
        if edge.remote_port is not None:
            out["remote_port"] = edge.remote_port
        if edge.confidence is not None:
            out["confidence"] = edge.confidence
        return out

    # --- metadata ----------------------------------------------------------
    confidence_counts: dict[str, int] = defaultdict(int)
    for _ep_id, (_parent, _port, conf) in parent_of.items():
        if conf:
            confidence_counts[conf] += 1

    unreachable = [
        {"node_id": n.node_id, "chassis_id": n.chassis_id, "ip": n.ip, "status": n.status}
        for n in device_nodes
        if n.pollable is False or n.status == "unreachable"
    ]

    metadata = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "network_scan_time": network_doc.get("scan_time"),
        "seed": network_doc.get("seed"),
        "counts": {
            "nodes": len(nodes_by_id),
            "endpoints": len(endpoint_nodes),
            "devices": len(device_nodes),
            "fdb_discovered_hosts": len(discovered_nodes),
            "lldp_edges": len(lldp_edges),
            "endpoint_edges": len(endpoint_edges),
            "unparented_endpoints": len(unparented),
        },
        "confidence": dict(confidence_counts),
        "merged_lldp_endpoints": len(phantom_chassis),
        "fdb_discovered_hosts": len(discovered_nodes),
        "fdb_enriched_nodes": len(enriched_ids),
        "unparented_endpoints": [
            {"node_id": ep_id, "hostname": nodes_by_id[ep_id].hostname,
             "reason": unparented_reason.get(ep_id)}
            for ep_id in unparented
        ],
        "unreachable_boundaries": unreachable,
    }

    ordered_nodes = sorted(nodes_by_id.values(), key=lambda n: n.discovery_order)
    return {
        "nodes": [n.to_dict() for n in ordered_nodes],
        "edges": [edge_dict(e) for e in all_edges],
        "metadata": metadata,
    }
