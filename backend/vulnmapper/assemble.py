"""Merge endpoints + network discovery into one unified graph document.

Consolidates the former ``assemble/merge.py`` and ``linking/fdb_link.py`` — the
linker is only ever used by the assembler, so they belong together:

  * MAC forwarding-table indexing — :class:`SwitchFdb` / :class:`HostFact` /
    :class:`MacTable` and :func:`build_mac_table` (the FDB/ARP lookup the
    parenting ladder and host discovery both read).
  * The assembly procedure — produces ``{nodes, edges, metadata}`` keyed by
    ``node_id`` and stamped with ``discovery_order`` / ``parent_id``.

Public surface: :func:`assemble` (the pipeline + tests call it) and the
:class:`GraphAssembler` wrapper it delegates to.

Parenting ladder (per endpoint, first tier that succeeds wins; the tier becomes
the edge ``confidence``):
  Tier 1 — LLDP match (merge the phantom device node into the endpoint).
  Tier 2 — per-VLAN FDB match (:func:`build_mac_table`).
  Tier 3 — IP/subnet fallback (:func:`same_subnet`), active endpoints only, else
  unparented with reason.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .schema import (
    DISCOVERY_SNMP_FDB,
    DISCOVERY_SNMP_LLDP,
    DISCOVERY_WAZUH,
    EDGE_ENDPOINT_LINK,
    EDGE_LLDP,
    KIND_DEVICE,
    KIND_ENDPOINT,
    Edge,
    Node,
    canonical_mac,
    device_node_id,
    endpoint_node_id,
    format_mac,
    host_node_id,
)
from .network.roles import decode_capabilities, derive_role


# ===========================================================================
# FDB-based access-port resolution (was linking/fdb_link.py)
# ===========================================================================

# Confidence levels stamped on an endpoint -> switch edge (one per ladder tier).
CONF_LLDP = "lldp"                       # Tier 1: exact LLDP adjacency
CONF_RESOLVED = "resolved"               # Tier 2: single FDB access-port survivor
CONF_TIEBREAK = "tiebreak"               # Tier 2: several survivors, fewest-MAC wins
CONF_SUBNET_FALLBACK = "subnet_fallback"  # Tier 3: parented by subnet, not L2
CONF_FDB = "fdb"                          # FDB/ARP-discovered host (no agent, no LLDP)
CONF_WIFI = "wifi"                        # in an access point's association table

# discovery_method of a host that announced itself over LLDP (no agent, not
# network equipment); emitted like an FDB-discovered host.
DISCOVERY_LLDP_HOST = "lldp"
# ...and one known only from a neighbour's CDP table.
DISCOVERY_CDP_HOST = "cdp"

# The crawler marks a wireless access point (association MIB, else its name).
ROLE_ACCESS_POINT = "access-point"
# discovery_method of a client only an access point's association table knows.
DISCOVERY_WIFI_HOST = "snmp_wifi"

# Reasons recorded for an endpoint that could not be placed.
REASON_NO_MAC = "no_endpoint_mac"
REASON_ABSENT = "mac_absent_from_all_fdb"
REASON_OFFLINE = "host_offline_no_l2_evidence"


@dataclass
class SwitchFdb:
    """Pre-indexed FDB view of one switch, ready for fast endpoint lookup."""

    node_id: str
    chassis_id: str
    ip: Optional[str]
    uplink_ports: set
    mac_to_ports: dict          # canonical_mac -> list[(port, vlan)]
    port_mac_count: dict        # port -> distinct MAC count on that port


def index_switches(network_nodes: list[dict]) -> list[SwitchFdb]:
    """Build a :class:`SwitchFdb` per network node that carries an FDB."""
    switches: list[SwitchFdb] = []
    for node in network_nodes:
        chassis_id = node.get("chassis_id")
        if chassis_id is None:
            continue

        mac_to_ports: dict[str, list] = {}
        port_macs: dict[str, set] = {}
        for entry in node.get("fdb") or []:
            mac = canonical_mac(entry.get("mac"))
            port = entry.get("port")
            if mac is None or port is None:
                continue
            vlan = entry.get("vlan")
            pairs = mac_to_ports.setdefault(mac, [])
            if (port, vlan) not in pairs:
                pairs.append((port, vlan))
            port_macs.setdefault(port, set()).add(mac)

        switches.append(SwitchFdb(
            node_id=device_node_id(chassis_id),
            chassis_id=chassis_id,
            ip=node.get("ip"),
            uplink_ports=set(node.get("uplink_ports") or []),
            mac_to_ports=mac_to_ports,
            port_mac_count={p: len(macs) for p, macs in port_macs.items()},
        ))
    return switches


@dataclass
class HostFact:
    """One row of the unified MAC lookup table: where a MAC lives on the fabric."""

    mac: str                    # canonical
    ip: Optional[str]           # from ARP, or None (seen at L2, not recently routed)
    switch_node_id: str
    port: str                   # human port name (the access port)
    vlan: Optional[int]
    confidence: str             # resolved | tiebreak (placement quality)


@dataclass
class MacTable:
    """``mac -> HostFact``, plus an IP index and the infra-MAC exclusion set.

    Built once per assemble and read two ways: parenting (a MAC matching an
    existing node attaches it) and discovery (a MAC matching nothing becomes a
    new host). ``by_ip`` lets an endpoint whose Wazuh MAC is null match by IP.
    ``arp_by_ip`` is every ARP entry (``ip -> mac``), FDB or not; it is only
    trusted when an LLDP announcement of that MAC corroborates it.
    ``infra_macs`` are the polling devices' own interface/SVI/chassis MACs, which
    are excluded so a router's gateway MACs never become phantom hosts.
    """

    by_mac: dict
    by_ip: dict
    infra_macs: set
    arp_by_ip: dict = field(default_factory=dict)


def _infra_macs(network_nodes: list[dict]) -> set:
    """The set of infrastructure MACs to exclude from host discovery.

    Every device's own interface MACs (ifPhysAddress) plus the chassis/base MAC
    of each *pollable* device. Endpoint/host MACs are deliberately NOT here, so
    they still resolve through the table for parenting.
    """
    macs: set = set()
    for node in network_nodes:
        for raw in node.get("own_macs") or []:
            mac = canonical_mac(raw)
            if mac:
                macs.add(mac)
        if node.get("pollable"):
            for raw in (node.get("chassis_id"), node.get("mac")):
                mac = canonical_mac(raw)
                if mac:
                    macs.add(mac)
    return macs


def build_mac_table(network_nodes: list[dict]) -> MacTable:
    """Build the single MAC lookup table from every device's FDB + ARP.

    For each switch, every FDB MAC that is not the device's own and not on an
    uplink/trunk port is a locally-attached candidate ``(switch, port, vlan)``.
    A MAC seen on several access ports is disambiguated by fewest-MACs-on-port
    (access vs trunk). IPs are joined in from the merged ARP tables by MAC.
    """
    switches = index_switches(network_nodes)
    infra_macs = _infra_macs(network_nodes)

    arp_ip: dict[str, str] = {}
    for node in network_nodes:
        for raw_mac, ip in (node.get("arp") or {}).items():
            mac = canonical_mac(raw_mac)
            if mac and ip:
                arp_ip[mac] = ip

    candidates: dict[str, list] = defaultdict(list)
    for sw in switches:
        for mac, pairs in sw.mac_to_ports.items():
            if mac in infra_macs:
                continue
            for port, vlan in pairs:
                if port in sw.uplink_ports:   # transit across a trunk, not a host
                    continue
                candidates[mac].append((sw.node_id, port, vlan, sw.port_mac_count.get(port, 0)))

    by_mac: dict[str, HostFact] = {}
    for mac, lst in candidates.items():
        if len(lst) == 1:
            node_id, port, vlan, _ = lst[0]
            confidence = CONF_RESOLVED
        else:
            node_id, port, vlan, _ = min(lst, key=lambda c: (c[3], c[0], c[1]))
            confidence = CONF_TIEBREAK
        by_mac[mac] = HostFact(mac, arp_ip.get(mac), node_id, port, vlan, confidence)

    by_ip = {fact.ip: mac for mac, fact in by_mac.items() if fact.ip}
    arp_by_ip = {ip: mac for mac, ip in arp_ip.items()}
    return MacTable(by_mac=by_mac, by_ip=by_ip, infra_macs=infra_macs, arp_by_ip=arp_by_ip)


def same_subnet(ip_a: Optional[str], ip_b: Optional[str], prefix: int = 24) -> bool:
    """True if two IPv4 addresses share the same ``/prefix`` network."""
    if not ip_a or not ip_b:
        return False
    try:
        net = ipaddress.ip_network(f"{ip_a}/{prefix}", strict=False)
        return ipaddress.ip_address(ip_b) in net
    except ValueError:
        return False


# ===========================================================================
# The assembly procedure (was assemble/merge.py)
# ===========================================================================

def _is_network_equipment(capabilities) -> bool:
    """True when an LLDP capability map advertises bridge or router."""
    return bool(decode_capabilities(capabilities) & {"bridge", "router"})


def _is_end_host(raw: dict) -> bool:
    """A non-pollable LLDP neighbour advertising no bridge/router capability.

    That is a host announcing itself (e.g. a PC whose chassis id is its
    hostname), not network equipment. A device we tried and failed to poll
    (status "unreachable") is left alone: it may be a switch we lack
    credentials for.
    """
    if raw.get("pollable") or raw.get("status") == "unreachable" or raw.get("access_point"):
        return False
    return not _is_network_equipment(raw.get("lldp_cap_enabled"))


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
        role=ROLE_ACCESS_POINT if raw.get("access_point") else derive_role(
            capabilities=raw.get("lldp_cap_enabled"),
            vendor=raw.get("vendor"),
            model=raw.get("model"),
            mac=raw.get("mac") or chassis_id,
            # an end host's fallback role is "host", not "Unknown Network Device"
            kind=KIND_ENDPOINT if _is_end_host(raw) else KIND_DEVICE,
        ),
        chassis_id=chassis_id,
        pollable=raw.get("pollable"),
        neighbor_ports=raw.get("neighbor_ports") or [],
        uplink_ports=raw.get("uplink_ports") or [],
        port_status=raw.get("port_status") or {},
        risk_score=raw.get("risk_score", 0) or 0,
        software_family=raw.get("software_family"),
    )


def _max_cvss(top_cves: list) -> Optional[float]:
    """Highest CVSS across an endpoint's CVEs, or None when there are none."""
    return max((c.get("cvss") for c in top_cves if c.get("cvss") is not None),
               default=None)


def _endpoint_node(raw: dict) -> Node:
    """Map a scored endpoint dict into a unified endpoint :class:`Node`."""
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
        risk_score=raw.get("risk_score", 0),  # None = unscored, kept as null
        max_cvss=_max_cvss(top_cves),
        top_cves=top_cves,
        cve_summary=raw.get("cve_summary"),
        is_wazuh_server=bool(raw.get("is_wazuh_server")),
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


def _build_graph(endpoints: list[dict], network_doc: dict) -> dict:
    """Build the unified graph document from endpoints + the network document."""
    raw_nodes = [n for n in (network_doc.get("nodes") or []) if n.get("chassis_id")]
    raw_edges = network_doc.get("edges") or []

    device_by_chassis = {n["chassis_id"]: _device_node(n) for n in raw_nodes}
    caps_by_chassis = {n["chassis_id"]: n.get("lldp_cap_enabled") for n in raw_nodes}

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

    # --- duplicate-IP / stale-agent detection (Issue 3) ---
    # Endpoints are keyed on MAC (correct), so two Wazuh agents can legitimately
    # share an IP after a reassignment/host rename. We never merge them; we record
    # the collision and mark the disconnected side `stale` so attack-path rankings
    # can separate a live foothold from a dead one. A stale node stays in the graph
    # (still shown, unparented, dimmed by the UI) with its risk intact.
    duplicate_ip_warnings: list[dict] = []
    endpoints_by_ip: dict[str, list[Node]] = defaultdict(list)
    for ep in endpoint_nodes:
        if ep.ip:
            endpoints_by_ip[ep.ip].append(ep)
    for ip, group in sorted(endpoints_by_ip.items()):
        if len(group) < 2:
            continue
        has_active = any((ep.status or "").lower() == "active" for ep in group)
        for ep in group:
            if has_active and (ep.status or "").lower() == "disconnected":
                ep.stale = True
        duplicate_ip_warnings.append({
            "type": "duplicate_ip",
            "ip": ip,
            "nodes": [
                {"node_id": ep.node_id, "hostname": ep.hostname,
                 "status": ep.status, "stale": ep.stale}
                for ep in group
            ],
        })

    # One MAC lookup table built from every device's FDB + ARP, read both for
    # parenting (below) and host discovery (further down) — never walked twice.
    mac_table = build_mac_table(raw_nodes)

    # parent_of: node_id -> (parent_node_id | None, port | None, confidence | None)
    parent_of: dict[str, tuple] = {}
    unparented_reason: dict[str, str] = {}
    enriched_ids: list[str] = []   # endpoints whose mac/port we filled from the table

    # A device whose MAC is an agent's is the same machine. An ordinary machine
    # (e.g. a server that answers SNMP) is merged into its endpoint; network
    # equipment running an agent (bridge/router capability) is kept, since
    # removing it would break the topology around it, and the pair is reported.
    agent_on_device_warnings: list[dict] = []

    def agent_on_network_device(chassis: str, ep: Node) -> None:
        device = device_by_chassis[chassis]
        agent_on_device_warnings.append({
            "type": "agent_on_network_device",
            "mac": format_mac(chassis),
            "nodes": [{"node_id": n.node_id, "hostname": n.hostname, "kind": n.kind}
                      for n in (device, ep)],
        })

    # --- TIER 1: merge LLDP phantom device nodes into their endpoints ---
    phantom_chassis: set[str] = set()
    for chassis in list(device_by_chassis):
        cmac = canonical_mac(chassis)
        ep = endpoints_by_mac.get(cmac) if cmac else None
        if ep is None:
            continue
        if _is_network_equipment(caps_by_chassis.get(chassis)):
            agent_on_network_device(chassis, ep)
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
                protocol=raw.get("protocol"),
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

        # Tier 3 only for a host that is online: sharing a /24 is not evidence
        # that an offline machine hangs off that device.
        gateway = _subnet_parent(ep.ip, device_nodes) if online else None
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

    # --- TIER 1 AGAIN: phantoms whose endpoint MAC was only learned above ---
    # Tier 1 ran before the switch tables filled in MACs Wazuh did not report,
    # so a phantom for such an endpoint survived it. An endpoint still without a
    # MAC may take one from ARP alone, but only when an LLDP phantom announcing
    # that MAC corroborates it (a bare ARP entry may be stale), the MAC is not an
    # infrastructure MAC, and the announcer advertises no bridge/router role.
    phantom_by_mac = {canonical_mac(c): c for c in device_by_chassis if canonical_mac(c)}
    warned = {w["mac"] for w in agent_on_device_warnings}
    late_phantoms: set[str] = set()
    for ep in endpoint_nodes:
        mac = canonical_mac(ep.mac)
        if mac is None and ep.ip:
            arp_mac = mac_table.arp_by_ip.get(ep.ip)
            announcer = phantom_by_mac.get(arp_mac) if arp_mac else None
            if (announcer and arp_mac not in mac_table.infra_macs
                    and not _is_network_equipment(caps_by_chassis.get(announcer))):
                mac = arp_mac
        chassis = phantom_by_mac.get(mac) if mac else None
        if chassis is None or chassis in late_phantoms:
            continue
        if _is_network_equipment(caps_by_chassis.get(chassis)):
            if ep.mac and format_mac(chassis) not in warned:
                agent_on_network_device(chassis, ep)
                warned.add(format_mac(chassis))
            continue
        switch_chassis, switch_port = _lldp_switch_and_port(chassis, raw_edges)
        if switch_chassis is None or switch_chassis not in device_by_chassis \
                or switch_chassis in late_phantoms:
            continue  # can't identify the reporting switch; leave both nodes
        late_phantoms.add(chassis)
        if ep.mac is None:
            ep.mac = format_mac(mac)
        ep.role = derive_role(capabilities=caps_by_mac.get(mac), vendor=ep.vendor,
                              model=ep.model, mac=ep.mac, kind=KIND_ENDPOINT)
        # An LLDP announcement is direct evidence: it wins unless the tables
        # already placed the endpoint on that very switch port.
        lldp_parent = (device_node_id(switch_chassis), switch_port, CONF_LLDP)
        parent, port, _conf = parent_of.get(ep.node_id, (None, None, None))
        if (parent, port) != lldp_parent[:2]:
            parent_of[ep.node_id] = lldp_parent
            unparented_reason.pop(ep.node_id, None)

    def retire_devices(chassis_ids) -> None:
        """Remove device nodes (and their LLDP edges) that became other nodes.

        A subnet-fallback parent can't be a node that no longer exists, so an
        endpoint parented on one is re-pointed (or left unparented with a reason).
        """
        ids = {device_node_id(c) for c in chassis_ids}
        if not ids:
            return
        for chassis in chassis_ids:
            device_by_chassis.pop(chassis, None)
        device_nodes[:] = [n for n in device_nodes if n.node_id not in ids]
        device_node_ids.difference_update(ids)
        lldp_edges[:] = [e for e in lldp_edges if e.source not in ids and e.target not in ids]
        for ep_id, (parent, _port, _conf) in list(parent_of.items()):
            if parent in ids:
                ep = next(n for n in endpoint_nodes if n.node_id == ep_id)
                online = (ep.status or "").lower() == "active"
                gateway = _subnet_parent(ep.ip, device_nodes) if online else None
                parent_of[ep_id] = (gateway, None, CONF_SUBNET_FALLBACK if gateway else None)
                if gateway is None:
                    unparented_reason[ep_id] = (REASON_ABSENT if ep.mac and online
                                                else REASON_NO_MAC if online
                                                else REASON_OFFLINE)

    phantom_chassis |= late_phantoms
    retire_devices(late_phantoms)

    # --- LLDP END HOSTS: non-pollable neighbours with no bridge/router role ---
    # What is left of them (no agent claimed them above) is a host that announced
    # itself, e.g. a PC with its hostname as chassis id. It becomes an endpoint-
    # kind discovered host on the reporting switch port, not a device.
    raw_by_chassis = {n["chassis_id"]: n for n in raw_nodes}
    end_hosts = [c for c in device_by_chassis if _is_end_host(raw_by_chassis[c])]
    lldp_hosts: list[Node] = []
    for chassis in end_hosts:
        dev = device_by_chassis[chassis]
        mac = dev.mac or format_mac(chassis)
        fact = mac_table.by_mac.get(canonical_mac(mac)) if mac else None
        node = Node(
            node_id=host_node_id(mac or chassis),
            kind=KIND_ENDPOINT,
            discovery_method=(DISCOVERY_CDP_HOST
                              if raw_by_chassis[chassis].get("discovery_method") == "snmp_cdp"
                              else DISCOVERY_LLDP_HOST),
            ip=dev.ip or (fact.ip if fact else None),
            hostname=dev.hostname, vendor=dev.vendor, model=dev.model,
            firmware=dev.firmware, serial=dev.serial,
            mac=mac,
            status="discovered",
            role=dev.role,            # Fix 2: caps-derived, else "host"
            risk_score=None,          # unscored — no Wazuh agent
        )
        switch_chassis, switch_port = _lldp_switch_and_port(chassis, raw_edges)
        if switch_chassis in device_by_chassis and switch_chassis not in end_hosts:
            parent_of[node.node_id] = (device_node_id(switch_chassis), switch_port, CONF_LLDP)
        else:
            parent_of[node.node_id] = (None, None, None)
        lldp_hosts.append(node)
    retire_devices(end_hosts)

    # --- FDB/ARP HOST DISCOVERY: a table MAC matching no node is a new host ---
    known_macs = {canonical_mac(n.chassis_id) for n in device_nodes}
    known_macs |= {canonical_mac(ep.mac) for ep in endpoint_nodes if ep.mac}
    known_macs |= {canonical_mac(h.mac) for h in lldp_hosts if h.mac}
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

    # --- Wi-Fi: an access point's association table places its clients ---
    # The table is live, direct evidence, so a client the switches learned on
    # the access point's port (or placed by subnet, or not at all) moves under
    # the access point. An LLDP placement (a wired adjacency) is kept. A client
    # nothing else knows becomes a host of its own.
    wifi_hosts: list[Node] = []
    by_mac = {canonical_mac(n.mac): n for n in endpoint_nodes + lldp_hosts + discovered_nodes
              if n.mac}
    ip_by_mac = {mac: ip for ip, mac in mac_table.arp_by_ip.items()}
    for raw in raw_nodes:
        ap = device_by_chassis.get(raw["chassis_id"])
        if ap is None or raw.get("wifi_clients") is None:
            continue
        clients = raw["wifi_clients"] or []
        ap.wifi_clients = len(clients)
        for client in clients:
            mac = canonical_mac(client.get("mac"))
            if mac is None or mac in mac_table.infra_macs:
                continue
            node = by_mac.get(mac)
            if node is None and client.get("ip"):
                # an agent Wazuh gave no MAC: the access point's own pairing
                # of this IP with this MAC identifies it
                owners = [ep for ep in endpoint_nodes if not ep.mac and ep.ip == client["ip"]]
                if len(owners) == 1:
                    node = owners[0]
                    node.mac = format_mac(mac)
                    enriched_ids.append(node.node_id)
            if node is None:
                node = Node(
                    node_id=host_node_id(format_mac(mac)),
                    kind=KIND_ENDPOINT,
                    discovery_method=DISCOVERY_WIFI_HOST,
                    ip=client.get("ip") or ip_by_mac.get(mac),
                    mac=format_mac(mac),
                    status="discovered",
                    role=derive_role(mac=format_mac(mac), kind=KIND_ENDPOINT),  # -> "host"
                    risk_score=None,
                )
                wifi_hosts.append(node)
            elif parent_of.get(node.node_id, (None, None, None))[2] == CONF_LLDP:
                continue
            by_mac[mac] = node
            parent_of[node.node_id] = (ap.node_id, client.get("radio"), CONF_WIFI)
            unparented_reason.pop(node.node_id, None)
            node.wifi = {"ssid": client.get("ssid"), "access_point": ap.node_id,
                         "radio": client.get("radio")}

    # --- an agent and a discovered host on one IP: warn, never merge ---
    # A stale ARP entry produces the same picture as a second interface, so the
    # two stay separate nodes; the host joins that IP's duplicate_ip warning.
    def ip_entry(n: Node) -> dict:
        return {"node_id": n.node_id, "hostname": n.hostname,
                "status": n.status, "stale": n.stale}

    warning_by_ip = {w["ip"]: w for w in duplicate_ip_warnings}
    for node in lldp_hosts + discovered_nodes + wifi_hosts:
        agents_on_ip = endpoints_by_ip.get(node.ip) if node.ip else None
        if not agents_on_ip:
            continue
        warning = warning_by_ip.get(node.ip)
        if warning is None:
            warning = {"type": "duplicate_ip", "ip": node.ip,
                       "nodes": [ip_entry(ep) for ep in agents_on_ip]}
            warning_by_ip[node.ip] = warning
            duplicate_ip_warnings.append(warning)
        warning["nodes"].append(ip_entry(node))
    duplicate_ip_warnings.sort(key=lambda w: w["ip"])

    # --- the VLAN a host was learned on, where its parent switch learned it ---
    for node in endpoint_nodes + lldp_hosts + discovered_nodes + wifi_hosts:
        fact = mac_table.by_mac.get(canonical_mac(node.mac)) if node.mac else None
        if fact is not None and fact.vlan is not None \
                and parent_of.get(node.node_id, (None,))[0] == fact.switch_node_id:
            node.vlan = fact.vlan

    # --- endpoint edges (no remote_port: the host's MAC is not a switch port) ---
    endpoint_edges = [
        Edge(source=ep_id, target=parent, type=EDGE_ENDPOINT_LINK,
             local_port=port, confidence=conf)
        for ep_id, (parent, port, conf) in parent_of.items()
        if parent is not None
    ]
    all_edges = lldp_edges + endpoint_edges

    # --- discovery stamping: devices BFS-first, endpoints after their switch ---
    nodes_by_id = {n.node_id: n for n in
                   device_nodes + endpoint_nodes + lldp_hosts + discovered_nodes + wifi_hosts}
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
        if edge.protocol is not None:
            out["protocol"] = edge.protocol
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

    # Attack-path source candidates: live footholds only. A disconnected/stale
    # endpoint is a dead host, not a foothold, so it is excluded here even though
    # it remains a node in the graph (with its risk preserved for reports).
    attack_path_sources = [
        ep.node_id for ep in endpoint_nodes
        if (ep.status or "").lower() == "active" and not ep.stale
    ]

    metadata = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "network_scan_time": network_doc.get("scan_time"),
        "seed": network_doc.get("seed"),
        "warnings": duplicate_ip_warnings + agent_on_device_warnings,
        "attack_path_sources": attack_path_sources,
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


# ===========================================================================
# Public entry point + OO wrapper (for the class diagram)
# ===========================================================================


class GraphAssembler:
    """OO wrapper around the assembly procedure.

    Holds the two inputs and builds the unified ``{nodes, edges, metadata}``
    document in :meth:`build`. ``assemble`` is the function the pipeline and tests
    call; it delegates here so the runtime behaviour is unchanged while the design
    presents a single clear assembler class on the diagram.
    """

    def __init__(self, endpoints: list[dict], network_doc: dict) -> None:
        self.endpoints = endpoints
        self.network_doc = network_doc

    def build(self) -> dict:
        return _build_graph(self.endpoints, self.network_doc)


def assemble(endpoints: list[dict], network_doc: dict) -> dict:
    """Build the unified graph document from endpoints + the network document."""
    return GraphAssembler(endpoints, network_doc).build()
