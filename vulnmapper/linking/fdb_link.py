"""FDB-based access-port resolution — Tier 2 of the parenting ladder.

The parenting ladder (orchestrated in :mod:`vulnmapper.assemble.merge`) tries, in
order of evidence quality:

  * Tier 1 — **LLDP match**: the endpoint speaks LLDP, so the switch already
    reported it as a neighbor with an exact local port. Handled in the assembler
    (it owns the node merge).
  * Tier 2 — **per-VLAN FDB match** (this module): an online host that doesn't
    speak LLDP. Its MAC is looked up in the switch forwarding tables; the LLDP
    uplink ports are subtracted so the MAC lands on the *access* switch, not
    every switch along the L2 path.
  * Tier 3 — **IP/subnet fallback**: an offline host (no live FDB entry) or one
    with no MAC. Parented by subnet ownership (:func:`same_subnet`), confidence
    ``subnet_fallback``.

This module is pure: it indexes plain network-node dicts and resolves a MAC to a
``(switch_node_id, access_port, confidence)`` triple, or ``None`` when the FDB
has no access-port placement. No I/O — fully unit-testable.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from ..schema import canonical_mac
from ..schema import device_node_id

# Confidence levels stamped on an endpoint -> switch edge (one per ladder tier).
CONF_LLDP = "lldp"                       # Tier 1: exact LLDP adjacency
CONF_RESOLVED = "resolved"               # Tier 2: single FDB access-port survivor
CONF_TIEBREAK = "tiebreak"               # Tier 2: several survivors, fewest-MAC wins
CONF_SUBNET_FALLBACK = "subnet_fallback"  # Tier 3: parented by subnet, not L2
CONF_FDB = "fdb"                          # FDB/ARP-discovered host (no agent, no LLDP)

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
    ``infra_macs`` are the polling devices' own interface/SVI/chassis MACs, which
    are excluded so a router's gateway MACs never become phantom hosts.
    """

    by_mac: dict
    by_ip: dict
    infra_macs: set


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
    return MacTable(by_mac=by_mac, by_ip=by_ip, infra_macs=infra_macs)


def same_subnet(ip_a: Optional[str], ip_b: Optional[str], prefix: int = 24) -> bool:
    """True if two IPv4 addresses share the same ``/prefix`` network."""
    if not ip_a or not ip_b:
        return False
    try:
        net = ipaddress.ip_network(f"{ip_a}/{prefix}", strict=False)
        return ipaddress.ip_address(ip_b) in net
    except ValueError:
        return False
