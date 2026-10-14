"""Assembly: the Wazuh endpoints and the crawl's network document become one
graph, each host hung off the switch port it sits on (``GraphAssembler``).
Runs right after the two inputs are read; every later stage works on its graph.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

from ..hosts import label
from ..network.roles import derive_role
from ..schema import (
    CONF_FDB,
    CONF_LLDP,
    CONF_SUBNET_FALLBACK,
    CONF_WIFI,
    DISCOVERY_SNMP_FDB,
    EDGE_ENDPOINT_LINK,
    EDGE_LLDP,
    KIND_DEVICE,
    KIND_ENDPOINT,
    Edge,
    Node,
    canonical_mac,
    device_node_id,
    format_mac,
)
from .mactable import build_mac_table, same_subnet
from .ports import set_port_states
from .nodes import device_node, discovered_host, endpoint_node, is_end_host, is_network_equipment

# discovery_method of a host known from a neighbour announcement: LLDP, or CDP...
DISCOVERY_LLDP_HOST = "lldp"
DISCOVERY_CDP_HOST = "cdp"
# ...or only from an access point's client list.
DISCOVERY_WIFI_HOST = "snmp_wifi"

# Why an endpoint could not be placed.
REASON_NO_MAC = "no_endpoint_mac"
REASON_ABSENT = "mac_absent_from_all_fdb"
REASON_OFFLINE = "host_offline_no_l2_evidence"

_UNPLACED = (None, None, None)


def _online(node: Node) -> bool:
    return (node.status or "").lower() == "active"


def _lldp_switch_and_port(phantom_chassis: str, raw_edges: list[dict]):
    """``(switch chassis, its port)`` of the LLDP link that reported a phantom,
    or ``(None, None)``. The switch is the end that is not the phantom; its
    port is ``local_port`` or ``remote_port`` depending on the direction."""
    for raw in raw_edges:
        src = raw.get("source_chassis_id")
        tgt = raw.get("target_chassis_id")
        if tgt == phantom_chassis:
            return src, raw.get("local_port")
        if src == phantom_chassis:
            return tgt, raw.get("remote_port")
    return None, None


def _subnet_parent(ip: Optional[str], device_nodes: list[Node]) -> Optional[str]:
    """A device on the same /24, a polled one (the segment's real switch or
    router) before one only seen in a table."""
    match = None
    for dev in device_nodes:
        if same_subnet(dev.ip, ip):
            if dev.pollable:
                return dev.node_id
            match = match or dev.node_id
    return match


def _bfs_device_order(device_ids: list[str], lldp_edges: list[Edge]):
    """``(order, parent)``: devices breadth-first from the seed, and the device
    each was reached from."""
    known = set(device_ids)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in lldp_edges:
        adjacency[edge.source].append(edge.target)
        adjacency[edge.target].append(edge.source)

    order: list[str] = []
    parent: dict[str, Optional[str]] = {}
    visited: set[str] = set()
    for seed in device_ids:  # document order: the seed first, then each component's root
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


class GraphAssembler:
    """Builds the ``{nodes, edges, metadata}`` graph from scored endpoints and
    the crawl's network document. One instance per assembly; ``build`` runs
    the steps in order, each reading what the ones before it left.

    Each endpoint is hung off the switch port it sits on, by the first rung of
    this ladder that works; the rung becomes the edge's ``confidence``:

      1. LLDP: the switch's neighbour table names the endpoint itself (the
         "phantom" device node it left is merged into the endpoint);
      2. the forwarding tables: its MAC is learned on one access port
         (``mactable.build_mac_table``);
      3. its /24 matches a device, for an endpoint that is online; else it stays
         unparented, with the reason.

    Hosts with no agent are added from the same evidence (LLDP announcements,
    forwarding tables, access point client lists), then every node gets a
    ``discovery_order`` and ``parent_id`` and the metadata is counted.
    """

    def __init__(self, endpoints: list[dict], network_doc: dict) -> None:
        self.endpoints = endpoints
        self.network_doc = network_doc

    def build(self) -> dict:
        self._map_inputs()
        self._find_duplicate_ips()
        self.mac_table = build_mac_table(self.raw_nodes)
        self._merge_lldp_phantoms()
        self._link_devices()
        self._place_from_tables()
        self._merge_late_phantoms()
        self._add_lldp_end_hosts()
        self._add_table_hosts()
        self._place_wifi_clients()
        self._warn_hosts_on_agent_ips()
        self._stamp_vlans()
        return self._document()

    # ---- inputs ---------------------------------------------------------------

    def _map_inputs(self) -> None:
        self.raw_nodes = [n for n in (self.network_doc.get("nodes") or []) if n.get("chassis_id")]
        self.raw_edges = self.network_doc.get("edges") or []
        self.raw_by_chassis = {n["chassis_id"]: n for n in self.raw_nodes}
        self.device_by_chassis = {n["chassis_id"]: device_node(n) for n in self.raw_nodes}
        self.caps_by_chassis = {n["chassis_id"]: n.get("lldp_cap_enabled") for n in self.raw_nodes}

        # A switch reports an LLDP neighbour's capabilities under the
        # neighbour's chassis id, which is its MAC. An endpoint that speaks
        # LLDP inherits them from that phantom (rung 1), so it gets a real role
        # ("station", say) instead of the generic "host".
        self.caps_by_mac: dict[str, str] = {}
        for n in self.raw_nodes:
            cmac = canonical_mac(n.get("chassis_id"))
            caps = n.get("lldp_cap_enabled")
            if cmac and caps:
                self.caps_by_mac[cmac] = caps

        self.endpoint_nodes = [endpoint_node(e) for e in self.endpoints]
        self.endpoints_by_mac = {}
        for ep in self.endpoint_nodes:
            mac = canonical_mac(ep.mac)
            if mac:
                self.endpoints_by_mac[mac] = ep
            ep.role = derive_role(capabilities=self.caps_by_mac.get(mac), vendor=ep.vendor,
                                  model=ep.model, mac=ep.mac, kind=KIND_ENDPOINT)

        # node_id -> (parent node_id or None, port or None, confidence or None)
        self.parent_of: dict[str, tuple] = {}
        self.unparented_reason: dict[str, str] = {}
        self.enriched_ids: list[str] = []   # endpoints whose MAC the tables filled in
        self.agent_on_device_warnings: list[dict] = []
        self.lldp_hosts: list[Node] = []
        self.discovered_nodes: list[Node] = []
        self.wifi_hosts: list[Node] = []

    def _find_duplicate_ips(self) -> None:
        """Two agents on one IP (an address reassigned, a host renamed).

        Endpoints are keyed on MAC, so both are real and are never merged. The
        collision is reported, and the disconnected one is marked ``stale``:
        it stays in the graph with its risk, unparented, but is no foothold.
        """
        self.duplicate_ip_warnings: list[dict] = []
        self.endpoints_by_ip: dict[str, list[Node]] = defaultdict(list)
        for ep in self.endpoint_nodes:
            if ep.ip:
                self.endpoints_by_ip[ep.ip].append(ep)
        for ip, group in sorted(self.endpoints_by_ip.items()):
            if len(group) < 2:
                continue
            has_active = any(_online(ep) for ep in group)
            for ep in group:
                if has_active and (ep.status or "").lower() == "disconnected":
                    ep.stale = True
            self.duplicate_ip_warnings.append({
                "type": "duplicate_ip",
                "ip": ip,
                "nodes": [{"node_id": ep.node_id, "hostname": ep.hostname,
                           "status": ep.status, "stale": ep.stale} for ep in group],
            })

    # ---- rung 1: LLDP ---------------------------------------------------------

    def _warn_agent_on_network_device(self, chassis: str, ep: Node) -> None:
        """A device whose MAC is an agent's is the same machine. An ordinary
        machine is merged into its endpoint, but network equipment running an
        agent is kept (removing it would break the topology around it) and
        the pair is reported."""
        device = self.device_by_chassis[chassis]
        self.agent_on_device_warnings.append({
            "type": "agent_on_network_device",
            "mac": format_mac(chassis),
            "nodes": [{"node_id": n.node_id, "hostname": n.hostname, "kind": n.kind}
                      for n in (device, ep)],
        })

    def _merge_lldp_phantoms(self) -> None:
        self.phantom_chassis: set[str] = set()
        for chassis in list(self.device_by_chassis):
            cmac = canonical_mac(chassis)
            ep = self.endpoints_by_mac.get(cmac) if cmac else None
            if ep is None:
                continue
            if is_network_equipment(self.caps_by_chassis.get(chassis)):
                self._warn_agent_on_network_device(chassis, ep)
                continue
            switch_chassis, switch_port = _lldp_switch_and_port(chassis, self.raw_edges)
            if switch_chassis is None or switch_chassis not in self.device_by_chassis:
                continue  # can't tell which switch reported it; keep both nodes
            self.phantom_chassis.add(chassis)
            self.parent_of[ep.node_id] = (device_node_id(switch_chassis), switch_port, CONF_LLDP)

        for chassis in self.phantom_chassis:
            self.device_by_chassis.pop(chassis, None)
        self.device_nodes = list(self.device_by_chassis.values())

    def _link_devices(self) -> None:
        """LLDP edges between the devices left (a phantom's edges drop out)."""
        device_node_ids = {n.node_id for n in self.device_nodes}
        self.lldp_edges: list[Edge] = []
        for raw in self.raw_edges:
            src = device_node_id(raw.get("source_chassis_id"))
            tgt = device_node_id(raw.get("target_chassis_id"))
            if src in device_node_ids and tgt in device_node_ids:
                self.lldp_edges.append(Edge(
                    source=src, target=tgt, type=EDGE_LLDP,
                    local_port=raw.get("local_port"), remote_port=raw.get("remote_port"),
                    protocol=raw.get("protocol"),
                ))

    # ---- rungs 2 and 3 --------------------------------------------------------

    def _place_from_tables(self) -> None:
        table = self.mac_table
        for ep in self.endpoint_nodes:
            if ep.node_id in self.parent_of:
                continue
            mac = canonical_mac(ep.mac)
            online = _online(ep)

            fact = table.by_mac.get(mac) if mac else None
            # Wazuh gave no MAC but the tables know the IP (an offline host
            # still in a forwarding table): the endpoint takes the table's MAC.
            if fact is None and not mac and ep.ip and ep.ip in table.by_ip:
                mac = table.by_ip[ep.ip]
                fact = table.by_mac[mac]
                ep.mac = format_mac(mac)
                self.enriched_ids.append(ep.node_id)

            if fact is not None:
                self.parent_of[ep.node_id] = (fact.switch_node_id, fact.port, fact.confidence)
                continue

            # Sharing a /24 is no evidence that an offline machine hangs off
            # that device, so rung 3 is for hosts that are online.
            gateway = _subnet_parent(ep.ip, self.device_nodes) if online else None
            if gateway:
                self.parent_of[ep.node_id] = (gateway, None, CONF_SUBNET_FALLBACK)
                continue

            self.parent_of[ep.node_id] = _UNPLACED
            if not ep.mac:
                self.unparented_reason[ep.node_id] = REASON_NO_MAC if online else REASON_OFFLINE
            elif not online:
                self.unparented_reason[ep.node_id] = REASON_OFFLINE
            else:
                self.unparented_reason[ep.node_id] = REASON_ABSENT

    def _merge_late_phantoms(self) -> None:
        """Rung 1 again, for endpoints whose MAC only the tables supplied.

        Rung 1 ran before the tables filled in MACs Wazuh did not report, so a
        phantom of such an endpoint survived it. An endpoint still without a
        MAC may take one from ARP alone, but only when an LLDP phantom
        announcing that MAC backs it up (a lone ARP entry may be stale), the
        MAC is not infrastructure, and the announcer is no bridge or router.
        """
        table = self.mac_table
        phantom_by_mac = {canonical_mac(c): c for c in self.device_by_chassis if canonical_mac(c)}
        warned = {w["mac"] for w in self.agent_on_device_warnings}
        late: set[str] = set()
        for ep in self.endpoint_nodes:
            mac = canonical_mac(ep.mac)
            if mac is None and ep.ip:
                arp_mac = table.arp_by_ip.get(ep.ip)
                announcer = phantom_by_mac.get(arp_mac) if arp_mac else None
                if (announcer and arp_mac not in table.infra_macs
                        and not is_network_equipment(self.caps_by_chassis.get(announcer))):
                    mac = arp_mac
            chassis = phantom_by_mac.get(mac) if mac else None
            if chassis is None or chassis in late:
                continue
            if is_network_equipment(self.caps_by_chassis.get(chassis)):
                if ep.mac and format_mac(chassis) not in warned:
                    self._warn_agent_on_network_device(chassis, ep)
                    warned.add(format_mac(chassis))
                continue
            switch_chassis, switch_port = _lldp_switch_and_port(chassis, self.raw_edges)
            if switch_chassis is None or switch_chassis not in self.device_by_chassis \
                    or switch_chassis in late:
                continue  # can't tell which switch reported it; keep both nodes
            late.add(chassis)
            if ep.mac is None:
                ep.mac = format_mac(mac)
            ep.role = derive_role(capabilities=self.caps_by_mac.get(mac), vendor=ep.vendor,
                                  model=ep.model, mac=ep.mac, kind=KIND_ENDPOINT)
            # An LLDP announcement is direct evidence: it wins unless the
            # tables already put the endpoint on that very switch port.
            lldp_parent = (device_node_id(switch_chassis), switch_port, CONF_LLDP)
            parent, port, _conf = self.parent_of.get(ep.node_id, _UNPLACED)
            if (parent, port) != lldp_parent[:2]:
                self.parent_of[ep.node_id] = lldp_parent
                self.unparented_reason.pop(ep.node_id, None)

        self.phantom_chassis |= late
        self._retire_devices(late)

    def _retire_devices(self, chassis_ids) -> None:
        """Drop device nodes that turned out to be other nodes, with their LLDP
        edges. An endpoint whose subnet parent was one of them is placed again
        (or left unparented, with the reason)."""
        ids = {device_node_id(c) for c in chassis_ids}
        if not ids:
            return
        for chassis in chassis_ids:
            self.device_by_chassis.pop(chassis, None)
        self.device_nodes[:] = [n for n in self.device_nodes if n.node_id not in ids]
        self.lldp_edges[:] = [e for e in self.lldp_edges
                              if e.source not in ids and e.target not in ids]
        for ep_id, (parent, _port, _conf) in list(self.parent_of.items()):
            if parent not in ids:
                continue
            ep = next(n for n in self.endpoint_nodes if n.node_id == ep_id)
            online = _online(ep)
            gateway = _subnet_parent(ep.ip, self.device_nodes) if online else None
            self.parent_of[ep_id] = (gateway, None, CONF_SUBNET_FALLBACK if gateway else None)
            if gateway is None:
                self.unparented_reason[ep_id] = (REASON_ABSENT if ep.mac and online
                                                 else REASON_NO_MAC if online
                                                 else REASON_OFFLINE)

    # ---- hosts with no agent --------------------------------------------------

    def _add_lldp_end_hosts(self) -> None:
        """Neighbours no agent claimed that advertise no bridge or router role
        are hosts that announced themselves (a PC with its hostname as chassis
        id, say): host nodes on the reporting switch port, not devices."""
        end_hosts = [c for c in self.device_by_chassis if is_end_host(self.raw_by_chassis[c])]
        for chassis in end_hosts:
            dev = self.device_by_chassis[chassis]
            mac = dev.mac or format_mac(chassis)
            fact = self.mac_table.by_mac.get(canonical_mac(mac)) if mac else None
            cdp = self.raw_by_chassis[chassis].get("discovery_method") == "snmp_cdp"
            node = discovered_host(
                mac or chassis, DISCOVERY_CDP_HOST if cdp else DISCOVERY_LLDP_HOST,
                ip=dev.ip or (fact.ip if fact else None), mac=mac,
                role=dev.role,            # from its capabilities, else "host"
                hostname=dev.hostname, vendor=dev.vendor, model=dev.model,
                firmware=dev.firmware, serial=dev.serial)
            switch_chassis, switch_port = _lldp_switch_and_port(chassis, self.raw_edges)
            if switch_chassis in self.device_by_chassis and switch_chassis not in end_hosts:
                self.parent_of[node.node_id] = (device_node_id(switch_chassis), switch_port,
                                                CONF_LLDP)
            else:
                self.parent_of[node.node_id] = _UNPLACED
            self.lldp_hosts.append(node)
        self._retire_devices(end_hosts)

    def _add_table_hosts(self) -> None:
        """A forwarding-table MAC that matches no node is a host of its own."""
        known_macs = {canonical_mac(n.chassis_id) for n in self.device_nodes}
        known_macs |= {canonical_mac(ep.mac) for ep in self.endpoint_nodes if ep.mac}
        known_macs |= {canonical_mac(h.mac) for h in self.lldp_hosts if h.mac}
        known_macs |= self.mac_table.infra_macs
        known_macs.discard(None)

        for mac, fact in self.mac_table.by_mac.items():
            if mac in known_macs:
                continue
            node = discovered_host(format_mac(mac), DISCOVERY_SNMP_FDB, ip=fact.ip,
                                   mac=format_mac(mac))
            self.discovered_nodes.append(node)
            self.parent_of[node.node_id] = (fact.switch_node_id, fact.port, CONF_FDB)

    def _place_wifi_clients(self) -> None:
        """An access point's client list is live, direct evidence: a client the
        switches learned on the AP's port (or placed by subnet, or not at all)
        moves under the AP. An LLDP placement, a wired adjacency, is kept. A
        client nothing else knows becomes a host of its own."""
        table = self.mac_table
        by_mac = {canonical_mac(n.mac): n for n in
                  self.endpoint_nodes + self.lldp_hosts + self.discovered_nodes if n.mac}
        ip_by_mac = {mac: ip for ip, mac in table.arp_by_ip.items()}
        for raw in self.raw_nodes:
            ap = self.device_by_chassis.get(raw["chassis_id"])
            if ap is None or raw.get("wifi_clients") is None:
                continue
            clients = raw["wifi_clients"] or []
            ap.wifi_clients = len(clients)
            for client in clients:
                mac = canonical_mac(client.get("mac"))
                if mac is None or mac in table.infra_macs:
                    continue
                node = by_mac.get(mac)
                if node is None and client.get("ip"):
                    # an agent Wazuh gave no MAC: the AP's own pairing of this
                    # IP with this MAC identifies it
                    owners = [ep for ep in self.endpoint_nodes
                              if not ep.mac and ep.ip == client["ip"]]
                    if len(owners) == 1:
                        node = owners[0]
                        node.mac = format_mac(mac)
                        self.enriched_ids.append(node.node_id)
                if node is None:
                    node = discovered_host(format_mac(mac), DISCOVERY_WIFI_HOST,
                                           ip=client.get("ip") or ip_by_mac.get(mac),
                                           mac=format_mac(mac))
                    self.wifi_hosts.append(node)
                elif self.parent_of.get(node.node_id, _UNPLACED)[2] == CONF_LLDP:
                    continue
                by_mac[mac] = node
                self.parent_of[node.node_id] = (ap.node_id, client.get("radio"), CONF_WIFI)
                self.unparented_reason.pop(node.node_id, None)
                node.wifi = {"ssid": client.get("ssid"), "access_point": ap.node_id,
                             "radio": client.get("radio")}

    @property
    def _new_hosts(self) -> list[Node]:
        return self.lldp_hosts + self.discovered_nodes + self.wifi_hosts

    def _warn_hosts_on_agent_ips(self) -> None:
        """A discovered host on an agent's IP: warned about, never merged. A
        stale ARP entry looks the same as a second interface, so the host joins
        that IP's duplicate_ip warning instead."""
        def ip_entry(n: Node) -> dict:
            return {"node_id": n.node_id, "hostname": n.hostname,
                    "status": n.status, "stale": n.stale}

        warning_by_ip = {w["ip"]: w for w in self.duplicate_ip_warnings}
        for node in self._new_hosts:
            agents_on_ip = self.endpoints_by_ip.get(node.ip) if node.ip else None
            if not agents_on_ip:
                continue
            warning = warning_by_ip.get(node.ip)
            if warning is None:
                warning = {"type": "duplicate_ip", "ip": node.ip,
                           "nodes": [ip_entry(ep) for ep in agents_on_ip]}
                warning_by_ip[node.ip] = warning
                self.duplicate_ip_warnings.append(warning)
            warning["nodes"].append(ip_entry(node))
        self.duplicate_ip_warnings.sort(key=lambda w: w["ip"])

    def _stamp_vlans(self) -> None:
        """A host's VLAN is the one its parent switch learned its MAC on."""
        for node in self.endpoint_nodes + self._new_hosts:
            fact = self.mac_table.by_mac.get(canonical_mac(node.mac)) if node.mac else None
            if fact is not None and fact.vlan is not None \
                    and self.parent_of.get(node.node_id, (None,))[0] == fact.switch_node_id:
                node.vlan = fact.vlan

    # ---- output ---------------------------------------------------------------

    def _document(self) -> dict:
        # endpoint edges carry no remote_port: a host's MAC is not a switch port
        endpoint_edges = [
            Edge(source=ep_id, target=parent, type=EDGE_ENDPOINT_LINK,
                 local_port=port, confidence=conf)
            for ep_id, (parent, port, conf) in self.parent_of.items()
            if parent is not None
        ]
        nodes_by_id = {n.node_id: n for n in
                       self.device_nodes + self.endpoint_nodes + self._new_hosts}
        unparented = self._stamp_discovery_order(nodes_by_id)

        def name_of(node_id: str) -> str:
            node = nodes_by_id.get(node_id)
            return node_id if node is None else node.hostname or node.ip or node_id

        def edge_dict(edge: Edge) -> dict:
            out = {"source": edge.source, "source_name": name_of(edge.source),
                   "target": edge.target, "target_name": name_of(edge.target),
                   "type": edge.type}
            for key in ("local_port", "remote_port", "confidence", "protocol"):
                if getattr(edge, key) is not None:
                    out[key] = getattr(edge, key)
            return out

        ordered_nodes = sorted(nodes_by_id.values(), key=lambda n: n.discovery_order)
        return {
            "nodes": [n.to_dict() for n in ordered_nodes],
            "edges": [edge_dict(e) for e in self.lldp_edges + endpoint_edges],
            "metadata": self._metadata(nodes_by_id, endpoint_edges, unparented),
        }

    def _stamp_discovery_order(self, nodes_by_id: dict) -> list[str]:
        """Devices breadth-first from the seed, each followed by the hosts on
        it; unparented hosts last. Returns the unparented ids."""
        device_order, device_parent = _bfs_device_order(
            [n.node_id for n in self.device_nodes], self.lldp_edges)

        endpoints_by_parent: dict[Optional[str], list[str]] = defaultdict(list)
        unparented: list[str] = []
        for ep_id, (parent, _port, _conf) in self.parent_of.items():
            (unparented if parent is None else endpoints_by_parent[parent]).append(ep_id)

        reveal: list[str] = []
        for device_id in device_order:
            reveal.append(device_id)
            reveal.extend(endpoints_by_parent.get(device_id, []))
        reveal.extend(unparented)
        for node_id in nodes_by_id:  # anything not placed yet
            if node_id not in reveal:
                reveal.append(node_id)

        for order, node_id in enumerate(reveal):
            node = nodes_by_id[node_id]
            node.discovery_order = order
            if node.kind == KIND_DEVICE:
                node.parent_id = device_parent.get(node_id)
            else:
                node.parent_id = self.parent_of[node_id][0]
        return unparented

    def _metadata(self, nodes_by_id: dict, endpoint_edges: list, unparented: list) -> dict:
        confidence_counts: dict[str, int] = defaultdict(int)
        for _parent, _port, conf in self.parent_of.values():
            if conf:
                confidence_counts[conf] += 1

        unreachable = [
            {"node_id": n.node_id, "chassis_id": n.chassis_id, "ip": n.ip, "status": n.status}
            for n in self.device_nodes
            if n.pollable is False or n.status == "unreachable"
        ]
        # Live footholds only: a disconnected or stale endpoint is a dead host,
        # still in the graph (with its risk, for reports) but no starting point.
        attack_path_sources = [ep.node_id for ep in self.endpoint_nodes
                               if _online(ep) and not ep.stale]

        return {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "network_scan_time": self.network_doc.get("scan_time"),
            "seed": self.network_doc.get("seed"),
            "warnings": self.duplicate_ip_warnings + self.agent_on_device_warnings,
            "attack_path_sources": attack_path_sources,
            "counts": {
                "nodes": len(nodes_by_id),
                "endpoints": len(self.endpoint_nodes),
                "devices": len(self.device_nodes),
                "fdb_discovered_hosts": len(self.discovered_nodes),
                "lldp_edges": len(self.lldp_edges),
                "endpoint_edges": len(endpoint_edges),
                "unparented_endpoints": len(unparented),
            },
            "confidence": dict(confidence_counts),
            "merged_lldp_endpoints": len(self.phantom_chassis),
            "fdb_discovered_hosts": len(self.discovered_nodes),
            "fdb_enriched_nodes": len(self.enriched_ids),
            "unparented_endpoints": [
                {"node_id": ep_id, "hostname": nodes_by_id[ep_id].hostname,
                 "reason": self.unparented_reason.get(ep_id)}
                for ep_id in unparented
            ],
            "unreachable_boundaries": unreachable,
        }


def assemble(endpoints: list[dict], network_doc: dict,
             previous_graph: Optional[dict] = None) -> dict:
    """The unified graph, with every host labelled managed or unmanaged
    (``hosts.label``) and every device port's state (``ports.set_port_states``,
    which reads ``previous_graph``, the graph this one replaces)."""
    graph = label(GraphAssembler(endpoints, network_doc).build())
    set_port_states(graph, previous_graph)
    return graph
