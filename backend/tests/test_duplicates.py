"""Placement and duplicate fixes seen on a real network (cases A-D).

A/B: an agent whose MAC Wazuh did not report is announced over LLDP; the
phantom device must merge into the endpoint once the switch tables reveal the
MAC. C: a non-pollable LLDP neighbour with no bridge/router capability is a
host. D: an agent and a discovered host sharing an IP are both kept, with a
duplicate_ip warning.
"""

import unittest

from vulnmapper.assemble import assemble

HP = "5c:8a:38:8b:a1:0b"
HP_ID = f"device:{HP}"
CYFOR4_MAC = "d4:be:d9:97:f6:a2"
CYFOR3_MAC = "d4:be:d9:98:2f:0e"


def bare(mac):
    return mac.replace(":", "")


def hp_switch(fdb=(), arp=None):
    return {"chassis_id": HP, "ip": "172.20.99.4", "hostname": "CYFOR-HP-Switch",
            "discovery_method": "snmp_lldp", "status": "online", "pollable": True,
            "lldp_cap_enabled": "0x28", "uplink_ports": [], "own_macs": [HP],
            "fdb": list(fdb), "arp": arp or {}}


def phantom(mac, caps="0x01"):
    """An LLDP neighbour the HP switch reported: an end host announcing its MAC."""
    return {"chassis_id": mac, "ip": None, "hostname": None, "discovery_method": "snmp_lldp",
            "status": "discovered", "pollable": False, "lldp_cap_enabled": caps, "fdb": []}


def lldp(target, port, remote=None):
    return {"source_chassis_id": HP, "target_chassis_id": target,
            "local_port": port, "remote_port": remote}


def agent(agent_id, hostname, ip, mac=None, status="active"):
    return {"agent_id": agent_id, "hostname": hostname, "ip": ip, "mac": mac,
            "status": status, "risk_score": 5.0, "top_cves": []}


class Graph:
    def __init__(self, endpoints, network):
        self.doc = assemble(endpoints, network)
        self.nodes = {n["node_id"]: n for n in self.doc["nodes"]}
        self.links = {e["source"]: e for e in self.doc["edges"] if e["type"] == "endpoint_link"}

    def ids_for_mac(self, mac):
        return sorted(i for i, n in self.nodes.items()
                      if n["mac"] == mac or i.endswith(mac))


class TestCaseA_MacLearnedFromFdb(unittest.TestCase):
    """No MAC from Wazuh; IP in ARP; MAC in the FDB and announced over LLDP."""

    def setUp(self):
        net = {"nodes": [
            hp_switch(fdb=[{"mac": bare(CYFOR4_MAC), "port": "GigabitEthernet1/0/37", "vlan": 40}],
                      arp={bare(CYFOR4_MAC): "172.20.40.11"}),
            phantom(CYFOR4_MAC),
        ], "edges": [lldp(CYFOR4_MAC, "GigabitEthernet1/0/37", "0xd4bed997f6a2")]}
        self.g = Graph([agent("003", "CYFOR-4", "172.20.40.11")], net)

    def test_one_node_no_leftover_device(self):
        self.assertEqual(self.g.ids_for_mac(CYFOR4_MAC), ["endpoint:003"])
        self.assertNotIn(f"device:{CYFOR4_MAC}", self.g.nodes)

    def test_placement_kept_on_same_switch_and_port(self):
        ep = self.g.nodes["endpoint:003"]
        self.assertEqual(ep["parent_id"], HP_ID)
        self.assertEqual(self.g.links["endpoint:003"]["local_port"], "GigabitEthernet1/0/37")
        self.assertEqual(self.g.links["endpoint:003"]["confidence"], "resolved")

    def test_inherits_lldp_role_and_counted(self):
        self.assertEqual(self.g.nodes["endpoint:003"]["role"], "station")
        self.assertEqual(self.g.doc["metadata"]["merged_lldp_endpoints"], 1)

    def test_phantom_lldp_edge_dropped(self):
        self.assertEqual([e for e in self.g.doc["edges"] if e["type"] == "lldp"], [])
        self.assertEqual(self.g.doc["metadata"]["counts"]["devices"], 1)


class TestCaseA_LldpPortWinsOverOtherFdbPort(unittest.TestCase):
    def test_lldp_placement_preferred_when_fdb_disagrees(self):
        net = {"nodes": [
            hp_switch(fdb=[{"mac": bare(CYFOR4_MAC), "port": "GigabitEthernet1/0/5", "vlan": 40}],
                      arp={bare(CYFOR4_MAC): "172.20.40.11"}),
            phantom(CYFOR4_MAC),
        ], "edges": [lldp(CYFOR4_MAC, "GigabitEthernet1/0/37")]}
        g = Graph([agent("003", "CYFOR-4", "172.20.40.11")], net)
        self.assertEqual(g.links["endpoint:003"]["local_port"], "GigabitEthernet1/0/37")
        self.assertEqual(g.links["endpoint:003"]["confidence"], "lldp")
        self.assertNotIn(f"device:{CYFOR4_MAC}", g.nodes)


class TestCaseB_MacOnlyInArp(unittest.TestCase):
    """No MAC from Wazuh, no FDB entry: the ARP MAC is corroborated by LLDP."""

    def setUp(self):
        net = {"nodes": [hp_switch(arp={bare(CYFOR3_MAC): "172.20.30.22"}), phantom(CYFOR3_MAC)],
               "edges": [lldp(CYFOR3_MAC, "GigabitEthernet1/0/26")]}
        self.g = Graph([agent("005", "CYFOR-3", "172.20.30.22")], net)

    def test_one_node_parented_on_lldp_switch_and_port(self):
        self.assertEqual(self.g.ids_for_mac(CYFOR3_MAC), ["endpoint:005"])
        ep = self.g.nodes["endpoint:005"]
        self.assertEqual(ep["parent_id"], HP_ID)
        self.assertEqual(ep["mac"], CYFOR3_MAC)
        link = self.g.links["endpoint:005"]
        self.assertEqual((link["local_port"], link["confidence"]),
                         ("GigabitEthernet1/0/26", "lldp"))

    def test_no_longer_unparented(self):
        meta = self.g.doc["metadata"]
        self.assertEqual(meta["unparented_endpoints"], [])
        self.assertEqual(meta["counts"]["unparented_endpoints"], 0)
        self.assertEqual(meta["merged_lldp_endpoints"], 1)

    def test_arp_mac_without_lldp_announcement_is_not_taken(self):
        net = {"nodes": [hp_switch(arp={bare(CYFOR3_MAC): "172.20.30.22"})], "edges": []}
        g = Graph([agent("005", "CYFOR-3", "172.20.30.22")], net)
        self.assertIsNone(g.nodes["endpoint:005"]["mac"])
        self.assertIsNone(g.nodes["endpoint:005"]["parent_id"])


class TestMacKnownUpFront(unittest.TestCase):
    def test_still_one_node(self):
        net = {"nodes": [hp_switch(), phantom(CYFOR4_MAC)],
               "edges": [lldp(CYFOR4_MAC, "GigabitEthernet1/0/37")]}
        g = Graph([agent("003", "CYFOR-4", "172.20.40.11", mac=CYFOR4_MAC)], net)
        self.assertEqual(g.ids_for_mac(CYFOR4_MAC), ["endpoint:003"])
        self.assertEqual(g.links["endpoint:003"]["confidence"], "lldp")
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 1)


class TestPollableNeverMerged(unittest.TestCase):
    """A Wazuh agent on a pollable box (e.g. a Linux router) must not swallow it."""

    ROUTER = "aa:bb:cc:00:10:01"

    def network(self, arp=None):
        router = {"chassis_id": self.ROUTER, "ip": "172.20.99.9", "hostname": "edge-router",
                  "discovery_method": "snmp_lldp", "status": "online", "pollable": True,
                  "lldp_cap_enabled": "0x08", "uplink_ports": [], "fdb": []}
        return {"nodes": [hp_switch(arp=arp), router],
                "edges": [lldp(self.ROUTER, "GigabitEthernet1/0/48")]}

    def test_mac_known_up_front(self):
        g = Graph([agent("009", "edge-router", "172.20.99.9", mac=self.ROUTER)], self.network())
        self.assertIn(f"device:{self.ROUTER}", g.nodes)
        self.assertIn("endpoint:009", g.nodes)
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 0)

    def test_mac_learned_from_arp(self):
        g = Graph([agent("009", "edge-router", "172.20.99.9")],
                  self.network(arp={bare(self.ROUTER): "172.20.99.9"}))
        self.assertIn(f"device:{self.ROUTER}", g.nodes)
        self.assertEqual(g.nodes[f"device:{self.ROUTER}"]["role"], "router")
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 0)


class TestLateMergeLeavesNoDanglingParent(unittest.TestCase):
    def test_subnet_child_of_merged_phantom_is_repointed(self):
        announced = dict(phantom(CYFOR3_MAC), ip="10.5.5.9")   # the only 10.5.5.x device
        net = {"nodes": [hp_switch(arp={bare(CYFOR3_MAC): "172.20.30.22"}), announced],
               "edges": [lldp(CYFOR3_MAC, "GigabitEthernet1/0/26")]}
        g = Graph([agent("005", "CYFOR-3", "172.20.30.22"),
                   agent("006", "lab-pc", "10.5.5.20")], net)
        self.assertNotIn(f"device:{CYFOR3_MAC}", g.nodes)
        self.assertIsNone(g.nodes["endpoint:006"]["parent_id"])
        reasons = {u["node_id"]: u["reason"] for u in g.doc["metadata"]["unparented_endpoints"]}
        self.assertEqual(reasons, {"endpoint:006": "no_endpoint_mac"})
        self.assertTrue(all(e["target"] in g.nodes for e in g.doc["edges"]))


class TestCaseC_HostnameChassisNeighbour(unittest.TestCase):
    def neighbour(self, caps=None, status="discovered", ip=None):
        node = {"chassis_id": "desktop-87u7d8b", "ip": ip, "hostname": None,
                "discovery_method": "snmp_lldp", "status": status, "pollable": False,
                "lldp_cap_enabled": caps, "fdb": []}
        net = {"nodes": [hp_switch(), node], "edges": [lldp("desktop-87u7d8b", "GigabitEthernet1/0/12")]}
        return Graph([], net)

    def test_no_capabilities_is_a_host_one_node(self):
        g = self.neighbour()
        matches = [i for i in g.nodes if "desktop-87u7d8b" in i]
        self.assertEqual(matches, ["device:desktop-87u7d8b"])
        self.assertEqual(g.nodes["device:desktop-87u7d8b"]["role"], "host")
        self.assertEqual(g.nodes["device:desktop-87u7d8b"]["parent_id"], HP_ID)

    def test_station_capability_kept(self):
        self.assertEqual(self.neighbour(caps="0x01").nodes["device:desktop-87u7d8b"]["role"],
                         "station")

    def test_bridge_capability_stays_network_equipment(self):
        self.assertEqual(self.neighbour(caps="0x20").nodes["device:desktop-87u7d8b"]["role"],
                         "l2-switch")

    def test_unreachable_poll_target_not_relabelled(self):
        g = self.neighbour(status="unreachable", ip="172.20.99.30")
        self.assertEqual(g.nodes["device:desktop-87u7d8b"]["role"], "Unknown Network Device")

    def test_pollable_without_capabilities_unchanged(self):
        net = {"nodes": [dict(hp_switch(), lldp_cap_enabled=None)], "edges": []}
        self.assertEqual(Graph([], net).nodes[HP_ID]["role"], "Unknown Network Device")


if __name__ == "__main__":
    unittest.main()
