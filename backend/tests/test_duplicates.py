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


def box(chassis, caps, pollable=True, hostname="box", ip="172.20.99.9"):
    """A device the HP switch sees over LLDP that may also run a Wazuh agent."""
    return {"chassis_id": chassis, "ip": ip, "hostname": hostname,
            "discovery_method": "snmp_lldp", "status": "online" if pollable else "discovered",
            "pollable": pollable, "lldp_cap_enabled": caps, "uplink_ports": [], "fdb": []}


class TestMergeByWhatTheDeviceIs(unittest.TestCase):
    """Merge an agent's device twin unless it advertises bridge/router capability."""

    SERVER = "aa:bb:cc:00:20:01"
    ROUTER = "aa:bb:cc:00:10:01"

    def graph(self, device, mac):
        net = {"nodes": [hp_switch(), device],
               "edges": [lldp(device["chassis_id"], "GigabitEthernet1/0/48")]}
        return Graph([agent("009", device["hostname"], device["ip"], mac=mac)], net)

    def test_snmp_answering_server_with_agent_is_one_node(self):
        g = self.graph(box(self.SERVER, None, hostname="file-server"), self.SERVER)
        self.assertEqual(g.ids_for_mac(self.SERVER), ["endpoint:009"])
        self.assertEqual(g.nodes["endpoint:009"]["parent_id"], HP_ID)
        self.assertEqual(g.links["endpoint:009"]["local_port"], "GigabitEthernet1/0/48")
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 1)
        self.assertEqual(g.doc["metadata"]["counts"]["devices"], 1)

    def test_router_capable_device_with_agent_keeps_both_and_warns(self):
        for pollable in (True, False):
            with self.subTest(pollable=pollable):
                g = self.graph(box(self.ROUTER, "0x08", pollable, "edge-router"), self.ROUTER)
                self.assertIn(f"device:{self.ROUTER}", g.nodes)
                self.assertIn("endpoint:009", g.nodes)
                self.assertEqual(g.nodes[f"device:{self.ROUTER}"]["role"], "router")
                self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 0)
                # the topology around the router is intact
                self.assertTrue(any(e["type"] == "lldp" and e["target"] == f"device:{self.ROUTER}"
                                    for e in g.doc["edges"]))
                warnings = [w for w in g.doc["metadata"]["warnings"]
                            if w["type"] == "agent_on_network_device"]
                self.assertEqual(len(warnings), 1)
                self.assertEqual(warnings[0]["mac"], self.ROUTER)
                self.assertEqual([n["node_id"] for n in warnings[0]["nodes"]],
                                 [f"device:{self.ROUTER}", "endpoint:009"])

    def test_bridge_capable_neighbour_with_agent_not_merged(self):
        g = self.graph(box(self.ROUTER, "0x20", False, "access-sw"), self.ROUTER)
        self.assertIn(f"device:{self.ROUTER}", g.nodes)
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 0)

    def test_switch_without_agent_untouched(self):
        net = {"nodes": [hp_switch(), box(self.ROUTER, "0x28", hostname="core")],
               "edges": [lldp(self.ROUTER, "GigabitEthernet1/0/48")]}
        g = Graph([], net)
        self.assertEqual(g.nodes[f"device:{self.ROUTER}"]["role"], "l3-switch")
        self.assertEqual(g.doc["metadata"]["counts"]["devices"], 2)
        self.assertEqual(g.doc["metadata"]["warnings"], [])


class TestArpMacGuards(unittest.TestCase):
    """The ARP-only MAC (confirmed by an LLDP announcement) is never an
    infrastructure MAC or a bridge/router's MAC."""

    ROUTER = "aa:bb:cc:00:10:01"
    SERVER = "aa:bb:cc:00:20:01"

    def graph(self, device):
        net = {"nodes": [hp_switch(arp={bare(device["chassis_id"]): "172.20.99.50"}), device],
               "edges": [lldp(device["chassis_id"], "GigabitEthernet1/0/48")]}
        return Graph([agent("011", "laptop", "172.20.99.50")], net)

    def assert_not_taken(self, g, chassis):
        self.assertIn(f"device:{chassis}", g.nodes)
        self.assertIsNone(g.nodes["endpoint:011"]["mac"])
        self.assertEqual(g.doc["metadata"]["merged_lldp_endpoints"], 0)
        self.assertNotIn("agent_on_network_device",
                         [w["type"] for w in g.doc["metadata"]["warnings"]])

    def test_router_announcing_itself_is_not_merged_and_mac_not_taken(self):
        for pollable in (False, True):
            with self.subTest(pollable=pollable):
                g = self.graph(box(self.ROUTER, "0x08", pollable, "edge-router"))
                self.assert_not_taken(g, self.ROUTER)

    def test_infrastructure_mac_not_taken(self):
        # A pollable machine's own MAC is an infrastructure MAC, even with no
        # bridge/router capability: an ARP entry pointing at it proves nothing.
        g = self.graph(box(self.SERVER, None, True, "file-server"))
        self.assert_not_taken(g, self.SERVER)


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


class TestCaseD_AgentAndDiscoveredHostShareIp(unittest.TestCase):
    MANNAN_MAC = "e4:a7:a0:25:ce:ac"
    OTHER_MAC = "e8:d0:fc:ca:35:1b"

    def setUp(self):
        net = {"nodes": [hp_switch(
            fdb=[{"mac": bare(self.OTHER_MAC), "port": "GigabitEthernet1/0/9", "vlan": 80}],
            arp={bare(self.OTHER_MAC): "172.20.80.2"})], "edges": []}
        self.g = Graph([agent("001", "Mannan-PC", "172.20.80.2", mac=self.MANNAN_MAC)], net)

    def test_both_kept(self):
        self.assertIn("endpoint:001", self.g.nodes)
        self.assertIn(f"host:{self.OTHER_MAC}", self.g.nodes)
        self.assertFalse(self.g.nodes["endpoint:001"]["stale"])

    def test_one_warning_naming_both(self):
        dups = [w for w in self.g.doc["metadata"]["warnings"] if w["type"] == "duplicate_ip"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["ip"], "172.20.80.2")
        self.assertEqual(dups[0]["nodes"], [
            {"node_id": "endpoint:001", "hostname": "Mannan-PC", "status": "active",
             "stale": False},
            {"node_id": f"host:{self.OTHER_MAC}", "hostname": None, "status": "discovered",
             "stale": False},
        ])

    def test_joins_an_existing_endpoint_warning_for_that_ip(self):
        net = {"nodes": [hp_switch(
            fdb=[{"mac": bare(self.OTHER_MAC), "port": "GigabitEthernet1/0/9", "vlan": 80}],
            arp={bare(self.OTHER_MAC): "172.20.80.2"})], "edges": []}
        g = Graph([agent("001", "Mannan-PC", "172.20.80.2", mac=self.MANNAN_MAC),
                   agent("002", "Old-PC", "172.20.80.2", mac="aa:bb:cc:00:00:02",
                         status="disconnected")], net)
        dups = [w for w in g.doc["metadata"]["warnings"] if w["type"] == "duplicate_ip"]
        self.assertEqual(len(dups), 1)
        self.assertEqual([n["node_id"] for n in dups[0]["nodes"]],
                         ["endpoint:001", "endpoint:002", f"host:{self.OTHER_MAC}"])


if __name__ == "__main__":
    unittest.main()
