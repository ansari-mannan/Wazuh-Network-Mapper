"""The assembler: parenting ladder (LLDP merge / FDB / subnet), edge names."""

import unittest

from vulnmapper.assemble import assemble

# CYFOR-1's real NIC MAC == the chassis_id of the phantom LLDP device node.
CYFOR1_MAC = "d4:be:d9:98:2e:d4"
NON_LLDP_MAC = "aa:bb:cc:00:00:09"


def network_doc():
    return {
        "scan_time": "2026-06-04T12:00:00+00:00",
        "seed": "172.20.99.2",
        "nodes": [
            {"chassis_id": "core", "ip": "172.20.99.2", "hostname": "L3-Switch",
             "discovery_method": "snmp_lldp", "status": "online", "pollable": True,
             # a configured-but-empty trunk port: in uplink_ports with no edge
             "uplink_ports": ["Fa1/0/2", "Fa1/0/24"], "neighbor_ports": ["Fa1/0/2"],
             "port_status": {"Fa1/0/2": "up", "Fa1/0/24": "down"},
             "lldp_cap_enabled": "0x28", "fdb": []},
            {"chassis_id": "access", "ip": "172.20.20.2", "hostname": "L2-Switch",
             "discovery_method": "snmp_lldp", "status": "online", "pollable": True,
             "uplink_ports": ["Gi2/0/1"], "neighbor_ports": ["Gi2/0/1", "Gi2/0/13"],
             "lldp_cap_enabled": "0x20",
             # an online non-LLDP host learned on an access port
             "fdb": [{"mac": NON_LLDP_MAC, "port": "Gi2/0/7", "vlan": 20}]},
            # phantom: CYFOR-1 seen as an LLDP neighbor (its MAC == chassis_id),
            # advertising Station capabilities (0x01) in the parent's remote table
            {"chassis_id": CYFOR1_MAC, "ip": None, "hostname": None,
             "discovery_method": "snmp_lldp", "status": "discovered", "pollable": False,
             "uplink_ports": [], "lldp_cap_enabled": "0x01", "fdb": []},
        ],
        "edges": [
            {"source_chassis_id": "core", "target_chassis_id": "access",
             "local_port": "Fa1/0/2", "remote_port": "Gi2/0/1"},
            # L2-Switch reported CYFOR-1 on Gi2/0/13 (host MAC as remote port id)
            {"source_chassis_id": "access", "target_chassis_id": CYFOR1_MAC,
             "local_port": "Gi2/0/13", "remote_port": "0xd4bed9982ed4"},
        ],
    }


def endpoints():
    return [
        # Tier 1: speaks LLDP, MAC == phantom chassis_id
        {"agent_id": "004", "hostname": "CYFOR-1", "mac": CYFOR1_MAC,
         "ip": "172.20.20.21", "status": "active", "risk_score": 9.8, "top_cves": []},
        # Tier 2: online, non-LLDP, in the access switch FDB
        {"agent_id": "010", "hostname": "PRN-1", "mac": NON_LLDP_MAC,
         "ip": "172.20.20.50", "status": "active", "risk_score": 0, "top_cves": []},
        # Tier 3: offline, same subnet as L2-Switch -> subnet fallback
        {"agent_id": "003", "hostname": "CYFOR-3", "mac": None,
         "ip": "172.20.20.99", "status": "disconnected", "risk_score": 0, "top_cves": []},
        # Unparented: offline, no MAC, no same-subnet device
        {"agent_id": "007", "hostname": "ANS", "mac": None,
         "ip": "10.9.9.9", "status": "disconnected", "risk_score": 0, "top_cves": []},
    ]


class TestParentingLadder(unittest.TestCase):
    def setUp(self):
        self.doc = assemble(endpoints(), network_doc())
        self.by_id = {n["node_id"]: n for n in self.doc["nodes"]}
        self.ep_edges = {e["source"]: e for e in self.doc["edges"]
                         if e["type"] == "endpoint_link"}

    def test_phantom_device_node_removed(self):
        # The bare d4:be:d9 device node is gone; CYFOR-1 exists once, as endpoint.
        self.assertNotIn(f"device:{CYFOR1_MAC}", self.by_id)
        self.assertIn("endpoint:004", self.by_id)
        self.assertEqual(self.by_id["endpoint:004"]["kind"], "endpoint")

    def test_tier1_lldp_parent_with_switch_port(self):
        edge = self.ep_edges["endpoint:004"]
        self.assertEqual(edge["target"], "device:access")
        self.assertEqual(edge["local_port"], "Gi2/0/13")
        self.assertEqual(edge["confidence"], "lldp")
        self.assertEqual(self.by_id["endpoint:004"]["parent_id"], "device:access")
        # the host MAC must not be presented as a switch port
        self.assertNotIn("remote_port", edge)

    def test_tier2_fdb_parent(self):
        edge = self.ep_edges["endpoint:010"]
        self.assertEqual(edge["target"], "device:access")
        self.assertEqual(edge["local_port"], "Gi2/0/7")
        self.assertEqual(edge["confidence"], "resolved")

    def test_tier3_subnet_fallback(self):
        edge = self.ep_edges["endpoint:003"]
        self.assertEqual(edge["confidence"], "subnet_fallback")
        self.assertEqual(edge["target"], "device:access")  # same /24

    def test_offline_no_evidence_unparented_with_honest_reason(self):
        self.assertNotIn("endpoint:007", self.ep_edges)  # no fabricated edge
        unp = {u["node_id"]: u for u in self.doc["metadata"]["unparented_endpoints"]}
        self.assertIn("endpoint:007", unp)
        self.assertEqual(unp["endpoint:007"]["reason"], "host_offline_no_l2_evidence")

    def test_every_edge_has_names(self):
        for e in self.doc["edges"]:
            self.assertIn("source_name", e)
            self.assertIn("target_name", e)
        # spot-check a readable endpoint edge
        edge = self.ep_edges["endpoint:004"]
        self.assertEqual(edge["source_name"], "CYFOR-1")
        self.assertEqual(edge["target_name"], "L2-Switch")

    def test_counts_after_merge(self):
        counts = self.doc["metadata"]["counts"]
        self.assertEqual(counts["devices"], 2)        # phantom removed (was 3)
        self.assertEqual(counts["endpoints"], 4)
        self.assertEqual(counts["lldp_edges"], 1)     # phantom edge dropped
        self.assertEqual(counts["endpoint_edges"], 3) # 004, 010, 003
        self.assertEqual(counts["unparented_endpoints"], 1)  # 007
        self.assertEqual(self.doc["metadata"]["merged_lldp_endpoints"], 1)

    def test_node_ids_unique(self):
        ids = [n["node_id"] for n in self.doc["nodes"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_roles_from_caps_and_fallback(self):
        # L3-Switch (router+bridge) / L2-Switch (bridge) from LLDP caps; CYFOR-1
        # inherits "station" from the caps it advertised; the plain Wazuh endpoint
        # PRN-1 has no caps -> "host".
        self.assertEqual(self.by_id["device:core"]["role"], "l3-switch")
        self.assertEqual(self.by_id["device:access"]["role"], "l2-switch")
        self.assertEqual(self.by_id["endpoint:004"]["role"], "station")
        self.assertEqual(self.by_id["endpoint:010"]["role"], "host")

    def test_neighbor_uplink_split_and_port_status_preserved(self):
        access = self.by_id["device:access"]
        # access port Gi2/0/13 is a neighbor port but NOT an uplink
        self.assertIn("Gi2/0/13", access["neighbor_ports"])
        self.assertNotIn("Gi2/0/13", access["uplink_ports"])
        self.assertEqual(access["uplink_ports"], ["Gi2/0/1"])
        # the L3-Switch's configured-but-empty trunk survives with no edge
        core = self.by_id["device:core"]
        self.assertIn("Fa1/0/24", core["uplink_ports"])
        edge_ports = {e.get("local_port") for e in self.doc["edges"]}
        self.assertNotIn("Fa1/0/24", edge_ports)
        self.assertEqual(core["port_status"]["Fa1/0/24"], "down")


SCANNER_MAC = "d4:be:d9:97:f4:ca"
ANS_MAC = "28:f1:0e:31:3f:0c"
SVI_MAC = "00:23:ac:e5:74:41"


class TestFdbArpDiscovery(unittest.TestCase):
    """The FDB+ARP host-discovery track: new hosts, enrichment, SVI exclusion."""

    def setUp(self):
        net = {
            "scan_time": "2026-06-06T00:00:00+00:00",
            "nodes": [{
                "chassis_id": "00:23:ac:e5:74:00", "ip": "172.20.40.254",
                "hostname": "L3-Switch", "discovery_method": "snmp_lldp",
                "status": "online", "pollable": True,
                "uplink_ports": ["Gi0/1"],
                "own_macs": [SVI_MAC, "00:23:ac:e5:74:00"],
                "arp": {SCANNER_MAC.replace(":", ""): "172.20.40.1",
                        ANS_MAC.replace(":", ""): "172.20.99.21"},
                "fdb": [
                    {"mac": SCANNER_MAC.replace(":", ""), "port": "Fa1/0/3", "vlan": 40},
                    {"mac": ANS_MAC.replace(":", ""), "port": "Fa1/0/5", "vlan": 99},
                    {"mac": SVI_MAC.replace(":", ""), "port": "Vl40", "vlan": 40},
                    {"mac": "aaaaaaaaaaaa", "port": "Gi0/1", "vlan": 1},  # transit on uplink
                ],
            }],
            "edges": [],
        }
        # ANS-Laptop: offline, Wazuh gave no MAC, but it's in the FDB/ARP.
        eps = [{"agent_id": "007", "hostname": "ANS-Laptop", "mac": None,
                "ip": "172.20.99.21", "status": "disconnected", "risk_score": 0,
                "top_cves": []}]
        self.doc = assemble(eps, net)
        self.by_id = {n["node_id"]: n for n in self.doc["nodes"]}
        self.ep_edges = {e["source"]: e for e in self.doc["edges"]
                         if e["type"] == "endpoint_link"}

    def test_scanner_host_discovered_with_no_special_casing(self):
        node = self.by_id[f"host:{SCANNER_MAC}"]
        self.assertEqual(node["discovery_method"], "snmp_fdb")
        self.assertEqual(node["ip"], "172.20.40.1")
        self.assertEqual(node["mac"], SCANNER_MAC)
        self.assertIsNone(node["risk_score"])
        self.assertEqual(node["role"], "host")  # sensible fallback for an FDB host
        edge = self.ep_edges[f"host:{SCANNER_MAC}"]
        self.assertEqual(edge["target"], "device:00:23:ac:e5:74:00")
        self.assertEqual(edge["local_port"], "Fa1/0/3")
        self.assertEqual(edge["confidence"], "fdb")

    def test_svi_gateway_mac_not_a_host(self):
        self.assertNotIn(f"host:{SVI_MAC}", self.by_id)

    def test_transit_mac_on_uplink_not_a_host(self):
        self.assertNotIn("host:aa:aa:aa:aa:aa:aa", self.by_id)

    def test_offline_endpoint_enriched_by_ip(self):
        ans = self.by_id["endpoint:007"]
        self.assertEqual(ans["mac"], ANS_MAC)             # MAC filled from the table
        self.assertEqual(ans["parent_id"], "device:00:23:ac:e5:74:00")
        self.assertEqual(self.ep_edges["endpoint:007"]["local_port"], "Fa1/0/5")
        # ANS must NOT also appear as a discovered host (it was enriched, not duped)
        self.assertNotIn(f"host:{ANS_MAC}", self.by_id)

    def test_metadata_counts(self):
        self.assertEqual(self.doc["metadata"]["fdb_discovered_hosts"], 1)
        self.assertEqual(self.doc["metadata"]["fdb_enriched_nodes"], 1)


if __name__ == "__main__":
    unittest.main()
