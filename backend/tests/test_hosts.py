"""Hosts without a Wazuh agent: the unmanaged label and the coverage numbers.

A hand-made network document with one host from each of the four sources a
host without an agent can come from; nothing touches the network.
"""

import unittest

from vulnmapper.assemble import assemble

SWITCH = "00:11:22:33:44:01"
AP = "00:11:22:33:44:02"
FDB_HOST = "00:50:56:aa:00:01"
LLDP_HOST = "00:50:56:aa:00:02"
CDP_HOST = "cdp:printer-1"
WIFI_HOST = "7a:bd:06:18:06:2c"
AGENT_MAC = "00:50:56:aa:00:09"


def network_doc():
    switch = {"chassis_id": SWITCH, "ip": "10.0.0.1", "status": "online", "pollable": True,
              "lldp_cap_enabled": "0x2800", "uplink_ports": ["Gi0/1"],
              "fdb": [{"mac": FDB_HOST, "port": "Fa0/3", "vlan": 10},
                      {"mac": AGENT_MAC, "port": "Fa0/4", "vlan": 10}],
              "arp": {FDB_HOST: "10.0.0.20"}}
    ap = {"chassis_id": AP, "ip": "10.0.0.2", "status": "online", "pollable": True,
          "access_point": True, "fdb": [],
          "wifi_clients": [{"mac": WIFI_HOST, "ip": "10.0.0.30", "ssid": "s", "radio": 0}]}
    lldp_host = {"chassis_id": LLDP_HOST, "hostname": "pc-7", "status": "discovered",
                 "pollable": False}
    cdp_host = {"chassis_id": CDP_HOST, "hostname": "printer-1", "ip": "10.0.0.40",
                "status": "discovered", "pollable": False, "discovery_method": "snmp_cdp"}
    edges = [{"source_chassis_id": SWITCH, "target_chassis_id": AP, "local_port": "Gi0/1"},
             {"source_chassis_id": SWITCH, "target_chassis_id": LLDP_HOST, "local_port": "Fa0/5"},
             {"source_chassis_id": SWITCH, "target_chassis_id": CDP_HOST, "local_port": "Fa0/6",
              "protocol": "cdp"}]
    return {"nodes": [switch, ap, lldp_host, cdp_host], "edges": edges}


def agents():
    return [{"agent_id": "000", "hostname": "wazuh", "ip": "10.0.0.5", "status": "active",
             "is_wazuh_server": True, "risk_score": 0.0},
            {"agent_id": "001", "hostname": "pc-1", "ip": "10.0.0.9", "mac": AGENT_MAC,
             "status": "active", "risk_score": 4.0},
            {"agent_id": "002", "hostname": "pc-2", "ip": "10.0.0.10", "status": "disconnected",
             "risk_score": 2.0}]


class TestUnmanaged(unittest.TestCase):
    def setUp(self):
        self.graph = assemble(agents(), network_doc())
        self.nodes = {n["node_id"]: n for n in self.graph["nodes"]}

    def test_each_source_without_an_agent_is_unmanaged(self):
        for node_id, method in ((f"host:{FDB_HOST}", "snmp_fdb"),
                                (f"host:{LLDP_HOST}", "lldp"),
                                (f"host:{CDP_HOST}", "cdp"),
                                (f"host:{WIFI_HOST}", "snmp_wifi")):
            node = self.nodes[node_id]
            self.assertEqual(node["discovery_method"], method, node_id)
            self.assertIs(node["unmanaged"], True, node_id)
            self.assertIsNone(node["risk_score"], node_id)

    def test_agents_are_managed_active_or_not_and_the_server_too(self):
        for agent_id in ("000", "001", "002"):
            self.assertIs(self.nodes[f"endpoint:{agent_id}"]["unmanaged"], False, agent_id)

    def test_network_devices_are_neither(self):
        for chassis in (SWITCH, AP):
            self.assertNotIn("unmanaged", self.nodes[f"device:{chassis}"])

    def test_coverage(self):
        self.assertEqual(self.graph["metadata"]["coverage"],
                         {"hosts": 7, "managed": 3, "unmanaged": 4, "managed_share": 0.429})

    def test_coverage_with_no_hosts(self):
        graph = assemble([], {"nodes": [], "edges": []})
        self.assertEqual(graph["metadata"]["coverage"],
                         {"hosts": 0, "managed": 0, "unmanaged": 0, "managed_share": None})


if __name__ == "__main__":
    unittest.main()
