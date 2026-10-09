"""Hosts without a Wazuh agent: the unmanaged label and the coverage numbers.

A hand-made network document with one host from each of the four sources a
host without an agent can come from; nothing touches the network.
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock

from test_cdp import crawl, lab
from vulnmapper import hosts
from vulnmapper.assemble import assemble
from vulnmapper.pipeline import Pipeline

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
             "vendor": "Microsoft", "status": "active", "risk_score": 4.0},
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


class TestMacClues(unittest.TestCase):
    def test_manufacturer_from_the_registry(self):
        self.assertEqual(hosts.manufacturer("00:50:56:aa:00:01"), "VMware, Inc.")
        self.assertEqual(hosts.manufacturer("E4-A7-A0-25-CE-AC"), "Intel Corporate")
        self.assertIsNone(hosts.manufacturer("not a mac"))

    def test_longest_block_wins_and_the_authority_is_not_a_maker(self):
        registry = {"70b3d5": hosts.REGISTRY_AUTHORITY, "70b3d5123": "Small Maker"}
        with unittest.mock.patch.object(hosts, "_registry", lambda: registry):
            self.assertEqual(hosts.manufacturer("70:b3:d5:12:34:56"), "Small Maker")
            self.assertIsNone(hosts.manufacturer("70:b3:d5:99:99:99"))

    def test_locally_administered_addresses_have_no_manufacturer(self):
        # a phone's randomised Wi-Fi address, and a QEMU/KVM virtual machine's
        for mac in ("7a:bd:06:18:06:2c", "52:54:00:12:34:56"):
            self.assertEqual(hosts.mac_type(mac), "local", mac)
            self.assertIsNone(hosts.manufacturer(mac), mac)
        self.assertEqual(hosts.mac_type("00:50:56:aa:00:01"), "global")

    def test_on_every_host_with_a_mac_and_vendor_untouched(self):
        nodes = {n["node_id"]: n for n in assemble(agents(), network_doc())["nodes"]}
        fdb = nodes[f"host:{FDB_HOST}"]
        self.assertEqual((fdb["mac_type"], fdb["mac_vendor"]), ("global", "VMware, Inc."))
        wifi = nodes[f"host:{WIFI_HOST}"]
        self.assertEqual((wifi["mac_type"], wifi["mac_vendor"]), ("local", None))
        agent = nodes["endpoint:001"]                   # managed hosts get it too
        self.assertEqual((agent["vendor"], agent["mac_vendor"]), ("Microsoft", "VMware, Inc."))
        self.assertNotIn("mac_type", nodes["endpoint:000"])   # no MAC: no clue
        self.assertNotIn("mac_vendor", nodes[f"device:{SWITCH}"])

    def test_registry_records_its_source_and_date(self):
        import gzip
        with gzip.open(hosts.REGISTRY, "rt", encoding="utf-8") as fh:
            header = [line for line in fh.read(2000).splitlines() if line.startswith("#")]
        self.assertTrue(any(line.startswith("# source: https://standards-oui.ieee.org/")
                            for line in header))
        self.assertTrue(any(line.startswith("# date: ") for line in header))


class TestNames(unittest.TestCase):
    def graph(self):
        return assemble(agents(), network_doc())

    def test_fills_only_hosts_without_a_name(self):
        asked = []

        def resolver(ip):
            asked.append(ip)
            if ip == "10.0.0.30":
                raise OSError("no PTR record")        # costs nothing but its time
            return f"name-{ip}"
        graph = self.graph()
        block = hosts.lookup_names(graph, resolver)
        nodes = {n["node_id"]: n for n in graph["nodes"]}
        # FDB host (10.0.0.20) and Wi-Fi client (10.0.0.30) had no name; the CDP
        # host and the agents had one, the LLDP host has no address
        self.assertEqual(sorted(asked), ["10.0.0.20", "10.0.0.30"])
        fdb = nodes[f"host:{FDB_HOST}"]
        self.assertEqual((fdb["hostname"], fdb["name_source"]), ("name-10.0.0.20", "dns"))
        self.assertNotIn("name_source", nodes[f"host:{WIFI_HOST}"])
        self.assertEqual(nodes[f"host:{CDP_HOST}"]["hostname"], "printer-1")
        self.assertNotIn("name_source", nodes["endpoint:001"])
        self.assertEqual(block, {"asked": 2, "named": 1, "budget_reached": False})
        edge = next(e for e in graph["edges"] if e["source"] == f"host:{FDB_HOST}")
        self.assertEqual(edge["source_name"], "name-10.0.0.20")

    def test_a_slow_answer_is_not_waited_for(self):
        release = threading.Event()

        def slow(ip):
            release.wait(5)
            return "late"
        graph = self.graph()
        t0 = time.monotonic()
        block = hosts.lookup_names(graph, slow, timeout_s=0.05)
        self.assertLess(time.monotonic() - t0, 1.0)
        release.set()
        self.assertEqual(block["named"], 0)
        self.assertFalse(any(n.get("name_source") for n in graph["nodes"]))

    def test_the_budget_stops_further_lookups(self):
        graph = {"nodes": [{"node_id": f"host:{i}", "kind": "endpoint", "ip": f"10.1.0.{i}",
                            "hostname": None} for i in range(10)], "edges": []}
        block = hosts.lookup_names(graph, lambda ip: time.sleep(0.1) or "x",
                                   timeout_s=0.2, budget_s=0.15, parallel=2)
        self.assertTrue(block["budget_reached"])
        self.assertLess(block["asked"], 10)

    def test_defaults(self):
        self.assertEqual((hosts.LOOKUP_TIMEOUT_S, hosts.LOOKUP_BUDGET_S), (1.0, 5.0))


class TestPipeline(unittest.TestCase):
    """The lab crawl's two Wi-Fi clients have an address and no name."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        with open(self.network, "w") as f:
            json.dump(crawl(lab()), f)
        self.asked = []

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra):
        def resolver(ip):
            self.asked.append(ip)
            return f"pc-{ip.split('.')[-1]}.lab"
        path = os.path.join(self.tmp, "graph.json")
        argv = ["--no-endpoints", "--no-device-cves", "--no-checklist",
                "--network", self.network, "-o", path, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline(resolver=resolver).run(argv), 0)
        with open(path) as f:
            return json.load(f)

    def test_off_asks_nothing(self):
        graph = self.run_pipeline("--no-name-lookup")
        self.assertEqual(self.asked, [])
        self.assertNotIn("name_lookup", graph["metadata"])

    def test_on_adds_only_the_names(self):
        off = self.run_pipeline("--no-name-lookup")
        on = self.run_pipeline()
        self.assertEqual(sorted(self.asked), ["172.20.80.1", "172.20.80.3"])
        self.assertEqual(on["metadata"]["name_lookup"],
                         {"asked": 2, "named": 2, "budget_reached": False})
        self.assertIsInstance(on["metadata"]["timing"]["name_lookup_s"], float)
        before = {n["node_id"]: n for n in off["nodes"]}
        for node in on["nodes"]:
            was = dict(before[node["node_id"]])
            if node.get("name_source"):
                self.assertEqual(node["name_source"], "dns")
                was.update(hostname=node["hostname"], name_source="dns")
            self.assertEqual(node, was)
        self.assertEqual(sum(bool(n.get("name_source")) for n in on["nodes"]), 2)


if __name__ == "__main__":
    unittest.main()
