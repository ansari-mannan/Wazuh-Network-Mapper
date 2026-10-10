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

from snmp_fakes import FakeSnmpClient, load_rows
from test_cdp import L2_CID, crawl, lab
from test_device_stage import lab_nvd
from test_nvd import FakeClock
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
        argv = ["--no-endpoints", "--no-device-cves", "--no-cve-vectors", "--network", self.network, "-o", path,
                *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline(resolver=resolver).run(argv), 0)
        with open(path) as f:
            return json.load(f)

    def test_off_asks_nothing(self):
        graph = self.run_pipeline("--no-name-lookup")
        self.assertEqual(self.asked, [])
        self.assertNotIn("name_lookup", graph["metadata"])

    def test_options_off_give_todays_document_plus_the_additions(self):
        """Against the output of 13e6ebd (main before this work) on the same crawl."""
        from snmp_fakes import FIXTURES
        with open(os.path.join(FIXTURES, "pipeline_lab_13e6ebd.json")) as f:
            today = json.load(f)
        graph = self.run_pipeline("--no-name-lookup")
        self.assertEqual(graph["edges"], today["edges"])
        self.assertEqual(len(graph["nodes"]), len(today["nodes"]))
        replaced = {"ports-enabled-unused", "spare-ports-in-used-vlan"}    # Part 2
        for node, was in zip(graph["nodes"], today["nodes"]):
            self.assertEqual("unmanaged" in node, node["kind"] == "endpoint")
            node = {k: v for k, v in node.items() if k not in ("unmanaged", "mac_type",
                                                                 "mac_vendor")}
            for n in (node, was):
                if "config_checks" in n:
                    n["config_checks"] = [c for c in n["config_checks"] if c["id"] not in replaced]
            self.assertEqual(node, was)
        meta = dict(graph["metadata"])
        for key in ("scan_time", "timing", "network_scan_time"):
            meta.pop(key)
        self.assertEqual(meta.pop("coverage"), {"hosts": 2, "managed": 0, "unmanaged": 2,
                                                "managed_share": 0.0})
        self.assertIs(meta["checklist"].pop("port_test_enabled"), False)
        self.assertEqual(meta, today["metadata"])

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


SILENT = ("00:50:56:bb:00:01", "10.0.0.60")
ANSWERS = ("00:50:56:bb:00:02", "10.0.0.50")
FORWARDS = (L2_CID, "172.20.10.100")        # the lab's L2 switch, seen as a host
SYSTEM_AND_INVENTORY = ("1.3.6.1.2.1.1.", "1.3.6.1.2.1.47.")


class TestSnmpQuestion(unittest.TestCase):
    """Three unmanaged hosts on one switch: silent, answering, forwarding."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        hosts_ = (SILENT, ANSWERS, FORWARDS)
        switch = {"chassis_id": SWITCH, "ip": "10.0.0.1", "hostname": "core", "status": "online",
                  "pollable": True, "lldp_cap_enabled": "0x2800",
                  "fdb": [{"mac": mac, "port": f"Fa0/{i + 2}", "vlan": 10}
                          for i, (mac, _ip) in enumerate(hosts_)],
                  "arp": {mac: ip for mac, ip in hosts_}}
        with open(self.network, "w") as f:
            json.dump({"nodes": [switch], "edges": []}, f)
        l2 = load_rows("cisco_l2_switch.snmp")
        # a machine that answers SNMP but has no neighbour or forwarding table
        system = [r for r in l2 if r[0].startswith(SYSTEM_AND_INVENTORY)]
        self.client = FakeSnmpClient({ANSWERS[1]: system, FORWARDS[1]: l2})

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra):
        path = os.path.join(self.tmp, "graph.json")
        argv = ["--no-endpoints", "--no-name-lookup", "--no-checklist",
                "--network", self.network, "-o", path, *extra]
        clock = FakeClock()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = Pipeline(nvd_transport=lab_nvd(clock), clock=clock,
                            snmp_client=self.client).run(argv)
        self.assertEqual(code, 0)
        with open(path) as f:
            graph = json.load(f)
        return graph, {n["node_id"]: n for n in graph["nodes"]}

    def test_off_makes_no_request(self):
        graph, _ = self.run_pipeline()
        self.assertEqual(self.client.calls, [])
        self.assertNotIn("snmp_question", graph["metadata"])

    def test_each_unmanaged_host_asked_once_never_a_default_name(self):
        graph, _ = self.run_pipeline("--probe-unmanaged-snmp")
        resolves = [c[1] for c in self.client.calls if c[0] == "resolve"]
        for _mac, ip in (SILENT, ANSWERS):
            self.assertEqual(resolves.count(ip), 1, ip)
        self.assertNotIn("probe", {c[0] for c in self.client.calls})
        self.assertEqual(graph["metadata"]["snmp_question"],
                         {"asked": 3, "answered": 2, "forwarding": 1, "cap": 256,
                          "cap_reached": False})

    def test_an_answering_host_gains_identity_and_cves(self):
        _, nodes = self.run_pipeline("--probe-unmanaged-snmp")
        host = nodes[f"host:{ANSWERS[0]}"]
        self.assertEqual(host["kind"], "endpoint")
        self.assertTrue(host["snmp"] and host["unmanaged"])
        self.assertEqual((host["hostname"], host["name_source"]), ("L2-Switch", "snmp"))
        self.assertIn("Cisco IOS Software", host["sys_descr"])
        self.assertEqual((host["vendor"], host["firmware"], host["software_family"]),
                         ("Cisco", "12.2(58)SE2", "cisco_ios"))
        # the device CVE stage, as for a device
        self.assertEqual(host["cve_lookup"]["status"], "ok")
        self.assertEqual(host["max_cvss"], 9.8)
        self.assertIsNotNone(host["risk_score"])
        self.assertEqual(host["cve_summary"]["total"], 2)

    def test_a_forwarding_host_joins_the_crawl(self):
        graph, nodes = self.run_pipeline("--probe-unmanaged-snmp")
        self.assertNotIn(f"host:{FORWARDS[0]}", nodes)
        device = nodes[f"device:{L2_CID}"]
        self.assertTrue(device["pollable"])
        self.assertEqual(device["hostname"], "L2-Switch")
        self.assertTrue(device["unmanaged"] and device["snmp"])
        self.assertEqual(device["cve_lookup"]["status"], "ok")
        # a device, so no longer counted as a host
        self.assertEqual(graph["metadata"]["coverage"]["hosts"], 2)

    def test_a_silent_host_is_unchanged(self):
        before, _ = self.run_pipeline()
        _, after = self.run_pipeline("--probe-unmanaged-snmp")
        was = {n["node_id"]: n for n in before["nodes"]}[f"host:{SILENT[0]}"]
        self.assertEqual(after[f"host:{SILENT[0]}"], was)
        self.assertNotIn("snmp", was)

    def test_the_cap(self):
        graph = {"nodes": [{"node_id": f"host:{i}", "kind": "endpoint", "unmanaged": True,
                            "ip": f"10.1.0.{i}"} for i in range(5)]
                 + [{"node_id": "endpoint:1", "kind": "endpoint", "unmanaged": False,
                     "ip": "10.1.1.1"}, {"node_id": "host:x", "kind": "endpoint",
                                         "unmanaged": True, "ip": None}]}
        targets, capped = hosts.question_targets(graph, cap=3)
        self.assertEqual([n["node_id"] for n in targets], ["host:0", "host:1", "host:2"])
        self.assertTrue(capped)
        self.assertEqual(hosts.question_targets(graph)[1], False)
        self.assertEqual(hosts.QUESTION_CAP, 256)

    def test_the_owners_credentials_one_attempt(self):
        made = []

        class Recorder(FakeSnmpClient):
            def __init__(self, credentials, **kw):
                made.append((credentials, kw))
                super().__init__({})
        clean = {k: v for k, v in os.environ.items() if not k.startswith("SNMP_")}
        with unittest.mock.patch("vulnmapper.network.snmp.SnmpClient", Recorder), \
                unittest.mock.patch.dict(os.environ, clean, clear=True):
            path = os.path.join(self.tmp, "g.json")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                Pipeline().run(["--no-endpoints", "--no-name-lookup", "--no-checklist",
                                "--no-device-cves", "--no-cve-vectors", "--network", self.network, "-o", path,
                                "--probe-unmanaged-snmp", "--community", "site-secret"])
        (credentials, kw), = made
        self.assertEqual([c.community for c in credentials], ["site-secret"])
        self.assertEqual(kw, {"timeout": 1.0, "retries": 0})


if __name__ == "__main__":
    unittest.main()
