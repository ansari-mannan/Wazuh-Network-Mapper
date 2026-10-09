"""Manager-API inventory: the Wazuh server (agent 000), syscollector retries,
and telling an agent Wazuh has not examined yet from a clean one. HTTP is mocked."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import requests

from test_cves import FakeIndexer, FakeManager, Outcomes, doc, http_error, score, source
from vulnmapper import endpoints as ep_mod
from vulnmapper.assemble import assemble
from vulnmapper.endpoints import server_ipv4
from vulnmapper.pipeline import Pipeline

# The lab's Wazuh server as the switches see it: a locally-administered MAC,
# which the MAC selection rules never pick.
SERVER_MAC = "c6:6f:b8:f1:1e:ae"
SERVER_IP = "172.20.40.1"

SERVER_AGENT = {"id": "000", "name": "wazuh-server", "ip": "127.0.0.1", "status": "active",
                "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "24.04"}}
PC_AGENT = {"id": "001", "name": "PC-1", "ip": "172.20.40.11", "status": "active",
            "os": {"platform": "windows", "name": "Windows 11", "version": "10.0"}}


def addr(iface, ip):
    return {"iface": iface, "proto": "ipv4", "address": ip}


def proto(iface, gateway):
    return {"iface": iface, "type": "ipv4", "gateway": gateway}


def server_routes(netiface, netaddr, netproto):
    return {
        "/agents": [SERVER_AGENT, PC_AGENT],
        "/syscollector/000/netiface": netiface,
        "/syscollector/000/netaddr": netaddr,
        "/syscollector/000/netproto": netproto,
        "/syscollector/001/netiface": [{"name": "eth0", "mac": "d4:be:d9:97:f6:a2", "state": "up"}],
        "/syscollector/001/netaddr": [addr("eth0", "172.20.40.11")],
    }


# The lab server: ens18 carries the real address and the gateway; a second,
# physical NIC (eth1) that the switches never see; plus docker0 and loopback.
LAB_NETIFACE = [
    {"name": "lo", "mac": "00:00:00:00:00:00", "state": "up"},
    {"name": "eth1", "mac": "d4:be:d9:aa:bb:cc", "state": "up"},
    {"name": "ens18", "mac": SERVER_MAC, "state": "up"},
    {"name": "docker0", "mac": "02:42:ac:11:00:01", "state": "up"},
]
LAB_NETADDR = [addr("lo", "127.0.0.1"), addr("docker0", "172.17.0.1"),
               addr("eth1", "10.99.0.5"), addr("ens18", SERVER_IP)]
LAB_NETPROTO = [proto("eth1", " "), proto("ens18", "172.20.40.254")]


def collect(routes):
    """Run WazuhSource.collect against a FakeManager; returns (src, nodes, sleep mock, manager)."""
    src = source()
    manager = FakeManager(routes)
    with mock.patch.object(ep_mod.WazuhSource, "_authenticate"), \
            mock.patch.object(ep_mod.requests, "get", manager), \
            mock.patch.object(ep_mod.time, "sleep") as sleep, \
            contextlib.redirect_stderr(io.StringIO()):
        nodes = src.collect()
    return src, nodes, sleep, manager


class TestServerAddressFallbackOrder(unittest.TestCase):
    def test_gateway_interface_wins_even_when_listed_later(self):
        self.assertEqual(server_ipv4(LAB_NETADDR, LAB_NETPROTO), SERVER_IP)

    def test_without_gateway_first_usable_ipv4(self):
        self.assertEqual(server_ipv4(LAB_NETADDR, []), "10.99.0.5")

    def test_skips_loopback_link_local_and_bridges(self):
        netaddr = [addr("lo", "127.0.0.1"), addr("eth0", "169.254.10.2"),
                   addr("docker0", "172.17.0.1"), addr("br-3f2a", "172.18.0.1"),
                   addr("veth12", "10.0.0.9"), addr("eth0", "192.168.5.20")]
        self.assertEqual(server_ipv4(netaddr, []), "192.168.5.20")

    def test_gateway_on_an_unusable_address_falls_through(self):
        netaddr = [addr("docker0", "172.17.0.1"), addr("eth0", "192.168.5.20")]
        self.assertEqual(server_ipv4(netaddr, [proto("docker0", "172.17.0.254")]),
                         "192.168.5.20")

    def test_ipv6_and_empty_gateways_ignored(self):
        netaddr = [{"iface": "eth0", "proto": "ipv6", "address": "fe80::1"},
                   addr("eth0", "192.168.5.20")]
        self.assertEqual(server_ipv4(netaddr, [proto("eth0", "")]), "192.168.5.20")

    def test_none_when_nothing_usable(self):
        self.assertIsNone(server_ipv4([addr("lo", "127.0.0.1"),
                                       addr("docker0", "172.17.0.1")], []))
        self.assertIsNone(server_ipv4([], []))


class TestWazuhServerMerged(unittest.TestCase):
    """Agent 000 with its real address merges with its switch-table twin."""

    def setUp(self):
        _src, self.nodes, _sleep, _m = collect(
            server_routes(LAB_NETIFACE, LAB_NETADDR, LAB_NETPROTO))
        self.server = next(n for n in self.nodes if n["agent_id"] == "000")
        network = {"nodes": [{
            "chassis_id": "00:23:ac:e5:74:00", "ip": "172.20.40.254", "hostname": "L3-Switch",
            "status": "online", "pollable": True, "uplink_ports": [],
            "own_macs": ["00:23:ac:e5:74:00"],
            "arp": {SERVER_MAC.replace(":", ""): SERVER_IP},
            "fdb": [{"mac": SERVER_MAC.replace(":", ""), "port": "Fa1/0/1", "vlan": 40}],
        }], "edges": []}
        self.doc = assemble(self.nodes, network)

    def test_collect_includes_server_with_real_address(self):
        self.assertEqual(self.server["ip"], SERVER_IP)
        self.assertTrue(self.server["is_wazuh_server"])
        self.assertNotIn("is_wazuh_server", next(n for n in self.nodes if n["agent_id"] == "001"))

    def test_mac_only_from_the_interface_with_that_address(self):
        # ens18's MAC is locally administered, so none is chosen; eth1 is
        # physical but carries another address, so it must not be picked.
        self.assertIsNone(self.server["mac"])

    def test_merged_into_one_parented_node(self):
        at_server_ip = [n for n in self.doc["nodes"] if n["ip"] == SERVER_IP]
        self.assertEqual([n["node_id"] for n in at_server_ip], ["endpoint:000"])
        node = at_server_ip[0]
        self.assertTrue(node["is_wazuh_server"])
        self.assertEqual(node["mac"], SERVER_MAC)            # filled from the table
        self.assertEqual(node["parent_id"], "device:00:23:ac:e5:74:00")
        self.assertNotIn(f"host:{SERVER_MAC}", {n["node_id"] for n in self.doc["nodes"]})
        self.assertEqual(self.doc["metadata"]["fdb_discovered_hosts"], 0)

    def test_flag_absent_on_other_nodes(self):
        others = [n for n in self.doc["nodes"] if n["node_id"] != "endpoint:000"]
        self.assertTrue(all("is_wazuh_server" not in n for n in others))


class TestWazuhServerSkipped(unittest.TestCase):
    ONLY_INTERNAL = ([{"name": "lo", "mac": "00:00:00:00:00:00"},
                      {"name": "docker0", "mac": "02:42:ac:11:00:01"}],
                     [addr("lo", "127.0.0.1"), addr("docker0", "172.17.0.1")], [])

    def test_no_real_address_skips_server_with_note(self):
        src, nodes, _sleep, _m = collect(server_routes(*self.ONLY_INTERNAL))
        self.assertEqual([n["agent_id"] for n in nodes], ["001"])
        self.assertEqual(len(src.collect_warnings), 1)
        note = src.collect_warnings[0]
        self.assertEqual(note["type"], "wazuh_server_skipped")
        self.assertEqual(note["agent_id"], "000")

    def test_unreadable_inventory_skips_server_not_listed_as_unavailable(self):
        routes = server_routes(*self.ONLY_INTERNAL)
        routes["/syscollector/000/netiface"] = Outcomes(http_error(500), http_error(500))
        src, nodes, _sleep, _m = collect(routes)
        self.assertEqual([n["agent_id"] for n in nodes], ["001"])
        self.assertEqual([w["type"] for w in src.collect_warnings], ["wazuh_server_skipped"])
        self.assertIn("could not be read", src.collect_warnings[0]["reason"])

    def test_skip_note_reaches_graph_metadata(self):
        manager = FakeManager(server_routes(*self.ONLY_INTERNAL))
        env = {"WAZUH_PASS": "x", "INDEXER_PASS": "y"}
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env), \
                mock.patch.object(ep_mod.WazuhSource, "_authenticate"), \
                mock.patch.object(ep_mod.requests, "get", manager), \
                mock.patch.object(ep_mod.requests, "post", FakeIndexer({})), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertLogs("vulnmapper.pipeline", "INFO"):
                Pipeline().run(["--no-network", "--no-name-lookup", "-o", os.path.join(tmp, "g.json"),
                                "--no-device-cves"])
            with open(os.path.join(tmp, "g.json")) as f:
                graph = json.load(f)
        self.assertNotIn("endpoint:000", {n["node_id"] for n in graph["nodes"]})
        self.assertIn("wazuh_server_skipped",
                      [w["type"] for w in graph["metadata"]["warnings"]])


class TestInventoryRetry(unittest.TestCase):
    def routes(self, outcome_001_netiface):
        routes = server_routes(LAB_NETIFACE, LAB_NETADDR, LAB_NETPROTO)
        routes["/syscollector/001/netiface"] = outcome_001_netiface
        return routes

    def test_5xx_retried_once_after_3s(self):
        good = [{"name": "eth0", "mac": "d4:be:d9:97:f6:a2", "state": "up"}]
        src, nodes, sleep, _m = collect(self.routes(Outcomes(http_error(500), good)))
        sleep.assert_called_once_with(3)
        pc = next(n for n in nodes if n["agent_id"] == "001")
        self.assertEqual(pc["mac"], "d4:be:d9:97:f6:a2")
        self.assertEqual(src.collect_warnings, [])

    def test_timeout_retried_once(self):
        good = [{"name": "eth0", "mac": "d4:be:d9:97:f6:a2", "state": "up"}]
        src, _nodes, sleep, _m = collect(self.routes(Outcomes(requests.Timeout("slow"), good)))
        sleep.assert_called_once_with(3)
        self.assertEqual(src.collect_warnings, [])

    def test_second_failure_warns_inventory_unavailable(self):
        src, nodes, sleep, manager = collect(
            self.routes(Outcomes(requests.Timeout("slow"), http_error(500))))
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            [p for p, _ in manager.calls].count("/syscollector/001/netiface"), 2)
        pc = next(n for n in nodes if n["agent_id"] == "001")   # kept, without inventory
        self.assertIsNone(pc["mac"])
        self.assertEqual(src.collect_warnings, [{
            "type": "inventory_unavailable", "agents": ["001"],
            "node_ids": ["endpoint:001"]}])

    def test_4xx_not_retried_but_reported(self):
        src, _nodes, sleep, _m = collect(self.routes(Outcomes(http_error(404))))
        sleep.assert_not_called()
        self.assertEqual(src.collect_warnings[0]["agents"], ["001"])


class TestNotYetInventoried(unittest.TestCase):
    AGENTS = [{"agent_id": "001", "hostname": "new-pc"}, {"agent_id": "002", "hostname": "clean"},
              {"agent_id": "003", "hostname": "vulnerable"}]

    def run_score(self, packages_001):
        manager = FakeManager({"/syscollector/001/packages": packages_001})
        src, out = score(self.AGENTS, FakeIndexer({"003": [doc("CVE-1", 9.8)]}), manager)
        return src, {a["agent_id"]: a for a in out}, manager

    def test_no_documents_and_no_packages_is_unscored(self):
        src, by_id, manager = self.run_score([])
        new = by_id["001"]
        self.assertIsNone(new["risk_score"])
        self.assertIsNone(new["cve_summary"])
        self.assertIsNone(new["findings"])
        self.assertIn(("/syscollector/001/packages", {"limit": 1}), manager.calls)
        self.assertEqual(src.warnings, [{
            "type": "not_yet_inventoried", "agents": ["001"], "node_ids": ["endpoint:001"]}])

    def test_no_documents_with_packages_scores_zero(self):
        src, by_id, _m = self.run_score([{"name": "bash"}])
        self.assertEqual(by_id["001"]["risk_score"], 0.0)
        self.assertEqual(by_id["001"]["cve_summary"]["total"], 0)
        self.assertEqual(src.warnings, [])

    def test_only_agents_without_documents_are_checked(self):
        _src, _by_id, manager = self.run_score([])
        checked = [p for p, _ in manager.calls if p.endswith("/packages")]
        self.assertEqual(checked, ["/syscollector/001/packages", "/syscollector/002/packages"])

    def test_failed_check_leaves_unscored_and_reports(self):
        src, by_id, _m = self.run_score(Outcomes(http_error(500), http_error(503)))
        self.assertIsNone(by_id["001"]["risk_score"])
        self.assertEqual(src.warnings[0]["type"], "inventory_unavailable")
        self.assertEqual(src.warnings[0]["agents"], ["001"])


if __name__ == "__main__":
    unittest.main()
