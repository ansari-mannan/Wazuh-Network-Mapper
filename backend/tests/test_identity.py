"""A MAC for every polled device, and the label of how it was first reached.

A device with no LLDP chassis id (the lab's access point speaks only CDP) used
to get the node id device:ip:<address>, which changes with the address. Its
base MAC, chosen from its own interface MACs, now names it.
"""

import asyncio
import unittest

from snmp_fakes import FakeSnmpClient, load_rows
from test_cdp import AP_IP, L2_CID, L3_CID, L3_IPS, crawl, lab
from vulnmapper.assemble import assemble
from vulnmapper.liveness import liveness_pass
from vulnmapper.network import parse
from vulnmapper.network.crawl import base_mac

AP_MAC = "54:75:d0:ab:bd:1a"        # Gi0 (and its sub-interfaces) of the access point
AP_NODE = f"device:{AP_MAC}"


class TestBaseMac(unittest.TestCase):
    def test_the_mac_most_interfaces_share(self):
        self.assertEqual(base_mac(["aca016bb23d0", "a40cc31a1e20", "5475d0abbd1a",
                                   "aca016bb23d0", "5475d0abbd1a", "5475d0abbd1a"]),
                         "54:75:d0:ab:bd:1a")

    def test_a_tie_goes_to_the_lowest(self):
        self.assertEqual(base_mac(["00:23:ac:e5:74:02", "00:23:ac:e5:74:01"]),
                         "00:23:ac:e5:74:01")

    def test_zero_multicast_and_locally_administered_are_skipped(self):
        self.assertEqual(base_mac(["000000000000", "ffffffffffff", "01005e000001",
                                   "020000000001", "020000000001", "00aabbccddee"]),
                         "00:aa:bb:cc:dd:ee")

    def test_no_usable_mac(self):
        self.assertIsNone(base_mac([]))
        self.assertIsNone(base_mac(["000000000000", "not a mac"]))


class TestLabIdentity(unittest.TestCase):
    def setUp(self):
        self.doc = crawl(lab())
        self.by_cid = {n["chassis_id"]: n for n in self.doc["nodes"]}

    def test_access_point_is_named_by_its_mac(self):
        self.assertIn(AP_MAC, self.by_cid)
        self.assertNotIn(f"ip:{AP_IP}", self.by_cid)
        ap = self.by_cid[AP_MAC]
        self.assertEqual((ap["mac"], ap["ip"], ap["pollable"]), (AP_MAC, AP_IP, True))
        self.assertFalse(any(cid.startswith("ip:") for cid in self.by_cid))

    def test_discovery_label_says_how_it_was_first_reached(self):
        self.assertEqual(self.by_cid[AP_MAC]["discovery_method"], "snmp_cdp")
        self.assertEqual(self.by_cid[L3_CID]["discovery_method"], "snmp_lldp")   # the seed
        self.assertEqual(self.by_cid[L2_CID]["discovery_method"], "snmp_lldp")   # LLDP first

    def test_lldp_chassis_ids_are_unchanged(self):
        for cid in (L3_CID, L2_CID):
            self.assertEqual(self.by_cid[cid]["mac"], cid)

    def test_every_reference_uses_the_new_id(self):
        graph = assemble([], self.doc)
        ids = {n["node_id"] for n in graph["nodes"]}
        self.assertIn(AP_NODE, ids)
        self.assertFalse(any(i.startswith("device:ip:") for i in ids))
        for edge in graph["edges"]:
            self.assertIn(edge["source"], ids)
            self.assertIn(edge["target"], ids)
        self.assertTrue(any({e["source"], e["target"]} == {AP_NODE, f"device:{L3_CID}"}
                            for e in graph["edges"]))
        clients = [n for n in graph["nodes"] if n.get("wifi")]
        self.assertTrue(clients)
        for n in clients:
            self.assertEqual(n["wifi"]["access_point"], AP_NODE)
            self.assertEqual(n["parent_id"], AP_NODE)
        for n in graph["nodes"]:
            if n.get("parent_id"):
                self.assertIn(n["parent_id"], ids)

    def test_no_second_node_for_the_device_mac(self):
        graph = assemble([], self.doc)
        self.assertNotIn(f"host:{AP_MAC}", {n["node_id"] for n in graph["nodes"]})
        with_mac = [n for n in graph["nodes"] if n.get("mac") == AP_MAC]
        self.assertEqual([n["node_id"] for n in with_mac], [AP_NODE])

    def test_liveness_keys_the_device_by_the_same_id(self):
        class Silent:
            has_snmp = False

            async def icmp(self, ip):
                return False

        graph = assemble([], self.doc)
        doc = asyncio.run(liveness_pass(graph, {}, Silent(), 2, now="2026-10-09T00:00:00+00:00"))
        self.assertIn(AP_NODE, doc["nodes"])


class TestNoMacAtAll(unittest.TestCase):
    def test_address_id_only_when_no_mac_can_be_read(self):
        client = lab()
        client.devices[AP_IP] = [(o, v) for o, v in client.devices[AP_IP]
                                 if not o.startswith(parse.IFPHYS_BASE + ".")]
        by_cid = {n["chassis_id"]: n for n in crawl(client)["nodes"]}
        self.assertIn(f"ip:{AP_IP}", by_cid)
        self.assertIsNone(by_cid[f"ip:{AP_IP}"]["mac"])


if __name__ == "__main__":
    unittest.main()
