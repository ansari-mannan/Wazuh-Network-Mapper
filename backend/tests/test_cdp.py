"""Part 1: CDP neighbours are followed like LLDP ones (fixtures from captures).

The lab: L3-Switch sees L2-Switch over both LLDP and CDP, and the access point
(no LLDP) over CDP only. The HP switch has no CDP table.
"""

import asyncio
import unittest

from snmp_fakes import FakeSnmpClient, load_rows
from vulnmapper.assemble import assemble
from vulnmapper.network import parse
from vulnmapper.network.crawl import Crawler, build_document

L3_IPS = ("172.20.20.254", "172.20.10.254", "172.20.80.254")
L3_CID = "00:23:ac:e5:74:00"
L2_CID = "00:17:95:be:b2:00"
AP_IP = "172.20.99.21"
# No LLDP chassis id: the access point is named by its base MAC (Gi0).
AP_CID = "54:75:d0:ab:bd:1a"

# The node/edge keys the crawler has always emitted (a network without CDP or
# access points must produce exactly these).
LEGACY_NODE_KEYS = {
    "ip", "hostname", "vendor", "model", "firmware", "serial", "mac", "chassis_id",
    "discovery_method", "status", "pollable", "neighbor_ports", "uplink_ports",
    "port_status", "lldp_cap_enabled", "fdb", "arp", "own_macs",
}
LEGACY_EDGE_KEYS = {"source_chassis_id", "target_chassis_id", "local_port", "remote_port"}


def strip_cdp(rows):
    return [(o, v) for o, v in rows if not o.startswith(parse.CDP_CACHE_BASE + ".")]


def lab(cdp=True):
    l3, l2, ap = (load_rows(f) for f in ("cisco_l3_switch.snmp", "cisco_l2_switch.snmp",
                                         "cisco_ap_c1140.snmp"))
    if not cdp:
        l3, l2, ap = strip_cdp(l3), strip_cdp(l2), strip_cdp(ap)
    devices = {ip: l3 for ip in L3_IPS}
    devices.update({"172.20.10.100": l2, AP_IP: ap,
                    "172.20.99.4": load_rows("hp_no_cdp.snmp")})
    return FakeSnmpClient(devices)


def crawl(client, seed="172.20.20.254"):
    async def go():
        crawler = Crawler(client, concurrency=4, max_nodes=50, queue_maxsize=50)
        await crawler.seed([seed])
        return await crawler.run()
    devices, links = asyncio.run(go())
    return build_document(devices, links)


def cdp_rows(rows):
    return [(o, v) for o, v in rows if o.startswith(parse.CDP_CACHE_BASE + ".")]


def ifnames(rows):
    return parse.parse_ifnames(rows, base=parse.IFDESCR_BASE)


class TestCdpParsing(unittest.TestCase):
    def setUp(self):
        rows = load_rows("cisco_l3_switch.snmp")
        self.nbs = {nb.sys_name: nb for nb in parse.parse_cdp_cache(
            cdp_rows(rows), ifnames(rows))}

    def test_two_neighbours_with_address_port_platform(self):
        self.assertEqual(set(self.nbs), {"L2-Switch", "CYFOR-AP1"})
        l2, ap = self.nbs["L2-Switch"], self.nbs["CYFOR-AP1"]
        self.assertEqual((l2.mgmt_ip, l2.remote_port, l2.platform),
                         ("172.20.10.100", "FastEthernet0/1", "cisco WS-C2960-48TT-L"))
        self.assertEqual((ap.mgmt_ip, ap.remote_port, ap.platform),
                         (AP_IP, "GigabitEthernet0", "cisco AIR-AP1142N-A-K9"))
        self.assertEqual({nb.protocol for nb in self.nbs.values()}, {"cdp"})

    def test_local_port_from_the_local_ifindex(self):
        self.assertEqual(self.nbs["L2-Switch"].local_port_num, "10002")
        self.assertEqual(self.nbs["L2-Switch"].local_port, "FastEthernet1/0/2")
        self.assertEqual(self.nbs["CYFOR-AP1"].local_port, "FastEthernet1/0/15")

    def test_capabilities(self):
        # 0x28 = switch + IGMP; 0x26 = transparent + source-route bridge + IGMP
        l2, ap = self.nbs["L2-Switch"], self.nbs["CYFOR-AP1"]
        self.assertTrue(parse.cdp_is_infrastructure(l2.cdp_capabilities))
        self.assertFalse(parse.cdp_is_infrastructure(ap.cdp_capabilities))
        self.assertEqual(l2.cap_enabled, "0x20")          # LLDP bridge bit
        self.assertEqual(ap.cap_enabled, "0x20")
        self.assertEqual(parse.translate_cdp_capabilities("0x00000029"), "0x28")  # router+bridge
        self.assertEqual(parse.translate_cdp_capabilities("0x00000090"), "0x05")  # phone+host

    def test_unknown_ifindex_keeps_the_index(self):
        rows = load_rows("cisco_l3_switch.snmp")
        nbs = parse.parse_cdp_cache(cdp_rows(rows), {})
        self.assertEqual({nb.local_port for nb in nbs}, {"10002", "10015"})

    def test_address_rendered_as_text_octets(self):
        # four printable octets come through as text, not 0x hex
        rows = [(f"{parse.CDP_CACHE_BASE}.3.5.1", "1"), (f"{parse.CDP_CACHE_BASE}.4.5.1", "ABCD"),
                (f"{parse.CDP_CACHE_BASE}.6.5.1", "x")]
        self.assertEqual(parse.parse_cdp_cache(rows, {})[0].mgmt_ip, "65.66.67.68")

    def test_no_cdp_table_parses_to_nothing(self):
        self.assertEqual(parse.parse_cdp_cache([], {}), [])


class TestCdpCrawl(unittest.TestCase):
    def setUp(self):
        self.client = lab()
        self.doc = crawl(self.client)
        self.nodes = {n["chassis_id"]: n for n in self.doc["nodes"]}

    def pair(self, a, b):
        return [e for e in self.doc["edges"]
                if {e["source_chassis_id"], e["target_chassis_id"]} == {a, b}]

    def test_access_point_found_over_cdp_and_polled(self):
        ap = self.nodes[AP_CID]
        self.assertTrue(ap["pollable"])
        self.assertEqual((ap["hostname"], ap["ip"], ap["status"]), ("CYFOR-AP1", AP_IP, "online"))

    def test_cdp_link_carries_both_ports_and_the_protocol(self):
        (edge,) = self.pair(L3_CID, AP_CID)
        ports = {edge["source_chassis_id"]: edge["local_port"],
                 edge["target_chassis_id"]: edge["remote_port"]}
        self.assertEqual(ports, {L3_CID: "FastEthernet1/0/15", AP_CID: "GigabitEthernet0"})
        self.assertEqual(edge["protocol"], "cdp")

    def test_neighbour_seen_over_lldp_and_cdp_is_one_device_one_link(self):
        l2_nodes = [n for n in self.doc["nodes"] if n["hostname"] == "L2-Switch"]
        self.assertEqual([n["chassis_id"] for n in l2_nodes], [L2_CID])
        (edge,) = self.pair(L3_CID, L2_CID)
        self.assertNotIn("protocol", edge)                  # LLDP found it
        self.assertEqual(len(self.doc["edges"]), len({frozenset(
            (e["source_chassis_id"], e["target_chassis_id"])) for e in self.doc["edges"]}))

    def test_each_device_polled_once(self):
        # L3 is announced at three addresses (seed, CDP from L2, CDP from the AP)
        fetches = [c[1] for c in self.client.calls
                   if c[0] == "get" and "1.3.6.1.2.1.1.1.0" in c[2]]
        self.assertEqual(len(fetches), len(set(fetches)))
        self.assertEqual(sum(ip in L3_IPS for ip in fetches), 1)

    def test_ports(self):
        l3, ap = self.nodes[L3_CID], self.nodes[AP_CID]
        self.assertIn("FastEthernet1/0/15", l3["neighbor_ports"])
        # an access point is not infrastructure: its port stays an access port,
        # so the hosts the switch learns there are still discovered
        self.assertNotIn("FastEthernet1/0/15", l3["uplink_ports"])
        self.assertIn("GigabitEthernet0", ap["uplink_ports"])  # L3 is a router/switch

    def test_role_hint_from_cdp_capabilities(self):
        self.assertEqual(self.nodes[AP_CID]["lldp_cap_enabled"], "0x20")

    def test_device_without_cdp_costs_one_request(self):
        hp = "172.20.99.4"
        self.assertEqual(len(self.client.walks(hp, parse.CDP_CACHE_BASE)), 1)
        self.assertEqual(self.nodes["5c:8a:38:8b:a1:0b"]["status"], "online")


class TestUnpollableCdpNeighbour(unittest.TestCase):
    def test_becomes_a_placeholder_like_an_lldp_one(self):
        client = lab()
        del client.devices[AP_IP]                            # no credential works
        nodes = {n["chassis_id"]: n for n in crawl(client)["nodes"]}
        ap = nodes[f"ip:{AP_IP}"]                            # no MAC can be read
        self.assertEqual((ap["pollable"], ap["status"], ap["hostname"], ap["vendor"]),
                         (False, "unreachable", "CYFOR-AP1", "Cisco"))

    def test_without_an_address_it_is_a_discovered_placeholder(self):
        client = lab()
        rows = [(o, v) for o, v in client.devices["172.20.20.254"]
                if not o.startswith(f"{parse.CDP_CACHE_BASE}.4.")]
        for ip in L3_IPS:
            client.devices[ip] = rows
        del client.devices[AP_IP]
        doc = crawl(client)
        nodes = {n["chassis_id"]: n for n in doc["nodes"]}
        self.assertEqual((nodes["cdp:CYFOR-AP1"]["status"], nodes["cdp:CYFOR-AP1"]["pollable"]),
                         ("discovered", False))
        self.assertEqual(nodes["cdp:CYFOR-AP1"]["discovery_method"], "snmp_cdp")


class TestNoCdpAnywhere(unittest.TestCase):
    def test_output_shape_is_todays(self):
        doc = crawl(lab(cdp=False))
        for node in doc["nodes"]:
            self.assertEqual(set(node), LEGACY_NODE_KEYS, node["chassis_id"])
        for edge in doc["edges"]:
            self.assertEqual(set(edge), LEGACY_EDGE_KEYS)
        # without CDP the access point is never found, as today
        self.assertNotIn(AP_CID, {n["chassis_id"] for n in doc["nodes"]})


class TestCdpInTheGraph(unittest.TestCase):
    def test_cdp_link_is_a_device_link_with_protocol_and_ports(self):
        graph = assemble([], crawl(lab()))
        (edge,) = [e for e in graph["edges"]
                   if {e["source"], e["target"]} == {f"device:{L3_CID}", f"device:{AP_CID}"}]
        self.assertEqual((edge["type"], edge["protocol"]), ("lldp", "cdp"))
        self.assertEqual({edge["local_port"], edge["remote_port"]},
                         {"FastEthernet1/0/15", "GigabitEthernet0"})
        self.assertEqual(sum(n["hostname"] == "L2-Switch" for n in graph["nodes"]), 1)

    def test_lldp_links_carry_no_protocol_field(self):
        graph = assemble([], crawl(lab(cdp=False)))
        self.assertTrue(graph["edges"])
        self.assertTrue(all("protocol" not in e for e in graph["edges"]))

    def test_cdp_only_end_host_is_labelled_cdp(self):
        # an unpollable CDP neighbour with host capability (e.g. an IP phone)
        net = {"nodes": [
            {"chassis_id": L3_CID, "ip": "172.20.20.254", "pollable": True, "status": "online",
             "lldp_cap_enabled": "0x28"},
            {"chassis_id": "cdp:SEP001122334455", "ip": "172.20.30.50", "pollable": False,
             "status": "discovered", "discovery_method": "snmp_cdp", "lldp_cap_enabled": "0x05"},
        ], "edges": [{"source_chassis_id": L3_CID, "target_chassis_id": "cdp:SEP001122334455",
                      "local_port": "Fa1/0/9", "remote_port": "Port 1", "protocol": "cdp"}]}
        nodes = {n["node_id"]: n for n in assemble([], net)["nodes"]}
        phone = nodes["host:cdp:SEP001122334455"]
        self.assertEqual((phone["discovery_method"], phone["role"], phone["parent_id"]),
                         ("cdp", "phone", f"device:{L3_CID}"))


if __name__ == "__main__":
    unittest.main()
