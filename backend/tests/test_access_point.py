"""Parts 2 and 3: recognise an access point; read and place its Wi-Fi clients.

Fixtures from the lab captures: the Cisco Aironet 1140 (CYFOR-AP1) answers the
CISCO-DOT11-ASSOCIATION-MIB with two clients, one per radio and SSID.
"""

import unittest

from snmp_fakes import load_rows
from test_cdp import AP_CID, AP_IP, L3_CID, crawl, lab
from vulnmapper.assemble import assemble
from vulnmapper.network import parse

AP_NODE = f"device:{AP_CID}"
L3_NODE = f"device:{L3_CID}"
PHONE = "7a:bd:06:18:06:2c"        # randomised MAC, BIG-CYFOR on radio 0
LAPTOP = "e4:a7:a0:25:ce:ac"       # BIG-CYFOR-5G on radio 1


def without(rows, *prefixes):
    return [(o, v) for o, v in rows if not any(o.startswith(p + ".") or o == p for p in prefixes)]


class TestAccessPointRole(unittest.TestCase):
    def setUp(self):
        self.doc = crawl(lab())
        self.ap = {n["chassis_id"]: n for n in self.doc["nodes"]}[AP_CID]

    def test_polled_access_point_is_marked_and_gets_the_role(self):
        self.assertTrue(self.ap["access_point"])
        nodes = {n["node_id"]: n for n in assemble([], self.doc)["nodes"]}
        self.assertEqual(nodes[AP_NODE]["role"], "access-point")
        self.assertEqual(nodes[L3_NODE]["role"], "l3-switch")

    def test_identity_through_the_existing_cisco_handling(self):
        self.assertEqual((self.ap["vendor"], self.ap["model"], self.ap["firmware"]),
                         ("Cisco", "C1140", "15.3(3)JB"))
        self.assertIsNone(self.ap["serial"])           # Cisco handling reads no serial
        self.assertEqual(self.ap["platform"], "cisco AIR-AP1142N-A-K9")

    def test_switches_are_not_access_points(self):
        for node in self.doc["nodes"]:
            if node["chassis_id"] != AP_CID:
                self.assertNotIn("access_point", node, node["chassis_id"])

    def test_access_point_bridge_table_is_not_used(self):
        # its association table is the source for clients; its bridge table
        # (clients on radio sub-interfaces, upstream MACs on Gi0.x) is not
        self.assertEqual(self.ap["fdb"], [])

    def test_association_table_alone_is_enough(self):
        client = lab()
        rows = [(o, "Generic Software, Version 1") if o == "1.3.6.1.2.1.1.1.0" else (o, v)
                for o, v in client.devices[AP_IP]]
        client.devices[AP_IP] = rows
        for ip in ("172.20.20.254", "172.20.10.254", "172.20.80.254"):   # no CDP platform
            client.devices[ip] = without(client.devices[ip], parse.CDP_CACHE_BASE)
        client.devices["172.20.20.254"] = client.devices["172.20.20.254"] + [
            (f"{parse.CDP_CACHE_BASE}.4.10015.2", "0xac146315"),
            (f"{parse.CDP_CACHE_BASE}.6.10015.2", "AP")]
        ap = {n["chassis_id"]: n for n in crawl(client)["nodes"]}[AP_CID]
        self.assertTrue(ap["access_point"])

    def test_platform_alone_is_enough(self):
        client = lab()
        client.devices[AP_IP] = without(client.devices[AP_IP], "1.3.6.1.4.1.9.9.273")
        ap = {n["chassis_id"]: n for n in crawl(client)["nodes"]}[AP_CID]
        self.assertTrue(ap["access_point"])
        self.assertNotIn("wifi_clients", ap)          # nothing to read them from

    def test_unpollable_placeholder_named_by_its_platform(self):
        client = lab()
        del client.devices[AP_IP]
        doc = crawl(client)
        nodes = {n["node_id"]: n for n in assemble([], doc)["nodes"]}
        self.assertEqual(nodes[AP_NODE]["role"], "access-point")

    def test_unpollable_access_point_without_capabilities_stays_a_device(self):
        net = {"nodes": [
            {"chassis_id": L3_CID, "ip": "172.20.20.254", "pollable": True, "status": "online"},
            {"chassis_id": "cdp:AP9", "ip": None, "pollable": False, "status": "discovered",
             "discovery_method": "snmp_cdp", "access_point": True}],
            "edges": [{"source_chassis_id": L3_CID, "target_chassis_id": "cdp:AP9",
                       "local_port": "Fa1/0/9", "remote_port": "Gi0", "protocol": "cdp"}]}
        nodes = {n["node_id"]: n for n in assemble([], net)["nodes"]}
        self.assertEqual((nodes["device:cdp:AP9"]["kind"], nodes["device:cdp:AP9"]["role"]),
                         ("device", "access-point"))

    def test_name_rules(self):
        self.assertTrue(parse.looks_like_access_point(None, "cisco AIR-AP1142N-A-K9"))
        self.assertTrue(parse.looks_like_access_point(None, "cisco AIR-LAP1142N-A-K9"))
        self.assertTrue(parse.looks_like_access_point(
            "Cisco IOS Software, C1140 Software (C1140-K9W7-M), Version 15.3(3)JB", None))
        self.assertTrue(parse.looks_like_access_point("Cisco Aironet 1240 Series", None))
        self.assertFalse(parse.looks_like_access_point(
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M)", "cisco WS-C3750-24P"))
        self.assertFalse(parse.looks_like_access_point(None, None))


AP_MAC = "54:75:d0:ab:bd:1a"        # the access point's own wired MAC


def bare(mac):
    return mac.replace(":", "")


class TestClientTable(unittest.TestCase):
    def test_parse_clients(self):
        rows = load_rows("cisco_ap_c1140.snmp")
        clients = {c["mac"]: c for c in parse.parse_wifi_clients(
            rows, parse.parse_ifnames(rows, base=parse.IFDESCR_BASE))}
        self.assertEqual(clients, {
            PHONE: {"mac": PHONE, "ip": "172.20.80.1", "ssid": "BIG-CYFOR",
                    "radio": "Dot11Radio0", "vlan": 80},
            LAPTOP: {"mac": LAPTOP, "ip": "172.20.80.3", "ssid": "BIG-CYFOR-5G",
                     "radio": "Dot11Radio1", "vlan": 80},
        })

    def test_missing_ip_and_vlan_columns(self):
        rows = [(o, v) for o, v in load_rows("cisco_ap_c1140.snmp")
                if not o.startswith((parse.DOT11_CLIENT_BASE + ".16.", parse.DOT11_CLIENT_BASE + ".17."))]
        clients = parse.parse_wifi_clients(rows, {})
        self.assertEqual({(c["ip"], c["vlan"], c["radio"]) for c in clients},
                         {(None, None, "1"), (None, None, "2")})

    def test_crawl_reads_the_client_list(self):
        ap = {n["chassis_id"]: n for n in crawl(lab())["nodes"]}[AP_CID]
        self.assertEqual(sorted(c["mac"] for c in ap["wifi_clients"]), [PHONE, LAPTOP])

    def test_not_an_access_point_reads_nothing(self):
        client = lab()
        crawl(client)
        self.assertEqual(client.walks("172.20.99.4", parse.DOT11_CLIENT_BASE + ".2"), [])


class TestClientPlacement(unittest.TestCase):
    """The switch learns the clients on the access point's port; the AP's
    association table moves them under the AP."""

    def network(self, fdb_macs=(PHONE, LAPTOP, AP_MAC), clients=None):
        doc = crawl(lab())
        nodes = {n["chassis_id"]: n for n in doc["nodes"]}
        nodes[L3_CID]["fdb"] = [{"mac": bare(m), "port": "FastEthernet1/0/15", "vlan": 80}
                                for m in fdb_macs]
        nodes[L3_CID]["arp"] = {bare(PHONE): "172.20.80.1", bare(AP_MAC): AP_IP}
        if clients is not None:
            nodes[AP_CID]["wifi_clients"] = clients
        return doc

    def graph(self, endpoints=(), **kw):
        g = assemble(list(endpoints), self.network(**kw))
        return g, {n["node_id"]: n for n in g["nodes"]}, \
            {e["source"]: e for e in g["edges"] if e["type"] == "endpoint_link"}

    def test_switch_learned_client_moves_under_the_access_point(self):
        _g, nodes, links = self.graph()
        phone = nodes[f"host:{PHONE}"]
        self.assertEqual((phone["discovery_method"], phone["parent_id"]), ("snmp_fdb", AP_NODE))
        self.assertEqual((links[f"host:{PHONE}"]["confidence"], links[f"host:{PHONE}"]["local_port"]),
                         ("wifi", "Dot11Radio0"))
        self.assertEqual(phone["wifi"], {"ssid": "BIG-CYFOR", "access_point": AP_NODE,
                                         "radio": "Dot11Radio0"})

    def test_agent_endpoint_moves_under_the_access_point(self):
        agent = {"agent_id": "001", "hostname": "Mannan-PC", "mac": LAPTOP, "ip": "172.20.80.3",
                 "status": "active", "risk_score": 5.0, "top_cves": []}
        _g, nodes, links = self.graph([agent])
        self.assertEqual(nodes["endpoint:001"]["parent_id"], AP_NODE)
        self.assertEqual(links["endpoint:001"]["confidence"], "wifi")
        self.assertEqual(nodes["endpoint:001"]["wifi"]["ssid"], "BIG-CYFOR-5G")
        self.assertNotIn(f"host:{LAPTOP}", nodes)

    def test_agent_known_only_by_ip_takes_the_clients_mac(self):
        agent = {"agent_id": "001", "hostname": "Mannan-PC", "mac": None, "ip": "172.20.80.3",
                 "status": "active", "risk_score": 5.0, "top_cves": []}
        _g, nodes, _links = self.graph([agent], fdb_macs=(AP_MAC,))
        self.assertEqual((nodes["endpoint:001"]["mac"], nodes["endpoint:001"]["parent_id"]),
                         (LAPTOP, AP_NODE))

    def test_client_no_other_source_knows_becomes_a_wifi_host(self):
        _g, nodes, links = self.graph(fdb_macs=(AP_MAC,))
        laptop = nodes[f"host:{LAPTOP}"]
        self.assertEqual((laptop["discovery_method"], laptop["status"], laptop["ip"], laptop["kind"]),
                         ("snmp_wifi", "discovered", "172.20.80.3", "endpoint"))
        self.assertEqual(links[f"host:{LAPTOP}"]["confidence"], "wifi")

    def test_access_point_on_its_cdp_port_with_its_client_count(self):
        g, nodes, _links = self.graph()
        ap = nodes[AP_NODE]
        self.assertEqual((ap["parent_id"], ap["wifi_clients"]), (L3_NODE, 2))
        self.assertNotIn(f"host:{AP_MAC}", nodes)              # not a host as well
        (edge,) = [e for e in g["edges"] if {e["source"], e["target"]} == {AP_NODE, L3_NODE}]
        port_on_l3 = edge["local_port"] if edge["source"] == L3_NODE else edge["remote_port"]
        self.assertEqual(port_on_l3, "FastEthernet1/0/15")

    def test_no_new_duplicates(self):
        g, nodes, _links = self.graph()
        macs = [n["mac"] for n in g["nodes"] if n["kind"] == "endpoint" and n["mac"]]
        self.assertEqual(len(macs), len(set(macs)))

    def test_empty_client_list(self):
        _g, nodes, _links = self.graph(clients=[])
        self.assertEqual(nodes[AP_NODE]["wifi_clients"], 0)
        self.assertEqual(nodes[f"host:{PHONE}"]["parent_id"], L3_NODE)   # as today


if __name__ == "__main__":
    unittest.main()
