"""Endpoint normalizers — agent_id carried, MAC canonicalized, risk from CVSS."""

import unittest

from vulnmapper.endpoints import (
    enrich_agent,
    is_locally_administered,
    is_physical_iface,
    normalize_agent,
    parse_hit,
    select_mac,
)


class TestNormalizeAgent(unittest.TestCase):
    def test_carries_agent_id_and_shapes_schema(self):
        agent = {
            "id": "004",
            "name": "CYFOR-1",
            "ip": "172.20.20.21",
            "os": {"platform": "windows", "name": "Microsoft Windows 10 Pro",
                   "version": "10.0.18363.449"},
            "status": "active",
        }
        netiface = [{"name": "Ethernet0", "mac": "E4-A7-A0-25-CE-AD", "state": "up"}]
        netaddr = [{"iface": "Ethernet0", "proto": "ipv4", "address": "172.20.20.21"}]
        hardware = [{"board_serial": "ABC123"}]
        node = normalize_agent(agent, netiface, hardware, netaddr)

        self.assertEqual(node["agent_id"], "004")          # hard join key carried
        self.assertEqual(node["mac"], "e4:a7:a0:25:ce:ad")  # canonicalized
        self.assertEqual(node["hostname"], "CYFOR-1")
        self.assertEqual(node["discovery_method"], "wazuh")
        self.assertEqual(node["status"], "active")

    def test_junk_serial_dropped(self):
        agent = {"id": "1", "name": "h", "ip": "1.2.3.4", "os": {}, "status": "active"}
        node = normalize_agent(
            agent,
            [{"name": "eth0", "mac": "e4:a7:a0:00:00:01", "state": "up"}],
            [{"board_serial": "To be filled by O.E.M."}],
            [{"iface": "eth0", "proto": "ipv4", "address": "1.2.3.4"}],
        )
        self.assertEqual(node["mac"], "e4:a7:a0:00:00:01")
        self.assertIsNone(node["serial"])


class TestSelectMac(unittest.TestCase):
    def test_locally_administered_bit(self):
        self.assertTrue(is_locally_administered("02:00:4c:4f:4f:50"))   # Npcap LOOP
        self.assertTrue(is_locally_administered("0a:00:27:00:00:00"))   # VirtualBox
        self.assertFalse(is_locally_administered("e4:a7:a0:25:ce:ad"))  # burned-in
        self.assertTrue(is_locally_administered("not-a-mac"))           # unparseable

    def test_physical_iface_blocklist(self):
        self.assertFalse(is_physical_iface("Npcap Loopback Adapter", "e4:a7:a0:25:ce:ad"))
        self.assertFalse(is_physical_iface("VMware Network Adapter", "e4:a7:a0:25:ce:ad"))
        self.assertTrue(is_physical_iface("Ethernet", "e4:a7:a0:25:ce:ad"))

    def test_npcap_loopback_never_selected(self):
        netiface = [
            {"name": "Npcap Loopback Adapter", "mac": "02:00:4c:4f:4f:50", "state": "up"},
            {"name": "Ethernet", "mac": "e4:a7:a0:25:ce:ad", "state": "up"},
        ]
        netaddr = [
            {"iface": "Npcap Loopback Adapter", "proto": "ipv4", "address": "169.254.1.1"},
            {"iface": "Ethernet", "proto": "ipv4", "address": "172.20.20.21"},
        ]
        self.assertEqual(select_mac(netiface, netaddr, "172.20.20.21"), "e4:a7:a0:25:ce:ad")

    def test_prefers_interface_matching_agent_ip(self):
        netiface = [
            {"name": "eth1", "mac": "e4:a7:a0:00:00:02", "state": "up"},
            {"name": "eth0", "mac": "e4:a7:a0:00:00:01", "state": "up"},
        ]
        netaddr = [
            {"iface": "eth1", "proto": "ipv4", "address": "10.0.0.5"},
            {"iface": "eth0", "proto": "ipv4", "address": "172.20.20.21"},
        ]
        self.assertEqual(select_mac(netiface, netaddr, "172.20.20.21"), "e4:a7:a0:00:00:01")

    def test_apipa_only_interface_excluded(self):
        netiface = [{"name": "Ethernet", "mac": "e4:a7:a0:25:ce:ad", "state": "up"}]
        netaddr = [{"iface": "Ethernet", "proto": "ipv4", "address": "169.254.10.10"}]
        self.assertIsNone(select_mac(netiface, netaddr, None))

    def test_only_virtual_adapters_yields_none(self):
        netiface = [{"name": "vEthernet (WSL)", "mac": "02:00:4c:4f:4f:50", "state": "up"}]
        netaddr = [{"iface": "vEthernet (WSL)", "proto": "ipv4", "address": "172.30.0.1"}]
        self.assertIsNone(select_mac(netiface, netaddr, None))

    def test_no_crash_on_empty(self):
        self.assertIsNone(select_mac([], [], None))
        self.assertIsNone(select_mac(None, None, None))


class TestCveNormalize(unittest.TestCase):
    def test_parse_hit_flattens(self):
        hit = {"_source": {
            "vulnerability": {"id": "CVE-2026-1", "severity": "Critical",
                              "description": "x", "score": {"base": 9.8, "version": "3.1"}},
            "package": {"name": "pkg", "version": "1.0"},
        }}
        cve = parse_hit(hit)
        self.assertEqual(cve["cve"], "CVE-2026-1")
        self.assertEqual(cve["cvss"], 9.8)
        self.assertEqual(cve["package"], "pkg")

    def test_enrich_uses_max_cvss(self):
        agent = {"agent_id": "1", "hostname": "h"}
        enriched = enrich_agent(agent, [{"cvss": 9.8}, {"cvss": 5.0}])
        self.assertEqual(enriched["risk_score"], 9.8)
        self.assertEqual(len(enriched["top_cves"]), 2)

    def test_enrich_no_cves_is_zero(self):
        self.assertEqual(enrich_agent({"agent_id": "1"}, [])["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
