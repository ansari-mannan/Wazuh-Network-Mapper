"""The unified MAC table: uplink subtraction, own-MAC/SVI exclusion, ARP join."""

import unittest

from vulnmapper.assemble import (
    CONF_RESOLVED,
    CONF_TIEBREAK,
    build_mac_table,
    same_subnet,
)

HOST = "aa:bb:cc:00:00:01"


def switch(chassis, ip, fdb_entries, uplinks, *, neighbor_ports=None,
           own_macs=None, arp=None, pollable=True):
    # uplink_ports is the INFRASTRUCTURE-facing subset that Tier-2 subtracts;
    # neighbor_ports (every LLDP-neighbor port, incl. access ports to hosts) is
    # carried for display and must NOT be subtracted.
    return {"chassis_id": chassis, "ip": ip, "discovery_method": "snmp_lldp",
            "pollable": pollable, "uplink_ports": uplinks,
            "neighbor_ports": neighbor_ports if neighbor_ports is not None else uplinks,
            "fdb": fdb_entries, "own_macs": own_macs or [], "arp": arp or {}}


class TestBuildMacTable(unittest.TestCase):
    def test_resolves_access_not_uplink_and_joins_arp_ip(self):
        access = switch("aa:aa:aa:aa:aa:aa", "172.20.20.2",
                        [{"mac": HOST, "port": "Gi0/3", "vlan": 20}],
                        uplinks=["Gi0/1"], arp={HOST.replace(":", ""): "172.20.20.21"})
        core = switch("bb:bb:bb:bb:bb:bb", "172.20.99.2",
                      [{"mac": HOST, "port": "Gi0/1", "vlan": 20}],  # on its uplink
                      uplinks=["Gi0/1", "Gi0/2"])
        table = build_mac_table([core, access])
        fact = table.by_mac["aabbcc000001"]
        self.assertEqual(fact.switch_node_id, "device:aa:aa:aa:aa:aa:aa")
        self.assertEqual(fact.port, "Gi0/3")
        self.assertEqual(fact.confidence, CONF_RESOLVED)
        self.assertEqual(fact.ip, "172.20.20.21")          # joined from ARP
        self.assertEqual(table.by_ip["172.20.20.21"], "aabbcc000001")

    def test_only_on_uplink_is_not_in_table(self):
        core = switch("bb:bb:bb:bb:bb:bb", "172.20.20.2",
                      [{"mac": HOST, "port": "Gi0/1", "vlan": 20}], uplinks=["Gi0/1"])
        self.assertNotIn("aabbcc000001", build_mac_table([core]).by_mac)

    def test_access_port_with_lldp_neighbor_not_subtracted(self):
        # Gi0/3 has an LLDP neighbor (it's in neighbor_ports) but the neighbor is
        # an end host, so it's NOT in uplink_ports. The host must still resolve —
        # only the filtered uplink subset is subtracted, never neighbor_ports.
        access = switch("aa:aa:aa:aa:aa:aa", "172.20.20.2",
                        [{"mac": HOST, "port": "Gi0/3", "vlan": 20}],
                        uplinks=["Gi0/1"], neighbor_ports=["Gi0/1", "Gi0/3"])
        fact = build_mac_table([access]).by_mac["aabbcc000001"]
        self.assertEqual(fact.switch_node_id, "device:aa:aa:aa:aa:aa:aa")
        self.assertEqual(fact.port, "Gi0/3")

    def test_own_mac_svi_excluded(self):
        # The switch's own SVI MAC appears in its FDB but must not become a host.
        svi = "00:23:ac:e5:74:41"
        sw = switch("00:23:ac:e5:74:00", "172.20.40.254",
                    [{"mac": svi, "port": "Vl40", "vlan": 40},
                     {"mac": HOST, "port": "Fa1/0/3", "vlan": 40}],
                    uplinks=[], own_macs=[svi, "00:23:ac:e5:74:00"])
        table = build_mac_table([sw])
        self.assertNotIn("0023ace57441", table.by_mac)   # SVI filtered
        self.assertIn("aabbcc000001", table.by_mac)       # real host kept

    def test_tiebreak_fewest_macs_on_port(self):
        access = switch("aa:aa:aa:aa:aa:aa", "172.20.20.2",
                        [{"mac": HOST, "port": "Gi0/3", "vlan": 20}], uplinks=[])
        trunk = switch("bb:bb:bb:bb:bb:bb", "172.20.99.2",
                       [{"mac": HOST, "port": "Gi0/9", "vlan": 20},
                        {"mac": "de:ad:be:ef:00:01", "port": "Gi0/9", "vlan": 20}],
                       uplinks=[])
        fact = build_mac_table([trunk, access]).by_mac["aabbcc000001"]
        self.assertEqual(fact.switch_node_id, "device:aa:aa:aa:aa:aa:aa")
        self.assertEqual(fact.confidence, CONF_TIEBREAK)


class TestSameSubnet(unittest.TestCase):
    def test_same_and_different(self):
        self.assertTrue(same_subnet("172.20.20.2", "172.20.20.21"))
        self.assertFalse(same_subnet("172.20.20.2", "172.20.30.21"))
        self.assertFalse(same_subnet(None, "172.20.20.21"))


if __name__ == "__main__":
    unittest.main()
