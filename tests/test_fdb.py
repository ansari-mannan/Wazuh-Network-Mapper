"""Pure FDB parsing: the fiddly dotted-decimal-MAC-in-the-OID decoding."""

import unittest

from vulnmapper.network import parse as fdb


def _mac_decimals(mac_hex: str) -> str:
    """'e4a7a025cead' -> '228.167.160.37.206.173' (OID-index form)."""
    return ".".join(str(int(mac_hex[i:i + 2], 16)) for i in range(0, 12, 2))


class TestFdbParsing(unittest.TestCase):
    def test_dot1q_index_decodes_vlan_and_mac(self):
        oid = f"{fdb.DOT1Q_FDB_PORT_BASE}.10.{_mac_decimals('e4a7a025cead')}"
        rows = [(oid, "3")]
        self.assertEqual(fdb.parse_dot1q_fdb(rows), [(10, "e4a7a025cead", "3")])

    def test_dot1d_index_decodes_mac(self):
        oid = f"{fdb.DOT1D_FDB_PORT_BASE}.{_mac_decimals('001122334455')}"
        rows = [(oid, "7")]
        self.assertEqual(fdb.parse_dot1d_fdb(rows), [("001122334455", "7")])

    def test_port_resolution_chain(self):
        baseport = fdb.parse_baseport_ifindex([(f"{fdb.DOT1D_BASEPORT_IFINDEX_BASE}.3", "10003")])
        ifnames = fdb.parse_ifnames([(f"{fdb.IFNAME_BASE}.10003", "GigabitEthernet0/3")])
        self.assertEqual(fdb.resolve_port("3", baseport, ifnames), "GigabitEthernet0/3")
        # Missing translation falls back to the raw bridge port, never lost.
        self.assertEqual(fdb.resolve_port("9", baseport, ifnames), "9")

    def test_build_fdb_prefers_dot1q_over_dot1d(self):
        q_oid = f"{fdb.DOT1Q_FDB_PORT_BASE}.10.{_mac_decimals('aaaaaaaaaaaa')}"
        d_oid = f"{fdb.DOT1D_FDB_PORT_BASE}.{_mac_decimals('bbbbbbbbbbbb')}"
        entries = fdb.build_fdb(
            dot1q_rows=[(q_oid, "3")],
            dot1d_rows=[(d_oid, "4")],
            baseport_rows=[(f"{fdb.DOT1D_BASEPORT_IFINDEX_BASE}.3", "10003")],
            ifname_rows=[(f"{fdb.IFNAME_BASE}.10003", "Gi0/3")],
        )
        # Only the 802.1Q entry survives; the flat table is the fallback, not merged.
        self.assertEqual(entries, [{"mac": "aaaaaaaaaaaa", "port": "Gi0/3", "vlan": 10}])

    def test_build_fdb_falls_back_to_dot1d_when_no_dot1q(self):
        d_oid = f"{fdb.DOT1D_FDB_PORT_BASE}.{_mac_decimals('bbbbbbbbbbbb')}"
        entries = fdb.build_fdb(dot1d_rows=[(d_oid, "4")])
        self.assertEqual(entries, [{"mac": "bbbbbbbbbbbb", "port": "4", "vlan": None}])

    def test_build_fdb_per_vlan_context(self):
        # Rows read under the community@10 context; in-index fdbId may be 0.
        oid = f"{fdb.DOT1Q_FDB_PORT_BASE}.0.{_mac_decimals('cccccccccccc')}"
        entries = fdb.build_fdb(dot1q_rows_by_vlan={10: [(oid, "5")]})
        self.assertEqual(entries, [{"mac": "cccccccccccc", "port": "5", "vlan": 10}])

    def test_parse_arp(self):
        # index = ifIndex.a.b.c.d ; value = MAC -> {canonical_mac: ip}
        oid = f"{fdb.ARP_BASE}.52.172.20.40.1"
        self.assertEqual(fdb.parse_arp([(oid, "d4:be:d9:97:f4:ca")]),
                         {"d4bed997f4ca": "172.20.40.1"})

    def test_parse_own_macs(self):
        rows = [
            (f"{fdb.IFPHYS_BASE}.1", "00:23:ac:e5:74:41"),
            (f"{fdb.IFPHYS_BASE}.2", "00 00 00 00 00 00"),  # empty -> still parses to zeros
            (f"{fdb.IFPHYS_BASE}.3", ""),                     # blank -> dropped
        ]
        macs = fdb.parse_own_macs(rows)
        self.assertIn("0023ace57441", macs)
        self.assertNotIn(None, macs)

    def test_build_port_status_maps_names_to_up_down(self):
        # ifOperStatus: 1=up, 2=down, anything else -> down; named via ifName.
        oper = [
            (f"{fdb.IFOPERSTATUS_BASE}.10001", "1"),   # up
            (f"{fdb.IFOPERSTATUS_BASE}.10002", "2"),   # down
            (f"{fdb.IFOPERSTATUS_BASE}.10003", "up(1)"),  # MIB-rendered up
            (f"{fdb.IFOPERSTATUS_BASE}.10004", "7"),   # other -> down
        ]
        ifname = [
            (f"{fdb.IFNAME_BASE}.10001", "Gi0/1"),
            (f"{fdb.IFNAME_BASE}.10002", "Gi0/2"),
            (f"{fdb.IFNAME_BASE}.10003", "Gi0/3"),
            # 10004 has no ifName -> falls back to the raw ifIndex
        ]
        self.assertEqual(
            fdb.build_port_status(oper, ifname),
            {"Gi0/1": "up", "Gi0/2": "down", "Gi0/3": "up", "10004": "down"},
        )

    def test_parse_vtp_vlans(self):
        rows = [
            (f"{fdb.VTP_VLAN_STATE_BASE}.1.10", "1"),     # operational
            (f"{fdb.VTP_VLAN_STATE_BASE}.1.20", "1"),     # operational
            (f"{fdb.VTP_VLAN_STATE_BASE}.1.30", "2"),     # suspended -> excluded
            (f"{fdb.VTP_VLAN_STATE_BASE}.1.1002", "1"),   # reserved -> excluded
        ]
        self.assertEqual(fdb.parse_vtp_vlans(rows), [10, 20])

    def test_assemble_dot1d_per_vlan_uses_context_vlan(self):
        # FDB + baseport read under the VLAN-99 community context.
        fdb_oid = f"{fdb.DOT1D_FDB_PORT_BASE}.{_mac_decimals('c85b7654ff0d')}"
        bp_oid = f"{fdb.DOT1D_BASEPORT_IFINDEX_BASE}.13"
        per_vlan = {99: {"fdb": [(fdb_oid, "13")], "baseport": [(bp_oid, "10013")]}}
        ifname = [(f"{fdb.IFNAME_BASE}.10013", "Gi2/0/13")]
        entries = fdb.assemble_dot1d_per_vlan(per_vlan, ifname)
        self.assertEqual(entries, [{"mac": "c85b7654ff0d", "port": "Gi2/0/13", "vlan": 99}])


if __name__ == "__main__":
    unittest.main()
