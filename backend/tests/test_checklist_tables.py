"""Parsing the tables the configuration checks read, from real captures.

Fixtures (checklist_<device>.snmp) were converted from the lab captures of
8 Oct 2026 by scripts/captures.py: two Cisco IOS switches (l3: 3750, l2:
2960), an HP 1920 (Comware) and a Cisco Aironet access point.
"""

import unittest
from collections import Counter

from snmp_fakes import load_rows
from vulnmapper.checklist import tables as t


def device(name):
    rows = load_rows(f"checklist_{name}.snmp")
    col = lambda base: [(o, v) for o, v in rows if o.startswith(base + ".")]
    return rows, col, dict(rows).get


class TestTcp(unittest.TestCase):
    def test_hp_lists_telnet_and_http_listeners(self):
        _rows, col, _ = device("hp")
        self.assertEqual(t.parse_tcp(col(t.TCP_CONN_STATE), col(t.TCP_LISTENER_PROCESS)),
                         {"read": True, "ports": [23, 80]})

    def test_access_point_lists_http_in_the_listener_table(self):
        _rows, col, _ = device("ap")
        self.assertEqual(t.parse_tcp(col(t.TCP_CONN_STATE), col(t.TCP_LISTENER_PROCESS)),
                         {"read": True, "ports": [80]})

    def test_cisco_switches_list_no_sockets_at_all(self):
        for name in ("l3", "l2"):
            _rows, col, _ = device(name)
            self.assertEqual(t.parse_tcp(col(t.TCP_CONN_STATE), col(t.TCP_LISTENER_PROCESS)),
                             {"read": False, "ports": []})

    def test_established_connection_counts_its_local_port(self):
        rows = [(f"{t.TCP_CONN_STATE}.10.0.0.2.23.10.0.0.9.51000", "5")]
        self.assertEqual(t.parse_tcp(rows, [])["ports"], [23])


class TestInterfaces(unittest.TestCase):
    def interfaces(self, name):
        _rows, col, _ = device(name)
        return t.parse_interfaces(col(t.IF_TYPE), col(t.IF_ADMIN_STATUS), col(t.IF_OPER_STATUS),
                                  col(t.IF_LAST_CHANGE), col(t.IF_NAME), col(t.IF_DESCR))

    def test_cisco_l3(self):
        ifs = self.interfaces("l3")
        self.assertEqual(len(ifs), 40)
        self.assertEqual(Counter(x["type"] for x in ifs.values()), {6: 26, 53: 13, 1: 1})
        self.assertEqual(ifs[10001], {"name": "FastEthernet1/0/1", "type": 6, "admin": 1,
                                      "oper": 1, "last_change": 931646})

    def test_hp(self):
        ifs = self.interfaces("hp")
        eth = [x for x in ifs.values() if x["type"] in t.ETHERNET_TYPES]
        self.assertEqual(len(eth), 52)
        self.assertEqual(Counter((x["admin"], x["oper"]) for x in eth), {(1, 2): 46, (1, 1): 6})

    def test_access_point_has_radios_and_subinterfaces(self):
        ifs = self.interfaces("ap")
        self.assertEqual(Counter(x["type"] for x in ifs.values()), {135: 4, 71: 2, 6: 2, 1: 1})

    def test_names_prefer_ifname(self):
        rows = [(f"{t.IF_TYPE}.5", "6")]
        ifs = t.parse_interfaces(rows, [], [], [], [(f"{t.IF_NAME}.5", "Gi0/5")],
                                 [(f"{t.IF_DESCR}.5", "GigabitEthernet0/5")])
        self.assertEqual(ifs[5]["name"], "Gi0/5")

    def test_no_interface_table_is_none(self):
        self.assertIsNone(t.parse_interfaces([], [], [], [], [], []))


class TestBridgeAndVlans(unittest.TestCase):
    def test_bridge_port_numbering_comes_from_the_device(self):
        # in the default context each Cisco switch lists only VLAN 1's ports,
        # with numbering that differs per model
        _r, col, _ = device("l3")
        self.assertEqual(t.parse_index_map(col(t.DOT1D_BASE_PORT_IFINDEX), t.DOT1D_BASE_PORT_IFINDEX),
                         {1: 10101, 2: 10102})
        _r, col, _ = device("l2")
        self.assertEqual(t.parse_index_map(col(t.DOT1D_BASE_PORT_IFINDEX), t.DOT1D_BASE_PORT_IFINDEX),
                         {2: 10002, 50: 10102})

    def test_hp_bridge_ports_and_no_pvid_in_the_capture(self):
        _r, col, _ = device("hp")
        self.assertEqual(len(t.parse_index_map(col(t.DOT1D_BASE_PORT_IFINDEX),
                                               t.DOT1D_BASE_PORT_IFINDEX)), 52)
        # the capture's walk stopped at the HP's out-of-order forwarding table
        self.assertIsNone(t.parse_index_map(col(t.DOT1Q_PVID), t.DOT1Q_PVID))

    def test_access_point_pvid(self):
        _r, col, _ = device("ap")
        self.assertEqual(t.parse_index_map(col(t.DOT1Q_PVID), t.DOT1Q_PVID),
                         {2: 0, 3: 0, 5: 0, 6: 0, 7: 0, 8: 0})

    def test_cisco_membership_lists_access_ports_only(self):
        _r, col, _ = device("l3")
        vm = t.parse_index_map(col(t.VM_VLAN), t.VM_VLAN)
        self.assertEqual(len(vm), 23)
        self.assertEqual((vm[10101], vm[10102], vm[10003]), (1, 1, 40))
        self.assertNotIn(10002, vm)          # the trunk to L2-Switch
        self.assertNotIn(10015, vm)          # the trunk to the access point


class TestCiscoTables(unittest.TestCase):
    def test_port_security(self):
        _r, col, get = device("l3")
        ps = t.parse_port_security(get(t.CPS_GLOBAL_ENABLE), col(t.CPS_IF_ENABLE))
        self.assertTrue(ps["global"])
        self.assertEqual(Counter(ps["ports"].values()), {False: 26})

    def test_bpdu_guard_off_everywhere_on_l3(self):
        _r, col, get = device("l3")
        bpdu = t.parse_bpdu(get(t.STPX_BPDU_GUARD_GLOBAL), get(t.STPX_FAST_START_DEFAULT),
                            col(t.STPX_PORT_MODE), col(t.STPX_PORT_BPDU_GUARD))
        self.assertEqual((bpdu["global_guard"], bpdu["global_portfast"], len(bpdu["ports"])),
                         (False, 2, 26))
        self.assertEqual({t.bpdu_guard_on(bpdu, bp) for bp in bpdu["ports"]}, {False})

    def test_hp_and_access_point_have_no_cisco_tables(self):
        for name in ("hp", "ap"):
            _r, col, get = device(name)
            self.assertIsNone(t.parse_index_map(col(t.VM_VLAN), t.VM_VLAN))
            self.assertIsNone(t.parse_port_security(get(t.CPS_GLOBAL_ENABLE), col(t.CPS_IF_ENABLE)))
            self.assertIsNone(t.parse_bpdu(get(t.STPX_BPDU_GUARD_GLOBAL),
                                           get(t.STPX_FAST_START_DEFAULT),
                                           col(t.STPX_PORT_MODE), col(t.STPX_PORT_BPDU_GUARD)))


class TestBpduGuardRules(unittest.TestCase):
    def bpdu(self, guard, portfast, global_guard=True, global_portfast=2):
        return {"global_guard": global_guard, "global_portfast": global_portfast,
                "ports": {7: {"portfast": portfast, "guard": guard}}}

    def test_explicit_mode_wins(self):
        self.assertTrue(t.bpdu_guard_on(self.bpdu(t.GUARD_ENABLE, t.PORTFAST_DISABLE, False), 7))
        self.assertFalse(t.bpdu_guard_on(self.bpdu(t.GUARD_DISABLE, t.PORTFAST_ENABLE, True), 7))

    def test_default_follows_global_only_with_port_fast_on(self):
        self.assertTrue(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_ENABLE), 7))
        self.assertFalse(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_DISABLE), 7))
        self.assertFalse(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_DEFAULT), 7))
        self.assertTrue(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_DEFAULT,
                                                  global_portfast=1), 7))
        self.assertFalse(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_ENABLE,
                                                   global_guard=False), 7))

    def test_unknown_when_not_read(self):
        self.assertIsNone(t.bpdu_guard_on(self.bpdu(t.GUARD_DEFAULT, t.PORTFAST_ENABLE,
                                                    global_guard=None), 7))
        self.assertIsNone(t.bpdu_guard_on(self.bpdu(t.GUARD_ENABLE, 1), 8))


if __name__ == "__main__":
    unittest.main()
