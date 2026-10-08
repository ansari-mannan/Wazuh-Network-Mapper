"""Part 6: confirm a wired host from its switch's MAC table, cheaply.

The lookup GETs specific forwarding-table entries (never a walk): Cisco in the
per-VLAN community context (802.1D table), anything else in the 802.1Q table.
Bridge port -> ifIndex -> ifName, the same chain the scan uses.
"""

import asyncio
import unittest

from snmp_fakes import FakeSnmpClient
from vulnmapper.assemble import assemble
from vulnmapper.network import parse

SW = "10.0.0.2"
QUIET = "28f10e313f0c"
OTHER = "d4bed997f665"


def dec(mac):
    return ".".join(str(int(mac[i:i + 2], 16)) for i in range(0, 12, 2))


def lookup(client, entries, per_vlan_context):
    return asyncio.run(parse.lookup_fdb_ports(client, SW, entries, per_vlan_context))


class TestLookup(unittest.TestCase):
    def cisco(self):
        vlan20 = [(f"{parse.DOT1D_FDB_PORT_BASE}.{dec(QUIET)}", "14"),
                  (f"{parse.DOT1D_BASEPORT_IFINDEX_BASE}.14", "10014")]
        return FakeSnmpClient({SW: [(f"{parse.IFNAME_BASE}.10014", "Fa1/0/14")]},
                              vlan_rows={(SW, 20): vlan20})

    def test_cisco_per_vlan_context(self):
        client = self.cisco()
        found = lookup(client, [(20, QUIET), (20, OTHER)], per_vlan_context=True)
        self.assertEqual(found, {(20, QUIET): "Fa1/0/14", (20, OTHER): None})
        self.assertEqual([c[0] for c in client.calls if c[0].startswith("walk")], [])  # no walks

    def test_dot1q_default_context(self):
        rows = [(f"{parse.DOT1Q_FDB_PORT_BASE}.20.{dec(QUIET)}", "14"),
                (f"{parse.DOT1D_BASEPORT_IFINDEX_BASE}.14", "14"),
                (f"{parse.IFNAME_BASE}.14", "GigabitEthernet1/0/14")]
        client = FakeSnmpClient({SW: rows})
        found = lookup(client, [(20, QUIET), (30, QUIET)], per_vlan_context=False)
        self.assertEqual(found, {(20, QUIET): "GigabitEthernet1/0/14", (30, QUIET): None})
        self.assertFalse([c for c in client.calls if c[0] == "get_vlan"])

    def test_no_vlan_uses_the_802_1d_table(self):
        rows = [(f"{parse.DOT1D_FDB_PORT_BASE}.{dec(QUIET)}", "3"),
                (f"{parse.DOT1D_BASEPORT_IFINDEX_BASE}.3", "3"),
                (f"{parse.IFNAME_BASE}.3", "port3")]
        found = lookup(FakeSnmpClient({SW: rows}), [(None, QUIET)], per_vlan_context=False)
        self.assertEqual(found, {(None, QUIET): "port3"})

    def test_requests_are_batched(self):
        client = self.cisco()
        macs = [f"0200000000{i:02x}" for i in range(45)] + [QUIET]
        lookup(client, [(20, m) for m in macs], per_vlan_context=True)
        gets = [c for c in client.calls if c[0] in ("get", "get_vlan")]
        self.assertLessEqual(max(len(c[-1]) for c in gets), parse.MAC_LOOKUP_BATCH)
        self.assertLessEqual(len(gets), 6)          # 3 FDB batches + base port + ifName


class TestVlanOnNodes(unittest.TestCase):
    """The scan records the VLAN a host was learned on, for the per-VLAN lookup."""

    def doc(self):
        sw = {"chassis_id": "sw", "ip": SW, "pollable": True, "status": "online",
              "uplink_ports": [], "own_macs": [],
              "fdb": [{"mac": QUIET, "port": "Fa1/0/14", "vlan": 20},
                      {"mac": OTHER, "port": "Fa1/0/15", "vlan": 30}]}
        return {"nodes": [sw], "edges": []}

    def test_discovered_host_and_endpoint_carry_their_vlan(self):
        agent = {"agent_id": "001", "mac": "d4:be:d9:97:f6:65", "ip": "10.0.0.9",
                 "status": "active", "risk_score": 1.0, "top_cves": []}
        nodes = {n["node_id"]: n for n in assemble([agent], self.doc())["nodes"]}
        self.assertEqual(nodes["host:28:f1:0e:31:3f:0c"]["vlan"], 20)
        self.assertEqual(nodes["endpoint:001"]["vlan"], 30)

    def test_no_vlan_field_without_a_table_entry(self):
        agent = {"agent_id": "002", "mac": None, "ip": "10.0.0.10", "status": "active",
                 "risk_score": 1.0, "top_cves": []}
        nodes = {n["node_id"]: n for n in assemble([agent], self.doc())["nodes"]}
        self.assertNotIn("vlan", nodes["endpoint:002"])
        self.assertNotIn("vlan", nodes["device:sw"])


if __name__ == "__main__":
    unittest.main()
