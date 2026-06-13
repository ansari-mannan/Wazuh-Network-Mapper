"""Comware (HP 1920 / H3C) vendor plugin + offline parsing against a live capture.

The fixture ``fixtures/comware_hp1920_cyfor.snmp`` is a real SNMP capture of the
lab HP 1920-48G (CYFOR-HP-Switch, 172.20.99.4), produced by
``tools/verify_comware.py --capture``. Capability/MAC octets are stored as
``0x<hex>`` (never the SNMP printable-octet rendering, e.g. 0x28 -> "("), so the
pure parsers and roles.decode_capabilities consume them as on a real run.

These tests are fully offline: they exercise the same pure parsers the live
crawler uses (lldp.build_neighbors, fdb.build_fdb, roles) against the captured
rows, asserting the re-baselined topology — the HP is a switch parented to
L3-Switch via LLDP and now owns several endpoints on its access ports.
"""

import asyncio
import os
import unittest

import re

from vulnmapper.common.mac import canonical_mac
from vulnmapper.network import fdb, lldp
from vulnmapper.network.roles import (
    decode_capabilities,
    derive_role,
    neighbor_is_infrastructure,
    role_from_capabilities,
)
from vulnmapper.network.vendors import comware

_PORT_TOKEN_LEAK_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{12}$|^\d+$")

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "comware_hp1920_cyfor.snmp")


def _load_rows(path):
    """Load a flat ``OID\\tVALUE`` capture into ``[(oid, value), ...]``.

    A missing value (empty column) becomes "" — the same thing the live client
    yields for an empty OctetString, so the parsers behave identically.
    """
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            oid, _, value = line.partition("\t")
            rows.append((oid, value))
    return rows


class TestComwarePlugin(unittest.TestCase):
    """The plugin's pure identity logic (no SNMP)."""

    def test_matches_by_enterprise_prefix_not_sysdescr(self):
        self.assertTrue(comware.matches("1.3.6.1.4.1.25506.11.1.169"))
        self.assertTrue(comware.matches("1.3.6.1.4.1.25506.1.2.3"))
        self.assertFalse(comware.matches("1.3.6.1.4.1.9.1.516"))     # Cisco
        self.assertFalse(comware.matches("1.3.6.1.4.1.12356.101.1"))  # Fortinet
        self.assertFalse(comware.matches(None))

    def test_parse_version_is_vendor_token_agnostic(self):
        descr = ("1920-48G Switch Software Version 5.20.99, Release 1107 "
                 "Copyright(c)2010-2015 Hewlett-Packard Development Company, L.P.")
        self.assertEqual(comware.parse_version(descr),
                         {"version": "5.20.99", "release": "1107"})
        # No "Comware"/"HP" token is required; a different vendor banner still parses.
        self.assertEqual(comware.parse_version("Anything Version 7.1.070, Release 0001")["version"],
                         "7.1.070")
        self.assertEqual(comware.parse_version("no version here"),
                         {"version": None, "release": None})

    def test_identify_model_and_firmware(self):
        descr = "1920-48G Switch Software Version 5.20.99, Release 1107"
        info = asyncio.run(comware.identify(descr, "1.3.6.1.4.1.25506.11.1.169", None, "x"))
        self.assertEqual(info["model"], "HP 1920-48G")
        self.assertEqual(info["firmware"], "5.20.99 Release 1107")
        self.assertIsNone(info["serial"])

    def test_identify_unknown_model_is_none_not_error(self):
        info = asyncio.run(comware.identify("Switch Version 5.20.99, Release 1107",
                                            "1.3.6.1.4.1.25506.99.99.99", None, "x"))
        self.assertIsNone(info["model"])           # unmapped sysObjectID -> None
        self.assertEqual(info["firmware"], "5.20.99 Release 1107")


class TestComwareLldpFromFixture(unittest.TestCase):
    """LLDP neighbor parsing + role/endpoint classification on the live capture."""

    @classmethod
    def setUpClass(cls):
        cls.rows = _load_rows(_FIXTURE)
        # build_neighbors filters each table by its own base, so the full flat
        # row list can be passed to all three arguments.
        cls.neighbors = lldp.build_neighbors(cls.rows, cls.rows, cls.rows)

    def test_exactly_one_infrastructure_uplink_the_l3_switch(self):
        infra = [n for n in self.neighbors
                 if neighbor_is_infrastructure(n.mgmt_ip, n.cap_enabled)]
        self.assertEqual(len(infra), 1)
        up = infra[0]
        self.assertEqual(up.chassis_id, "00:23:ac:e5:74:00")
        self.assertEqual(up.sys_name, "L3-Switch")
        self.assertEqual(up.port_id, "Fa1/0/2")
        self.assertEqual(up.port_descr, "FastEthernet1/0/2")
        self.assertIn("C3750", up.sys_descr)
        self.assertIn("12.2(55)SE12", up.sys_descr)
        # The capability-bitmap trap: 0x28 (single octet) must decode correctly.
        self.assertEqual(decode_capabilities(up.cap_enabled), {"bridge", "router"})
        self.assertEqual(role_from_capabilities(decode_capabilities(up.cap_enabled)),
                         "l3-switch")

    def test_local_ports_resolve_to_ifnames_no_leaked_tokens(self):
        # Issue 1: the HP advertises lldpLocPortId inconsistently (uplink as a
        # name, access ports as a MAC, some as a bare integer). After resolution
        # every local_port must be a GigabitEthernet name, no 0x-MAC / bare-int.
        ifname_by_index = fdb.parse_ifnames(self.rows)
        ifindex_by_mac = fdb.parse_ifphys_ifindex(self.rows)
        lldp.normalize_neighbor_ports(self.neighbors, ifname_by_index, ifindex_by_mac,
                                      node_label="CYFOR-HP-Switch")
        ports = {nb.local_port for nb in self.neighbors if nb.local_port}
        self.assertTrue(ports)
        for p in ports:
            self.assertFalse(_PORT_TOKEN_LEAK_RE.match(p), f"leaked raw token: {p}")
            self.assertTrue(p.startswith("GigabitEthernet1/0/"), p)
        # The three CYFOR access ports resolve exactly per the spec table.
        self.assertEqual({"GigabitEthernet1/0/5", "GigabitEthernet1/0/15",
                          "GigabitEthernet1/0/25"} & ports,
                         {"GigabitEthernet1/0/5", "GigabitEthernet1/0/15",
                          "GigabitEthernet1/0/25"})

    def test_non_uplink_neighbors_are_endpoint_hints_not_devices(self):
        endpoints = [n for n in self.neighbors
                     if not neighbor_is_infrastructure(n.mgmt_ip, n.cap_enabled)]
        self.assertTrue(endpoints)  # the HP has directly-attached endpoints
        for n in endpoints:
            # macAddress chassis, empty sysName/sysDesc, no capabilities ->
            # classified as an endpoint hint (MAC for the Wazuh matcher), never
            # crawled as a kind:device node.
            self.assertIsNotNone(n.chassis_mac)
            self.assertFalse(n.sys_name)
            self.assertFalse(n.sys_descr)
            self.assertEqual(decode_capabilities(n.cap_enabled), set())
            self.assertEqual(derive_role(capabilities=n.cap_enabled, kind="endpoint"),
                             "host")


class TestComwareFdbFromFixture(unittest.TestCase):
    """FDB parsing + the bridge-port -> ifIndex -> ifName resolution chain."""

    @classmethod
    def setUpClass(cls):
        cls.rows = _load_rows(_FIXTURE)
        # Each parser inside build_fdb filters the flat list by its own base.
        cls.entries = fdb.build_fdb(
            dot1q_rows=cls.rows, baseport_rows=cls.rows, ifname_rows=cls.rows)

    def test_dot1q_parse_is_order_independent(self):
        # Comware returns dot1qTpFdbPort sorted by MAC (non-increasing OID). The
        # pure parser is order-independent, which is exactly WHY this pipeline
        # needs no ignoreNonIncreasingOid workaround.
        parsed = fdb.parse_dot1q_fdb(self.rows)
        self.assertEqual(len(parsed), len(self.entries))
        self.assertGreater(len(parsed), 6)  # full table, not a truncated 6 rows

    def test_every_port_resolves_via_tables_to_a_real_name(self):
        # No raw bridge-port / ifIndex fallbacks: the chain resolved every row.
        for e in self.entries:
            self.assertTrue(e["port"].startswith("GigabitEthernet1/0/"),
                            f"unresolved port: {e}")

    def test_gateway_mac_on_uplink_in_every_vlan(self):
        gw = "0023ace57404"  # the L3-Switch SVI/gateway riding the trunk
        vlans = {e["vlan"] for e in self.entries
                 if e["mac"] == gw and e["port"] == "GigabitEthernet1/0/1"}
        self.assertTrue({10, 20, 30, 40, 99}.issubset(vlans))

    def test_hp_owns_endpoints_on_access_ports(self):
        # Re-baselined reality: the HP learns non-gateway endpoint MACs on access
        # ports (not just the uplink) -> it owns endpoints.
        access = [e for e in self.entries
                  if e["port"] != "GigabitEthernet1/0/1"
                  and not canonical_mac(e["mac"]).startswith("0023ac")]
        self.assertTrue(access)
        # A specific known endpoint resolves through the bridge-port table.
        self.assertIn(
            {"mac": "d4bed997f4ca", "port": "GigabitEthernet1/0/5", "vlan": 10},
            self.entries,
        )


if __name__ == "__main__":
    unittest.main()
