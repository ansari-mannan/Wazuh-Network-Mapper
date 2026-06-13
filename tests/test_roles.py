"""Device-role derivation: LLDP capability-bitmap decode, fallbacks, and the
neighbor-port vs uplink-port (infrastructure) split."""

import unittest

from vulnmapper.network.parse import build_neighbors
from vulnmapper.network.roles import (
    decode_capabilities,
    derive_role,
    neighbor_is_infrastructure,
    role_from_capabilities,
)


class TestDecodeCapabilities(unittest.TestCase):
    def test_known_bitmaps(self):
        # BITS encoded MSB-first: bridge=cap3=0x20, router=cap5=0x08, etc.
        self.assertEqual(decode_capabilities("0x28"), {"bridge", "router"})  # L3
        self.assertEqual(decode_capabilities("0x20"), {"bridge"})           # L2
        self.assertEqual(decode_capabilities("0x08"), {"router"})
        self.assertEqual(decode_capabilities("0x10"), {"wlan-ap"})
        self.assertEqual(decode_capabilities("0x04"), {"telephone"})
        self.assertEqual(decode_capabilities("0x01"), {"station"})

    def test_accepts_two_byte_and_bytes_and_separators(self):
        self.assertEqual(decode_capabilities("0x2800"), {"bridge", "router"})
        self.assertEqual(decode_capabilities(bytes([0x28])), {"bridge", "router"})
        self.assertEqual(decode_capabilities("28 00"), {"bridge", "router"})

    def test_empty_or_garbage_is_no_caps(self):
        self.assertEqual(decode_capabilities(None), set())
        self.assertEqual(decode_capabilities(""), set())
        self.assertEqual(decode_capabilities("not-hex"), set())

    def test_printable_octet_rendering(self):
        # A 1-octet capability map whose byte is printable comes through SNMP as
        # the literal character: 0x28 -> "(" (HP Comware, some Cisco). It must
        # still decode to Bridge+Router, not be mistaken for text.
        self.assertEqual(decode_capabilities("("), {"bridge", "router"})
        self.assertEqual(decode_capabilities("\x00"), set())  # 1-octet no-caps
        # Longer non-hex input is still genuine garbage, never a false positive.
        self.assertEqual(decode_capabilities("router"), set())


class TestRoleFromCapabilities(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(role_from_capabilities({"router", "bridge"}), "l3-switch")
        self.assertEqual(role_from_capabilities({"bridge"}), "l2-switch")
        self.assertEqual(role_from_capabilities({"router"}), "router")
        self.assertEqual(role_from_capabilities({"wlan-ap"}), "access-point")
        self.assertEqual(role_from_capabilities({"telephone"}), "phone")
        self.assertEqual(role_from_capabilities({"station"}), "station")
        self.assertIsNone(role_from_capabilities({"other"}))
        self.assertIsNone(role_from_capabilities(set()))


class TestDeriveRole(unittest.TestCase):
    def test_capabilities_win_over_fallback(self):
        # An L3 switch advertises caps even though the vendor is Cisco.
        self.assertEqual(derive_role(capabilities="0x28", vendor="Cisco"), "l3-switch")

    def test_no_vendor_guessing_fortigate_uses_its_caps(self):
        # A FortiGate advertises the Router capability; with no vendor guessing it
        # is reported honestly as "router" from its own LLDP evidence.
        self.assertEqual(
            derive_role(capabilities="0x08", vendor="Fortinet",
                        model="FortiGate 200D", kind="device"),
            "router",
        )

    def test_endpoint_without_caps_is_host(self):
        self.assertEqual(derive_role(kind="endpoint"), "host")

    def test_lldp_station_endpoint(self):
        # A Wazuh endpoint that also speaks LLDP (station caps) -> station.
        self.assertEqual(derive_role(capabilities="0x01", kind="endpoint"), "station")

    def test_unidentified_device_is_unknown_network_device(self):
        # No caps, no usable LLDP evidence -> honest label, never a vendor guess.
        self.assertEqual(derive_role(kind="device"), "Unknown Network Device")
        self.assertEqual(
            derive_role(vendor="Fortinet", model="FortiGate-60F", kind="device"),
            "Unknown Network Device",
        )


class TestNeighborIsInfrastructure(unittest.TestCase):
    def test_mgmt_ip_is_infra(self):
        self.assertTrue(neighbor_is_infrastructure("172.20.99.2", None))

    def test_station_caps_is_not_infra(self):
        self.assertFalse(neighbor_is_infrastructure(None, "0x01"))

    def test_bridge_caps_without_mgmt_is_infra(self):
        # A switch still being configured: no mgmt IP yet, but advertises bridge.
        self.assertTrue(neighbor_is_infrastructure(None, "0x20"))

    def test_no_signal_is_access_port(self):
        self.assertFalse(neighbor_is_infrastructure(None, None))


def _rem_rows(local_port, rem_index, *, chassis, cap_enabled):
    """Minimal lldpRemTable rows for one neighbor (cols 5=chassis, 12=cap)."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    tm = "0"  # timeMark
    return [
        (f"{base}.5.{tm}.{local_port}.{rem_index}", chassis),
        (f"{base}.12.{tm}.{local_port}.{rem_index}", cap_enabled),
    ]


def _man_rows(local_port, rem_index, ip):
    """An lldpRemManAddr row advertising an IPv4 management address."""
    base = "1.0.8802.1.1.2.1.4.2.1"
    octets = ".".join(ip.split("."))
    # column.timeMark.localPort.remIndex.subtype(1=ipv4).len(4).a.b.c.d
    return [(f"{base}.1.0.{local_port}.{rem_index}.1.4.{octets}", "1")]


class TestNeighborUplinkSplit(unittest.TestCase):
    """The crawler's port split: neighbor_ports (all) vs uplink_ports (infra)."""

    def test_lldp_caps_parsed_into_neighbor(self):
        rem = _rem_rows("1", "1", chassis="0xaabbccddeeff", cap_enabled="0x28")
        nbrs = build_neighbors(rem, [], [])
        self.assertEqual(nbrs[0].cap_enabled, "0x28")

    def test_split_infra_vs_access(self):
        # Port 1 -> an infra switch (has mgmt IP); port 2 -> a station end host.
        rem = (
            _rem_rows("1", "1", chassis="core", cap_enabled="0x28")
            + _rem_rows("2", "1", chassis="0x001122334455", cap_enabled="0x01")
        )
        man = _man_rows("1", "1", "172.20.99.2")
        loc = [("1.0.8802.1.1.2.1.3.7.1.3.1", "Gi2/0/1"),
               ("1.0.8802.1.1.2.1.3.7.1.3.2", "Gi2/0/7")]
        neighbors = build_neighbors(rem, man, loc)

        neighbor_ports = {n.local_port for n in neighbors if n.local_port}
        uplink_ports = {
            n.local_port for n in neighbors
            if n.local_port and neighbor_is_infrastructure(n.mgmt_ip, n.cap_enabled)
        }
        self.assertEqual(neighbor_ports, {"Gi2/0/1", "Gi2/0/7"})
        self.assertEqual(uplink_ports, {"Gi2/0/1"})  # access port excluded


if __name__ == "__main__":
    unittest.main()
