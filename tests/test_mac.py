"""MAC canonicalization — the one comparison key both sides must agree on."""

import unittest

from vulnmapper.common.mac import canonical_mac, format_mac, normalize_mac


class TestCanonicalMac(unittest.TestCase):
    def test_all_forms_collapse_to_same_key(self):
        forms = [
            "e4:a7:a0:25:ce:ad",      # endpoint / colon
            "E4-A7-A0-25-CE-AD",      # dash, upper
            "0xe4a7a025cead",          # pysnmp prettyPrint
            "E4 A7 A0 25 CE AD",      # net-snmp Hex-STRING
            "e4a7.a025.cead",          # Cisco dotted
            b"\xe4\xa7\xa0\x25\xce\xad",  # raw 6-byte OctetString
        ]
        keys = {canonical_mac(f) for f in forms}
        self.assertEqual(keys, {"e4a7a025cead"})

    def test_non_mac_returns_none(self):
        for value in (None, "", "not-a-mac", "172.20.10.1", "0x1234"):
            self.assertIsNone(canonical_mac(value))

    def test_format_mac_colon_form(self):
        self.assertEqual(format_mac("E4A7A025CEAD"), "e4:a7:a0:25:ce:ad")
        self.assertIsNone(format_mac("nope"))

    def test_normalize_mac_is_colon_form(self):
        # The network crawler imports normalize_mac expecting the colon form.
        self.assertEqual(normalize_mac(b"\x00\x23\xac\xe5\x74\x00"), "00:23:ac:e5:74:00")

    def test_endpoint_and_fdb_sides_match(self):
        # Endpoint reports colon form; FDB parser yields bare hex. They must equal.
        endpoint_side = canonical_mac("e4:a7:a0:25:ce:ad")
        fdb_side = canonical_mac("e4a7a025cead")
        self.assertEqual(endpoint_side, fdb_side)


if __name__ == "__main__":
    unittest.main()
