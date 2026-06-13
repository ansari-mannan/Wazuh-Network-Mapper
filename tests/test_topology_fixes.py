"""Regression tests for the topology-output fixes (graph.json defects 1, 3, 4).

These are offline: Issue 1 exercises the pure LLDP local-port resolver with the
real HP 1920 values; Issues 3 & 4 drive the real ``assemble()`` with small inputs
carrying the exact lab values (duplicate IP 172.20.30.21, the CYFOR-3 / Laptop-1
CVSS scores). Each assertion encodes the CORRECT post-fix behavior; the pre-fix
state is captured in fixtures/graph_2026-06-13.json (0x-MAC ports, null max_cvss,
no stale flag).
"""

import unittest

from vulnmapper.assemble import assemble
from vulnmapper.network.parse import (
    needs_port_resolution,
    normalize_local_port,
)

# Real HP 1920 (CYFOR-HP-Switch) interface maps, verified live 2026-06-13.
_IFNAME = {
    "1": "GigabitEthernet1/0/1",
    "5": "GigabitEthernet1/0/5",
    "15": "GigabitEthernet1/0/15",
    "25": "GigabitEthernet1/0/25",
    "35": "GigabitEthernet1/0/35",
}
_IFINDEX_BY_MAC = {
    "5c8a388ba111": "5",
    "5c8a388ba11b": "15",
    "5c8a388ba125": "25",
    "5c8a388ba12f": "35",
}


class TestIssue1LocalPortResolution(unittest.TestCase):
    """Issue 1 — LLDP local ports must never leak as MAC hex / bare integers."""

    def test_mac_form_resolves_via_localportnum(self):
        # Primary chain: lldpRemLocalPortNum -> ifIndex -> ifName.
        self.assertEqual(
            normalize_local_port("0x5c8a388ba111", "5", _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/5", True))
        self.assertEqual(
            normalize_local_port("0x5c8a388ba11b", "15", _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/15", True))
        self.assertEqual(
            normalize_local_port("0x5c8a388ba125", "25", _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/25", True))

    def test_mac_form_resolves_via_ifphysaddress_when_no_portnum(self):
        # Fallback chain: advertised MAC -> ifPhysAddress -> ifIndex -> ifName.
        self.assertEqual(
            normalize_local_port("0x5c8a388ba111", None, _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/5", True))

    def test_bare_integer_resolves_as_ifindex(self):
        self.assertEqual(
            normalize_local_port("35", "35", _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/35", True))
        self.assertEqual(
            normalize_local_port("35", None, _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/35", True))

    def test_real_interface_name_is_left_untouched(self):
        # Cisco/Fortinet advertise proper port names — never rewritten.
        self.assertEqual(
            normalize_local_port("Fa1/0/2", "7", _IFNAME, _IFINDEX_BY_MAC),
            ("Fa1/0/2", True))
        self.assertEqual(
            normalize_local_port("GigabitEthernet1/0/1", "1", _IFNAME, _IFINDEX_BY_MAC),
            ("GigabitEthernet1/0/1", True))

    def test_unresolvable_keeps_raw_and_flags_not_ok(self):
        resolved, ok = normalize_local_port("0xaaaaaaaaaaaa", None, {}, {})
        self.assertEqual(resolved, "0xaaaaaaaaaaaa")
        self.assertFalse(ok)

    def test_needs_port_resolution_predicate(self):
        self.assertTrue(needs_port_resolution("0x5c8a388ba111"))
        self.assertTrue(needs_port_resolution("5c8a388ba111"))
        self.assertTrue(needs_port_resolution("35"))
        self.assertFalse(needs_port_resolution("GigabitEthernet1/0/1"))
        self.assertFalse(needs_port_resolution("Fa1/0/2"))
        self.assertFalse(needs_port_resolution(None))


def _cve(cvss):
    return {"cve": f"CVE-X-{cvss}", "cvss": cvss, "severity": "Critical"}


def _assembled_lab_graph():
    """assemble() with the real duplicate-IP + CVSS lab values, no network side."""
    endpoints = [
        {"agent_id": "001", "ip": "172.20.10.21", "hostname": "CYFOR-3",
         "status": "active", "mac": "d4:be:d9:97:f4:ca", "risk_score": 9.8,
         "top_cves": [_cve(9.8), _cve(9.8), _cve(9.6)]},
        {"agent_id": "004", "ip": "172.20.30.21", "hostname": "CYFOR-1",
         "status": "active", "mac": "d4:be:d9:98:2e:d4", "risk_score": 9.6,
         "top_cves": [_cve(9.6), _cve(9.6), _cve(9.6)]},
        {"agent_id": "008", "ip": "172.20.30.21", "hostname": "Laptop-1",
         "status": "disconnected", "mac": "c8:5a:cf:6d:3d:61", "risk_score": 10.0,
         "top_cves": [_cve(10.0), _cve(9.8), _cve(9.1)]},
    ]
    network_doc = {"nodes": [
        {"chassis_id": "00:23:ac:e5:74:00", "ip": "172.20.40.254",
         "hostname": "L3-Switch", "vendor": "Cisco", "model": "C3750",
         "status": "online", "pollable": True, "lldp_cap_enabled": "0x28",
         "risk_score": 0},
    ], "edges": []}
    doc = assemble(endpoints, network_doc)
    return doc, {n["node_id"]: n for n in doc["nodes"]}


class TestIssue3DuplicateIpAndStale(unittest.TestCase):
    """Issue 3 — duplicate IP flagged, stale agent marked + excluded as a source."""

    def setUp(self):
        self.doc, self.by_id = _assembled_lab_graph()

    def test_duplicate_ip_warning_names_both_nodes(self):
        warnings = self.doc["metadata"]["warnings"]
        dup = [w for w in warnings
               if w.get("type") == "duplicate_ip" and w.get("ip") == "172.20.30.21"]
        self.assertEqual(len(dup), 1)
        ids = {n["node_id"] for n in dup[0]["nodes"]}
        self.assertEqual(ids, {"endpoint:004", "endpoint:008"})

    def test_stale_flag_on_disconnected_collider_only(self):
        self.assertTrue(self.by_id["endpoint:008"]["stale"])
        self.assertFalse(self.by_id["endpoint:004"]["stale"])

    def test_attack_path_sources_exclude_stale_disconnected(self):
        sources = self.doc["metadata"]["attack_path_sources"]
        self.assertNotIn("endpoint:008", sources)
        self.assertIn("endpoint:004", sources)
        self.assertIn("endpoint:001", sources)

    def test_stale_node_still_present_unparented_with_reason(self):
        self.assertIn("endpoint:008", self.by_id)
        self.assertIsNone(self.by_id["endpoint:008"]["parent_id"])
        unparented = self.doc["metadata"]["unparented_endpoints"]
        reason = {u["node_id"]: u["reason"] for u in unparented}
        self.assertEqual(reason.get("endpoint:008"), "host_offline_no_l2_evidence")


class TestIssue4MaxCvss(unittest.TestCase):
    """Issue 4 — max_cvss populated from top_cves; risk_score stays for ranking."""

    def setUp(self):
        self.doc, self.by_id = _assembled_lab_graph()

    def test_endpoint_max_cvss_from_top_cves(self):
        self.assertEqual(self.by_id["endpoint:001"]["max_cvss"], 9.8)
        self.assertEqual(self.by_id["endpoint:008"]["max_cvss"], 10.0)

    def test_device_without_cves_has_null_max_cvss(self):
        dev = self.by_id["device:00:23:ac:e5:74:00"]
        self.assertIsNone(dev["max_cvss"])
        self.assertEqual(dev["risk_score"], 0)

    def test_risk_score_still_present(self):
        self.assertEqual(self.by_id["endpoint:001"]["risk_score"], 9.8)


if __name__ == "__main__":
    unittest.main()
