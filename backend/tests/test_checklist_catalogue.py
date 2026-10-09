"""The configuration check catalogue: every severity comes from a reference."""

import unittest

from vulnmapper.checklist.catalogue import CATALOGUE, SEVERITIES, by_id, references_for

FIRST_PASS = ["mgmt-telnet-enabled", "mgmt-http-enabled", "snmp-no-auth",
              "snmp-default-community", "spare-ports-in-used-vlan", "access-ports-default-vlan",
              "bpdu-guard-missing", "port-security-disabled"]


class TestCatalogue(unittest.TestCase):
    def test_first_pass_in_order(self):
        self.assertEqual([c["id"] for c in CATALOGUE], FIRST_PASS)

    def test_every_entry_is_complete(self):
        for c in CATALOGUE:
            with self.subTest(check=c["id"]):
                for key in ("id", "title", "why", "applies_to", "references", "severity",
                            "cwe", "remediation"):
                    self.assertIn(key, c)
                self.assertTrue(c["title"] and c["why"] and c["remediation"])
                self.assertIn(c["severity"], SEVERITIES + (None,))

    def test_severity_only_with_a_reference_that_carries_it(self):
        for c in CATALOGUE:
            with self.subTest(check=c["id"]):
                binding = [r for r in c["references"] if r["relation"] == "requires"]
                if c["severity"] is None:            # Advisory
                    self.assertEqual(binding, [])
                    continue
                self.assertTrue(binding)
                for ref in binding:
                    self.assertEqual(ref["severity"], c["severity"])
                    self.assertTrue(ref["rule_id"] and ref["url"].startswith("https://"))

    def test_every_reference_has_an_id_and_a_url(self):
        for c in CATALOGUE:
            for ref in c["references"]:
                with self.subTest(check=c["id"], ref=ref["rule_id"]):
                    self.assertTrue(ref["rule_id"])
                    self.assertTrue(ref["url"].startswith("https://"))
                    self.assertIn(ref["scope"], ("cisco_ios", "any"))
                    self.assertIn(ref["relation"], ("requires", "related"))

    def test_stig_categories_match_severity(self):
        cat = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
        for c in CATALOGUE:
            for ref in c["references"]:
                if ref["source"] == "DISA" and ref["severity"]:
                    self.assertEqual(ref["category"], cat[ref["severity"]], ref["rule_id"])

    def test_cwe_ids_are_well_formed(self):
        for c in CATALOGUE:
            if c["cwe"] is not None:
                self.assertRegex(c["cwe"], r"^CWE-\d+$")

    def test_advisory_checks(self):
        self.assertIsNone(by_id("port-security-disabled")["severity"])

    def test_spare_ports_implement_the_unused_vlan_rule(self):
        check = by_id("spare-ports-in-used-vlan")
        self.assertEqual(check["severity"], "medium")
        self.assertEqual([(r["rule_id"], r["relation"]) for r in check["references"]],
                         [("V-220641", "requires"), ("V-206666", "requires")])

    def test_cisco_devices_get_the_cisco_rule_others_the_srg(self):
        cisco = [r["rule_id"] for r in references_for(by_id("bpdu-guard-missing"), "cisco_ios")]
        other = [r["rule_id"] for r in references_for(by_id("bpdu-guard-missing"), "hp_comware")]
        self.assertEqual(cisco, ["V-220630"])
        self.assertEqual(other, ["V-206655"])
        # a reference that is not vendor-specific goes to everyone
        self.assertEqual([r["rule_id"] for r in references_for(by_id("snmp-default-community"), None)],
                         ["CVE-1999-0517"])


if __name__ == "__main__":
    unittest.main()
