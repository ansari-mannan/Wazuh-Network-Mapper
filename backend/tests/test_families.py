"""From device identity to a standard product identifier (CPE 2.3)."""

import json
import os
import unittest

from vulnmapper.devicecves import families as fam

HERE = os.path.dirname(os.path.abspath(__file__))
NVD = os.path.join(HERE, "fixtures", "nvd")

IOS = ("Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 12.2(55)SE12, "
       "RELEASE SOFTWARE (fc2) Technical Support: http://www.cisco.com/techsupport")
IOS_OLD = ("Cisco Internetwork Operating System Software IOS (tm) C2950 Software "
           "(C2950-I6Q4L2-M), Version 12.1(22)EA14, RELEASE SOFTWARE (fc1)")
IOS_XE = ("Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT9K_IOSXE), "
          "Version 16.9.4, RELEASE SOFTWARE (fc2)")
IOS_XE_17 = "Cisco IOS XE Software, Version 17.03.04a"
IOS_XR = "Cisco IOS XR Software (Cisco ASR9K Series), Version 6.1.4[Default]"
NXOS = "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(8), RELEASE SOFTWARE"
ASA = "Cisco Adaptive Security Appliance Version 9.8(4)32"
COMWARE = ("1920-48G Switch Software Version 5.20.99, Release 1107 "
           "Copyright(c)2010-2015 Hewlett-Packard Development Company, L.P.")
FORTIGATE_OID = "1.3.6.1.4.1.12356.101.1.2005"


def detect(vendor, descr, oid=None):
    return fam.detect_family(vendor, descr, oid)


class TestFamilyDetection(unittest.TestCase):
    def test_cisco_families(self):
        self.assertEqual(detect("Cisco", IOS), "cisco_ios")
        self.assertEqual(detect("Cisco", IOS_OLD), "cisco_ios")
        self.assertEqual(detect("Cisco", NXOS), "cisco_nx_os")
        self.assertEqual(detect("Cisco", ASA), "cisco_asa")
        self.assertEqual(detect("Cisco", IOS_XR), "cisco_ios_xr")

    def test_ios_xe_before_ios(self):
        # an IOS XE description also contains the words "IOS Software"
        self.assertEqual(detect("Cisco", IOS_XE), "cisco_ios_xe")
        self.assertEqual(detect("Cisco", IOS_XE_17), "cisco_ios_xe")

    def test_fortios_from_the_fortigate_object_id(self):
        self.assertEqual(detect("Fortinet", "", FORTIGATE_OID), "fortinet_fortios")
        self.assertIsNone(detect("Fortinet", "", "1.3.6.1.4.1.12356.106.1.1"))   # FortiSwitch

    def test_comware(self):
        self.assertEqual(detect("HP", COMWARE, "1.3.6.1.4.1.25506.11.1.169"), "hp_comware")

    def test_gbe2c(self):
        self.assertEqual(detect("HP", "GbE2c L2/L3 Ethernet Blade Switch for HP c-Class BladeSystem"),
                         "hp_gbe2c")

    def test_unknown(self):
        self.assertIsNone(detect("Cisco", "Generic Software, Version 1"))
        self.assertIsNone(detect("unknown vendor", IOS))
        self.assertIsNone(detect(None, None))

    def test_no_family_is_keyed_to_a_lab_device(self):
        # rules are per vendor and family: hostnames, addresses and models play no part
        for entry in fam.FAMILIES.values():
            text = json.dumps(entry, default=sorted)
            for lab in ("CYFOR", "172.20.", "L3-Switch", "C3750", "1920-48G"):
                self.assertNotIn(lab, text)


class TestRecordedAtIdentification(unittest.TestCase):
    """The crawler decides the family when it identifies a device; the graph keeps it."""

    def test_lab_crawl(self):
        import sys
        sys.path.insert(0, HERE)
        from test_cdp import AP_CID, L2_CID, L3_CID, crawl, lab
        from vulnmapper.assemble import assemble
        doc = crawl(lab())
        by_cid = {n["chassis_id"]: n for n in doc["nodes"]}
        self.assertEqual(by_cid[L3_CID]["software_family"], "cisco_ios")
        self.assertEqual(by_cid[L2_CID]["software_family"], "cisco_ios")
        self.assertEqual(by_cid[AP_CID]["software_family"], "cisco_ios")
        hp = next(n for n in doc["nodes"] if n.get("ip") == "172.20.99.4")
        self.assertEqual(hp["software_family"], "hp_comware")
        graph = {n["node_id"]: n for n in assemble([], doc)["nodes"]}
        self.assertEqual(graph[f"device:{L3_CID}"]["software_family"], "cisco_ios")

    def test_unknown_family_adds_no_field(self):
        from vulnmapper.assemble import assemble
        net = {"nodes": [{"chassis_id": "aa:bb:cc:00:00:01", "pollable": True, "status": "online",
                          "vendor": "unknown vendor"}], "edges": []}
        node = assemble([], net)["nodes"][0]
        self.assertNotIn("software_family", node)


class TestCpe(unittest.TestCase):
    def ident(self, **node):
        return fam.identify({"kind": "device", "pollable": True, **node})

    def test_cisco_ios(self):
        r = self.ident(vendor="Cisco", firmware="12.2(55)SE12", software_family="cisco_ios")
        self.assertEqual(r["cpe"], r"cpe:2.3:o:cisco:ios:12.2\(55\)se12:*:*:*:*:*:*:*")
        self.assertEqual((r["product"], r["match"]), ("Cisco IOS 12.2(55)SE12", "cpe"))

    def test_cisco_ios_xe(self):
        r = self.ident(vendor="Cisco", firmware="17.03.04a", software_family="cisco_ios_xe")
        self.assertEqual(r["cpe"], "cpe:2.3:o:cisco:ios_xe:17.03.04a:*:*:*:*:*:*:*")
        self.assertEqual(r["product"], "Cisco IOS XE 17.03.04a")

    def test_cisco_nx_os(self):
        r = self.ident(vendor="Cisco", firmware="9.3(8)", software_family="cisco_nx_os")
        self.assertEqual(r["cpe"], r"cpe:2.3:o:cisco:nx-os:9.3\(8\):*:*:*:*:*:*:*")

    def test_cisco_asa(self):
        r = self.ident(vendor="Cisco", firmware="9.8(4)32", software_family="cisco_asa")
        self.assertEqual(r["cpe"],
                         r"cpe:2.3:a:cisco:adaptive_security_appliance_software:9.8\(4\)32:*:*:*:*:*:*:*")

    def test_fortios(self):
        r = self.ident(vendor="Fortinet", firmware="6.0.16", software_family="fortinet_fortios")
        self.assertEqual(r["cpe"], "cpe:2.3:o:fortinet:fortios:6.0.16:*:*:*:*:*:*:*")
        self.assertEqual(r["product"], "Fortinet FortiOS 6.0.16")

    def test_junos_cpe_has_thirteen_components_and_no_build(self):
        # NVD answers HTTP 404 for a cpeName with a build component added
        for firmware, cpe in (
                ("JUNOS 22.4R3-S1.6", "cpe:2.3:o:juniper:junos:22.4:r3-s1:*:*:*:*:*:*"),
                ("JUNOS 15.1R6-S4", "cpe:2.3:o:juniper:junos:15.1:r6-s4:*:*:*:*:*:*"),
                ("JUNOS 21.4R3.5", "cpe:2.3:o:juniper:junos:21.4:r3:*:*:*:*:*:*")):
            with self.subTest(firmware=firmware):
                r = self.ident(vendor="Juniper", firmware=firmware)
                self.assertEqual(r["family"], "juniper_junos")
                self.assertEqual(r["cpe"], cpe)
                self.assertEqual(len(r["cpe"].split(":")), 13)
                self.assertEqual((r["product"], r["version"], r["match"]),
                                 (f"Juniper Junos {firmware}", firmware, "cpe"))

    def test_comware_has_no_cpe_rule_only_the_keyword_fallback(self):
        r = self.ident(vendor="HP", model="HP 1920-48G", firmware="5.20.99 Release 1107",
                       software_family="hp_comware")
        self.assertIsNone(r["cpe"])
        self.assertEqual((r["match"], r["product"]), ("keyword", "HP Comware 5.20.99 Release 1107"))
        self.assertEqual(r["keyword"], {"query": "1920", "vendors": sorted(fam.HP_VENDORS),
                                        "line": "1920", "version": "5.20.99 Release 1107"})

    def test_escaping(self):
        self.assertEqual(fam.cpe_value("12.2(55)SE12"), r"12.2\(55\)se12")
        self.assertEqual(fam.cpe_value("6.1.4[Default]"), r"6.1.4\[default\]")
        self.assertEqual(fam.cpe_value("a b:c*d?e"), r"a_b\:c\*d\?e")
        self.assertEqual(fam.cpe_value("1.0-rc_2"), "1.0-rc_2")

    def test_unidentified(self):
        for node in ({"vendor": "Cisco", "firmware": None, "software_family": "cisco_ios"},
                     {"vendor": "Cisco", "firmware": "16.9.4"},   # no family, none inferable
                     {"vendor": None, "firmware": None}):
            with self.subTest(node=node):
                r = self.ident(**node)
                self.assertEqual((r["match"], r["cpe"]), ("unidentified", None))

    def test_family_without_a_cpe_rule_is_identified_with_match_none(self):
        r = self.ident(vendor="Cisco", firmware="6.1.4", software_family="cisco_ios_xr")
        self.assertEqual((r["family"], r["match"], r["cpe"], r["product"]),
                         ("cisco_ios_xr", "none", None, "Cisco IOS XR 6.1.4"))

    def test_families_without_an_nvd_product_are_match_none(self):
        for family, firmware in (("hp_procurve", "K.15.18.0013"), ("brocade_nos", "7.2.0a"),
                                 ("dcn_switch", "7.0.3.1"), ("ibm_networking_os", "7.9.11.0"),
                                 ("hp_gbe2c", "5.1.0")):
            with self.subTest(family=family):
                r = self.ident(vendor="X", firmware=firmware, software_family=family)
                self.assertEqual((r["family"], r["match"], r["cpe"], r["version"]),
                                 (family, "none", None, firmware))

    def test_junos_evolved(self):
        r = self.ident(vendor="Juniper", firmware="JUNOS 22.2R3-S1.2-EVO")
        self.assertEqual((r["family"], r["match"], r["cpe"]),
                         ("juniper_junos_evolved", "cpe",
                          "cpe:2.3:o:juniper:junos_os_evolved:22.2:r3-s1:*:*:*:*:*:*"))
        self.assertEqual(r["product"], "Juniper Junos OS Evolved JUNOS 22.2R3-S1.2-EVO")

    def test_junos_release_of_the_other_branch_is_no_claim(self):
        for firmware, family in (("JUNOS 22.2R3-S1.2-EVO", "juniper_junos"),
                                 ("JUNOS 22.2R3-S1.2", "juniper_junos_evolved")):
            with self.subTest(firmware=firmware, family=family):
                r = self.ident(vendor="Juniper", firmware=firmware, software_family=family)
                self.assertEqual((r["family"], r["match"], r["cpe"], r["product"]),
                                 (family, "unidentified", None, None))

    def test_arubaos_switch_asks_both_nvd_names(self):
        r = self.ident(vendor="HP", model="Aruba 2620-48", firmware="KA.16.04.0024",
                       software_family="hp_arubaos_switch")
        self.assertEqual((r["match"], r["version"], r["cpe"]),
                         ("cpe", "16.04.0024", "cpe:2.3:o:hpe:arubaos-switch:16.04.0024:*:*:*:*:*:*:*"))
        self.assertEqual(r["extra_cpes"],
                         ["cpe:2.3:o:arubanetworks:2620_firmware:16.04.0024:*:*:*:*:*:*:*"])

    def test_arubaos_switch_without_a_product_line(self):
        r = self.ident(vendor="HP", model="J0000A", firmware="16.04.0024",
                       software_family="hp_arubaos_switch")
        self.assertEqual((r["match"], r["extra_cpes"]), ("cpe", []))

    def test_arubaos_switch_before_16_is_unidentified(self):
        r = self.ident(vendor="HP", model="Aruba 2620-48", firmware="RA.15.16.0021",
                       software_family="hp_arubaos_switch")
        self.assertEqual((r["family"], r["match"], r["cpe"]),
                         ("hp_arubaos_switch", "unidentified", None))

    def test_arubaos_switch_line(self):
        for model, line in (("Aruba 2620-48", "2620"), ("HP 2930F-24G Switch (JL259A)", "2930f"),
                            ("J0000A", None), (None, None), ("Switch 26200", None)):
            with self.subTest(model=model):
                self.assertEqual(fam.aos_s_line(model), line)

    def test_comware_without_a_product_line_is_unidentified(self):
        r = self.ident(vendor="HP", model=None, firmware="5.20.99 Release 1107",
                       software_family="hp_comware")
        self.assertEqual(r["match"], "unidentified")

    def test_device_never_polled_keeps_its_recorded_family(self):
        r = fam.identify({"kind": "device", "pollable": False, "vendor": "Cisco",
                          "firmware": "12.2(55)SE12", "software_family": "cisco_ios"})
        self.assertEqual((r["match"], r["family"]), ("cpe", "cisco_ios"))

    def test_device_seen_only_in_a_neighbour_table_is_unidentified(self):
        r = fam.identify({"kind": "device", "pollable": False, "vendor": "Cisco"})
        self.assertEqual(r["match"], "unidentified")


class TestInferenceForOlderGraphs(unittest.TestCase):
    """A graph from before families were recorded: inferred only when unambiguous."""

    def family(self, **node):
        return fam.family_of({"kind": "device", "pollable": True, **node})

    def test_cases(self):
        self.assertEqual(self.family(vendor="Cisco", model="C3750", firmware="12.2(55)SE12"),
                         "cisco_ios")
        self.assertEqual(self.family(vendor="Cisco", model="C1140", firmware="15.3(3)JB"),
                         "cisco_ios")
        self.assertEqual(self.family(vendor="Fortinet", model="FortiGate 200D", firmware="6.0.16"),
                         "fortinet_fortios")
        self.assertEqual(self.family(vendor="HP", model="HP 1920-48G",
                                     firmware="5.20.99 Release 1107"), "hp_comware")
        # ambiguous: IOS XE, NX-OS and ASA versions look alike without a description
        for fw in ("16.9.4", "9.3(8)", "9.8(4)", "7.0(3)I7(6)"):
            self.assertIsNone(self.family(vendor="Cisco", firmware=fw), fw)
        self.assertIsNone(self.family(vendor="Fortinet", model="FortiSwitch 248D", firmware="6.0.16"))

    def test_recorded_family_wins(self):
        self.assertEqual(self.family(vendor="Cisco", firmware="12.2(55)SE12",
                                     software_family="cisco_ios_xe"), "cisco_ios_xe")


def cve_from_fixture(name, cve_id):
    with open(os.path.join(NVD, name), encoding="utf-8") as f:
        doc = json.load(f)
    return next(v["cve"] for v in doc["vulnerabilities"] if v["cve"]["id"] == cve_id)


def cve(desc, *matches):
    return {"id": "CVE-0000-0001", "descriptions": [{"lang": "en", "value": desc}],
            "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}] if matches else []}


def match(criteria, **bounds):
    return {"vulnerable": True, "criteria": criteria, **bounds}


KW = {"vendors": sorted(fam.HP_VENDORS), "line": "1920", "version": "5.20.99 Release 1107"}


class TestKeywordRule(unittest.TestCase):
    def accept(self, c, **kw):
        return fam.keyword_accepts(c, **{**KW, **kw})

    def test_1920s_is_not_1920(self):
        # the real NVD entry: HPE OfficeConnect 1820/1850/1920S, a different product
        self.assertFalse(self.accept(cve_from_fixture("cves_keyword_1920.json", "CVE-2022-37932")))
        self.assertFalse(self.accept(cve(
            "Hewlett Packard Enterprise OfficeConnect 1920S switches allow ...",
            match("cpe:2.3:o:hpe:officeconnect_1920s_24g_2sfp_firmware:*:*:*:*:*:*:*:*"))))

    def test_unrelated_numbers_do_not_match(self):
        for cve_id in ("CVE-1999-1170", "CVE-2024-26748", "CVE-2020-4952"):
            self.assertFalse(self.accept(cve_from_fixture("cves_keyword_1920.json", cve_id)), cve_id)

    def test_comware_advisory_not_naming_the_1920_does_not_match(self):
        self.assertFalse(self.accept(cve_from_fixture("cves_keyword_comware.json", "CVE-2015-5434")))

    def test_same_vendor_and_line_in_configuration_matches(self):
        self.assertTrue(self.accept(cve("A flaw in a switch.",
                                        match("cpe:2.3:h:hp:1920-48g_switch:-:*:*:*:*:*:*:*"))))

    def test_same_vendor_and_line_in_text_matches(self):
        self.assertTrue(self.accept(cve("HP 1920-48G switches allow remote attackers to ...")))
        self.assertFalse(self.accept(cve("Some 1920 product of another vendor allows ...")))

    def test_vendor_must_match(self):
        self.assertFalse(self.accept(cve("A flaw.", match("cpe:2.3:h:acme:1920_switch:-:*:*:*:*:*:*:*"))))

    def test_version_outside_the_range_does_not_match(self):
        inside = match("cpe:2.3:o:hp:1920_firmware:*:*:*:*:*:*:*:*",
                       versionStartIncluding="5.20.0", versionEndExcluding="5.20.200")
        outside = match("cpe:2.3:o:hp:1920_firmware:*:*:*:*:*:*:*:*", versionEndExcluding="5.20.50")
        exact_other = match("cpe:2.3:o:hp:1920_firmware:5.20.1:*:*:*:*:*:*:*")
        self.assertTrue(self.accept(cve("A flaw.", inside)))
        self.assertFalse(self.accept(cve("A flaw.", outside)))
        self.assertFalse(self.accept(cve("A flaw.", exact_other)))

    def test_versions_that_cannot_be_compared_do_not_reject(self):
        self.assertTrue(self.accept(cve("A flaw.", match("cpe:2.3:o:hp:1920_firmware:r1111p02:*:*:*:*:*:*:*"))))


if __name__ == "__main__":
    unittest.main()
