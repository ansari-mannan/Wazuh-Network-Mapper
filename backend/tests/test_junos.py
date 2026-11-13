"""Junos release comparison against Juniper's own CVE records.

The records under fixtures/juniper/ are Juniper's published CVE JSON 5 records
as the CVE Services API serves them. Each expected status below was checked
against the record's description text, not only against this module.
"""

import json
import os
import unittest

from vulnmapper.devicecves import junos
from vulnmapper.devicecves.junos import AFFECTED, UNAFFECTED, UNDECIDED, Release
from vulnmapper.devicecves.juniper import trim_record

HERE = os.path.dirname(os.path.abspath(__file__))
JUNIPER_DIR = os.path.join(HERE, "fixtures", "juniper")
MODELS = ("mx204", "ex4300-48t", "750-123456")      # the last: a part number, not placeable


def cna_record(cve_id):
    with open(os.path.join(JUNIPER_DIR, cve_id + ".json"), encoding="utf-8") as f:
        return json.load(f)


def blocks_of(cve_id):
    return trim_record(cna_record(cve_id))["blocks"]


def block(*versions, platforms=None, product="Junos OS"):
    out = {"vendor": "Juniper Networks", "product": product, "versions": list(versions)}
    if platforms:
        out["platforms"] = platforms
    return out


def rng(version, less_than, status=AFFECTED, changes=None):
    entry = {"version": version, "status": status, "lessThan": less_than, "versionType": "custom"}
    if changes:
        entry["changes"] = [{"at": at, "status": st} for at, st in changes]
    return entry


def decide(blocks, firmware, model="mx204"):
    return junos.decide(blocks, junos.parse_device(firmware), model)


class TestParseDevice(unittest.TestCase):
    def test_regular_releases(self):
        self.assertEqual(junos.parse_device("JUNOS 22.4R3-S1.6"), Release(22, 4, 3, 1, 6))
        self.assertEqual(junos.parse_device("21.4R3.5"), Release(21, 4, 3, 0, 5))
        self.assertEqual(junos.parse_device("15.1R6-S4"), Release(15, 1, 6, 4, None))

    def test_other_branches_are_not_compared(self):
        for fw in ("15.1X49-D200.5", "22.4R3-S1-EVO", "18.4F1", "", "JUNOS"):
            self.assertIsNone(junos.parse_device(fw), fw)

    def test_evolved_releases(self):
        self.assertEqual(junos.parse_device("JUNOS 22.2R3-S1.2-EVO", evolved=True),
                         Release(22, 2, 3, 1, 2))
        self.assertEqual(junos.parse_device("21.1R2-EVO", evolved=True), Release(21, 1, 2, 0, None))
        self.assertTrue(junos.is_evolved("21.1R2-evo"))
        self.assertFalse(junos.is_evolved("21.1R2"))
        for fw in ("21.1R2", "15.1X49-D200.5", ""):
            self.assertIsNone(junos.parse_device(fw, evolved=True), fw)


class TestEvolved(unittest.TestCase):
    """The Junos OS Evolved block of CVE-2021-31353: affected before
    20.4R2-S3 and 20.4R3, 21.1 before 21.1R2, 21.2 before 21.2R2."""

    def setUp(self):
        self.blocks = trim_record(cna_record("CVE-2021-31353"))["evo_blocks"]

    def test_record_keeps_its_evolved_block_apart(self):
        self.assertEqual([b["product"] for b in self.blocks], ["Junos OS Evolved"])
        self.assertTrue(junos.is_evolved_block(self.blocks[0]))
        self.assertFalse(junos.is_junos_block(self.blocks[0]))

    def test_decisions(self):
        for fw, want in (("21.1R1-S1-EVO", AFFECTED), ("20.4R2-S2-EVO", AFFECTED),
                         ("21.2R1-EVO", AFFECTED), ("21.1R2-EVO", UNAFFECTED),
                         ("20.4R3-EVO", UNAFFECTED), ("22.1R1-EVO", UNAFFECTED)):
            with self.subTest(fw=fw):
                v = junos.parse_device(fw, evolved=True)
                self.assertEqual(junos.decide(self.blocks, v, "ptx10008", evolved=True)[0], want)

    def test_regular_blocks_do_not_decide_an_evolved_release(self):
        # Junos OS: 20.3 before 20.3R2 unaffected; Evolved: everything before
        # 20.4R2-S3 affected
        v = junos.parse_device("20.3R1-EVO", evolved=True)
        regular = trim_record(cna_record("CVE-2021-31353"))["blocks"]
        self.assertEqual(junos.decide(self.blocks, v, "ptx10008", evolved=True)[0], AFFECTED)
        self.assertNotEqual(junos.decide(regular, v, "ptx10008")[0], AFFECTED)

    def test_changes_drop_the_suffix(self):
        b = block(rng("21.1-EVO", "21.1R3-EVO", changes=[("21.1R2-EVO", UNAFFECTED)]),
                  product="Junos OS Evolved")
        self.assertEqual(junos.decide([b], junos.parse_device("21.1R1-EVO", evolved=True),
                                      "x", evolved=True)[0], AFFECTED)
        self.assertEqual(junos.decide([b], junos.parse_device("21.1R2-EVO", evolved=True),
                                      "x", evolved=True)[0], UNAFFECTED)

    def test_evo_blocks(self):
        self.assertEqual(junos.evo_blocks(None), [])
        self.assertEqual(junos.evo_blocks([block(product="Junos OS"), "x"]), [])
        self.assertEqual(len(junos.evo_blocks([block(product="Junos OS Evolved")])), 1)


class TestPublishedRecords(unittest.TestCase):
    """Decisions for real records: (firmware, {model: status}) per CVE."""

    def check(self, cve_id, cases):
        blocks = blocks_of(cve_id)
        self.assertTrue(blocks)
        for firmware, expected in cases:
            for model, want in expected.items():
                with self.subTest(cve=cve_id, firmware=firmware, model=model):
                    self.assertEqual(decide(blocks, firmware, model), want)

    def every(self, status, why=None):
        return {m: (status, why) for m in MODELS}

    def test_ranges_without_platforms_and_a_train_left_out(self):
        # "0 before 20.4R3-S8; 21.2 before 21.2R3-S6; 21.3 ...; 22.4 before
        # 22.4R3": 21.1 and 21.4 are named by no entry, trains on both sides are
        self.check("CVE-2023-44176", [
            ("18.4R2-S2.1", self.every(AFFECTED)),
            ("20.4R3.8", self.every(AFFECTED)),
            ("20.4R3-S9.2", self.every(UNAFFECTED)),
            ("21.1R1.11", self.every(UNDECIDED, "train_not_listed")),
            ("21.2R2.6", self.every(AFFECTED)),
            ("21.4R3-S5.4", self.every(UNDECIDED, "train_not_listed")),
            ("22.4R2.8", self.every(AFFECTED)),
        ])

    def test_platform_block_and_an_unaffected_block(self):
        # affected on QFX5000 and MX only; a second block states 21.1 unaffected
        self.check("CVE-2022-22210", [
            ("20.4R3.8", {"mx204": (AFFECTED, None), "ex4300-48t": (UNAFFECTED, None),
                          "qfx5130-32cd": (AFFECTED, None), "750-123456": (AFFECTED, None)}),
            ("21.2R2.6", {"mx204": (AFFECTED, None), "ex4300-48t": (UNAFFECTED, None)}),
            ("21.4R3-S5.4", self.every(UNAFFECTED)),
            # named in the other block, so assessed: not train_not_listed
            ("21.1R1.11", self.every(UNAFFECTED)),
        ])

    def test_single_releases_and_timeline_entries(self):
        # "19.3R3-S2; 19.4R3-S3; 20.2 versions 20.2R2-S3 and later, prior to
        # 20.2R3-S2; 20.3 versions 20.3R2 and later, prior to 20.3R3; 20.4
        # versions 20.4R2 and later, prior to 20.4R3; 21.1 versions prior to
        # 21.1R2. Junos OS 20.1 is not affected."
        self.check("CVE-2021-31353", [
            ("19.4R3-S3.1", self.every(AFFECTED)),
            ("19.4R3-S4.1", self.every(UNAFFECTED)),
            ("20.1R2.6", self.every(UNAFFECTED)),
            ("20.2R2-S2.1", self.every(UNAFFECTED)),
            ("20.2R2-S3.4", self.every(AFFECTED)),
            ("20.2R3-S1.1", self.every(AFFECTED)),
            ("20.2R3-S2.1", self.every(UNAFFECTED)),
            ("20.3R1.8", self.every(UNAFFECTED)),
            ("20.3R2.4", self.every(AFFECTED)),
            ("20.3R3.1", self.every(UNAFFECTED)),
            ("20.4R2.7", self.every(AFFECTED)),
            ("20.4R3.8", self.every(UNAFFECTED)),
            ("21.1R1.11", self.every(AFFECTED)),
        ])

    def test_affected_again_from_a_later_release(self):
        # "17.4 versions prior to 17.4R2-S10; 17.4 version 17.4R3 and later versions"
        self.check("CVE-2021-0245", [
            ("17.4R2-S9.1", self.every(AFFECTED)),
            ("17.4R2-S10.2", self.every(UNAFFECTED)),
            ("17.4R3.5", self.every(AFFECTED)),
            ("17.4R3-S2.2", self.every(AFFECTED)),
        ])

    def test_signature_package_versions_decide_nothing(self):
        # SRX and MX Series, versions stated as SigPack releases, not Junos releases
        self.check("CVE-2023-28985", [
            ("21.4R3-S5.4", {"mx204": (UNDECIDED, "SigPack"), "srx345": (UNDECIDED, "SigPack"),
                             "750-123456": (UNDECIDED, "SigPack"),
                             "ex4300-48t": (UNAFFECTED, "platform")}),
        ])


class TestRules(unittest.TestCase):
    """Each comparison rule on a minimal record."""

    def test_unaffected_entry_wins_within_a_block(self):
        b = [block(rng("21.4", "21.4R3-S5"), {"version": "21.4R1", "status": UNAFFECTED})]
        self.assertEqual(decide(b, "21.4R1.9"), (UNAFFECTED, "conflict"))
        self.assertEqual(decide(b, "21.4R2.6"), (AFFECTED, None))

    def test_affected_wins_across_blocks(self):
        b = [block(rng("21.4", "21.4R3-S5")),
             block({"version": "21.4R2", "status": UNAFFECTED})]
        self.assertEqual(decide(b, "21.4R2.6"), (AFFECTED, None))

    def test_fixed_release_without_build_covers_every_build(self):
        b = [block(rng("21.4", "21.4R3-S5"))]
        self.assertEqual(decide(b, "21.4R3-S5.3"), (UNAFFECTED, None))
        self.assertEqual(decide(b, "21.4R3-S1.5"), (AFFECTED, None))

    def test_per_branch_fix_list(self):
        # "before 19.2R1-S7, 19.2R3-S3": 19.2R2 has no fix of its own
        b = [block(rng("19.2", "19.2R1-S7, 19.2R3-S3"))]
        self.assertEqual(decide(b, "19.2R1-S7.1"), (UNAFFECTED, None))
        self.assertEqual(decide(b, "19.2R2.5"), (AFFECTED, None))
        self.assertEqual(decide(b, "19.2R3-S2.1"), (AFFECTED, None))
        self.assertEqual(decide(b, "19.2R3-S3.1"), (UNAFFECTED, None))

    def test_train_not_listed_needs_affected_trains_on_both_sides(self):
        b = [block(rng("21.2", "21.2R3-S6"), rng("22.1", "22.1R3-S3"))]
        self.assertEqual(decide(b, "21.4R3.7"), (UNDECIDED, "train_not_listed"))
        self.assertEqual(decide(b, "22.2R1.9"), (UNAFFECTED, None))     # nothing above
        self.assertEqual(decide(b, "20.4R3.8"), (UNAFFECTED, None))     # nothing below

    def test_train_named_by_another_applicable_block_is_assessed(self):
        listed = block({"version": "21.4R1", "status": UNAFFECTED, "lessThan": "21.4*"})
        b = [block(rng("21.2", "21.2R3-S6"), rng("22.1", "22.1R3-S3"), platforms=["MX Series"]),
             listed]
        self.assertEqual(decide(b, "21.4R3.7", "mx204"), (UNAFFECTED, None))
        # a block for other platforms does not count
        other = block({"version": "21.4R1", "status": UNAFFECTED, "lessThan": "21.4*"},
                      platforms=["EX Series"])
        b = [block(rng("21.2", "21.2R3-S6"), rng("22.1", "22.1R3-S3"), platforms=["MX Series"]),
             other]
        self.assertEqual(decide(b, "21.4R3.7", "mx204"), (UNDECIDED, "train_not_listed"))

    def test_timeline_entry(self):
        b = [block(rng("20.2", "20.2R2-S3", UNAFFECTED, [("20.2R3-S2", UNAFFECTED)]))]
        self.assertEqual(decide(b, "20.2R2-S2.1"), (UNAFFECTED, None))
        self.assertEqual(decide(b, "20.2R2-S3.1"), (AFFECTED, None))
        self.assertEqual(decide(b, "20.2R3.8"), (AFFECTED, None))
        self.assertEqual(decide(b, "20.2R3-S2.1"), (UNAFFECTED, None))
        self.assertEqual(decide(b, "20.3R1.8"), (UNAFFECTED, None))     # other train

    def test_changes_inside_the_range_are_not_a_timeline(self):
        e = rng("17.2", "17.2R1-S9, 17.2R3-S3", AFFECTED, [("17.2R2", AFFECTED)])
        self.assertFalse(junos.normalise(e)["timeline"])
        e = rng("20.2", "20.2R2-S3", UNAFFECTED, [("20.2R3-S2", UNAFFECTED)])
        self.assertTrue(junos.normalise(e)["timeline"])

    def test_platforms(self):
        b = [block(rng("21.4", "21.4R3-S5"), platforms=["QFX5000 Series, MX Series"])]
        self.assertEqual(decide(b, "21.4R2.6", "mx204"), (AFFECTED, None))
        self.assertEqual(decide(b, "21.4R2.6", "qfx5130-32cd"), (AFFECTED, None))
        self.assertEqual(decide(b, "21.4R2.6", "ex4300-48t"), (UNAFFECTED, "platform"))
        # a model this module cannot place matches every platform block
        self.assertEqual(decide(b, "21.4R2.6", "750-123456"), (AFFECTED, None))
        self.assertEqual(decide(b, "21.4R2.6", ""), (AFFECTED, None))

    def test_platform_in_product_name(self):
        b = [block(rng("21.4", "21.4R3-S5"), product="Junos OS on SRX Series")]
        self.assertEqual(decide(b, "21.4R2.6", "srx345"), (AFFECTED, None))
        self.assertEqual(decide(b, "21.4R2.6", "mx204"), (UNAFFECTED, "platform"))

    def test_other_branches_never_apply_to_a_regular_release(self):
        b = [block(rng("15.1X49", "15.1X49-D220"), rng("21.4-EVO", "21.4R3-S5-EVO"))]
        self.assertEqual(decide(b, "15.1R6-S4", "srx345"), (UNAFFECTED, None))

    def test_unreadable_version_is_undecided(self):
        b = [block({"version": "some release", "status": AFFECTED})]
        status, why = decide(b, "21.4R2.6")
        self.assertEqual(status, UNDECIDED)
        self.assertTrue(why)

    def test_no_blocks(self):
        self.assertEqual(decide([], "21.4R2.6"), (None, None))

    def test_only_junos_os_blocks_are_kept(self):
        affected = [block(rng("21.4", "21.4R3-S5")),
                    block(rng("21.4-EVO", "21.4R3-S5-EVO"), product="Junos OS Evolved"),
                    {"vendor": "Juniper Networks", "product": "Session Smart Router",
                     "versions": [rng("6.0", "6.0.8")]}]
        self.assertEqual([b["product"] for b in junos.junos_blocks(affected)], ["Junos OS"])
        self.assertEqual(junos.junos_blocks(None), [])


if __name__ == "__main__":
    unittest.main()
