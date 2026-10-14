"""The sample in data/ carries what the dashboard reads, and nothing from the
lab: it is rebuilt from the saved test inputs (scripts/make_sample_data.py)."""

import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(os.path.dirname(HERE)), "data")
FIXTURES = os.path.join(HERE, "fixtures")
# a MAC with colons or as 12 bare hex digits, compared without the colons
MAC = re.compile(r"\b[0-9a-f]{2}(?::?[0-9a-f]{2}){5}\b", re.I)


def macs(text):
    return {m.lower().replace(":", "") for m in MAC.findall(text)}


def read(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


class TestSampleData(unittest.TestCase):
    def setUp(self):
        self.graph = read("graph.json")
        self.meta = self.graph["metadata"]

    def test_graph_has_the_ovss_fields_the_ui_reads(self):
        for key in ("scan_time", "stages", "threat_feeds", "ovss", "warnings"):
            self.assertIn(key, self.meta)
        for node in self.graph["nodes"]:
            for key in ("node_id", "kind", "node_tier", "risk_score", "ovss_status"):
                self.assertIn(key, node, node.get("node_id"))
        self.assertTrue(any(n["node_tier"] for n in self.graph["nodes"]))

    def test_the_three_files_are_from_one_scan(self):
        self.assertEqual(read("vulnerabilities.json")["metadata"]["scan_time"], self.meta["scan_time"])
        paths = read("attack_paths.json")["metadata"]
        self.assertEqual(paths["source_scan"], self.meta["scan_time"])
        self.assertEqual(paths["counts"]["targets_missing"], 0)   # the sample targets are in it

    def test_no_address_from_outside_the_saved_inputs(self):
        known = set()
        for name in ("offline_scored.json", "offline_network.json"):
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
                known |= macs(f.read())
        for name in ("graph.json", "vulnerabilities.json", "attack_paths.json"):
            with open(os.path.join(DATA, name), encoding="utf-8") as f:
                found = macs(f.read())
            self.assertLessEqual(found, known, name)


if __name__ == "__main__":
    unittest.main()
