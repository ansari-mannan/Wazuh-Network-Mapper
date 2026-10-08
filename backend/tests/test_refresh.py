"""python -m vulnmapper.devicecves: refresh device CVEs on an existing graph."""

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest

from test_cdp import L2_CID, L3_CID, crawl, lab
from test_device_stage import lab_nvd
from test_nvd import FakeClock
from vulnmapper.assemble import assemble
from vulnmapper.devicecves.__main__ import main

HOST = {"agent_id": "001", "hostname": "pc1", "ip": "172.20.80.3", "status": "active",
        "mac": "e4:a7:a0:25:ce:ac", "risk_score": 7.1, "top_cves": [], "cve_summary": None}
CVE_FIELDS = {"risk_score", "max_cvss", "cve_summary", "top_cves", "cve_lookup"}


class TestRefresh(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph_path = os.path.join(self.tmp, "graph.json")
        self.graph = assemble([HOST], crawl(lab()))
        self.graph["metadata"]["warnings"].append({"type": "duplicate_ip", "ip": "10.0.0.9"})
        self.write(self.graph_path, self.graph)
        self.clock = FakeClock()
        self.fake = lab_nvd(self.clock)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, path, doc):
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)

    def load(self, name):
        with open(os.path.join(self.tmp, name)) as f:
            return json.load(f)

    def refresh(self, *extra, fake=None):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return main(["--graph", self.graph_path, *extra],
                        transport=fake or self.fake, clock=self.clock)

    def test_topology_and_host_data_untouched(self):
        self.assertEqual(self.refresh(), 0)
        after = self.load("graph.json")
        self.assertEqual(after["edges"], self.graph["edges"])
        before = {n["node_id"]: n for n in self.graph["nodes"]}
        for node in after["nodes"]:
            old = before[node["node_id"]]
            if node["kind"] == "endpoint":
                self.assertEqual(node, old)
            else:
                changed = {k for k in set(node) | set(old) if node.get(k) != old.get(k)}
                self.assertLessEqual(changed, CVE_FIELDS, node["node_id"])
        self.assertEqual([n["node_id"] for n in after["nodes"]],
                         [n["node_id"] for n in self.graph["nodes"]])
        meta_before = {k: v for k, v in self.graph["metadata"].items() if k != "warnings"}
        meta_after = {k: v for k, v in after["metadata"].items()
                      if k not in ("warnings", "device_cves")}
        self.assertEqual(meta_after, meta_before)
        self.assertIn({"type": "duplicate_ip", "ip": "10.0.0.9"}, after["metadata"]["warnings"])

    def test_devices_get_their_cves(self):
        self.refresh()
        nodes = {n["node_id"]: n for n in self.load("graph.json")["nodes"]}
        self.assertEqual(nodes[f"device:{L3_CID}"]["cve_lookup"]["total"], 8)
        self.assertEqual(nodes[f"device:{L2_CID}"]["max_cvss"], 9.8)
        self.assertIn("refreshed_at", self.load("graph.json")["metadata"]["device_cves"])

    def test_old_device_warnings_are_replaced(self):
        self.refresh(fake=lab_nvd(self.clock, script=["down"] * 50))
        self.assertIn("nvd_unreachable",
                      [w["type"] for w in self.load("graph.json")["metadata"]["warnings"]])
        self.clock.advance(seconds=60)
        self.refresh()
        types = [w["type"] for w in self.load("graph.json")["metadata"]["warnings"]]
        self.assertNotIn("nvd_unreachable", types)
        self.assertEqual(types.count("duplicate_ip"), 1)

    def test_creates_a_devices_only_vulnerabilities_file(self):
        self.refresh()
        vulns = self.load("vulnerabilities.json")
        self.assertEqual({v["kind"] for v in vulns["hosts"].values()}, {"device"})
        self.assertEqual(vulns["metadata"]["counts"]["hosts"], 0)
        self.assertEqual(vulns["metadata"]["counts"]["devices"], 5)
        self.assertIn("CVE-2021-0001", vulns["cves"])

    def test_leaves_host_entries_in_an_existing_file_untouched(self):
        existing = {
            "metadata": {"scan_time": "2026-10-08T12:58:20+00:00",
                         "counts": {"hosts": 1, "cves": 1, "findings": 1}},
            "cves": {"CVE-2021-0001": {"cvss": 9.9, "cvss_version": "3.1", "severity": "Critical",
                                       "description": "Wazuh's text", "reference": None,
                                       "published_at": None}},
            "hosts": {"endpoint:001": {"hostname": "pc1", "agent_id": "001",
                                       "findings": [{"cve": "CVE-2021-0001", "package": "x",
                                                     "version": "1", "detected_at": None}]}},
        }
        self.write(os.path.join(self.tmp, "vulnerabilities.json"), existing)
        self.refresh()
        vulns = self.load("vulnerabilities.json")
        self.assertEqual(vulns["hosts"]["endpoint:001"], existing["hosts"]["endpoint:001"])
        self.assertEqual(vulns["cves"]["CVE-2021-0001"]["description"], "Wazuh's text")  # higher score kept
        self.assertEqual(vulns["metadata"]["scan_time"], existing["metadata"]["scan_time"])
        self.assertEqual(vulns["metadata"]["counts"]["hosts"], 1)
        self.assertEqual(vulns["metadata"]["counts"]["devices"], 5)
        self.assertEqual(vulns["hosts"][f"device:{L2_CID}"]["kind"], "device")

    def test_second_refresh_is_served_from_the_cache(self):
        self.refresh()
        warm = lab_nvd(self.clock)
        self.refresh(fake=warm)
        self.assertEqual(warm.calls, [])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "nvd-cache.json")))

    def test_unreadable_graph(self):
        with open(self.graph_path, "w") as f:
            f.write("{broken")
        self.assertEqual(self.refresh(), 1)
        with open(self.graph_path) as f:
            self.assertEqual(f.read(), "{broken")

    def test_written_atomically(self):
        self.refresh()
        self.assertEqual(sorted(os.listdir(self.tmp)),
                         ["graph.json", "nvd-cache.json", "vulnerabilities.json"])


if __name__ == "__main__":
    unittest.main()
