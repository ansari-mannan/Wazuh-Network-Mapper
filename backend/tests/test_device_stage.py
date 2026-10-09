"""The device vulnerability stage: status -> score, pipeline outputs.

Every NVD reply is served by FakeNvd (test_nvd); nothing touches the network.
"""

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest

from test_cdp import AP_CID, L2_CID, L3_CID, crawl, lab
from test_nvd import IOS_CPE, FakeClock, FakeNvd, ios_cves, listed, metric, record, saved
from vulnmapper import scoring
from vulnmapper.assemble import assemble
from vulnmapper.devicecves import nvd
from vulnmapper.devicecves.cache import Cache
from vulnmapper.devicecves.stage import run_stage
from vulnmapper.pipeline import Pipeline

L2_CPE = r"cpe:2.3:o:cisco:ios:12.2\(58\)se2:*:*:*:*:*:*:*"
AP_CPE = r"cpe:2.3:o:cisco:ios:15.3\(3\)jb:*:*:*:*:*:*:*"
FORTI_CPE = "cpe:2.3:o:fortinet:fortios:6.0.16:*:*:*:*:*:*:*"
L2_CVES = [record("CVE-2021-0001", metric("3.1", 9.8, severity="CRITICAL")),
           record("CVE-2021-0002", metric("3.1", 5.3, severity="MEDIUM"))]


def lab_nvd(clock, **kw):
    """The lab's software as NVD knows it (IOS from a saved reply)."""
    kw.setdefault("cves", {IOS_CPE: ios_cves(), L2_CPE: L2_CVES, AP_CPE: [],
                           "1920": saved("cves_keyword_1920.json")["vulnerabilities"]})
    kw.setdefault("dictionary", {c: listed(c) for c in (IOS_CPE, L2_CPE, AP_CPE)})
    return FakeNvd(clock=clock, **kw)


def device(node_id="device:aa:bb:cc:00:00:01", **fields):
    node = {"node_id": node_id, "kind": "device", "pollable": True, "status": "online",
            "vendor": "Cisco", "model": "WS-C3750-48TS-S", "firmware": "12.2(55)SE12",
            "software_family": "cisco_ios", "risk_score": 0, "max_cvss": None}
    node.update(fields)
    return node


class TestStatusTable(unittest.TestCase):
    """One test per row of the status -> score table."""

    def setUp(self):
        self.clock = FakeClock()

    def stage(self, *nodes, fake=None, cache=None, budget=180.0):
        graph = {"nodes": list(nodes), "edges": [], "metadata": {}}
        fake = fake if fake is not None else lab_nvd(self.clock)
        self.client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="",
                                    budget_s=budget, use_env_key=False)
        result = run_stage(graph, self.client, cache or Cache(None, self.clock))
        return graph["nodes"], result

    def test_cpe_answered_cves_found(self):
        (node,), _ = self.stage(device())
        rows = [nvd.parse_cve(v["cve"], package=None, version=None, detected_at=None)
                for v in ios_cves()]
        self.assertEqual(node["risk_score"], scoring.base_score(rows))
        self.assertEqual(node["cve_lookup"]["status"], "ok")
        self.assertEqual(node["cve_lookup"]["match"], "cpe")
        self.assertEqual(node["cve_lookup"]["total"], 8)
        self.assertEqual(node["max_cvss"], 10.0)
        self.assertEqual(node["cve_summary"]["total"], 8)
        self.assertEqual(len(node["top_cves"]), 8)

    def test_cpe_answered_nothing_found_is_a_real_zero(self):
        (node,), _ = self.stage(device(firmware="15.3(3)JB"))
        self.assertEqual(node["risk_score"], 0.0)
        self.assertEqual((node["cve_lookup"]["status"], node["cve_lookup"]["total"]), ("ok", 0))
        self.assertEqual(node["cve_summary"]["total"], 0)

    def test_keyword_fallback_cves_found(self):
        accepted = record("CVE-2019-1111", metric("3.1", 7.5))
        accepted["cve"]["descriptions"] = [{"lang": "en", "value": "HP 1920 switches allow ..."}]
        fake = lab_nvd(self.clock, cves={"1920": [accepted]})
        (node,), _ = self.stage(device(vendor="HP", model="HP 1920-48G",
                                       firmware="5.20.99 Release 1107",
                                       software_family="hp_comware"), fake=fake)
        self.assertEqual((node["cve_lookup"]["status"], node["cve_lookup"]["match"]), ("ok", "keyword"))
        self.assertEqual(node["risk_score"], scoring.base_score([{"cve": "CVE-2019-1111", "cvss": 7.5}]))

    def test_keyword_fallback_nothing_found_is_unscored(self):
        # the lab's HP 1920: NVD's "1920" CVEs are about other products
        (node,), _ = self.stage(device(vendor="HP", model="HP 1920-48G",
                                       firmware="5.20.99 Release 1107",
                                       software_family="hp_comware"))
        self.assertEqual((node["cve_lookup"]["status"], node["cve_lookup"]["match"]), ("ok", "keyword"))
        self.assertIsNone(node["risk_score"])
        self.assertIsNone(node["cve_summary"])
        self.assertEqual(node["cve_lookup"]["total"], 0)

    def test_vendor_family_or_version_missing(self):
        nodes, result = self.stage(device("device:a", firmware=None),
                                   device("device:b", vendor="unknown vendor", software_family=None,
                                          firmware="1.0"))
        for node in nodes:
            self.assertEqual(node["cve_lookup"]["status"], "unidentified")
            self.assertIsNone(node["risk_score"])
        self.assertEqual(self.client.requests, 0)
        self.assertIn({"type": "device_unidentified", "node_ids": ["device:a", "device:b"]},
                      result.warnings)

    def test_nvd_unreachable_nothing_cached(self):
        (node,), result = self.stage(device(), fake=lab_nvd(self.clock, script=["down"] * 9))
        self.assertEqual(node["cve_lookup"]["status"], "unavailable")
        self.assertIsNone(node["risk_score"])
        self.assertIsNone(node["cve_summary"])
        self.assertIn({"type": "nvd_unreachable", "node_ids": [node["node_id"]]}, result.warnings)

    def test_nvd_could_not_confirm_the_query(self):
        (node,), _ = self.stage(device(firmware="12.2(99)ZZ99"))
        self.assertEqual(node["cve_lookup"]["status"], "unverified")
        self.assertIsNone(node["risk_score"])

    def test_device_not_polled(self):
        (node,), result = self.stage(device(pollable=False, status="discovered"))
        self.assertEqual(node["cve_lookup"]["status"], "unidentified")
        self.assertIsNone(node["risk_score"])
        self.assertEqual(self.client.requests, 0)
        self.assertEqual(result.warnings, [])          # expected, so no warning

    def test_stale_cache_is_used_and_flagged(self):
        cache = Cache(None, self.clock)
        self.stage(device(), cache=cache)
        self.clock.advance(days=30)
        (node,), result = self.stage(device(), cache=cache,
                                     fake=lab_nvd(self.clock, script=["down"] * 9))
        self.assertEqual((node["cve_lookup"]["status"], node["cve_lookup"]["stale"]), ("ok", True))
        self.assertIsNotNone(node["risk_score"])
        self.assertIn({"type": "nvd_stale_cache", "node_ids": [node["node_id"]]}, result.warnings)

    def test_budget_runs_out_the_rest_wait_for_the_next_scan(self):
        nodes, result = self.stage(device("device:a"), device("device:b", firmware="12.2(58)SE2"),
                                   budget=8.0)
        self.assertEqual(nodes[0]["cve_lookup"]["status"], "ok")
        self.assertEqual(nodes[1]["cve_lookup"]["status"], "unavailable")
        self.assertIsNone(nodes[1]["risk_score"])
        self.assertIn({"type": "nvd_budget_exceeded", "node_ids": ["device:b"]}, result.warnings)

    def test_metadata_block(self):
        _, result = self.stage(device("device:a"), device("device:b"),
                               device("device:c", pollable=False))
        self.assertEqual(result.block, {"looked_up": 3, "by_status": {"ok": 2, "unidentified": 1},
                                        "from_cache": 1, "nvd_requests": 2, "stale": 0,
                                        "api_key": False, "budget_s": 180.0})


NEW_DEVICE_FIELDS = {"cve_summary", "top_cves", "cve_lookup"}


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        with open(self.network, "w") as f:
            json.dump(crawl(lab()), f)
        self.graph_path = os.path.join(self.tmp, "graph.json")
        self.clock = FakeClock()
        self.fake = lab_nvd(self.clock)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra, fake=None):
        argv = ["--no-endpoints", "--network", self.network, "-o", self.graph_path, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = Pipeline(nvd_transport=fake or self.fake, clock=self.clock).run(argv)
        self.assertEqual(code, 0)
        with open(self.graph_path) as f:
            return json.load(f)

    def load(self, name):
        with open(os.path.join(self.tmp, name)) as f:
            return json.load(f)

    def test_stage_skipped_gives_todays_document(self):
        graph = self.run_pipeline("--no-device-cves", "--no-checklist")
        with open(self.network) as f:
            today = assemble([], json.load(f))
        self.assertEqual(graph["nodes"], today["nodes"])
        self.assertEqual(graph["edges"], today["edges"])
        self.assertIsNone(graph["metadata"]["timing"]["device_cves_s"])
        self.assertNotIn("device_cves", graph["metadata"])
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "nvd-cache.json")))
        vulns = self.load("vulnerabilities.json")
        self.assertEqual(vulns["metadata"]["counts"]["devices"], 0)

    def test_stage_on_adds_exactly_the_documented_fields(self):
        before = {n["node_id"]: n for n in self.run_pipeline("--no-device-cves")["nodes"]}
        graph = self.run_pipeline()
        after = {n["node_id"]: n for n in graph["nodes"]}
        self.assertEqual(set(after), set(before))
        for nid, node in after.items():
            old = before[nid]
            if node["kind"] != "device":
                self.assertEqual(node, old, nid)
                continue
            self.assertEqual(set(node) - set(old), NEW_DEVICE_FIELDS, nid)
            changed = {k for k in old if old[k] != node[k]}
            self.assertLessEqual(changed, {"risk_score", "max_cvss"}, nid)
        self.assertIsInstance(graph["metadata"]["timing"]["device_cves_s"], float)
        self.assertIn("device_cves", graph["metadata"])

    def test_lab_results(self):
        nodes = {n["node_id"]: n for n in self.run_pipeline()["nodes"]}
        l3, l2, ap = (nodes[f"device:{c}"] for c in (L3_CID, L2_CID, AP_CID))
        self.assertEqual(l3["cve_lookup"], {
            "status": "ok", "match": "cpe", "product": "Cisco IOS 12.2(55)SE12", "cpe": IOS_CPE,
            "source": "nvd", "fetched_at": l3["cve_lookup"]["fetched_at"], "stale": False, "total": 8})
        self.assertEqual((l2["cve_lookup"]["total"], l2["max_cvss"]), (2, 9.8))
        self.assertEqual((ap["cve_lookup"]["total"], ap["risk_score"]), (0, 0.0))
        hp = next(n for n in nodes.values() if n.get("ip") == "172.20.99.4")
        self.assertEqual((hp["cve_lookup"]["match"], hp["risk_score"]), ("keyword", None))

    def test_vulnerabilities_file_gains_device_entries(self):
        self.run_pipeline()
        vulns = self.load("vulnerabilities.json")
        entry = vulns["hosts"][f"device:{L2_CID}"]
        self.assertEqual((entry["kind"], entry["agent_id"], entry["hostname"]),
                         ("device", None, "L2-Switch"))
        self.assertEqual(entry["cve_lookup"]["product"], "Cisco IOS 12.2(58)SE2")
        self.assertEqual(entry["findings"][0], {
            "cve": "CVE-2021-0001", "package": "Cisco IOS 12.2(58)SE2", "version": "12.2(58)SE2",
            "detected_at": entry["cve_lookup"]["fetched_at"]})
        self.assertEqual(vulns["cves"]["CVE-2021-0001"]["description"], "An issue.")
        # every device node has an entry; the firewall (not in the fixtures, so
        # unreachable) is one, unidentified, with no findings
        self.assertEqual(vulns["metadata"]["counts"]["devices"], 5)
        self.assertIsNone(vulns["hosts"]["device:90:6c:ac:d7:43:7f"]["findings"])
        self.assertEqual(vulns["metadata"]["counts"]["hosts"], 0)
        hp = next(k for k, v in vulns["hosts"].items() if v["hostname"] == "CYFOR-HP-Switch")
        self.assertEqual(vulns["hosts"][hp]["findings"], [])

    def test_cache_beside_the_vulnerabilities_file_and_warm_scan_makes_no_request(self):
        self.run_pipeline()
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "nvd-cache.json")))
        first = len(self.fake.calls)
        self.assertGreater(first, 0)
        warm = lab_nvd(self.clock)
        graph = self.run_pipeline(fake=warm)
        self.assertEqual(warm.calls, [])
        self.assertEqual(graph["metadata"]["device_cves"]["nvd_requests"], 0)

    def test_explicit_cache_path(self):
        path = os.path.join(self.tmp, "elsewhere.json")
        self.run_pipeline("--nvd-cache", path)
        self.assertTrue(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "nvd-cache.json")))

    def test_nvd_down_never_fails_the_scan(self):
        graph = self.run_pipeline(fake=lab_nvd(self.clock, script=["down"] * 50))
        devices = [n for n in graph["nodes"] if n["kind"] == "device" and n["pollable"]]
        self.assertTrue(all(n["cve_lookup"]["status"] == "unavailable" for n in devices
                            if n["cve_lookup"]["match"]))
        self.assertIn("nvd_unreachable", [w["type"] for w in graph["metadata"]["warnings"]])


if __name__ == "__main__":
    unittest.main()
