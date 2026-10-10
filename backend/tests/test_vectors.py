"""The CVE vector stage: each asset's most easily reached CVE, from saved replies.

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

from test_nvd import IOS_CPE, FakeClock, FakeNvd, ios_cves, vector
from vulnmapper.devicecves import nvd, vectors
from vulnmapper.devicecves.cache import Cache, trim_cve
from vulnmapper.devicecves.lookup import Unanswered

HERE = os.path.dirname(os.path.abspath(__file__))
FOUR = set(nvd.VECTOR_FIELDS)


def v3(cve_id, score, av="NETWORK", ac="LOW", pr="NONE", ui="NONE"):
    return vector(cve_id, "3.1", score, f"CVSS:3.1/AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}",
                  attackVector=av, attackComplexity=ac, privilegesRequired=pr, userInteraction=ui)


# CVE id -> (score, its record in NVD)
CVES = {
    "CVE-2026-0001": v3("CVE-2026-0001", 9.8),                       # NETWORK, LOW: unbeatable
    "CVE-2026-0002": v3("CVE-2026-0002", 9.0, pr="LOW"),
    "CVE-2026-0003": v3("CVE-2026-0003", 8.0, ac="HIGH"),
    "CVE-2026-0004": v3("CVE-2026-0004", 9.9, av="LOCAL"),
    "CVE-2026-0005": v3("CVE-2026-0005", 7.0, ac="HIGH"),
    "CVE-2026-0006": v3("CVE-2026-0006", 8.8, av="ADJACENT_NETWORK"),  # ADJACENT, LOW
    "CVE-2026-0007": v3("CVE-2026-0007", 6.5, ui="REQUIRED"),
}


def score(cve_id):
    return CVES[cve_id]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]


def host(n, *cve_ids, summary=True):
    rows = sorted(({"cve": c, "cvss": score(c)} for c in cve_ids), key=lambda r: -r["cvss"])
    return {"node_id": f"endpoint:{n:03d}", "kind": "endpoint", "top_cves": rows,
            "cve_summary": {"total": len(rows)} if summary else None}


def by_id_nvd(clock, **kw):
    return FakeNvd(cves={c: [rec] for c, rec in CVES.items()}, clock=clock, **kw)


class TestAssess(unittest.TestCase):
    def fields(self, table):
        self.asked = []

        def fields_of(cve_id):
            self.asked.append(cve_id)
            f = table[cve_id]
            if f == "budget":
                raise Unanswered("budget")
            return f and dict(zip(nvd.VECTOR_FIELDS, f))
        return fields_of

    def rows(self, *pairs):
        return [{"cve": c, "cvss": s} for c, s in pairs]

    def test_lowest_complexity_then_higher_score(self):
        table = {"A": ("NETWORK", "HIGH", "NONE", "NONE"), "B": ("ADJACENT", "LOW", "NONE", "NONE"),
                 "C": ("NETWORK", "LOW", "NONE", "NONE"), "D": ("NETWORK", "LOW", "NONE", "NONE")}
        out = vectors.assess(self.rows(("A", 9.8), ("B", 7.5), ("C", 5.0), ("D", 4.0)),
                             self.fields(table))
        self.assertEqual(out, {"status": "found", "cve": "B", "attack_vector": "ADJACENT",
                               "attack_complexity": "LOW", "privileges_required": "NONE",
                               "user_interaction": "NONE", "cvss": 7.5})
        self.assertEqual(self.asked, ["A", "B", "C"])         # stops at C (NETWORK, LOW)

    def test_medium_ranks_between_low_and_high(self):
        table = {"A": ("NETWORK", "HIGH", "NONE", "NONE"), "B": ("NETWORK", "MEDIUM", "NONE", "NONE")}
        out = vectors.assess(self.rows(("A", 9.8), ("B", 5.0)), self.fields(table))
        self.assertEqual(out["cve"], "B")

    def test_stops_at_the_first_unbeatable(self):
        table = {"A": ("NETWORK", "LOW", "NONE", "NONE"), "B": None}
        out = vectors.assess(self.rows(("A", 9.8), ("B", 9.0)), self.fields(table))
        self.assertEqual((out["cve"], self.asked), ("A", ["A"]))

    def test_none_found(self):
        table = {"A": ("LOCAL", "LOW", "NONE", "NONE"), "B": ("NETWORK", "LOW", "LOW", "NONE"),
                 "C": ("NETWORK", "LOW", "NONE", "REQUIRED"), "D": None,
                 "E": ("NETWORK", "LOW", "NONE", None), "F": (None,) * 4}
        out = vectors.assess(self.rows(*((c, 5.0) for c in "ABCDEF")), self.fields(table))
        self.assertEqual(out, {"status": "none_found"})
        self.assertEqual(vectors.assess([], self.fields({})), {"status": "none_found"})

    def test_unverified_even_after_a_qualifying_cve(self):
        table = {"A": ("NETWORK", "HIGH", "NONE", "NONE"), "B": "budget",
                 "C": ("NETWORK", "LOW", "NONE", "NONE")}
        out = vectors.assess(self.rows(("A", 9.8), ("B", 9.0), ("C", 5.0)), self.fields(table))
        self.assertEqual(out, {"status": "unverified"})


class TestStage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "nvd-cache.json")
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def graph(self):
        return {"nodes": [
            host(1, "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"),
            host(2, "CVE-2026-0004", "CVE-2026-0001"),
            host(3, "CVE-2026-0005", "CVE-2026-0007"),
            host(4, "CVE-2026-0002"),
            host(5, summary=False),
            {"node_id": "device:x", "kind": "device", "cve_summary": {"total": 0}, "top_cves": []},
            {"node_id": "switch-port", "kind": "port"},
        ], "edges": [], "metadata": {}}

    def stage(self, graph, fake, budget=180.0, hosts=None, catalogue=None, cache=None):
        self.client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="",
                                    budget_s=budget, use_env_key=False)
        result = vectors.run_stage(graph, hosts or {}, catalogue if catalogue is not None else {},
                                   self.client, cache or Cache(self.path, self.clock))
        return {n["node_id"]: n.get(vectors.FIELD, "absent") for n in graph["nodes"]}, result

    def test_summaries_and_few_requests_shared_across_assets(self):
        fake = by_id_nvd(self.clock)
        out, result = self.stage(self.graph(), fake)
        self.assertEqual(out["endpoint:001"]["cve"], "CVE-2026-0001")
        self.assertEqual(out["endpoint:002"]["cve"], "CVE-2026-0001")
        self.assertEqual(out["endpoint:003"], {
            "status": "found", "source": "top_cves", "cve": "CVE-2026-0005",
            "attack_vector": "NETWORK", "attack_complexity": "HIGH", "privileges_required": "NONE",
            "user_interaction": "NONE", "cvss": 7.0})
        self.assertEqual(out["endpoint:004"], {"status": "none_found", "source": "top_cves"})
        self.assertIsNone(out["endpoint:005"])
        self.assertEqual(out["device:x"], {"status": "none_found", "source": "top_cves"})
        self.assertEqual(out["switch-port"], "absent")
        # host 1 stops at 0001; host 2 asks 0004 and reuses 0001; 0003 is never asked
        asked = [c["params"]["cveId"] for c in fake.calls]
        self.assertEqual(asked, ["CVE-2026-0001", "CVE-2026-0004", "CVE-2026-0005",
                                 "CVE-2026-0007", "CVE-2026-0002"])
        self.assertEqual(result.block, {"assets": 6, "by_status": {"found": 3, "none_found": 2},
                                        "looked_up": 5, "nvd_requests": 5, "api_key": False,
                                        "budget_s": 180.0})
        self.assertEqual(result.warnings, [])

    def test_warm_cache_makes_zero_requests(self):
        cold, _ = self.stage(self.graph(), by_id_nvd(self.clock))
        warm_fake = by_id_nvd(self.clock)
        warm, result = self.stage(self.graph(), warm_fake)
        self.assertEqual((warm_fake.calls, result.block["nvd_requests"]), ([], 0))
        self.assertEqual(warm, cold)

    def test_budget_out_is_unverified_never_none_found(self):
        fake = by_id_nvd(self.clock)
        out, result = self.stage(self.graph(), fake, budget=10.0)    # room for 2 requests
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(out["endpoint:001"]["status"], "found")
        self.assertEqual(out["endpoint:002"]["status"], "found")
        self.assertEqual(out["endpoint:003"], {"status": "unverified", "source": "top_cves"})
        self.assertEqual(out["endpoint:004"], {"status": "unverified", "source": "top_cves"})
        self.assertEqual(result.warnings, [{"type": "cve_vectors_unverified",
                                            "node_ids": ["endpoint:003", "endpoint:004"]}])
        # the next run finishes from where this one stopped
        fake = by_id_nvd(self.clock)
        out, _ = self.stage(self.graph(), fake)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(out["endpoint:004"]["status"], "none_found")

    def test_nvd_down_is_unverified(self):
        out, result = self.stage(self.graph(), by_id_nvd(self.clock, script=["down"] * 50))
        self.assertEqual(out["endpoint:001"]["status"], "unverified")
        self.assertEqual(result.block["by_status"], {"none_found": 1, "unverified": 4})

    def test_full_findings_before_top_cves(self):
        node = host(1, "CVE-2026-0002")
        hosts = {"endpoint:001": {"findings": [{"cve": "CVE-2026-0002"}, {"cve": "CVE-2026-0006"},
                                               {"cve": "CVE-2026-0006"}]}}
        catalogue = {"CVE-2026-0002": {"cvss": 9.0}, "CVE-2026-0006": {"cvss": 8.8}}
        out, _ = self.stage({"nodes": [node]}, by_id_nvd(self.clock), hosts=hosts,
                            catalogue=catalogue)
        self.assertEqual((out["endpoint:001"]["source"], out["endpoint:001"]["cve"],
                          out["endpoint:001"]["attack_vector"], out["endpoint:001"]["cvss"]),
                         ("findings", "CVE-2026-0006", "ADJACENT", 8.8))

    def test_four_fields_on_top_cves_and_catalogue_when_known(self):
        graph = self.graph()
        catalogue = {c: {"cvss": score(c), "description": "x"} for c in CVES}
        self.stage(graph, by_id_nvd(self.clock), catalogue=catalogue)
        top = {r["cve"]: r for r in graph["nodes"][0]["top_cves"]}
        self.assertEqual({k: top["CVE-2026-0001"][k] for k in FOUR},
                         {"attack_vector": "NETWORK", "attack_complexity": "LOW",
                          "privileges_required": "NONE", "user_interaction": "NONE"})
        self.assertEqual(set(top["CVE-2026-0003"]), {"cve", "cvss"})     # never looked up
        self.assertEqual(catalogue["CVE-2026-0004"]["attack_vector"], "LOCAL")
        self.assertEqual(catalogue["CVE-2026-0003"], {"cvss": 8.0, "description": "x"})
        self.assertNotIn("cvss_vector", catalogue["CVE-2026-0001"])

    def test_device_cves_come_from_the_device_answers_in_the_cache(self):
        cache = Cache(self.path, self.clock)
        cache.put(f"cves:{IOS_CPE}", found=True, data=[trim_cve(v["cve"]) for v in ios_cves()])
        node = {"node_id": "device:l3", "kind": "device", "cve_summary": {"total": 1},
                "top_cves": [{"cve": "CVE-2006-4950", "cvss": 10.0}]}
        fake = by_id_nvd(self.clock)
        out, _ = self.stage({"nodes": [node]}, fake, cache=cache)
        self.assertEqual(fake.calls, [])
        self.assertEqual(out["device:l3"]["cve"], "CVE-2006-4950")


class TestRefresh(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph_path = os.path.join(self.tmp, "graph.json")
        self.graph = {"nodes": [host(1, "CVE-2026-0001", "CVE-2026-0003"),
                                host(2, "CVE-2026-0004"),
                                {"node_id": "device:x", "kind": "device", "ip": "10.0.0.1"}],
                      "edges": [{"source": "endpoint:001", "target": "device:x"}],
                      "metadata": {"scan_time": "2026-10-08T12:58:20+00:00",
                                   "warnings": [{"type": "duplicate_ip", "ip": "10.0.0.9"}]}}
        self.write(self.graph_path, self.graph)
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, path, doc):
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)

    def load(self, name):
        with open(os.path.join(self.tmp, name)) as f:
            return json.load(f)

    def refresh(self, fake=None):
        self.fake = fake or by_id_nvd(self.clock)
        with contextlib.redirect_stderr(io.StringIO()):
            return vectors.main(["--graph", self.graph_path], transport=self.fake, clock=self.clock)

    def test_changes_nothing_else_in_the_graph(self):
        self.assertEqual(self.refresh(), 0)
        after = self.load("graph.json")
        self.assertEqual(after["metadata"].pop("cve_vectors")["nvd_requests"], 2)
        expected = copy.deepcopy(self.graph)
        for node in after["nodes"]:
            node.pop(vectors.FIELD, None)
            for row in node.get("top_cves") or []:
                for k in FOUR:
                    row.pop(k, None)
        self.assertEqual(after, expected)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["graph.json", "nvd-cache.json"])

    def test_summaries_and_warm_refresh(self):
        self.refresh()
        nodes = {n["node_id"]: n for n in self.load("graph.json")["nodes"]}
        self.assertEqual(nodes["endpoint:001"][vectors.FIELD]["cve"], "CVE-2026-0001")
        self.assertEqual(nodes["endpoint:002"][vectors.FIELD]["status"], "none_found")
        self.assertIsNone(nodes["device:x"][vectors.FIELD])
        self.refresh()
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.load("graph.json")["metadata"]["cve_vectors"]["nvd_requests"], 0)

    def test_old_warning_is_replaced(self):
        self.refresh(by_id_nvd(self.clock, script=["down"] * 50))
        types = [w["type"] for w in self.load("graph.json")["metadata"]["warnings"]]
        self.assertIn("cve_vectors_unverified", types)
        self.clock.advance(seconds=60)
        self.refresh()
        types = [w["type"] for w in self.load("graph.json")["metadata"]["warnings"]]
        self.assertEqual(types, ["duplicate_ip"])

    def test_existing_vulnerabilities_file_gains_the_fields_only(self):
        vulns = {"metadata": {"scan_time": "2026-10-08T12:58:20+00:00", "counts": {}},
                 "cves": {c: {"cvss": score(c), "description": "x"} for c in
                          ("CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0006")},
                 "hosts": {"endpoint:001": {"kind": "endpoint", "findings": [
                     {"cve": "CVE-2026-0003"}, {"cve": "CVE-2026-0006"}]}}}
        self.write(os.path.join(self.tmp, "vulnerabilities.json"), vulns)
        self.refresh()
        after = self.load("vulnerabilities.json")
        self.assertEqual((after["metadata"], after["hosts"]), (vulns["metadata"], vulns["hosts"]))
        self.assertEqual(after["cves"]["CVE-2026-0006"]["attack_vector"], "ADJACENT")
        self.assertEqual(after["cves"]["CVE-2026-0001"], vulns["cves"]["CVE-2026-0001"])
        node = self.load("graph.json")["nodes"][0]
        self.assertEqual((node[vectors.FIELD]["source"], node[vectors.FIELD]["cve"]),
                         ("findings", "CVE-2026-0006"))

    def test_unreadable_graph(self):
        with open(self.graph_path, "w") as f:
            f.write("{broken")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vectors.main(["--graph", self.graph_path],
                                          transport=by_id_nvd(self.clock), clock=self.clock), 1)


if __name__ == "__main__":
    unittest.main()
