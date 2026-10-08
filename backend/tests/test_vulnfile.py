"""The CLI's second output, vulnerabilities.json, and the graph fields that go
with it. Offline: driven by the --scored / --network fixtures."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import requests

from vulnmapper import endpoints as ep_mod
from vulnmapper.assemble import assemble
from vulnmapper.pipeline import Pipeline, build_parser

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SCORED = os.path.join(_FIX, "offline_scored.json")
SCORED_OLD = os.path.join(_FIX, "offline_scored_old_shape.json")
NETWORK = os.path.join(_FIX, "offline_network.json")


def run(argv):
    """Run the pipeline; returns (exit code, stdout text, pipeline log lines).

    The device CVE stage is off here (it has its own tests, test_device_stage):
    these tests pin the endpoint side, and must never reach NVD.
    """
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
            unittest.TestCase().assertLogs("vulnmapper.pipeline", "INFO") as logs:
        code = Pipeline().run(list(argv) + ["--no-device-cves"])
    return code, out.getvalue(), logs.output


class TestVulnsFileRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph = os.path.join(self.tmp, "graph.json")
        self.default = os.path.join(self.tmp, "vulnerabilities.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def load(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_help_lists_vulns_out(self):
        self.assertIn("--vulns-out", build_parser().format_help())

    def test_written_next_to_output_by_default(self):
        code, stdout, _ = run(["--scored", SCORED, "--network", NETWORK, "-o", self.graph])
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "")
        vulns = self.load(self.default)
        graph = self.load(self.graph)
        graph_ids = {n["node_id"] for n in graph["nodes"] if n.get("agent_id")}
        self.assertEqual(set(vulns["hosts"]), graph_ids)
        self.assertEqual(vulns["metadata"]["scan_time"], graph["metadata"]["scan_time"])
        self.assertEqual(vulns["metadata"]["counts"], {"hosts": 4, "devices": 0, "cves": 17,
                                                     "findings": 19})
        self.assertEqual(len(vulns["hosts"]["endpoint:101"]["findings"]), 15)
        self.assertEqual(vulns["hosts"]["endpoint:103"]["findings"], [])
        self.assertIsNone(vulns["hosts"]["endpoint:104"]["findings"])   # unscored
        self.assertEqual(set(vulns["cves"]["CVE-2026-90000"]),
                         {"cvss", "cvss_version", "severity", "description",
                          "reference", "published_at"})
        # written via a temp file + rename: nothing else is left in the folder
        self.assertEqual(sorted(os.listdir(self.tmp)), ["graph.json", "vulnerabilities.json"])

    def test_explicit_vulns_out_wins(self):
        target = os.path.join(self.tmp, "sub-findings.json")
        run(["--scored", SCORED, "--network", NETWORK, "-o", self.graph,
             "--vulns-out", target])
        self.assertTrue(os.path.exists(target))
        self.assertFalse(os.path.exists(self.default))

    def test_vulns_out_with_graph_on_stdout(self):
        target = os.path.join(self.tmp, "v.json")
        _code, stdout, _ = run(["--scored", SCORED, "--network", NETWORK,
                                "--vulns-out", target])
        self.assertIn("nodes", json.loads(stdout))       # stdout is only the graph
        self.assertEqual(self.load(target)["metadata"]["counts"]["hosts"], 4)

    def test_skipped_when_graph_on_stdout(self):
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            code, stdout, logs = run(["--scored", SCORED, "--network", NETWORK])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0)
        self.assertIn("nodes", json.loads(stdout))
        self.assertEqual(os.listdir(self.tmp), [])
        skip = [line for line in logs if "vulnerabilities.json" in line]
        self.assertEqual(len(skip), 1)
        self.assertIn("not writing", skip[0])

    def test_not_written_when_scan_fails(self):
        with open(self.default, "w") as f:
            f.write("previous\n")
        with self.assertRaises(FileNotFoundError), \
                contextlib.redirect_stderr(io.StringIO()):
            Pipeline().run(["--scored", SCORED, "--network",
                            os.path.join(self.tmp, "missing.json"), "-o", self.graph,
                            "--no-device-cves"])
        with open(self.default) as f:
            self.assertEqual(f.read(), "previous\n")    # untouched
        self.assertEqual(sorted(os.listdir(self.tmp)), ["vulnerabilities.json"])

    def test_old_shape_scored_file_still_loads(self):
        code, _, _ = run(["--scored", SCORED_OLD, "--network", NETWORK, "-o", self.graph])
        self.assertEqual(code, 0)
        by_id = {n["node_id"]: n for n in self.load(self.graph)["nodes"]}
        web = by_id["endpoint:101"]
        self.assertEqual(web["risk_score"], 9.8)          # as stored in the old file
        self.assertEqual(len(web["top_cves"]), 3)
        self.assertIsNone(web["cve_summary"])
        vulns = self.load(self.default)
        self.assertEqual(vulns["cves"], {})
        self.assertTrue(all(h["findings"] is None for h in vulns["hosts"].values()))

    def test_graph_carries_new_fields_and_score_warnings(self):
        run(["--scored", SCORED, "--network", NETWORK, "-o", self.graph])
        graph = self.load(self.graph)
        by_id = {n["node_id"]: n for n in graph["nodes"]}
        web = by_id["endpoint:101"]
        self.assertEqual(web["cve_summary"]["total"], 14)
        self.assertEqual(len(web["top_cves"]), 10)
        self.assertEqual(web["max_cvss"], 9.8)
        self.assertEqual(web["risk_score"], 8.2)
        self.assertNotIn("findings", web)
        self.assertEqual(by_id["endpoint:103"]["risk_score"], 0.0)
        types = [w["type"] for w in graph["metadata"]["warnings"]]
        self.assertIn("indexer_unreachable", types)


class TestIndexerDownScanCompletes(unittest.TestCase):
    """A live run whose indexer refuses connections still emits a full graph."""

    def test_unreachable_indexer(self):
        agents = [{"agent_id": "001", "hostname": "a", "ip": "10.0.0.1", "status": "active"},
                  {"agent_id": "002", "hostname": "b", "ip": "10.0.0.2", "status": "active"}]
        env = {"WAZUH_PASS": "x", "INDEXER_PASS": "y"}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, env), \
                mock.patch.object(ep_mod.WazuhSource, "collect", return_value=agents), \
                mock.patch.object(ep_mod.requests, "post",
                                  side_effect=requests.ConnectionError("refused")):
            graph_path = os.path.join(tmp, "graph.json")
            code, _, _ = run(["--no-network", "-o", graph_path])
            with open(graph_path) as f:
                graph = json.load(f)
            with open(os.path.join(tmp, "vulnerabilities.json")) as f:
                vulns = json.load(f)

        self.assertEqual(code, 0)
        endpoints = [n for n in graph["nodes"] if n["kind"] == "endpoint"]
        self.assertEqual(len(endpoints), 2)
        for node in endpoints:
            self.assertIsNone(node["risk_score"])
            self.assertIsNone(node["cve_summary"])
        warning = [w for w in graph["metadata"]["warnings"]
                   if w["type"] == "indexer_unreachable"]
        self.assertEqual(len(warning), 1)
        self.assertEqual(warning[0]["agents"], ["001", "002"])
        self.assertEqual(vulns["metadata"]["counts"], {"hosts": 2, "devices": 0, "cves": 0,
                                                     "findings": 0})


class TestRiskScoreNull(unittest.TestCase):
    NET = {"nodes": [{"chassis_id": "sw", "ip": "10.0.0.254", "status": "online",
                      "pollable": True}], "edges": []}

    def test_unscored_endpoint_reaches_graph_as_null(self):
        doc = assemble([{"agent_id": "001", "ip": "10.0.0.1", "status": "active",
                         "risk_score": None, "max_cvss": None, "top_cves": [],
                         "cve_summary": None}], self.NET)
        node = next(n for n in doc["nodes"] if n["node_id"] == "endpoint:001")
        self.assertIsNone(node["risk_score"])
        self.assertIsNone(node["cve_summary"])

    def test_scanned_clean_endpoint_stays_zero(self):
        doc = assemble([{"agent_id": "001", "risk_score": 0.0, "top_cves": [],
                         "cve_summary": {"total": 0}}], self.NET)
        node = next(n for n in doc["nodes"] if n["node_id"] == "endpoint:001")
        self.assertEqual(node["risk_score"], 0.0)

    def test_devices_unchanged(self):
        doc = assemble([], self.NET)
        self.assertEqual(doc["nodes"][0]["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
