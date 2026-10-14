"""Rescoring after a protected asset is marked: OVSS sees the new importance,
the routes are recomputed, and nothing is downloaded or rescanned."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from vulnmapper.pipeline import Pipeline
from vulnmapper.scoring import rescore

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def read(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestRescore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph = os.path.join(self.tmp, "graph.json")
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"),
                "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-name-lookup", "-o", self.graph]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_marking_an_asset_high_raises_its_score_offline(self):
        before = read(self.graph)
        node = next(n for n in before["nodes"]
                    if n.get("risk_score") is not None and n.get("dependency", 1) < 1)
        nid = node["node_id"]
        with open(os.path.join(self.tmp, "targets.json"), "w", encoding="utf-8") as f:
            json.dump({nid: {"importance": "high"}}, f)

        with mock.patch("requests.sessions.Session.send",
                        side_effect=AssertionError("a rescore attempted a request")) as send, \
                mock.patch.object(rescore, "no_network", wraps=rescore.no_network) as refused, \
                self.assertLogs("vulnmapper", "INFO"):
            self.assertEqual(rescore.main(["--graph", self.graph]), 0)
        send.assert_not_called()
        refused.assert_called()                     # every download went to the refusing transport

        after = read(self.graph)
        scored = next(n for n in after["nodes"] if n["node_id"] == nid)
        self.assertEqual(scored["dependency"], 1.0)
        self.assertGreater(scored["risk_score"], node["risk_score"])
        self.assertEqual(after["metadata"]["scan_time"], before["metadata"]["scan_time"])
        findings = read(os.path.join(self.tmp, "vulnerabilities.json"))["hosts"][nid]["findings"]
        self.assertEqual(max(f["score"] for f in findings if f["score"] is not None),
                         scored["risk_score"])
        paths = read(os.path.join(self.tmp, "attack_paths.json"))
        self.assertEqual(paths["metadata"]["counts"]["targets_present"], 1)

    def test_a_missing_graph_exits_1(self):
        with self.assertLogs("vulnmapper", "ERROR"):
            self.assertEqual(rescore.main(["--graph", os.path.join(self.tmp, "none.json")]), 1)


if __name__ == "__main__":
    unittest.main()
