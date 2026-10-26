"""A crawl that polls no device says why (metadata.warnings, the stage note),
so the dashboard can keep the previous map."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from snmp_fakes import FakeSnmpClient
from vulnmapper.network import crawl
from vulnmapper.network.config import Config
from vulnmapper.network.model import Credential
from vulnmapper.pipeline import Pipeline

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CRED = [Credential(version="v2c", index=1, community="x")]


def reason(doc):
    return [(w["type"], w["reason"]) for w in doc.get("warnings") or []]


class TestCrawlDocument(unittest.TestCase):
    def crawl(self, seeds, client=None):
        with mock.patch.object(crawl, "discover_seeds", lambda explicit: seeds), \
                mock.patch.object(crawl, "SnmpClient", lambda *a, **k: client or FakeSnmpClient({})), \
                self.assertLogs(level="ERROR"):
            return crawl.crawl_document(Config(credentials=CRED, seeds=[]))

    def test_no_device_answers(self):
        doc = self.crawl(["192.0.2.1"])
        self.assertEqual(reason(doc), [("crawl_empty", "no device answered")])

    def test_no_seed(self):
        self.assertEqual(reason(self.crawl([])), [("crawl_empty", "no seed")])

    def test_crawl_error(self):
        with mock.patch.object(crawl, "Crawler", side_effect=RuntimeError("boom")):
            doc = self.crawl(["192.0.2.1"])
        self.assertEqual(reason(doc), [("crawl_empty", "crawl error")])


class TestPipelineCarriesIt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_network(self, doc):
        network = os.path.join(self.tmp, "network.json")
        with open(network, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        graph = os.path.join(self.tmp, "graph.json")
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"), "--network", network,
                "--no-device-cves", "--no-cve-vectors", "--no-name-lookup", "-o", graph]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(graph, encoding="utf-8") as f:
            return json.load(f)["metadata"]

    def test_warning_and_stage_note(self):
        metadata = self.run_network({"nodes": [], "edges": [],
                                     "warnings": [{"type": "crawl_empty", "reason": "no seed"}]})
        self.assertIn({"type": "crawl_empty", "reason": "no seed"}, metadata["warnings"])
        stage = next(s for s in metadata["stages"] if s["name"] == "Network crawl")
        self.assertIn("(no seed)", stage["note"])

    def test_snmp_sources_and_fallback_warning_reach_the_graph(self):
        fallback = {"type": "snmp_fallback", "devices": ["sw2"]}
        metadata = self.run_network({"nodes": [], "edges": [], "warnings": [fallback],
                                     "snmp": {"entered": ["device:a"], "server": ["device:b"]}})
        self.assertEqual(metadata["snmp"], {"entered": ["device:a"], "server": ["device:b"]})
        self.assertIn(fallback, metadata["warnings"])

    def test_every_poll_in_the_note_with_its_fallback(self):
        polls = {f"sw{i}": float(i) for i in range(1, 8)}
        metadata = self.run_network({"nodes": [], "edges": [], "poll_seconds": polls,
                                     "bulk_fallback": ["sw2"]})
        stage = next(s for s in metadata["stages"] if s["name"] == "Network crawl")
        self.assertTrue(stage["note"].endswith(
            "; slowest polls: sw7 7.0 s, sw6 6.0 s, sw5 5.0 s, sw4 4.0 s, sw3 3.0 s, "
            "sw2 2.0 s (GETBULK failed, row at a time), sw1 1.0 s"), stage["note"])

    def test_live_crawl_times_each_device(self):
        from test_cdp import lab

        with mock.patch.object(crawl, "discover_seeds", lambda explicit: ["172.20.20.254"]), \
                mock.patch.object(crawl, "SnmpClient", lambda *a, **k: lab()):
            doc = crawl.crawl_document(Config(credentials=CRED, seeds=[]))
        polled = [n.get("hostname") or n["ip"] for n in doc["nodes"] if n.get("pollable")]
        self.assertEqual(sorted(doc["poll_seconds"]), sorted(polled))
        self.assertTrue(all(s >= 0 for s in doc["poll_seconds"].values()))
        self.assertEqual(doc["bulk_fallback"], [])


if __name__ == "__main__":
    unittest.main()
