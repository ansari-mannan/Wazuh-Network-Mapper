"""The CVE record prefetch: cve.org is asked in the background from the moment
the scan knows its CVEs, so the fetch overlaps the crawl."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from test_scoring import cve_record
from vulnmapper.network import crawl
from vulnmapper.pipeline import Pipeline

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SCORED = os.path.join(FIXTURES, "offline_scored.json")
NETWORK = os.path.join(FIXTURES, "offline_network.json")
LATE = "CVE-2026-90000"          # the worst CVE, so fetched first


class SlowCveOrg:
    """Serves a CNA 5.0 for every CVE. ``LATE`` waits for ``release``; every
    request sets ``asked``."""

    def __init__(self):
        self.asked = threading.Event()
        self.release = threading.Event()

    def __call__(self, url, timeout):
        if "/api/cve/" not in url:
            return 404, b""                   # no KEV / EPSS feed
        self.asked.set()
        if url.endswith(LATE):
            self.release.wait(10)
        return 200, cve_record(5.0)


def read(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestPrefetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph = os.path.join(self.tmp, "graph.json")
        self.org = SlowCveOrg()

    def tearDown(self):
        self.org.release.set()
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra):
        argv = ["--scored", SCORED, "--no-device-cves", "--no-cve-vectors", "--no-name-lookup",
                "-o", self.graph, *extra]
        with contextlib.redirect_stdout(io.StringIO()), self.assertLogs("vulnmapper", "INFO") as logs:
            self.assertEqual(Pipeline(threat_transport=self.org).run(argv), 0)
        return "\n".join(logs.output)

    def test_the_fetch_overlaps_the_crawl(self):
        seen = []

        def slow_crawl(cfg):
            # cve.org is asked while the crawl is still running
            seen.append(self.org.asked.wait(5))
            return read(NETWORK)

        self.org.release.set()
        with mock.patch.object(crawl, "crawl_document", slow_crawl):
            self.run_pipeline("--community", "x")
        self.assertEqual(seen, [True])

    def test_a_command_line_scan_waits_for_every_record(self):
        threading.Timer(0.3, self.org.release.set).start()
        log_text = self.run_pipeline("--network", NETWORK)
        finding = next(f for h in read(os.path.join(self.tmp, "vulnerabilities.json"))
                       ["hosts"].values() for f in h["findings"] if f["cve"] == LATE)
        self.assertEqual(finding["cvss_src"], "CNA")
        self.assertNotIn("CVE records after the scan", log_text)


if __name__ == "__main__":
    unittest.main()
