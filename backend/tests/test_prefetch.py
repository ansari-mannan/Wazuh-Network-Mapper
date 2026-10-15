"""The CVE record prefetch: cve.org is asked in the background from the moment
the scan knows its CVEs, so the fetch overlaps the crawl; with
--records-in-background the OVSS stage waits at most RECORDS_WAIT_S, the
outputs are written while the fetch goes on, and a rescore afterwards uses
what arrived late."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_scoring import cve_record
from vulnmapper.devicecves.nvd import SystemClock
from vulnmapper.network import crawl
from vulnmapper.pipeline import Pipeline
from vulnmapper.scoring import cvss_select, rescore, stage

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

    def test_ovss_waits_briefly_then_the_fetch_finishes_after_the_outputs(self):
        done = threading.Event()
        logs = []
        self.assertEqual(stage.RECORDS_WAIT_S, 5.0)

        def scan():
            logs.append(self.run_pipeline("--network", NETWORK, "--records-in-background"))
            done.set()

        with mock.patch.object(stage, "RECORDS_WAIT_S", 0.3):
            worker = threading.Thread(target=scan)
            worker.start()
            # the outputs appear while LATE is still being fetched
            for _ in range(100):
                if os.path.exists(self.graph):
                    break
                time.sleep(0.05)
            self.assertFalse(done.is_set())
            graph = read(self.graph)
            ovss = next(s for s in graph["metadata"]["stages"] if s["name"] == "OVSS scoring")
            self.assertLess(ovss["seconds"], 5.0)
            finding = next(f for h in read(os.path.join(self.tmp, "vulnerabilities.json"))
                           ["hosts"].values() for f in h["findings"] if f["cve"] == LATE)
            self.assertEqual(finding["cvss_src"], "tool")          # not in hand yet
            self.org.release.set()
            worker.join(10)
        self.assertTrue(done.is_set())
        self.assertIn("CVE records after the scan: 1 new", logs[0])

        # the late record is cached, and a rescore (no network) scores with it
        cache = cvss_select.records_cache(os.path.join(self.tmp, cvss_select.FILENAME),
                                          SystemClock())
        self.assertTrue(cache.get(LATE)["found"])
        with contextlib.redirect_stderr(io.StringIO()):
            rescore.rescore(self.graph)
        finding = next(f for h in read(os.path.join(self.tmp, "vulnerabilities.json"))
                       ["hosts"].values() for f in h["findings"] if f["cve"] == LATE)
        self.assertEqual((finding["cvss_src"], finding["cvss_used"]), ("CNA", 5.0))

    def test_a_command_line_scan_waits_for_every_record(self):
        threading.Timer(0.3, self.org.release.set).start()
        log_text = self.run_pipeline("--network", NETWORK)
        finding = next(f for h in read(os.path.join(self.tmp, "vulnerabilities.json"))
                       ["hosts"].values() for f in h["findings"] if f["cve"] == LATE)
        self.assertEqual(finding["cvss_src"], "CNA")
        self.assertNotIn("CVE records after the scan", log_text)


if __name__ == "__main__":
    unittest.main()
