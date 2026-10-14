"""Tests never touch the network, and a download failure never aborts a scan."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import glob
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from vulnmapper.pipeline import Pipeline
from vulnmapper.scoring import feeds

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
# an import a test module needs to run a scan, or the OVSS downloads directly
SCAN_PATH = re.compile(r"^\s*(?:from|import) .*(?:\bPipeline\b|devicecves\.__main__|"
                       r"vulnmapper\.scoring|vulnmapper\.attackpaths|"
                       r"vulnmapper import .*\b(?:attackpaths|scoring)\b)", re.M)


class TestEveryScanTestIsOffline(unittest.TestCase):
    def test_each_module_that_can_scan_imports_the_guard(self):
        """unittest never imports tests/__init__.py, so each module must."""
        missing = []
        for path in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if SCAN_PATH.search(text) and not re.search(r"^import offline\b", text, re.M):
                missing.append(os.path.basename(path))
        self.assertEqual(missing, [])


class ScanRun(unittest.TestCase):
    """A scan of the saved endpoints (with CVEs) and network, every NVD stage off."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def scan(self) -> dict:
        graph = os.path.join(self.tmp, "graph.json")
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"),
                "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-name-lookup", "-o", graph]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(graph, encoding="utf-8") as f:
            return json.load(f)

    def assert_scored_without_threat_data(self, graph: dict) -> None:
        feeds_block = graph["metadata"]["threat_feeds"]
        self.assertEqual((feeds_block["kev"], feeds_block["epss"]), ("unavailable", "unavailable"))
        self.assertGreater(graph["metadata"]["ovss"]["cve_records"]["unanswered"], 0)


class TestNoRealRequest(ScanRun):
    def test_a_scan_with_the_default_transports_sends_nothing(self):
        with mock.patch("requests.sessions.Session.send",
                        side_effect=AssertionError("a test attempted a real HTTP request")) as send:
            graph = self.scan()
        send.assert_not_called()
        self.assert_scored_without_threat_data(graph)


class TestDownloadFailureNeverAbortsAScan(ScanRun):
    """The real http_get, with requests failing in ways it does not expect."""

    def test_unexpected_exceptions_leave_the_feeds_unavailable(self):
        for name, get in (("TypeError", mock.Mock(side_effect=TypeError("boom"))),
                          ("not a context manager", mock.Mock())):
            with self.subTest(name), mock.patch.object(feeds, "http_get", offline.REAL_HTTP_GET), \
                    mock.patch("requests.get", get), \
                    self.assertLogs("vulnmapper.scoring", "WARNING") as logs:
                graph = self.scan()
            get.assert_called()
            self.assert_scored_without_threat_data(graph)
            text = "\n".join(logs.output)
            self.assertNotIn("boom", text)                 # the exception type only

    def test_http_get_turns_any_failure_into_feed_unavailable(self):
        with mock.patch("requests.get", side_effect=TypeError("boom")):
            with self.assertRaisesRegex(feeds.FeedUnavailable, "^TypeError$"):
                offline.REAL_HTTP_GET("https://feed", 20.0)


if __name__ == "__main__":
    unittest.main()
