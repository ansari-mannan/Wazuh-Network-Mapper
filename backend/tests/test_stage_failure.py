"""An optional stage that crashes is recorded and skipped; the scan still
writes its graph. A malformed targets.json is ignored with a warning."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from vulnmapper import pipeline
from vulnmapper.pipeline import Pipeline

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TestStageFailure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.graph = os.path.join(self.tmp, "graph.json")
        self.paths = os.path.join(self.tmp, "attack_paths.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def scan(self) -> dict:
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"),
                "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-name-lookup", "-o", self.graph]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(self.graph, encoding="utf-8") as f:
            return json.load(f)

    def stage(self, graph, name):
        return next(s for s in graph["metadata"]["stages"] if s["name"] == name)

    def test_a_crashing_stage_is_recorded_and_the_scan_goes_on(self):
        with mock.patch.object(pipeline, "run_checklist", side_effect=KeyError("boom")), \
                self.assertLogs("vulnmapper.pipeline", "ERROR"):
            graph = self.scan()
        self.assertIn({"type": "stage_failed", "stage": "Configuration checks", "error": "KeyError"},
                      graph["metadata"]["warnings"])
        self.assertEqual(self.stage(graph, "Configuration checks")["status"], "failed")
        self.assertEqual(self.stage(graph, "Attack paths")["status"], "ran")
        self.assertTrue(os.path.exists(self.paths))

    def test_ovss_failing_skips_the_attack_paths(self):
        with mock.patch.object(pipeline, "run_ovss", side_effect=ValueError("boom")), \
                self.assertLogs("vulnmapper.pipeline", "ERROR"):
            graph = self.scan()
        self.assertEqual(self.stage(graph, "OVSS scoring")["status"], "failed")
        self.assertEqual(self.stage(graph, "Attack paths"),
                         {"name": "Attack paths", "status": "skipped", "seconds": None,
                          "note": "OVSS failed"})
        self.assertFalse(os.path.exists(self.paths))

    def test_attack_paths_failing_writes_no_file(self):
        with mock.patch.object(pipeline.attackpaths, "run_attack_paths",
                               side_effect=RuntimeError("boom")), \
                self.assertLogs("vulnmapper.pipeline", "ERROR"):
            graph = self.scan()
        self.assertEqual(self.stage(graph, "Attack paths")["status"], "failed")
        self.assertFalse(os.path.exists(self.paths))

    def test_malformed_targets_are_ignored(self):
        for body in ('["not", "a", "dict"]', '{"x": {"importance": "urgent"}}', "{broken"):
            with self.subTest(body), open(os.path.join(self.tmp, "targets.json"), "w") as f:
                f.write(body)
            with self.subTest(body), self.assertLogs("vulnmapper.attackpaths", "WARNING"):
                self.scan()
            with open(self.paths, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["metadata"]["state"], "no_targets")


if __name__ == "__main__":
    unittest.main()
