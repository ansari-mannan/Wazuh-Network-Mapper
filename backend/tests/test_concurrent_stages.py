"""Reverse DNS and nmap run beside the device CVE stage: the outputs are the
same as a run that takes the stages one after another (but for the notes
saying so), nmap really does overlap the name lookups, and each stage's time is
its own work."""

import offline  # noqa: F401  (no test reaches the internet)
import json
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

import test_golden
import test_service_scan
from vulnmapper import hosts, pipeline

SLOW_S = 0.3
ALONGSIDE = " (ran alongside Device CVEs)"


def without_alongside(produced: dict) -> dict:
    """The notes as a sequential run writes them."""
    return json.loads(json.dumps(produced).replace(ALONGSIDE, ""))


class TestConcurrentStages(unittest.TestCase):
    def test_outputs_match_a_sequential_run(self):
        for name in ("lab", "unmanaged"):
            with self.subTest(scenario=name):
                with mock.patch.object(pipeline, "CONCURRENT", False):
                    sequential = test_golden.produce(name)
                concurrent = test_golden.produce(name)
                self.assertEqual(without_alongside(concurrent), sequential)
                if name == "unmanaged":
                    notes = {st["name"]: st["note"] for st in
                             concurrent["unmanaged.graph.json"]["metadata"]["stages"]}
                    for stage in ("Reverse DNS names", "nmap service scan"):
                        self.assertTrue(notes[stage].endswith(ALONGSIDE), notes[stage])
                    self.assertNotIn(ALONGSIDE, json.dumps(sequential))

    def test_nmap_overlaps_the_name_lookups(self):
        spans = {}
        run_name_lookup, scan = hosts.run_name_lookup, test_service_scan.FakeRunner.scan

        def slow(key, fn):
            def wrapped(*a, **kw):
                start = time.monotonic()
                time.sleep(SLOW_S)
                try:
                    return fn(*a, **kw)
                finally:
                    spans[key] = (start, time.monotonic(), threading.current_thread().name)
            return wrapped

        with mock.patch.object(hosts, "run_name_lookup", slow("names", run_name_lookup)), \
                mock.patch.object(test_service_scan.FakeRunner, "scan", slow("nmap", scan)):
            produced = test_golden.produce("unmanaged")
        (n0, n1, n_thread), (m0, m1, m_thread) = spans["names"], spans["nmap"]
        self.assertLess(max(n0, m0), min(n1, m1))          # the two spans overlap
        self.assertNotEqual(n_thread, m_thread)
        # the outputs are still the frozen ones
        with open(f"{test_golden._GOLDEN}/unmanaged.graph.json", encoding="utf-8") as f:
            self.assertEqual(test_golden.dump(produced["unmanaged.graph.json"]), f.read())

    def test_each_stage_times_its_own_work(self):
        # NVD slow for the device CVE stage; nmap fast (as when served from its cache)
        run_device_cves = pipeline.run_device_cves

        def slow_nvd(scan):
            time.sleep(SLOW_S)
            return run_device_cves(scan)

        tmp = tempfile.mkdtemp()
        try:
            with mock.patch.object(pipeline, "run_device_cves", slow_nvd):
                graph = test_golden._unmanaged(tmp)["unmanaged.graph.json"]
        finally:
            shutil.rmtree(tmp)
        seconds = {st["name"]: st["seconds"] for st in graph["metadata"]["stages"]}
        self.assertGreaterEqual(seconds["Device CVEs (NVD)"], SLOW_S)
        self.assertLess(seconds["nmap service scan"], 0.1)      # not the group's time
        self.assertLess(seconds["Reverse DNS names"], 0.1)
        timing = graph["metadata"]["timing"]
        self.assertGreaterEqual(timing["alongside_device_cves_s"], SLOW_S)
        self.assertLess(timing["nmap_s"], 0.1)


if __name__ == "__main__":
    unittest.main()
