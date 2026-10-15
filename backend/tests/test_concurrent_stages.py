"""Reverse DNS and nmap run beside the device CVE stage: the outputs are the
same as a run that takes the stages one after another, and nmap really does
overlap the name lookups."""

import offline  # noqa: F401  (no test reaches the internet)
import threading
import time
import unittest
from unittest import mock

import test_golden
import test_service_scan
from vulnmapper import hosts, pipeline

SLOW_S = 0.3


class TestConcurrentStages(unittest.TestCase):
    def test_outputs_match_a_sequential_run(self):
        for name in ("lab", "unmanaged"):
            with self.subTest(scenario=name):
                with mock.patch.object(pipeline, "CONCURRENT", False):
                    sequential = test_golden.produce(name)
                self.assertEqual(test_golden.produce(name), sequential)

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
        # the outputs are still the frozen (sequential) ones
        with open(f"{test_golden._GOLDEN}/unmanaged.graph.json", encoding="utf-8") as f:
            self.assertEqual(test_golden.dump(produced["unmanaged.graph.json"]), f.read())


if __name__ == "__main__":
    unittest.main()
