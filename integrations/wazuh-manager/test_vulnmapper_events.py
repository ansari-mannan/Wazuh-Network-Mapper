"""Tests for the event emitter. Run from this directory:

    python -m unittest test_vulnmapper_events

The emitter reads its paths from the environment at import time, so each test
imports it fresh against a temporary data directory.
"""
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(os.path.dirname(os.path.dirname(HERE)), "data")


def load_emitter(data_dir):
    os.environ["VM_DATA"] = data_dir
    os.environ["VM_PREV"] = os.path.join(data_dir, "last-good")
    os.environ["VM_EVENTS"] = os.path.join(data_dir, "events.json")
    os.environ["VM_SCANNER"] = "scanner.test"
    spec = importlib.util.spec_from_loader(
        "vulnmapper_events",
        importlib.machinery.SourceFileLoader(
            "vulnmapper_events", os.path.join(HERE, "vulnmapper-events")
        ),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EmitterTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.prev = os.path.join(self.dir, "last-good")
        os.makedirs(self.prev)
        for name in ("graph.json", "vulnerabilities.json", "attack_paths.json"):
            shutil.copy(os.path.join(SAMPLE, name), os.path.join(self.dir, name))
            shutil.copy(os.path.join(SAMPLE, name), os.path.join(self.prev, name))

    def write(self, where, name, doc):
        with open(os.path.join(where, name), "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def read(self, where, name):
        with open(os.path.join(where, name), encoding="utf-8") as fh:
            return json.load(fh)

    def run_emitter(self):
        load_emitter(self.dir).main()
        path = os.path.join(self.dir, "events.json")
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_unchanged_scan_emits_only_the_result(self):
        events = self.run_emitter()
        self.assertEqual([e["event"] for e in events], ["scan_result"])
        self.assertEqual(events[0]["result"], "OK")
        self.assertEqual(events[0]["severity_class"], "normal")
        self.assertEqual(events[0]["integration"], "vulnmapper")
        self.assertIn("devices", events[0])

    def test_status_file_overrides_the_derived_result(self):
        self.write(self.dir, "scan-status.json",
                   {"result": "FAIL", "detail": "publish gate"})
        events = self.run_emitter()
        self.assertEqual([e["event"] for e in events], ["scan_result"])
        self.assertEqual(events[0]["severity_class"], "critical")
        self.assertEqual(events[0]["detail"], "publish gate")

    def test_device_firmware_and_link_changes(self):
        old = self.read(self.prev, "graph.json")
        device = next(n for n in old["nodes"] if n["kind"] == "device")
        device["firmware"] = "old-1.0"
        extra = dict(device, node_id="device:0c:00:00:00:10:99", hostname="gone-sw")
        old["nodes"].append(extra)
        old["edges"] = []
        self.write(self.prev, "graph.json", old)

        new = self.read(self.dir, "graph.json")
        new_device = next(n for n in new["nodes"] if n["kind"] == "device")
        new_device["firmware"] = "new-2.0"
        new["nodes"].append(dict(new_device, node_id="device:0c:00:00:00:10:98",
                                 hostname="added-sw", ip="10.10.0.98"))
        self.write(self.dir, "graph.json", new)

        kinds = [e["event"] for e in self.run_emitter()]
        self.assertEqual(kinds[0], "scan_result")
        for expected in ("device_new", "device_removed", "firmware_change",
                         "link_change"):
            self.assertIn(expected, kinds)

    def test_new_findings_are_classified(self):
        old = self.read(self.prev, "vulnerabilities.json")
        for host in old["hosts"].values():
            host["findings"] = []
        self.write(self.prev, "vulnerabilities.json", old)

        new = self.read(self.dir, "vulnerabilities.json")
        host = next(h for h in new["hosts"].values() if h.get("findings"))
        host["findings"][0]["tier"] = "P0"
        if len(host["findings"]) > 1:
            host["findings"][1]["tier"] = "P1"
            host["findings"][1]["kev"] = False
        self.write(self.dir, "vulnerabilities.json", new)

        events = self.run_emitter()
        classes = {e["severity_class"] for e in events if e["event"] == "finding_new"}
        self.assertIn("critical", classes)
        self.assertTrue(classes <= {"critical", "high", "normal"})

    def test_a_cap_emits_one_truncated_event(self):
        module = load_emitter(self.dir)
        module.MAX_FINDINGS = 1
        old = self.read(self.prev, "vulnerabilities.json")
        for host in old["hosts"].values():
            host["findings"] = []
        self.write(self.prev, "vulnerabilities.json", old)
        module.main()
        with open(os.path.join(self.dir, "events.json"), encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]
        kinds = [e["event"] for e in events]
        self.assertEqual(kinds.count("finding_new"), 1)
        self.assertEqual(kinds.count("finding_truncated"), 1)
        truncated = next(e for e in events if e["event"] == "finding_truncated")
        self.assertGreater(truncated["total"], truncated["emitted"])

    def test_new_attack_paths(self):
        old = self.read(self.prev, "attack_paths.json")
        for target in old["targets"]:
            target["routes"] = []
        self.write(self.prev, "attack_paths.json", old)

        new = self.read(self.dir, "attack_paths.json")
        new["targets"][0]["routes"] = [{
            "target": new["targets"][0]["id"],
            "start": "endpoint:101",
            "importance": "high",
            "likelihood": "likely",
            "steps": [{"kind": "same-subnet", "check": "reachable"}],
        }]
        self.write(self.dir, "attack_paths.json", new)

        events = self.run_emitter()
        path = next(e for e in events if e["event"] == "attack_path_new")
        self.assertEqual(path["severity_class"], "critical")
        self.assertEqual(path["hops"], 1)

    def test_rotation_keeps_logcollector_following_a_new_inode(self):
        module = load_emitter(self.dir)
        module.MAX_BYTES = 1
        out = os.path.join(self.dir, "events.json")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write('{"event": "old"}\n')
        module.main()
        self.assertTrue(os.path.exists(out + ".1"))
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(len(fh.readlines()), 1)


if __name__ == "__main__":
    unittest.main()
