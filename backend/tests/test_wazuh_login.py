"""The Wazuh login: retried a few times, then one plain message and a failed scan.

For hours after the Wazuh server restarts its API refuses or times out. The scan
must not die with a traceback, and must not go on with a graph that has lost
every PC (the plugin keeps the previous graph only when a scan fails).
"""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import requests

from vulnmapper.endpoints import wazuh as ep_mod
from vulnmapper.endpoints import WazuhSource
from vulnmapper.pipeline import Pipeline
from vulnmapper.schema import IndexerConfig, WazuhConfig


def source():
    return WazuhSource(WazuhConfig(host="wazuh.example", port="55000", user="u",
                                   password="not-a-real-password"),
                       IndexerConfig(host="i", port="9200", user="u", password="p"))


class Answer:
    ok = True
    status_code = 200

    def json(self):
        return {"data": {"token": "T"}}


class TestLoginRetry(unittest.TestCase):
    def collect(self, outcomes):
        """Run collect() with requests.post giving ``outcomes`` in turn."""
        calls = []

        def post(*args, **kwargs):
            calls.append(kwargs.get("timeout"))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        src = source()
        with mock.patch.object(ep_mod.requests, "post", post), \
                mock.patch.object(ep_mod.time, "sleep") as sleep, \
                mock.patch.object(WazuhSource, "_get", return_value=[]):
            try:
                result = src.collect()
            except SystemExit as e:
                result = e
        return result, calls, sleep

    def test_refused_then_answered_goes_on(self):
        result, calls, sleep = self.collect([requests.ConnectionError("refused"),
                                             requests.Timeout("slow"), Answer()])
        self.assertEqual(result, [])
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_never_answering_ends_with_one_plain_line(self):
        result, calls, sleep = self.collect([requests.ConnectionError("refused")] * 3)
        self.assertIsInstance(result, SystemExit)
        message = str(result.code)
        self.assertTrue(message.startswith("vulnmapper: "))
        self.assertIn("wazuh.example:55000", message)
        self.assertIn("did not answer the login", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("not-a-real-password", message)
        self.assertEqual(len(calls), ep_mod.LOGIN_ATTEMPTS)
        self.assertEqual(sleep.call_count, ep_mod.LOGIN_ATTEMPTS - 1)

    def test_a_timeout_is_named(self):
        result, _, _ = self.collect([requests.Timeout("slow")] * 3)
        self.assertIn("timed out", str(result.code))

    def rejected(self, status):
        class Rejected:
            ok = False
            status_code = status
            reason = "Unauthorized"
            text = "Invalid credentials for not-a-real-password"

        posts = []

        def post(*args, **kwargs):
            posts.append(1)
            return Rejected()
        src = source()
        with mock.patch.object(ep_mod.requests, "post", post), \
                mock.patch.object(ep_mod.time, "sleep") as sleep:
            try:
                src.collect()
            except BaseException as e:      # SystemExit is the point
                return e, len(posts), sleep.call_count
        self.fail("a rejected login went on")

    def test_a_rejected_login_ends_at_once_with_one_plain_line(self):
        for status in (401, 403):
            error, posts, sleeps = self.rejected(status)
            self.assertIsInstance(error, SystemExit, status)
            message = str(error.code)
            self.assertEqual(message,
                             f"vulnmapper: the Wazuh Manager API at wazuh.example:55000 rejected "
                             f"the login (HTTP {status}); check WAZUH_USER and WAZUH_PASS.")
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)   # no "during handling" traceback
            self.assertEqual((posts, sleeps), (1, 0))     # not retried

    def test_other_http_errors_are_not_turned_into_a_login_message(self):
        error, posts, sleeps = self.rejected(500)
        self.assertIsInstance(error, requests.HTTPError)
        self.assertEqual((posts, sleeps), (1, 0))


class TestScanFailsCleanly(unittest.TestCase):
    def test_no_graph_without_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = os.path.join(tmp, "graph.json")
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"WAZUH_PASS": "x", "INDEXER_PASS": "y",
                                              "WAZUH_HOST": "wazuh.example"}), \
                    mock.patch.object(ep_mod.requests, "post",
                                      side_effect=requests.ConnectionError("refused")), \
                    mock.patch.object(ep_mod.time, "sleep"), \
                    contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
                Pipeline().run(["--no-network", "-o", graph, "--no-device-cves", "--no-cve-vectors",
                                "--no-name-lookup"])
            self.assertNotEqual(ctx.exception.code, 0)
            self.assertIn("did not answer the login", str(ctx.exception.code))
            self.assertEqual(os.listdir(tmp), [])          # no graph, no vulnerabilities file

    def test_rejected_login_prints_one_line_and_writes_nothing(self):
        """Run as the plugin does: a child process, stderr read back."""
        import subprocess
        import sys
        import textwrap
        with tempfile.TemporaryDirectory() as tmp:
            graph = os.path.join(tmp, "graph.json")
            script = textwrap.dedent(f"""
                from unittest import mock
                import requests
                from vulnmapper.endpoints import wazuh as endpoints
                from vulnmapper.pipeline import Pipeline

                class Rejected:
                    ok, status_code, reason, text = False, 401, "Unauthorized", "no"

                with mock.patch.object(endpoints.requests, "post", return_value=Rejected()):
                    Pipeline().run(["--no-network", "-o", {graph!r}, "--no-device-cves", "--no-cve-vectors", "--no-name-lookup"])
                """)
            env = dict(os.environ, WAZUH_PASS="not-a-real-password", INDEXER_PASS="y",
                       WAZUH_HOST="wazuh.example")
            here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            done = subprocess.run([sys.executable, "-c", script], cwd=here, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 1)
            lines = [line for line in done.stderr.splitlines() if line.strip()]
            self.assertEqual(lines[-1], "vulnmapper: the Wazuh Manager API at wazuh.example:55000 "
                                        "rejected the login (HTTP 401); check WAZUH_USER and "
                                        "WAZUH_PASS.")
            self.assertNotIn("Traceback", done.stderr)
            self.assertNotIn("not-a-real-password", done.stderr + done.stdout)
            self.assertEqual(done.stdout, "")
            self.assertEqual(os.listdir(tmp), [])


class TestAgentPaging(unittest.TestCase):
    """/agents is paged in collect() as in agent_status(): no 1000-agent cap."""

    def test_every_agent_is_collected(self):
        src = source()
        pages = [1000, 1000, 3]
        offsets = []

        def fake_get(path, params):
            offsets.append(params["offset"])
            n = pages[len(offsets) - 1]
            return [{"id": f"{params['offset'] + i + 1:05d}", "name": "pc", "ip": "10.0.0.1"}
                    for i in range(n)]

        with mock.patch.object(src, "_login"), mock.patch.object(src, "_get", fake_get), \
                mock.patch.object(src, "_inventory", return_value=([], [], [], [], False)):
            nodes = src.collect()
        self.assertEqual(len(nodes), 2003)
        self.assertEqual(offsets, [0, 1000, 2000])


class TestInventoryInParallel(unittest.TestCase):
    def test_a_few_agents_at_once_in_order(self):
        src = source()
        agents = [{"id": f"{i:03d}", "name": f"pc{i}", "ip": f"10.0.0.{i}"} for i in range(1, 21)]
        lock, state = threading.Lock(), {"now": 0, "max": 0}

        def slow_inventory(agent_id, is_server):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.002 * (30 - int(agent_id)))     # later agents finish first
            with lock:
                state["now"] -= 1
            mac = f"d4:be:d9:00:00:{int(agent_id):02x}"
            return ([{"name": "eth0", "mac": mac, "state": "up"}], [],
                    [{"iface": "eth0", "proto": "ipv4", "address": f"10.0.0.{int(agent_id)}"}], [], False)

        with mock.patch.object(src, "_login"), mock.patch.object(src, "_get", return_value=agents), \
                mock.patch.object(src, "_inventory", slow_inventory):
            nodes = src.collect()
        self.assertEqual([n["agent_id"] for n in nodes], [a["id"] for a in agents])
        self.assertEqual([n["mac"] for n in nodes],               # each with its own
                         [f"d4:be:d9:00:00:{i:02x}" for i in range(1, 21)])
        self.assertGreater(state["max"], 1)
        self.assertLessEqual(state["max"], ep_mod.INVENTORY_WORKERS)


class TestTlsWarning(unittest.TestCase):
    def warnings(self, wazuh_verify, indexer_verify):
        return WazuhSource(WazuhConfig(host="w", port="55000", user="u", password="p",
                                       verify=wazuh_verify),
                           IndexerConfig(host="i", port="9200", user="u", password="p",
                                         verify=indexer_verify)).tls_warnings()

    def test_names_each_unverified_service(self):
        self.assertEqual(self.warnings(False, "/ca.pem"),
                         [{"type": "tls_unverified", "services": ["Wazuh Manager API"]}])
        self.assertEqual(self.warnings(False, False)[0]["services"],
                         ["Wazuh Manager API", "Wazuh Indexer"])

    def test_none_when_both_verify(self):
        self.assertEqual(self.warnings(True, "/ca.pem"), [])

    def test_a_live_scan_puts_it_on_the_graph(self):
        source = mock.Mock(collect=mock.Mock(return_value=[]), score=mock.Mock(return_value=[]),
                           cves={}, collect_warnings=[], warnings=[],
                           tls_warnings=mock.Mock(return_value=[{"type": "tls_unverified",
                                                                 "services": ["Wazuh Indexer"]}]))
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("vulnmapper.endpoints.WazuhSource", return_value=source), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            out = os.path.join(tmp, "graph.json")
            self.assertEqual(Pipeline().run(["--no-network", "--no-device-cves", "--no-cve-vectors",
                                             "--no-name-lookup", "-o", out]), 0)
            with open(out, encoding="utf-8") as f:
                warnings = json.load(f)["metadata"]["warnings"]
        self.assertIn({"type": "tls_unverified", "services": ["Wazuh Indexer"]}, warnings)

if __name__ == "__main__":
    unittest.main()
