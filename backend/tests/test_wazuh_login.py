"""The Wazuh login: retried a few times, then one plain message and a failed scan.

For hours after the Wazuh server restarts its API refuses or times out. The scan
must not die with a traceback, and must not go on with a graph that has lost
every PC (the plugin keeps the previous graph only when a scan fails).
"""

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import requests

from vulnmapper import endpoints as ep_mod
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

    def test_a_rejected_password_is_not_retried(self):
        class Rejected:
            ok = False
            status_code = 401
            reason = "Unauthorized"
            text = "Invalid credentials"

        with self.assertRaises(requests.HTTPError):
            src = source()
            with mock.patch.object(ep_mod.requests, "post", return_value=Rejected()), \
                    mock.patch.object(ep_mod.time, "sleep") as sleep:
                src.collect()
        self.assertEqual(sleep.call_count, 0)


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
                Pipeline().run(["--no-network", "-o", graph, "--no-device-cves"])
            self.assertNotEqual(ctx.exception.code, 0)
            self.assertIn("did not answer the login", str(ctx.exception.code))
            self.assertEqual(os.listdir(tmp), [])          # no graph, no vulnerabilities file


if __name__ == "__main__":
    unittest.main()
